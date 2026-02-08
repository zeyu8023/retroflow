import socket
import struct
import threading
import time
import json
import logging
import os
import sqlite3
from flask import Flask, jsonify, send_file, request
import docker

# --- 核心配置区：在这里定义你的 NAS 服务 ---
# 格式：端口号: "显示名称"
# 即使 Docker API 挂了，这些服务也会强制显示在面板上
HOST_SERVICES = {
    # 媒体服务
    8096: "Emby",
    8920: "Emby (HTTPS)",
    32400: "Plex",
    8090: "Jellyfin",
    
    # 下载工具
    8080: "Qbittorrent",  # 如果你的 QB 是其他端口请修改
    8999: "Qbittorrent (UI)",
    9091: "Transmission",
    51413: "Transmission (Data)",
    
    # 核心服务
    10308: "RetroFlow",
    80: "Nginx (Web)",
    443: "Nginx (SSL)",
    
    # 文件与系统
    445: "SMB (文件共享)",
    22: "SSH (终端)",
    5000: "群晖 DSM",
    5001: "群晖 DSM (SSL)",
    
    # 数据库
    3306: "MySQL",
    6379: "Redis",
    
    # 智能家居
    8123: "HomeAssistant"
}

# --- 全局数据 ---
stats_store = {}
last_saved_stats = {}
lock = threading.Lock()

app = Flask(__name__)
try:
    # 尝试连接 Docker，如果失败也不会崩溃，会使用 HOST_SERVICES 兜底
    docker_client = docker.from_env()
except Exception as e:
    docker_client = None
    print(f"⚠️ Docker API 连接失败: {e} (将使用端口映射模式)")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
DB_PATH = 'data/traffic.db'

# --- 数据库 ---
def init_db():
    if not os.path.exists('data'):
        os.makedirs('data')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS history 
                 (timestamp INTEGER, name TEXT, upload INTEGER, download INTEGER)''')
    c.execute('''CREATE INDEX IF NOT EXISTS idx_time ON history (timestamp)''')
    conn.commit()
    conn.close()

def ensure_stats(name, net_type, init_only=False):
    """确保服务在列表中"""
    if name not in stats_store:
        stats_store[name] = {
            "name": name, 
            "type": net_type, 
            "upload": 0, 
            "download": 0,
            "speed_up": 0,
            "speed_down": 0
        }

# --- 初始化逻辑 (关键修改) ---
def init_services():
    """启动时把配置好的服务全部加载进去，防止列表为空"""
    with lock:
        # 1. 先加载手动配置的服务 (Host模式)
        for port, name in HOST_SERVICES.items():
            ensure_stats(name, "host")
            
        # 2. 再尝试加载 Docker 容器 (Bridge模式)
        if docker_client:
            try:
                containers = docker_client.containers.list()
                for c in containers:
                    # 如果容器名已经在手动配置里了，就跳过，避免重复
                    # 这里主要为了捕获那些不在 HOST_SERVICES 里的 Bridge 容器
                    if c.attrs['HostConfig']['NetworkMode'] != 'host':
                        ensure_stats(c.name, "bridge")
                logging.info(f"✅ Docker API 已连接，扫描到 {len(containers)} 个容器")
            except Exception as e:
                logging.error(f"❌ Docker 扫描失败: {e}")
        else:
            logging.warning("⚠️ 未检测到 Docker API，仅显示 HOST_SERVICES 配置的服务")

# --- 抓包模块 ---
def start_sniffer(interface="eth0"):
    logging.info(f"🕸️ [Sniffer] 开始监听 {interface}...")
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        sock.bind((interface, 0))
    except Exception as e:
        logging.error(f"❌ 抓包失败 (请确保 --privileged): {e}")
        return

    while True:
        try:
            raw_data, _ = sock.recvfrom(65535)
            packet_len = len(raw_data)
            
            # 快速解析 IP 头
            # 偏移14字节(Ethernet header)
            if raw_data[12:14] != b'\x08\x00': continue # 非 IPv4

            ip_header = raw_data[14:34]
            # 取出 IP 协议号 (第10个字节, index 9)
            protocol = ip_header[9] 
            if protocol != 6 and protocol != 17: continue # 非 TCP/UDP

            # 取出 IP 头长度 (前4位)
            ihl = (ip_header[0] & 0xF) * 4
            
            # 解析端口 (TCP/UDP 头的前4字节是 src_port, dst_port)
            transport_offset = 14 + ihl
            # struct unpack '!HH' 读取两个 unsigned short (2字节)
            src_port, dst_port = struct.unpack('!HH', raw_data[transport_offset:transport_offset+4])

            with lock:
                # 核心匹配逻辑：只匹配 HOST_SERVICES 定义的端口
                # 下载 (别人 -> NAS端口)
                if dst_port in HOST_SERVICES:
                    name = HOST_SERVICES[dst_port]
                    ensure_stats(name, "host")
                    stats_store[name]["download"] += packet_len
                
                # 上传 (NAS端口 -> 别人)
                if src_port in HOST_SERVICES:
                    name = HOST_SERVICES[src_port]
                    ensure_stats(name, "host")
                    stats_store[name]["upload"] += packet_len

        except Exception:
            continue

# --- Docker 监控 (Bridge) ---
def start_docker_monitor():
    while True:
        if not docker_client:
            time.sleep(10)
            continue
        try:
            # 只是为了发现新启动的 bridge 容器
            containers = docker_client.containers.list()
            for c in containers:
                if c.attrs['HostConfig']['NetworkMode'] != 'host':
                    with lock:
                        ensure_stats(c.name, "bridge")
        except:
            pass
        time.sleep(5)

# --- 历史记录 ---
def save_history_task():
    while True:
        time.sleep(60)
        timestamp = int(time.time())
        with lock:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            for name, data in stats_store.items():
                current_up = data['upload']
                current_down = data['download']
                last = last_saved_stats.get(name, {'upload': 0, 'download': 0})
                
                delta_up = current_up - last['upload']
                delta_down = current_down - last['download']
                
                if delta_up > 0 or delta_down > 0:
                    c.execute("INSERT INTO history VALUES (?, ?, ?, ?)", 
                              (timestamp, name, delta_up, delta_down))
                
                last_saved_stats[name] = {'upload': current_up, 'download': current_down}
            conn.commit()
            conn.close()

# --- 路由 ---
@app.route('/')
def index():
    return send_file('index.html')

@app.route('/api/realtime')
def get_realtime():
    with lock:
        # 简单按下载量排序，活跃的在前
        data = list(stats_store.values())
        return jsonify(data)

@app.route('/api/history')
def get_history():
    time_range = request.args.get('range', 'day')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = int(time.time())
    
    if time_range == 'day':
        start_time = now - 24 * 3600
        fmt = '%H:00'
    elif time_range == 'month':
        start_time = now - 30 * 24 * 3600
        fmt = '%m-%d'
    else:
        start_time = now - 365 * 24 * 3600
        fmt = '%Y-%m'

    sql = f"""
        SELECT strftime('{fmt}', datetime(timestamp, 'unixepoch', 'localtime')) as time_label,
               name, sum(upload), sum(download)
        FROM history WHERE timestamp > ?
        GROUP BY time_label, name
        ORDER BY timestamp
    """
    c.execute(sql, (start_time,))
    rows = c.fetchall()
    conn.close()
    
    result = {}
    for row in rows:
        label, name, up, down = row
        if label not in result: result[label] = {}
        if name not in result[label]: result[label][name] = {'up': 0, 'down': 0}
        result[label][name]['up'] += up
        result[label][name]['down'] += down
    return jsonify(result)

if __name__ == '__main__':
    init_db()
    # 关键：启动时就加载所有配置的服务
    init_services()
    
    t1 = threading.Thread(target=start_sniffer, args=("eth0",), daemon=True)
    t1.start()
    t2 = threading.Thread(target=start_docker_monitor, daemon=True)
    t2.start()
    t3 = threading.Thread(target=save_history_task, daemon=True)
    t3.start()

    logging.info("🚀 RetroFlow Ready :10308")
    app.run(host='0.0.0.0', port=10308)