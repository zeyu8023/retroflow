import socket
import struct
import threading
import time
import json
import logging
import os
import sqlite3
import psutil
from flask import Flask, jsonify, send_file, request
import docker

# --- 端口映射 (仅用于 Host 模式容器的识别) ---
PORT_MAP = {
    8096: "Emby (媒体)", 8920: "Emby (SSL)",
    32400: "Plex", 8090: "Jellyfin",
    8080: "Qbittorrent", 8999: "QB管理口",
    9091: "Transmission", 51413: "Transmission数据",
    10308: "RetroFlow",
    80: "Web (HTTP)", 443: "Web (SSL)",
    445: "SMB共享", 22: "SSH",
    3306: "MySQL", 6379: "Redis",
    8123: "HomeAssistant", 5000: "DSM", 5001: "DSM (SSL)"
}

stats_store = {}
last_saved_stats = {}
system_status = {}
# 用于存储 Docker API 上一次的读数，用来计算增量
docker_last_read = {} 

lock = threading.Lock()

app = Flask(__name__)
try:
    docker_client = docker.from_env()
except:
    docker_client = None

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
DB_PATH = 'data/traffic.db'

def init_db():
    if not os.path.exists('data'): os.makedirs('data')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS history 
                 (timestamp INTEGER, name TEXT, upload INTEGER, download INTEGER)''')
    c.execute('''CREATE INDEX IF NOT EXISTS idx_time ON history (timestamp)''')
    conn.commit()
    conn.close()

def ensure_stats(name, net_type):
    if name not in stats_store:
        stats_store[name] = {"name": name, "type": net_type, "upload": 0, "download": 0}

# --- 引擎 A: Docker API 直读 (针对 Bridge 模式) ---
def start_docker_monitor():
    """直接读取容器虚拟网卡的计数器，100% 精准"""
    logging.info("🚀 [引擎A] Docker API 监控已启动 (Bridge精准模式)")
    while True:
        if not docker_client:
            time.sleep(5)
            continue
            
        try:
            containers = docker_client.containers.list()
            
            for c in containers:
                name = c.name
                net_mode = c.attrs['HostConfig']['NetworkMode']
                
                # 只处理非 Host 模式 (Bridge, Macvlan 等)
                if net_mode != 'host':
                    with lock:
                        ensure_stats(name, "bridge")
                    
                    try:
                        # 获取实时统计 (不流式，只取一次快照)
                        stats = c.stats(stream=False)
                        
                        # 计算流量总和 (可能有多个网卡)
                        rx_total = 0 # 下载
                        tx_total = 0 # 上传
                        networks = stats.get('networks', {})
                        
                        if networks:
                            for iface, data in networks.items():
                                rx_total += data['rx_bytes']
                                tx_total += data['tx_bytes']
                        
                        # --- 差值计算逻辑 ---
                        # Docker API 返回的是容器启动后的累计总量
                        # 我们需要计算 "自上次读取以来增加了多少"
                        if name in docker_last_read:
                            last_rx = docker_last_read[name]['rx']
                            last_tx = docker_last_read[name]['tx']
                            
                            # 计算增量 (如果重启了容器，数值变小，则忽略本次)
                            delta_rx = rx_total - last_rx
                            delta_tx = tx_total - last_tx
                            
                            if delta_rx >= 0 and delta_tx >= 0:
                                with lock:
                                    # 累加到我们的主存储里
                                    stats_store[name]['download'] += delta_rx
                                    stats_store[name]['upload'] += delta_tx
                        
                        # 更新上一次读数
                        docker_last_read[name] = {'rx': rx_total, 'tx': tx_total}
                        
                    except Exception as e:
                        # 容器可能刚启动或正好停止
                        pass

        except Exception as e:
            logging.error(f"Docker API 轮询错误: {e}")
            
        # 1秒刷新一次，保证实时性
        time.sleep(1)

# --- 引擎 B: 抓包 (针对 Host 模式) ---
def start_sniffer(interface="eth0"):
    """针对 Host 模式容器的端口流量分析"""
    logging.info(f"🕸️ [引擎B] 抓包监控已启动 (Host兼容模式) - {interface}")
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        sock.bind((interface, 0))
    except Exception as e:
        logging.error(f"❌ 抓包失败: {e}")
        return

    while True:
        try:
            raw_data, _ = sock.recvfrom(65535)
            packet_len = len(raw_data)
            
            if raw_data[12:14] != b'\x08\x00': continue # IPv4
            ip_h = raw_data[14:34]
            if ip_h[9] != 6 and ip_h[9] != 17: continue # TCP/UDP
            
            ihl = (ip_h[0] & 0xF) * 4
            src_port, dst_port = struct.unpack('!HH', raw_data[14+ihl:14+ihl+4])

            with lock:
                # 仅匹配 Host 模式的已知端口
                # Bridge 模式的流量由引擎 A 接管，这里不再处理，避免重复或误判
                
                # 下载
                if dst_port in PORT_MAP:
                    name = PORT_MAP[dst_port]
                    # 只有当该服务被标记为 host 时才由抓包统计
                    # (或者尚未被识别类型的服务)
                    if name not in stats_store or stats_store[name]['type'] == 'host':
                        ensure_stats(name, "host")
                        stats_store[name]["download"] += packet_len
                
                # 上传
                if src_port in PORT_MAP:
                    name = PORT_MAP[src_port]
                    if name not in stats_store or stats_store[name]['type'] == 'host':
                        ensure_stats(name, "host")
                        stats_store[name]["upload"] += packet_len
        except:
            continue

# --- 系统监控 ---
def monitor_system_task():
    while True:
        try:
            with lock:
                system_status['cpu'] = psutil.cpu_percent(interval=None)
                mem = psutil.virtual_memory()
                system_status['mem_percent'] = mem.percent
                system_status['boot_time'] = psutil.boot_time()
        except: pass
        time.sleep(2)

# --- 历史记录 ---
def save_history_task():
    while True:
        time.sleep(60)
        timestamp = int(time.time())
        with lock:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            for name, data in stats_store.items():
                curr_up, curr_down = data['upload'], data['download']
                last = last_saved_stats.get(name, {'u':0, 'd':0})
                du, dd = curr_up - last['u'], curr_down - last['d']
                if du > 0 or dd > 0:
                    c.execute("INSERT INTO history VALUES (?,?,?,?)", (timestamp, name, du, dd))
                last_saved_stats[name] = {'u': curr_up, 'd': curr_down}
            conn.commit()
            conn.close()

# --- 路由 ---
@app.route('/')
def index(): return send_file('index.html')

@app.route('/api/status')
def get_status():
    with lock:
        return jsonify({"containers": list(stats_store.values()), "system": system_status})

@app.route('/api/history')
def get_history():
    range_arg = request.args.get('range', 'day')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = int(time.time())
    if range_arg == 'day': start, fmt = now-86400, '%H:00'
    elif range_arg == 'month': start, fmt = now-2592000, '%m-%d'
    else: start, fmt = now-31536000, '%Y-%m'
    
    c.execute(f"SELECT strftime('{fmt}', datetime(timestamp, 'unixepoch', 'localtime')) as t, name, sum(upload), sum(download) FROM history WHERE timestamp > ? GROUP BY t, name ORDER BY timestamp", (start,))
    rows = c.fetchall()
    conn.close()
    
    res = {}
    for t, n, u, d in rows:
        if t not in res: res[t] = {}
        if n not in res[t]: res[t][n] = {'up':0, 'down':0}
        res[t][n]['up']+=u; res[t][n]['down']+=d
    return jsonify(res)

if __name__ == '__main__':
    init_db()
    # 启动双引擎
    threading.Thread(target=start_sniffer, args=("eth0",), daemon=True).start()
    threading.Thread(target=start_docker_monitor, daemon=True).start()
    threading.Thread(target=save_history_task, daemon=True).start()
    threading.Thread(target=monitor_system_task, daemon=True).start()
    
    logging.info("🚀 RetroFlow Dual-Engine Ready :10308")
    app.run(host='0.0.0.0', port=10308)