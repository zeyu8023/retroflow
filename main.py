import socket
import struct
import threading
import time
import json
import logging
import os
import sqlite3
import psutil  # 新增：系统监控库
from flask import Flask, jsonify, send_file, request
import docker

# --- 端口映射字典 (仅用于将端口号翻译成中文名) ---
# 注意：这里不再强制显示，只有当有流量或容器存在时才用这个名字
PORT_MAP = {
    8096: "Emby (媒体服)",
    8920: "Emby (安全)",
    32400: "Plex (媒体)",
    8090: "Jellyfin",
    8080: "Qbittorrent",
    8999: "QB管理口",
    9091: "Transmission",
    51413: "Transmission数据",
    10308: "RetroFlow (本服务)",
    80: "Web服务 (HTTP)",
    443: "Web服务 (SSL)",
    445: "SMB文件共享",
    22: "SSH终端",
    5000: "群晖DSM",
    5001: "群晖DSM (SSL)",
    3306: "MySQL数据库",
    6379: "Redis缓存",
    8123: "HomeAssistant"
}

# --- 全局数据 ---
stats_store = {}
last_saved_stats = {}
system_status = {} # 存放CPU/内存信息
lock = threading.Lock()

app = Flask(__name__)
try:
    docker_client = docker.from_env()
except:
    docker_client = None

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
DB_PATH = 'data/traffic.db'

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

def ensure_stats(name, net_type):
    if name not in stats_store:
        stats_store[name] = {
            "name": name, 
            "type": net_type, 
            "upload": 0, 
            "download": 0
        }

# --- 任务A: 系统状态监控 (新功能) ---
def monitor_system_task():
    while True:
        try:
            cpu = psutil.cpu_percent(interval=1)
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # 获取网络总速率 (eth0)
            net_io = psutil.net_io_counters()
            
            with lock:
                system_status['cpu'] = cpu
                system_status['mem_percent'] = mem.percent
                system_status['mem_used'] = mem.used
                system_status['mem_total'] = mem.total
                system_status['disk_percent'] = disk.percent
                # 记录开机时间
                system_status['boot_time'] = psutil.boot_time()
        except Exception as e:
            logging.error(f"系统监控错误: {e}")
        time.sleep(2)

# --- 任务B: 抓包 (精准匹配) ---
def start_sniffer(interface="eth0"):
    logging.info(f"🕸️ [抓包] 开始监听 {interface}...")
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
            
            if raw_data[12:14] != b'\x08\x00': continue # 只看IPv4
            ip_header = raw_data[14:34]
            protocol = ip_header[9]
            if protocol != 6 and protocol != 17: continue # 只看TCP/UDP
            
            ihl = (ip_header[0] & 0xF) * 4
            src_port, dst_port = struct.unpack('!HH', raw_data[14+ihl:14+ihl+4])

            with lock:
                # 逻辑：只有当流量出现在“已知端口”时，才记录
                # 或者如果 Docker 扫描到了该端口的服务，也会自动关联
                
                # 下载流量 (外部 -> NAS端口)
                if dst_port in PORT_MAP:
                    name = PORT_MAP[dst_port]
                    ensure_stats(name, "host")
                    stats_store[name]["download"] += packet_len
                
                # 上传流量 (NAS端口 -> 外部)
                if src_port in PORT_MAP:
                    name = PORT_MAP[src_port]
                    ensure_stats(name, "host")
                    stats_store[name]["upload"] += packet_len

        except:
            continue

# --- 任务C: Docker 扫描 (只扫真实存在的) ---
def start_docker_monitor():
    while True:
        if not docker_client:
            time.sleep(10)
            continue
        try:
            containers = docker_client.containers.list()
            with lock:
                current_names = set()
                for c in containers:
                    # 获取容器名 (去掉斜杠)
                    raw_name = c.name
                    current_names.add(raw_name)
                    
                    # 只有 Bridge 模式的才需要强制添加
                    # Host 模式的容器通常通过端口抓包来识别，但也可以把它们列出来作为占位
                    net_mode = c.attrs['HostConfig']['NetworkMode']
                    
                    if net_mode != 'host':
                        # Bridge 容器直接用容器名
                        ensure_stats(raw_name, "bridge")
                    else:
                        # Host 容器尝试匹配端口名，匹配不到就用容器名
                        # 这里我们只记录容器名，不凭空猜测端口
                        # 如果你有特定需求，可以在这里做更多逻辑
                        if raw_name not in stats_store:
                            ensure_stats(raw_name, "host")
                            
        except Exception as e:
            logging.error(f"Docker API 错误: {e}")
        time.sleep(5)

# --- 任务D: 历史存储 ---
def save_history_task():
    while True:
        time.sleep(60)
        timestamp = int(time.time())
        with lock:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            for name, data in stats_store.items():
                curr_up = data['upload']
                curr_down = data['download']
                last = last_saved_stats.get(name, {'upload': 0, 'download': 0})
                
                delta_up = curr_up - last['upload']
                delta_down = curr_down - last['download']
                
                if delta_up > 0 or delta_down > 0:
                    c.execute("INSERT INTO history VALUES (?, ?, ?, ?)", 
                              (timestamp, name, delta_up, delta_down))
                last_saved_stats[name] = {'upload': curr_up, 'download': curr_down}
            conn.commit()
            conn.close()

# --- 路由 ---
@app.route('/')
def index():
    return send_file('index.html')

@app.route('/api/status')
def get_status():
    """返回所有信息：容器流量 + 系统状态"""
    with lock:
        return jsonify({
            "containers": list(stats_store.values()),
            "system": system_status
        })

@app.route('/api/history')
def get_history():
    time_range = request.args.get('range', 'day')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = int(time.time())
    
    if time_range == 'day':
        start = now - 86400
        fmt = '%H:00'
    elif time_range == 'month':
        start = now - 2592000
        fmt = '%m-%d'
    else:
        start = now - 31536000
        fmt = '%Y-%m'

    sql = f"""SELECT strftime('{fmt}', datetime(timestamp, 'unixepoch', 'localtime')) as t,
              name, sum(upload), sum(download) FROM history WHERE timestamp > ? 
              GROUP BY t, name ORDER BY timestamp"""
    c.execute(sql, (start,))
    rows = c.fetchall()
    conn.close()
    
    res = {}
    for r in rows:
        t, n, u, d = r
        if t not in res: res[t] = {}
        if n not in res[t]: res[t][n] = {'up':0, 'down':0}
        res[t][n]['up'] += u
        res[t][n]['down'] += d
    return jsonify(res)

if __name__ == '__main__':
    init_db()
    t1 = threading.Thread(target=start_sniffer, args=("eth0",), daemon=True)
    t1.start()
    t2 = threading.Thread(target=start_docker_monitor, daemon=True)
    t2.start()
    t3 = threading.Thread(target=save_history_task, daemon=True)
    t3.start()
    t4 = threading.Thread(target=monitor_system_task, daemon=True) # 新增系统监控
    t4.start()

    logging.info("🚀 RetroFlow v4.1 Ready :10308")
    app.run(host='0.0.0.0', port=10308)