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

# --- 配置区 ---
HOST_SERVICES = {
    8096: "Emby (媒体)",
    8920: "Emby (HTTPS)",
    10308: "RetroFlow (本服务)",
    80: "Nginx (Web)",
    443: "Nginx (SSL)",
    # 在这里添加其他Host模式端口...
}

stats_store = {}
last_saved_stats = {}
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
        stats_store[name] = {"name": name, "type": net_type, "upload": 0, "download": 0}

# --- 核心：初始化容器列表 ---
def init_containers_list():
    """启动时立即扫描所有容器，防止列表为空"""
    if not docker_client: return
    try:
        containers = docker_client.containers.list()
        with lock:
            for c in containers:
                name = c.name
                # 判断网络模式
                net_mode = c.attrs['HostConfig']['NetworkMode']
                net_type = "host" if net_mode == "host" else "bridge"
                ensure_stats(name, net_type)
        logging.info(f"✅ 初始化扫描完成，发现 {len(containers)} 个容器")
    except Exception as e:
        logging.error(f"初始化扫描失败: {e}")

# --- 抓包模块 ---
def start_sniffer(interface="eth0"):
    logging.info(f"🕸️ [Sniffer] 开始监听 {interface}...")
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
            eth_proto = struct.unpack("!6s6sH", raw_data[:14])[2]
            if eth_proto != 0x0800: continue

            ip_header = raw_data[14:34]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            protocol = iph[6]
            if protocol != 6 and protocol != 17: continue

            ihl = (iph[0] & 0xF) * 4
            transport_offset = 14 + ihl
            transport_header = raw_data[transport_offset:transport_offset+4]
            src_port, dst_port = struct.unpack('!HH', transport_header)

            with lock:
                if dst_port in HOST_SERVICES:
                    name = HOST_SERVICES[dst_port]
                    ensure_stats(name, "host")
                    stats_store[name]["download"] += packet_len
                if src_port in HOST_SERVICES:
                    name = HOST_SERVICES[src_port]
                    ensure_stats(name, "host")
                    stats_store[name]["upload"] += packet_len
        except:
            continue

# --- Docker 监控 (Bridge) ---
def start_docker_monitor():
    while True:
        if not docker_client:
            time.sleep(5)
            continue
        try:
            containers = docker_client.containers.list()
            for c in containers:
                name = c.name
                net_mode = c.attrs['HostConfig']['NetworkMode']
                
                # 只要不是host模式，都算作bridge (或者自定义网络)
                if net_mode != 'host':
                    with lock:
                        ensure_stats(name, "bridge")
                        # 暂时只做存活扫描，不更新流量(Python读cgroup比较复杂)
        except Exception as e:
            logging.error(f"Docker API 错误: {e}")
        time.sleep(5)

# --- 历史记录保存 ---
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
        return jsonify(list(stats_store.values()))

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
    # 启动时先扫描一遍
    init_containers_list()
    
    t1 = threading.Thread(target=start_sniffer, args=("eth0",), daemon=True)
    t1.start()
    t2 = threading.Thread(target=start_docker_monitor, daemon=True)
    t2.start()
    t3 = threading.Thread(target=save_history_task, daemon=True)
    t3.start()

    logging.info("🚀 RetroFlow Dashboard Ready :10308")
    app.run(host='0.0.0.0', port=10308)