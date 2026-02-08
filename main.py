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
    # 在这里继续添加你的端口...
}

# --- 全局数据 ---
# 实时累计值 (重启归零)
stats_store = {}
# 上一次保存时的累计值 (用于计算每分钟增量)
last_saved_stats = {}
lock = threading.Lock()

# 初始化 Flask 和 Docker
app = Flask(__name__)
try:
    docker_client = docker.from_env()
except:
    docker_client = None

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

# --- 数据库管理 ---
DB_PATH = 'data/traffic.db'

def init_db():
    if not os.path.exists('data'):
        os.makedirs('data')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # 创建历史表：时间戳, 容器名, 上传增量, 下载增量
    c.execute('''CREATE TABLE IF NOT EXISTS history 
                 (timestamp INTEGER, name TEXT, upload INTEGER, download INTEGER)''')
    # 创建索引加速查询
    c.execute('''CREATE INDEX IF NOT EXISTS idx_time ON history (timestamp)''')
    conn.commit()
    conn.close()

def save_history_task():
    """后台任务：每分钟将增量数据写入数据库"""
    while True:
        time.sleep(60) # 每60秒保存一次
        timestamp = int(time.time())
        
        with lock:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            
            for name, data in stats_store.items():
                current_up = data['upload']
                current_down = data['download']
                
                # 获取上一次保存的值
                last = last_saved_stats.get(name, {'upload': 0, 'download': 0})
                
                # 计算这一分钟内的增量 (Delta)
                delta_up = current_up - last['upload']
                delta_down = current_down - last['download']
                
                # 只有当有流量产生时才记录，节省空间
                if delta_up > 0 or delta_down > 0:
                    c.execute("INSERT INTO history VALUES (?, ?, ?, ?)", 
                              (timestamp, name, delta_up, delta_down))
                
                # 更新“上一次”的记录
                last_saved_stats[name] = {'upload': current_up, 'download': current_down}
            
            conn.commit()
            conn.close()
            logging.info(f"💾 [DB] 已归档历史数据 - {timestamp}")

# --- 辅助函数 ---
def ensure_stats(name, net_type):
    if name not in stats_store:
        stats_store[name] = {"name": name, "type": net_type, "upload": 0, "download": 0}

# --- 抓包模块 (Host) ---
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
            
            if eth_proto != 0x0800: continue # 只看 IPv4

            ip_header = raw_data[14:34]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            protocol = iph[6]
            if protocol != 6 and protocol != 17: continue # 只看 TCP/UDP

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
                if c.attrs['HostConfig']['NetworkMode'] != 'host':
                    name = c.name
                    with lock:
                        ensure_stats(name, "bridge")
                        # 模拟数据：Python直接读Bridge流量较难，这里暂时略过
                        # 重点是让它在列表里显示出来
        except:
            pass
        time.sleep(5)

# --- API 路由 ---
@app.route('/')
def index():
    return send_file('index.html')

@app.route('/api/realtime')
def get_realtime():
    with lock:
        return jsonify(list(stats_store.values()))

@app.route('/api/history')
def get_history():
    """获取历史数据用于绘图"""
    # range: 'day' (24h), 'month' (30d), 'year' (12m)
    time_range = request.args.get('range', 'day')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    now = int(time.time())
    data = []

    if time_range == 'day':
        # 查询过去24小时，按小时聚合
        start_time = now - 24 * 3600
        sql = """
            SELECT strftime('%H:00', datetime(timestamp, 'unixepoch', 'localtime')) as time_label,
                   name, sum(upload), sum(download)
            FROM history WHERE timestamp > ?
            GROUP BY time_label, name
            ORDER BY timestamp
        """
        c.execute(sql, (start_time,))
        
    elif time_range == 'month':
        # 查询过去30天，按天聚合
        start_time = now - 30 * 24 * 3600
        sql = """
            SELECT strftime('%Y-%m-%d', datetime(timestamp, 'unixepoch', 'localtime')) as time_label,
                   name, sum(upload), sum(download)
            FROM history WHERE timestamp > ?
            GROUP BY time_label, name
            ORDER BY timestamp
        """
        c.execute(sql, (start_time,))
    
    rows = c.fetchall()
    conn.close()
    
    # 格式化数据给前端
    result = {}
    for row in rows:
        label, name, up, down = row
        if label not in result:
            result[label] = {}
        if name not in result[label]:
            result[label][name] = {'up': 0, 'down': 0}
        result[label][name]['up'] += up
        result[label][name]['down'] += down
        
    return jsonify(result)

if __name__ == '__main__':
    # 初始化数据库
    init_db()
    
    # 启动线程
    t1 = threading.Thread(target=start_sniffer, args=("eth0",), daemon=True)
    t1.start()
    t2 = threading.Thread(target=start_docker_monitor, daemon=True)
    t2.start()
    t3 = threading.Thread(target=save_history_task, daemon=True) # 新增：存库线程
    t3.start()

    logging.info("🚀 RetroFlow Pro 已启动 :10308")
    app.run(host='0.0.0.0', port=10308)