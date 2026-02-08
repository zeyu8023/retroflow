import socket
import struct
import threading
import time
import json
import logging
import os
from flask import Flask, jsonify
import docker

# --- 配置区：Host 模式容器的端口映射 ---
HOST_SERVICES = {
    8096: "Emby (媒体)",
    8920: "Emby (HTTPS)",
    10308: "RetroFlow (本服务)",
    80: "Nginx (Web)",
    443: "Nginx (SSL)",
    # 你可以在这里继续添加端口
}

# --- 全局数据 ---
stats_store = {}
lock = threading.Lock()

# 初始化 Flask 和 Docker
app = Flask(__name__)
try:
    docker_client = docker.from_env()
except:
    docker_client = None
    print("⚠️ 无法连接 Docker 守护进程，请确保挂载了 /var/run/docker.sock")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

def ensure_stats(name, net_type):
    """确保字典里有这个容器的占位符"""
    if name not in stats_store:
        stats_store[name] = {
            "name": name,
            "type": net_type,
            "upload": 0,
            "download": 0
        }

# --- 模块 A: Host 模式抓包 (Raw Socket) ---
def start_sniffer(interface="eth0"):
    logging.info(f"🕸️ [Sniffer] 开始监听网卡 {interface} (Host模式)...")
    
    # 创建原始套接字 (需要 root 权限)
    try:
        # ETH_P_ALL = 0x0003 (监听所有协议)
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        sock.bind((interface, 0))
    except PermissionError:
        logging.error("❌ 权限不足！请在 Docker 命令中加入 --privileged")
        return
    except Exception as e:
        logging.error(f"❌ 抓包启动失败: {e}")
        return

    while True:
        try:
            # 读取数据包 (最大 65535 字节)
            raw_data, _ = sock.recvfrom(65535)
            packet_len = len(raw_data)

            # 1. 解析以太网头 (14字节)
            eth_header = raw_data[:14]
            # Unpack: 6s(dest), 6s(src), H(type)
            eth_proto = struct.unpack("!6s6sH", eth_header)[2]

            # 2. 只处理 IP 数据包 (0x0800)
            if eth_proto != 0x0800:
                continue

            # 3. 解析 IP 头
            ip_header = raw_data[14:34]
            # Unpack IP header to get protocol and header length
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            version_ihl = iph[0]
            ihl = version_ihl & 0xF
            ip_header_len = ihl * 4
            protocol = iph[6] # 6=TCP, 17=UDP

            # 只处理 TCP (6) 和 UDP (17)
            if protocol != 6 and protocol != 17:
                continue

            # 4. 解析 TCP/UDP 头
            transport_offset = 14 + ip_header_len
            transport_header = raw_data[transport_offset:transport_offset+4]
            # Unpack source and dest ports
            src_port, dst_port = struct.unpack('!HH', transport_header)

            # 5. 统计逻辑
            with lock:
                # 下载 (别人发给 NAS) -> 目标端口匹配
                if dst_port in HOST_SERVICES:
                    name = HOST_SERVICES[dst_port]
                    ensure_stats(name, "host")
                    stats_store[name]["download"] += packet_len
                
                # 上传 (NAS 发给别人) -> 源端口匹配
                if src_port in HOST_SERVICES:
                    name = HOST_SERVICES[src_port]
                    ensure_stats(name, "host")
                    stats_store[name]["upload"] += packet_len

        except Exception:
            continue

# --- 模块 B: Docker Bridge 监控 ---
def start_docker_monitor():
    logging.info("🐳 [Docker] 监控模块已启动...")
    while True:
        if not docker_client:
            time.sleep(5)
            continue
            
        try:
            containers = docker_client.containers.list()
            for c in containers:
                # 只处理非 Host 模式
                if c.attrs['HostConfig']['NetworkMode'] != 'host':
                    name = c.name
                    with lock:
                        ensure_stats(name, "bridge")
                        # 简单的活跃标记 (Python 版暂时做不到精确统计 Bridge 流量，需读 cgroup)
                        # 这里为了演示，每次循环增加一点模拟数据
                        stats_store[name]["download"] += 0 
        except Exception as e:
            logging.error(f"Docker API 出错: {e}")
        
        time.sleep(3)

# --- Web 路由 ---
@app.route('/')
def index():
    return f"RetroFlow (Python版) 运行中...<br>当前时间: {time.strftime('%Y-%m-%d %H:%M:%S')}"

@app.route('/api/stats')
def get_stats():
    with lock:
        # 将字典转为列表返回
        data = list(stats_store.values())
    return jsonify(data)

if __name__ == '__main__':
    # 启动后台线程
    t1 = threading.Thread(target=start_sniffer, args=("eth0",), daemon=True)
    t1.start()

    t2 = threading.Thread(target=start_docker_monitor, daemon=True)
    t2.start()

    logging.info("🚀 服务启动在 :10308")
    app.run(host='0.0.0.0', port=10308)