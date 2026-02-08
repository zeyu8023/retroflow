import socket
import struct
import threading
import time
import json
import logging
import os
from flask import Flask, jsonify, send_file # 引入 send_file
import docker

# ... (中间的配置区、Host抓包函数、Docker监控函数 全部保持不变，直接复制之前的即可) ...
# 为了节省你的篇幅，这里只展示需要修改的 Web 路由部分，其他请保留原样！

HOST_SERVICES = {
    8096: "Emby (媒体)",
    8920: "Emby (HTTPS)",
    10308: "RetroFlow (本服务)",
    80: "Nginx (Web)",
    443: "Nginx (SSL)",
}
stats_store = {}
lock = threading.Lock()

app = Flask(__name__)

# --- 这里改了！ ---
@app.route('/')
def index():
    # 返回同目录下的 index.html 文件
    return send_file('index.html')

@app.route('/api/stats')
def get_stats():
    with lock:
        data = list(stats_store.values())
    return jsonify(data)

# ... (后面的启动代码保持不变) ...
# 记得保留 start_sniffer 和 start_docker_monitor 的实现

# 下面是完整的启动部分，确保你的代码里有
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    
    t1 = threading.Thread(target=start_sniffer, args=("eth0",), daemon=True)
    t1.start()

    # 如果需要 docker 监控，把下面注释打开 (需确保 docker SDK 已安装且 sock 已挂载)
    # t2 = threading.Thread(target=start_docker_monitor, daemon=True)
    # t2.start()

    logging.info("🚀 服务启动在 :10308")
    app.run(host='0.0.0.0', port=10308)