# 使用官方轻量级 Python 镜像
FROM python:3.9-slim

WORKDIR /app

# 1. 复制依赖清单并安装
# (pip 安装比编译 Go 可靠多了)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 2. 复制核心代码
COPY main.py .

# 3. 设置时区 (可选，方便看日志)
RUN ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

# 暴露端口
EXPOSE 10308

# 启动命令
CMD ["python", "main.py"]