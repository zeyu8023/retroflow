FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 1. 复制核心代码
COPY main.py .
# 2. 复制前端页面 (新增这行)
COPY index.html .

RUN ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

EXPOSE 10308

CMD ["python", "main.py"]