# === 第一阶段：构建环境 (使用 Debian，工具最全) ===
FROM golang:1.22 AS builder
WORKDIR /app

# 1. 换源并安装 libpcap-dev (Debian 下叫这个名字)
# 这一步非常稳，不会像 Alpine 那样缺这缺那
RUN apt-get update && apt-get install -y libpcap-dev

# 2. 设置 Go 代理 (使用官方源，速度快且稳)
ENV GOPROXY=https://proxy.golang.org,direct

# 3. 复制依赖文件
COPY go.mod ./
# 如果你有 go.sum 也复制，没有也没关系
COPY go.sum* ./

# 4. 自动下载依赖 (Git 和 GCC 都有，这里绝对不会报错了)
RUN go mod download
RUN go mod tidy

# 5. 复制源码并编译
COPY . .
# CGO_ENABLED=1 开启抓包支持
RUN CGO_ENABLED=1 go build -ldflags="-s -w" -o app main.go

# === 第二阶段：运行环境 (还是用 Alpine 保持轻量) ===
FROM alpine:latest
WORKDIR /root/

# 安装运行时库 (必须要有 libpcap)
# 换个源防止安装慢
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories
RUN apk add --no-cache libpcap tzdata ca-certificates

COPY --from=builder /app/app .

# 暴露端口
EXPOSE 10308

CMD ["./app"]