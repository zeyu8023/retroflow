# 第一阶段：编译环境
FROM golang:1.21-alpine AS builder
WORKDIR /app

# 1. 安装系统级依赖 (Git + GCC + Libpcap)
# 这一步必不可少，否则无法抓包和下载代码
RUN apk add --no-cache git gcc musl-dev libpcap-dev

# 2. 设置 Go 代理 (关键！解决网络超时问题)
ENV GOPROXY=https://goproxy.io,direct

# 3. 复制源代码
COPY . .

# 4. 强制初始化依赖 (解决依赖冲突)
# 我们先删掉你本地可能残留的 go.mod，让 Docker 重新生成一个干净的
RUN rm -f go.mod go.sum
RUN go mod init retroflow

# 5. 手动下载核心库 (分步执行，防止卡死)
RUN go get github.com/gin-gonic/gin
RUN go get github.com/google/gopacket
RUN go get github.com/docker/docker/client

# 6. 最后整理一次依赖
RUN go mod tidy

# 7. 编译 (开启 CGO 支持)
RUN CGO_ENABLED=1 go build -ldflags="-s -w" -o app main.go

# 第二阶段：运行环境 (保持小巧)
FROM alpine:latest
WORKDIR /root/

# 安装运行时库
RUN apk add --no-cache libpcap tzdata

COPY --from=builder /app/app .

# 暴露端口
EXPOSE 10308

CMD ["./app"]