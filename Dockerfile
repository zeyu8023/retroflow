# 第一阶段：编译环境 (升级到 1.22)
FROM golang:1.22-alpine AS builder
WORKDIR /app

# 1. 安装系统依赖 (Git + GCC + Libpcap)
RUN apk add --no-cache git gcc musl-dev libpcap-dev

# 2. 设置 Go 代理 (使用官方源，速度快且稳)
ENV GOPROXY=https://proxy.golang.org,direct

# 3. 复制 main.go (只复制这一个文件，保证纯净)
COPY main.go .

# 4. 初始化模块
# 强制删除旧的 go.mod，重新生成
RUN rm -f go.mod go.sum
RUN go mod init retroflow

# 5. === 手动安装核心库 (逐个击破) ===
# Gin Web 框架
RUN go get github.com/gin-gonic/gin@v1.9.1
# Gopacket 抓包库
RUN go get github.com/google/gopacket@v1.1.19
# Docker SDK (指定兼容版本，避免 conflict)
RUN go get github.com/docker/docker/client@v24.0.7+incompatible
RUN go get github.com/docker/docker/api/types@v24.0.7+incompatible

# 6. 整理依赖
RUN go mod tidy

# 7. 编译 (CGO 必须开启)
RUN CGO_ENABLED=1 go build -ldflags="-s -w" -o app main.go

# 第二阶段：运行环境
FROM alpine:latest
WORKDIR /root/
# 安装 libpcap
RUN apk add --no-cache libpcap tzdata
COPY --from=builder /app/app .
EXPOSE 10308
CMD ["./app"]