# 第一阶段：编译环境
FROM golang:1.21-alpine AS builder
WORKDIR /app

# === 核心修复 ===
# 1. 安装 git (下载代码必须)
# 2. 安装 gcc, musl-dev, libpcap-dev (抓包库编译必须)
RUN apk add --no-cache git gcc musl-dev libpcap-dev

COPY . .

# === 依赖管理 ===
# 强制重置 go.mod，防止本地残留导致冲突
RUN rm -f go.mod go.sum
RUN go mod init retroflow

# 这里的 GOPROXY 删除掉，GitHub Actions 在海外直连最快
# 自动下载 main.go 中引用的所有库
RUN go mod tidy

# 编译 (CGO_ENABLED=1 开启抓包支持)
RUN CGO_ENABLED=1 go build -ldflags="-s -w" -o app main.go

# 第二阶段：运行环境
FROM alpine:latest
WORKDIR /root/
# 安装运行时库
RUN apk add --no-cache libpcap tzdata
COPY --from=builder /app/app .
EXPOSE 10308
CMD ["./app"]