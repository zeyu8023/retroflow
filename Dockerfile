# 第一阶段：编译环境 (增加 libpcap-dev)
FROM golang:1.21-alpine AS builder
WORKDIR /app

# 安装 gcc 和 libpcap 开发库 (抓包必备)
RUN apk add --no-cache gcc musl-dev libpcap-dev

COPY . .

# 1. 自动下载 Go 依赖 (因为你本地没装 Go，让云端来做)
RUN go mod tidy

# 2. 编译 (注意：开启 CGO_ENABLED=1)
RUN CGO_ENABLED=1 go build -ldflags="-s -w" -o app main.go

# 第二阶段：运行环境
FROM alpine:latest
WORKDIR /root/

# 安装 libpcap 运行时库
RUN apk add --no-cache libpcap tzdata

COPY --from=builder /app/app .

# 暴露端口
EXPOSE 10308

CMD ["./app"]