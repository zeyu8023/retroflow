# 第一阶段：编译环境
FROM golang:1.21-alpine AS builder
WORKDIR /app

# === 关键修正 ===
# 必须安装 git，否则 go mod tidy 无法下载依赖！
# gcc, musl-dev, libpcap-dev 是 CGO 编译和抓包必备的
RUN apk add --no-cache git gcc musl-dev libpcap-dev

COPY . .

# 1. 自动下载 Go 依赖
# (现在有了 git，这一步就能成功下载代码了)
RUN go mod tidy

# 2. 编译 (CGO_ENABLED=1 开启抓包支持)
RUN CGO_ENABLED=1 go build -ldflags="-s -w" -o app main.go

# 第二阶段：运行环境 (保持小巧)
FROM alpine:latest
WORKDIR /root/

# 安装 libpcap 运行时库 (否则抓包程序跑不起来)
RUN apk add --no-cache libpcap tzdata

COPY --from=builder /app/app .

# 暴露端口
EXPOSE 10308

CMD ["./app"]