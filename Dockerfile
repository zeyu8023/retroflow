# 第一阶段：编译环境
FROM golang:1.21-alpine AS builder
WORKDIR /app

# 1. 安装 Git 和 GCC (下载和编译必须)
RUN apk add --no-cache git gcc musl-dev libpcap-dev

# 2. 设置 Go 代理 (解决国内/GitHub网络超时)
ENV GOPROXY=https://goproxy.io,direct

# 3. 复制所有代码 (main.go 和 go.mod)
COPY . .

# 4. 强制刷新依赖
# 删除旧的 go.mod，重新生成，确保干净
RUN rm -f go.mod go.sum
RUN go mod init retroflow

# 5. 自动下载依赖 (因为 main.go 里有 import，这一步会自动下载 Gin 等库)
RUN go mod tidy

# 6. 编译
RUN CGO_ENABLED=1 go build -ldflags="-s -w" -o app main.go

# 第二阶段：运行环境
FROM alpine:latest
WORKDIR /root/
# 安装运行时库
RUN apk add --no-cache libpcap tzdata
COPY --from=builder /app/app .
EXPOSE 10308
CMD ["./app"]