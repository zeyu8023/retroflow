# 第一阶段：编译环境
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
# CGO_ENABLED=0 表示静态编译
RUN CGO_ENABLED=0 go build -o app main.go

# 第二阶段：运行环境 (极小)
FROM alpine:latest
WORKDIR /root/
COPY --from=builder /app/app .

# === 这里改了 ===
EXPOSE 10308

CMD ["./app"]