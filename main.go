package main

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	// 定义端口变量
	port := ":10308"

	fmt.Println("RetroFlow - Pipeline Test Started...")
	fmt.Printf("Server is starting on port %s\n", port)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		hostname, _ := os.Hostname()
		// 网页上显示的内容
		fmt.Fprintf(w, "构建成功！端口已修改为 10308\n来自容器: %s\n当前时间: %s", hostname, time.Now().Format("2006-01-02 15:04:05"))
	})

	// 启动监听
	err := http.ListenAndServe(port, nil)
	if err != nil {
		fmt.Println("Error starting server:", err)
	}
}