package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/gin-gonic/gin"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// --- 配置区：Host 模式容器的端口映射 ---
// 你可以在这里手动添加你的 Host 模式容器
var HostServices = map[uint16]string{
	8096:  "Emby (媒体)",
	8920:  "Emby (HTTPS)",
	10308: "RetroFlow (本服务)",
	80:    "Nginx (Web)",
	443:   "Nginx (SSL)",
}

// --- 数据结构 ---
type ContainerStats struct {
	Name     string `json:"name"`
	Type     string `json:"type"` // "bridge" 或 "host"
	Upload   uint64 `json:"upload"`
	Download uint64 `json:"download"`
	SpeedIn  uint64 `json:"speed_in"`  // 字节/秒
	SpeedOut uint64 `json:"speed_out"` // 字节/秒
}

// 内存数据库
var (
	StatsStore = make(map[string]*ContainerStats)
	mu         sync.RWMutex
)

func main() {
	// 初始化 Gin 框架
	r := gin.Default()

	// 1. 启动 Host 模式抓包 (协程)
	go startHostSniffer("eth0")

	// 2. 启动 Docker API 监控 (协程)
	go startDockerMonitor()

	// API: 获取实时数据
	r.GET("/api/stats", func(c *gin.Context) {
		mu.RLock()
		defer mu.RUnlock()
		
		// 转换 Map 为 List
		var list []*ContainerStats
		for _, v := range StatsStore {
			list = append(list, v)
		}
		c.JSON(http.StatusOK, list)
	})

	log.Println("🚀 RetroFlow 监控核心已启动，端口 :10308")
	r.Run(":10308")
}

// --- 模块 A: Host 模式抓包 (核心黑科技) ---
func startHostSniffer(device string) {
	log.Printf("🕸️ 开始监听网卡 %s (Host模式监控)...", device)

	// 打开网卡，只抓前 1024 字节 (高性能模式)
	handle, err := pcap.OpenLive(device, 1024, false, 30*time.Second)
	if err != nil {
		log.Printf("❌ 无法打开网卡 (如果是本地测试请忽略): %v", err)
		return
	}
	defer handle.Close()

	// 设置过滤器：只看 TCP 和 UDP
	handle.SetBPFFilter("tcp or udp")
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		// 解析网络层 (获取包大小)
		netLayer := packet.NetworkLayer()
		if netLayer == nil {
			continue
		}
		length := uint64(len(packet.Data()))

		// 解析传输层 (获取端口)
		transLayer := packet.TransportLayer()
		if transLayer == nil {
			continue
		}

		// 获取源端口和目标端口
		var srcPort, dstPort uint16
		if tcp, ok := transLayer.(*layers.TCP); ok {
			srcPort, dstPort = uint16(tcp.SrcPort), uint16(tcp.DstPort)
		} else if udp, ok := transLayer.(*layers.UDP); ok {
			srcPort, dstPort = uint16(udp.SrcPort), uint16(udp.DstPort)
		}

		mu.Lock()
		// 逻辑：如果是我们配置列表里的端口，就记账
		// 情况 1: 别人发给 NAS (下载) -> 目标端口匹配
		if name, ok := HostServices[dstPort]; ok {
			ensureStats(name, "host")
			StatsStore[name].Download += length
		}
		// 情况 2: NAS 发给别人 (上传) -> 源端口匹配
		if name, ok := HostServices[srcPort]; ok {
			ensureStats(name, "host")
			StatsStore[name].Upload += length
		}
		mu.Unlock()
	}
}

// --- 模块 B: Docker Bridge 模式监控 (官方 API) ---
func startDockerMonitor() {
	log.Println("🐳 开始连接 Docker 守护进程...")
	
	// 连接 Docker
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Printf("❌ Docker 连接失败: %v", err)
		return
	}

	for {
		containers, err := cli.ContainerList(context.Background(), types.ContainerListOptions{})
		if err == nil {
			for _, container := range containers {
				// 我们简单通过网络模式过滤，这里只处理非 host 模式
				// 注意：这里只是为了演示，真实环境 bridge 统计需要读取 /sys/fs/cgroup 或调用 stats API
				// 为了不卡死 CPU，我们这里先用一个模拟值代替 Bridge 流量
				// 真正实现 Bridge 监控需要流式读取 stats，代码量较大，将在下一版完善
				
				if container.HostConfig.NetworkMode != "host" {
					mu.Lock()
					name := container.Names[0][1:] // 去掉前面的 /
					ensureStats(name, "bridge")
					// 模拟心跳数据，证明程序扫描到了它
					StatsStore[name].Download += 1024 
					mu.Unlock()
				}
			}
		}
		time.Sleep(3 * time.Second)
	}
}

// 辅助工具：确保 Map 里有这个容器
func ensureStats(name, netType string) {
	if _, ok := StatsStore[name]; !ok {
		StatsStore[name] = &ContainerStats{Name: name, Type: netType}
	}
}