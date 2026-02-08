package main

import (
	"context"
	"fmt"
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
	Type     string `json:"type"` 
	Upload   uint64 `json:"upload"`
	Download uint64 `json:"download"`
}

var (
	StatsStore = make(map[string]*ContainerStats)
	mu         sync.RWMutex
)

func main() {
	r := gin.Default()

	// 1. 启动 Host 模式抓包
	go startHostSniffer("eth0")

	// 2. 启动 Docker API 监控
	go startDockerMonitor()

	r.GET("/api/stats", func(c *gin.Context) {
		mu.RLock()
		defer mu.RUnlock()
		var list []*ContainerStats
		for _, v := range StatsStore {
			list = append(list, v)
		}
		c.JSON(http.StatusOK, list)
	})

	log.Println("🚀 RetroFlow 监控核心已启动，端口 :10308")
	r.Run(":10308")
}

func startHostSniffer(device string) {
	log.Printf("🕸️ 开始监听网卡 %s (Host模式监控)...", device)
	
	// 尝试打开网卡，如果是在非特权容器或 Windows 下可能会失败
	handle, err := pcap.OpenLive(device, 1024, false, 30*time.Second)
	if err != nil {
		log.Printf("⚠️ 无法打开网卡: %v (请确保以 --privileged 和 --net=host 运行)", err)
		return
	}
	defer handle.Close()

	handle.SetBPFFilter("tcp or udp")
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		netLayer := packet.NetworkLayer()
		transLayer := packet.TransportLayer()
		if netLayer == nil || transLayer == nil {
			continue
		}
		length := uint64(len(packet.Data()))

		var srcPort, dstPort uint16
		if tcp, ok := transLayer.(*layers.TCP); ok {
			srcPort, dstPort = uint16(tcp.SrcPort), uint16(tcp.DstPort)
		} else if udp, ok := transLayer.(*layers.UDP); ok {
			srcPort, dstPort = uint16(udp.SrcPort), uint16(udp.DstPort)
		}

		mu.Lock()
		if name, ok := HostServices[dstPort]; ok {
			ensureStats(name, "host")
			StatsStore[name].Download += length
		}
		if name, ok := HostServices[srcPort]; ok {
			ensureStats(name, "host")
			StatsStore[name].Upload += length
		}
		mu.Unlock()
	}
}

func startDockerMonitor() {
	log.Println("🐳 开始连接 Docker 守护进程...")
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Printf("❌ Docker 连接失败: %v", err)
		return
	}

	for {
		containers, err := cli.ContainerList(context.Background(), types.ContainerListOptions{})
		if err == nil {
			for _, container := range containers {
				if container.HostConfig.NetworkMode != "host" {
					mu.Lock()
					name := "unknown"
					if len(container.Names) > 0 {
						name = container.Names[0][1:]
					}
					ensureStats(name, "bridge")
					// 暂时只做活跃度标记，Bridge 流量需要进一步读取
					StatsStore[name].Download += 1 
					mu.Unlock()
				}
			}
		}
		time.Sleep(3 * time.Second)
	}
}

func ensureStats(name, netType string) {
	if _, ok := StatsStore[name]; !ok {
		StatsStore[name] = &ContainerStats{Name: name, Type: netType}
	}
}