package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os/exec"
	"regexp"
	"strings"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func handler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}
	defer conn.Close()

	for {
		messageType, p, err := conn.ReadMessage()
		if err != nil {
			log.Println(err)
			return
		}
		if string(p) == "获取设备信息" {
			deviceInfo, err := getDeviceInfo()
			if err != nil {
				log.Println(err)
				conn.WriteMessage(messageType, []byte(fmt.Sprintf("获取设备信息失败: %v", err)))
				continue
			}
			if err := conn.WriteMessage(messageType, []byte(deviceInfo)); err != nil {
				log.Println(err)
				return
			}
		}
	}
}

func getDeviceInfo() (string, error) {
	deviceIP := getDeviceIP()
	deviceInfo := map[string]string{
		"设备编号": getDeviceSerial(),
		"设备IP":  deviceIP,
		"设备MAC": getDeviceMAC(),
		"设备区域": getDeviceRegion(deviceIP),
		"操作系统": "Linux",
		"主机名":   getHostname(),
		"内核版本": getKernelVersion(),
		"内核编译信息": getKernelCompileInfo(),
		"处理器架构": getArchitecture(),
	}

	jsonData, err := json.Marshal(deviceInfo)
	if err != nil {
		return "", err
	}

	return string(jsonData), nil
}

func getDeviceSerial() string {
	data, err := ioutil.ReadFile("/sys/class/dmi/id/product_serial")
	if err != nil {
		log.Println("获取设备序列号失败:", err)
		return "未知"
	}
	return strings.TrimSpace(string(data))
}

func getDeviceIP() string {
	cmd := exec.Command("ip", "-4", "addr", "show", "ens33")
	out, err := cmd.Output()
	if err != nil {
		log.Println("获取设备IP失败:", err)
		return "未知"
	}
	ips := parseIPOutput(string(out))
	if len(ips) > 0 {
		return ips[0]
	}
	log.Println("获取设备IP失败: ens33接口无IP地址")
	return "未知"
}

func getDeviceMAC() string {
	cmd := exec.Command("ip", "link", "show", "ens33")
	out, err := cmd.Output()
	if err != nil {
		log.Println("获取设备MAC失败:", err)
		return "未知"
	}
	macs := parseMACOutput(string(out))
	if len(macs) > 0 {
		return macs[0]
	}
	log.Println("获取设备MAC失败: ens33接口无MAC地址")
	return "未知"
}

func parseMACOutput(output string) []string {
	var macs []string
	re := regexp.MustCompile(`link/ether\s+([0-9a-fA-F:]+)`)
	matches := re.FindAllStringSubmatch(output, -1)
	for _, match := range matches {
		if len(match) > 1 {
			macs = append(macs, match[1])
		}
	}
	return macs
}

func parseIPOutput(output string) []string {
	var ips []string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "inet ") {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				ip := strings.Split(fields[1], "/")[0]
				ips = append(ips, ip)
			}
		}
	}
	return ips
}

func getDeviceRegion(ip string) string {
	url := fmt.Sprintf("http://ip-api.com/json/")
	resp, err := http.Get(url)
	if err != nil {
		log.Println("获取设备区域失败:", err)
		return "未知"
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("读取设备区域响应失败:", err)
		return "未知"
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		log.Println("解析设备区域响应失败:", err)
		return "未知"
	}

	city, ok := result["city"].(string)
	if !ok {
		city = "未知"
	}
	isp, ok := result["isp"].(string)
	if !ok {
		isp = "未知"
	}

	region := fmt.Sprintf("%s\t%s", city, isp)
	return region
}

func getHostname() string {
	cmd := exec.Command("uname", "-n")
	out, err := cmd.Output()
	if err != nil {
		log.Println("获取主机名失败:", err)
		return "未知"
	}
	return strings.TrimSpace(string(out))
}

func getKernelVersion() string {
	cmd := exec.Command("uname", "-r")
	out, err := cmd.Output()
	if err != nil {
		log.Println("获取内核版本失败:", err)
		return "未知"
	}
	return strings.TrimSpace(string(out))
}

func getKernelCompileInfo() string {
	cmd := exec.Command("uname", "-v")
	out, err := cmd.Output()
	if err != nil {
		log.Println("获取内核编译信息失败:", err)
		return "未知"
	}
	return strings.TrimSpace(string(out))
}

func getArchitecture() string {
	cmd := exec.Command("uname", "-m")
	out, err := cmd.Output()
	if err != nil {
		log.Println("获取处理器架构失败:", err)
		return "未知"
	}
	return strings.TrimSpace(string(out))
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "index.html")
}

func main() {
	http.HandleFunc("/ws", handler)
	http.HandleFunc("/", serveIndex)
	fmt.Println("Server started at :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
