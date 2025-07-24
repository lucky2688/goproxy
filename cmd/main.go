package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"goproxy"
	"log"
	"net"
	"net/http"
	"strings"
)

const (
	username = "admin"
	password = "123456"
)

// 认证逻辑
func basicAuthPassed(r *http.Request) bool {
	if r == nil {
		return false
	}
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" || !strings.HasPrefix(auth, "Basic ") {
		return false
	}
	payload, err := base64.StdEncoding.DecodeString(auth[len("Basic "):])
	if err != nil {
		return false
	}
	parts := strings.SplitN(string(payload), ":", 2)
	return len(parts) == 2 && parts[0] == username && parts[1] == password
}

func main() {
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true

	//CONNECT 请求（用于 HTTPS）认证逻辑
	proxy.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		req := ctx.Req
		reqUrlLogRecover(req.URL.String(), getClientIP(req))
		if !basicAuthPassed(req) {
			log.Printf("CONNECT 拒绝，认证失败 [%s]\n", host)
			return goproxy.RejectConnect, host
		}

		log.Printf("CONNECT 认证通过MITM [%s]\n", host)
		return goproxy.MitmConnect, host
	})

	//proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	//proxy.Tr = &http.Transport{
	//	DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
	//		// 实际连接 google 的 IP 和正确的 SNI
	//		return tls.DialWithDialer(&net.Dialer{}, network, "47.243.240.62:443", &tls.Config{
	//			ServerName:         "test.ergew.com",
	//			InsecureSkipVerify: true, // 可视情况决定
	//		})
	//		return tls.Dial(network, addr, &tls.Config{InsecureSkipVerify: true})
	//	},
	//}
	// 处理 HTTPS CONNECT 请求，启用 MITM

	////普通 HTTP 请求认证逻辑(可选)
	//proxy.OnRequest().DoFunc(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	//	//reqUrlLogRecover(r.URL.String(), getClientIP(r))
	//	//if !basicAuthPassed(r) {
	//	//	log.Printf("HTTP 请求认证失败 [%s %s]\n", r.Method, r.URL.String())
	//	//	resp := goproxy.NewResponse(r,
	//	//		goproxy.ContentTypeText,
	//	//		http.StatusProxyAuthRequired,
	//	//		"407 Proxy Authentication Required")
	//	//	resp.Header.Set("Proxy-Authenticate", `Basic realm="GoProxy"`)
	//	//	return nil, resp
	//	//}
	//	log.Printf("HTTP 请求认证通过 [%s %s]\n", r.Method, r.URL.String())
	//	return r, nil
	//})

	// 记录响应信息
	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if resp != nil {
			log.Printf("Response for %s: Status %d", ctx.Req.URL.String(), resp.StatusCode)
		}
		return resp
	})

	fmt.Println("正向代理服务器启动中，监听 0.0.0.0:8090（支持 CONNECT + Basic Auth）...")
	err := http.ListenAndServe("0.0.0.0:8090", proxy)
	if err != nil {
		log.Fatal("启动失败：", err)
	}
}

func reqUrlLogRecover(url string, ip string) {
	go func() { //异步执行
		defer func() { //捕获异常
			if r := recover(); r != nil {
				log.Printf("[reqUrlLog] panic recovered: %v", r)
			}
		}()
		err := reqUrlLog(url, ip)
		if err != nil {
			log.Printf("[reqUrlLog] request error: %v", err)
		}
	}()
}

func reqUrlLog(url string, ip string) error {
	// 构造 JSON 数据
	data := map[string]string{
		"url": url,
		"ip":  ip,
	}
	// 编码为 JSON 字节流
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		//log.Fatalf("JSON encode error: %v", err)
		return fmt.Errorf("JSON encode error: %v", err)
	}
	// 创建 POST 请求
	req, err := http.NewRequest("POST", "http://127.0.0.1:8000/analyze/log", bytes.NewBuffer(jsonBytes))
	if err != nil {
		//log.Fatalf("NewRequest error: %v", err)
		return fmt.Errorf("NewRequest error: %v", err)
	}
	// 设置请求头
	req.Header.Set("Content-Type", "application/json")
	// 发起请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		//log.Fatalf("Request error: %v", err)
		return fmt.Errorf("Request error: %v", err)
	}
	defer resp.Body.Close()

	log.Printf("Status: %s", resp.Status)

	return nil
}

func getClientIP(r *http.Request) string {
	// 优先获取 X-Forwarded-For（可能由代理或负载均衡设置）
	ip := r.Header.Get("X-Forwarded-For")
	if ip != "" {
		// 可能是多个 IP，以逗号分隔，取第一个
		ips := strings.Split(ip, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}
	// 其次获取 X-Real-IP
	ip = r.Header.Get("X-Real-IP")
	if ip != "" {
		return ip
	}
	// 最后从 RemoteAddr 获取
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr // 返回原始地址
	}
	return ip
}
