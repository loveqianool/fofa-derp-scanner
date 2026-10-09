package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"tailscale.com/derp"
	"tailscale.com/net/stun"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// ProbeDERP 对单个 DERP 节点做真实 DERP 协议探测：
// TCP 建连 -> TLS 握手(跳过证书校验) -> HTTP Upgrade 到 DERP ->
// DERP 握手(ServerKey/ClientInfo) -> 发送 samples 次 ping 取中位 RTT ->
// UDP STUN 探测（Tailscale 客户端靠 STUN 测量延迟、决定是否使用该中继，不可用则丢弃）。
// 任何一步失败都返回 error，调用方可视为节点不可用。
// 若 TLS 握手发现对端是明文 HTTP（如 80 端口），自动降级为明文探测。
// relayTest 为 true 时，额外验证服务器真正的客户端间中继转发
// （建立两个客户端，A 发包、B 收包），比单纯 ping 更严格。
// stunTimeout <= 0 时跳过 STUN 探测（仅测试用）。
func ProbeDERP(ctx context.Context, host string, port int, samples int, pingTimeout, stunTimeout time.Duration, relayTest bool) (time.Duration, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	rtt, useTLS, err := probeOnceWithFallback(ctx, addr, samples, pingTimeout)
	if err != nil {
		return 0, err
	}
	// STUN 必须可用：Tailscale 客户端靠 UDP STUN 测量 DERP 延迟，
	// STUN 不通的中继会被客户端直接忽略（表现为无延迟、永不选用）。
	if stunTimeout > 0 {
		stunCtx, cancel := context.WithTimeout(ctx, stunTimeout)
		defer cancel()
		if err := probeSTUN(stunCtx, host, 3478); err != nil {
			return 0, err
		}
	}
	if relayTest {
		if err := probeRelay(ctx, addr, useTLS, pingTimeout); err != nil {
			return 0, err
		}
	}
	return rtt, nil
}

// probeSTUN 向 host:port 发送 STUN Binding Request 并等待响应，
// 逻辑对齐官方 derpprober 的 derpProbeUDP。host 可为 IP 或域名，port 传 0 表示 3478。
// 域名解析出多个 IP（v4/v6）时逐个尝试，任一成功即返回 nil。
func probeSTUN(ctx context.Context, host string, port int) error {
	if port == 0 {
		port = 3478
	}
	var ipStrs []string
	if ip := net.ParseIP(host); ip != nil {
		ipStrs = []string{ip.String()}
	} else {
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil || len(addrs) == 0 {
			return fmt.Errorf("STUN 解析 %s 失败: %v", host, err)
		}
		seen := make(map[string]bool)
		for _, a := range addrs {
			s := a.IP.String()
			if !seen[s] {
				seen[s] = true
				ipStrs = append(ipStrs, s)
			}
		}
	}

	var lastErr error
	for _, ipStr := range ipStrs {
		if err := probeSTUNOne(ctx, ipStr, port); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("无可用 IP")
	}
	return fmt.Errorf("STUN 无响应: %v", shortErr(lastErr))
}

// probeSTUNOne 对单个 IP 的 UDP 端口做一次 STUN Binding Request/Response。
func probeSTUNOne(ctx context.Context, ipStr string, port int) error {
	dst, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ipStr, strconv.Itoa(port)))
	if err != nil {
		return fmt.Errorf("STUN 解析地址失败: %v", err)
	}

	pc, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return fmt.Errorf("STUN 创建 UDP socket 失败: %v", err)
	}
	defer pc.Close()
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		return fmt.Errorf("STUN: 非预期 packet conn 类型")
	}
	// 用 ctx 的 deadline 做读写超时
	if deadline, ok := ctx.Deadline(); ok {
		uc.SetDeadline(deadline)
	}

	tx := stun.NewTxID()
	req := stun.Request(tx)
	if _, err := uc.WriteToUDP(req, dst); err != nil {
		return fmt.Errorf("STUN 发送请求失败: %v", err)
	}
	buf := make([]byte, 1500)
	n, _, err := uc.ReadFromUDP(buf)
	if err != nil {
		return fmt.Errorf("STUN 无响应: %v", shortErr(err))
	}
	txBack, _, err := stun.ParseResponse(buf[:n])
	if err != nil {
		return fmt.Errorf("STUN 解析响应失败: %v", err)
	}
	if txBack != tx {
		return fmt.Errorf("STUN 事务 ID 不匹配")
	}
	return nil
}

// probeOnceWithFallback 先尝试 TLS 探测；若 TLS 握手发现对端是明文 HTTP，
// 则降级为明文探测。返回 RTT 和最终使用的 useTLS。
func probeOnceWithFallback(ctx context.Context, addr string, samples int, pingTimeout time.Duration) (time.Duration, bool, error) {
	// 注意：Tailscale 生产客户端只用 HTTPS 连接 DERP（derphttp.urlString 硬编码 https，
	// 仅 TS_DEBUG_USE_DERP_HTTP 调试环境变量可切换为 http），因此这里不做明文降级：
	// TLS 握手失败的节点直接丢弃，否则输出的节点 Tailscale 根本连不上。
	rtt, err := probeOnce(ctx, addr, true, samples, pingTimeout)
	return rtt, true, err
}

func probeOnce(ctx context.Context, addr string, useTLS bool, samples int, pingTimeout time.Duration) (time.Duration, error) {
	conn, dc, err := dialDERP(ctx, addr, useTLS, key.NewNode(), pingTimeout)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	rtts := make([]time.Duration, 0, samples)
	for i := 0; i < samples; i++ {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		rtt, err := pingOnce(ctx, dc, conn, pingTimeout)
		if err != nil {
			return 0, err
		}
		rtts = append(rtts, rtt)
	}
	conn.SetDeadline(time.Time{})

	sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
	return rtts[len(rtts)/2], nil
}

// pingOnce 发送一次 ping 并等待对应的 pong，返回 RTT。
// 会忽略 pong 之外的其他帧（keepalive、serverinfo 等）。
func pingOnce(ctx context.Context, dc *derp.Client, conn net.Conn, timeout time.Duration) (time.Duration, error) {
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return 0, err
	}
	conn.SetDeadline(time.Now().Add(timeout)) // 保障写超时；读超时由 recvWithTimeout 控制
	start := time.Now()
	if err := dc.SendPing(nonce); err != nil {
		return 0, fmt.Errorf("ping 发送: %w", err)
	}
	for {
		m, err := recvWithTimeout(ctx, dc, conn, timeout)
		if err != nil {
			return 0, fmt.Errorf("pong 等待: %w", err)
		}
		if pong, ok := m.(derp.PongMessage); ok && [8]byte(pong) == nonce {
			return time.Since(start), nil
		}
	}
}

// recvWithTimeout 调用 dc.Recv，但最多等待 timeout。
// 注意：derp.Client.Recv 内部硬编码了 120 秒读 deadline，每次调用都会
// 覆盖我们设置的 conn deadline，因此这里用 goroutine + 超时关闭连接的
// 方式来实现真正的超时——关闭连接会立即中断阻塞中的 Recv，不泄漏 goroutine。
func recvWithTimeout(ctx context.Context, dc *derp.Client, conn net.Conn, timeout time.Duration) (derp.ReceivedMessage, error) {
	type res struct {
		m   derp.ReceivedMessage
		err error
	}
	ch := make(chan res, 1)
	go func() {
		m, err := dc.Recv()
		ch <- res{m, err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r := <-ch:
		return r.m, r.err
	case <-timer.C:
		conn.Close() // 中断阻塞中的 Recv
		<-ch         // 等其返回（应立即失败）
		return nil, fmt.Errorf("等待响应超时（%v）", timeout)
	case <-ctx.Done():
		conn.Close()
		<-ch
		return nil, ctx.Err()
	}
}

// probeRelay 验证服务器真正的客户端间中继转发能力：在同一服务器上建立
// 两个 DERP 客户端 A 和 B，A 发包给 B，B 必须能收到。
// 这比 ping 更进一步——ping 只证明 client<->server 通，
// 这里验证的才是中继的实际用法：server 在两个 client 之间转发。
func probeRelay(ctx context.Context, addr string, useTLS bool, timeout time.Duration) error {
	keyA := key.NewNode()
	keyB := key.NewNode()

	connA, dcA, err := dialDERP(ctx, addr, useTLS, keyA, timeout)
	if err != nil {
		return fmt.Errorf("客户端 A 建连: %w", err)
	}
	defer connA.Close()
	connB, dcB, err := dialDERP(ctx, addr, useTLS, keyB, timeout)
	if err != nil {
		return fmt.Errorf("客户端 B 建连: %w", err)
	}
	defer connB.Close()

	// B 先 ping 一次：证明 B 已被服务器接纳（enrollment 完成）。
	// 否则 A 的包可能因 B 尚未注册而被丢弃，造成误判。
	if _, err := pingOnce(ctx, dcB, connB, timeout); err != nil {
		return fmt.Errorf("客户端 B 自检: %w", err)
	}

	payload := []byte("derp-scan relay probe")
	connA.SetDeadline(time.Now().Add(timeout))
	connB.SetDeadline(time.Now().Add(timeout))
	if err := dcA.Send(keyB.Public(), payload); err != nil {
		return fmt.Errorf("A 发送: %w", err)
	}
	for {
		m, err := recvWithTimeout(ctx, dcB, connB, timeout)
		if err != nil {
			return fmt.Errorf("B 接收: %w", err)
		}
		if rp, ok := m.(derp.ReceivedPacket); ok {
			if rp.Source == keyA.Public() && string(rp.Data) == string(payload) {
				return nil
			}
			// 收到非预期的包，继续等
			continue
		}
		// 忽略 pong 等其他帧
	}
}

// dialDERP 完成到 addr 的 TCP 建连、TLS 握手（可选）、HTTP Upgrade 到 DERP
// 以及 DERP 握手（ServerKey/ClientInfo），返回顶层连接和 client。
// 调用方负责 Close(conn)。timeout 用于握手阶段的整体 deadline。
func dialDERP(ctx context.Context, addr string, useTLS bool, privKey key.NodePrivate, timeout time.Duration) (net.Conn, *derp.Client, error) {
	rawConn, err := dialTarget(ctx, addr)
	if err != nil {
		return nil, nil, fmt.Errorf("tcp: %w", err)
	}
	// 出错时关闭底层连接；成功后由调用方关闭返回的 conn
	//（会级联关闭到底层）。
	failed := true
	defer func() {
		if failed {
			rawConn.Close()
		}
	}()

	var conn net.Conn = rawConn
	scheme := "http"
	if useTLS {
		tlsConf := &tls.Config{
			InsecureSkipVerify: true,
			// 带上 ALPN（像浏览器/curl 一样）：某些出口网关会优待带 ALPN 的 ClientHello，
			// 对标准 DERP 服务端无影响（不支持则直接忽略）。
			NextProtos: []string{"http/1.1"},
		}
		if host, _, _ := net.SplitHostPort(addr); net.ParseIP(host) == nil {
			tlsConf.ServerName = host // 域名节点带上 SNI
		}
		tlsConn := tls.Client(rawConn, tlsConf)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, nil, fmt.Errorf("tls: %w", err)
		}
		conn = tlsConn
		scheme = "https"
	}

	// HTTP Upgrade 切换到 DERP 协议
	br := bufio.NewReader(conn)
	bw := bufio.NewWriter(conn)
	req, err := http.NewRequest("GET", scheme+"://"+addr+"/derp", nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Upgrade", "DERP")
	req.Header.Set("Connection", "Upgrade")
	conn.SetDeadline(time.Now().Add(timeout))
	if err := req.Write(bw); err != nil {
		return nil, nil, fmt.Errorf("upgrade 请求: %w", err)
	}
	if err := bw.Flush(); err != nil {
		return nil, nil, fmt.Errorf("upgrade 请求: %w", err)
	}
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, nil, fmt.Errorf("upgrade 响应: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, nil, fmt.Errorf("upgrade 被拒绝: HTTP %d", resp.StatusCode)
	}

	// DERP 握手：服务端下发 ServerKey，客户端回 ClientInfo（内部处理 nacl 加密）
	brw := bufio.NewReadWriter(br, bw)
	dc, err := derp.NewClient(privKey, conn, brw, logger.Discard, derp.IsProber(true))
	if err != nil {
		return nil, nil, fmt.Errorf("derp 握手: %w", err)
	}

	failed = false
	return conn, dc, nil
}

// dialTarget 建立到 addr 的 TCP 连接。如果环境变量中配置了代理
// （HTTPS_PROXY/HTTP_PROXY，含 NO_PROXY 处理），则通过 HTTP CONNECT
// 隧道建连；否则直连。
func dialTarget(ctx context.Context, addr string) (net.Conn, error) {
	if proxyURL := proxyForTarget(addr); proxyURL != nil {
		return dialViaCONNECT(ctx, proxyURL, addr)
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
}

// proxyForTarget 返回适用于 addr 的代理 URL。
// Go 的 http.ProxyFromEnvironment 不会为 https 目标回落到 HTTP_PROXY
// （curl 会），这里在 HTTPS_PROXY 完全未设置时手动补上；
// 若 HTTPS_PROXY 已设置则完全走标准逻辑，避免绕过 NO_PROXY。
func proxyForTarget(addr string) *url.URL {
	req := &http.Request{URL: &url.URL{Scheme: "https", Host: addr}}
	if pu, err := http.ProxyFromEnvironment(req); err == nil && pu != nil {
		return pu
	}
	if os.Getenv("HTTPS_PROXY") != "" || os.Getenv("https_proxy") != "" {
		return nil
	}
	return proxyFromHTTPOnly()
}

// proxyFromHTTPOnly 在 HTTPS_PROXY 未设置时，从 HTTP_PROXY 取代理地址
// （curl 的行为）。单独拆出来以便测试（http.ProxyFromEnvironment 内部
// 有 sync.Once 缓存，直接测它会受测试执行顺序影响）。
func proxyFromHTTPOnly() *url.URL {
	for _, k := range []string{"HTTP_PROXY", "http_proxy"} {
		v := strings.TrimSpace(os.Getenv(k))
		if v == "" {
			continue
		}
		if !strings.Contains(v, "://") {
			v = "http://" + v
		}
		if pu, err := url.Parse(v); err == nil && pu.Host != "" {
			return pu
		}
	}
	return nil
}

// dialViaCONNECT 通过代理的 HTTP CONNECT 方法建立到 target 的隧道。
func dialViaCONNECT(ctx context.Context, proxyURL *url.URL, target string) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxyURL.Host)
	if err != nil {
		return nil, fmt.Errorf("代理连接: %w", err)
	}

	req := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: target},
		Host:   target,
		Header: make(http.Header),
	}
	if ui := proxyURL.User; ui != nil {
		pw, _ := ui.Password()
		cred := base64.StdEncoding.EncodeToString([]byte(ui.Username() + ":" + pw))
		req.Header.Set("Proxy-Authorization", "Basic "+cred)
	}
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("CONNECT 请求: %w", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("CONNECT 响应: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("代理拒绝 CONNECT: HTTP %d", resp.StatusCode)
	}
	// 包装 conn，保证 Read 时先消费 br 中可能残留的字节
	return &bufferedConn{Conn: conn, r: br}, nil
}

// bufferedConn 在底层 conn 前叠加一个已存在的 bufio.Reader。
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }
