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
	"sort"
	"strconv"
	"strings"
	"time"

	"tailscale.com/derp"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// ProbeDERP 对单个 DERP 节点做真实 DERP 协议探测：
// TCP 建连 -> TLS 握手(跳过证书校验) -> HTTP Upgrade 到 DERP ->
// DERP 握手(ServerKey/ClientInfo) -> 发送 samples 次 ping 取中位 RTT。
// 任何一步失败都返回 error，调用方可视为节点不可用。
// 若 TLS 握手发现对端是明文 HTTP（如 80 端口），自动降级为明文探测。
func ProbeDERP(ctx context.Context, host string, port int, samples int, pingTimeout time.Duration) (time.Duration, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	rtt, err := probeOnce(ctx, addr, true, samples, pingTimeout)
	if err == nil {
		return rtt, nil
	}
	if !isPlaintextHint(err) {
		return 0, err
	}
	// 对端不是 TLS，重新拨号做明文 HTTP Upgrade 探测
	return probeOnce(ctx, addr, false, samples, pingTimeout)
}

// isPlaintextHint 判断 err 是否为"对端返回的不是 TLS 记录"——
// 说明该端口跑的是明文 HTTP，应降级重试。
func isPlaintextHint(err error) bool {
	return err != nil && strings.Contains(err.Error(), "first record does not look like a TLS handshake")
}

func probeOnce(ctx context.Context, addr string, useTLS bool, samples int, pingTimeout time.Duration) (time.Duration, error) {
	rawConn, err := dialTarget(ctx, addr)
	if err != nil {
		return 0, fmt.Errorf("tcp: %w", err)
	}
	defer rawConn.Close()

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
			return 0, fmt.Errorf("tls: %w", err)
		}
		conn = tlsConn
		scheme = "https"
	}

	// HTTP Upgrade 切换到 DERP 协议
	br := bufio.NewReader(conn)
	bw := bufio.NewWriter(conn)
	req, err := http.NewRequest("GET", scheme+"://"+addr+"/derp", nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Upgrade", "DERP")
	req.Header.Set("Connection", "Upgrade")
	conn.SetDeadline(time.Now().Add(pingTimeout))
	if err := req.Write(bw); err != nil {
		return 0, fmt.Errorf("upgrade 请求: %w", err)
	}
	if err := bw.Flush(); err != nil {
		return 0, fmt.Errorf("upgrade 请求: %w", err)
	}
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return 0, fmt.Errorf("upgrade 响应: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return 0, fmt.Errorf("upgrade 被拒绝: HTTP %d", resp.StatusCode)
	}

	// DERP 握手：服务端下发 ServerKey，客户端回 ClientInfo（内部处理 nacl 加密）
	brw := bufio.NewReadWriter(br, bw)
	dc, err := derp.NewClient(key.NewNode(), conn, brw, logger.Discard, derp.IsProber(true))
	if err != nil {
		return 0, fmt.Errorf("derp 握手: %w", err)
	}

	rtts := make([]time.Duration, 0, samples)
	for i := 0; i < samples; i++ {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		var nonce [8]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return 0, err
		}
		conn.SetDeadline(time.Now().Add(pingTimeout))
		start := time.Now()
		if err := dc.SendPing(nonce); err != nil {
			return 0, fmt.Errorf("ping 发送: %w", err)
		}
		for {
			m, err := dc.Recv()
			if err != nil {
				return 0, fmt.Errorf("pong 等待: %w", err)
			}
			if pong, ok := m.(derp.PongMessage); ok && [8]byte(pong) == nonce {
				rtts = append(rtts, time.Since(start))
				break
			}
			// 忽略其他帧（keepalive、serverinfo 等）
		}
	}
	conn.SetDeadline(time.Time{})

	sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
	return rtts[len(rtts)/2], nil
}

// dialTarget 建立到 addr 的 TCP 连接。如果环境变量中配置了代理
// （HTTPS_PROXY/HTTP_PROXY，含 NO_PROXY 处理），则通过 HTTP CONNECT
// 隧道建连；否则直连。
func dialTarget(ctx context.Context, addr string) (net.Conn, error) {
	proxyURL, err := http.ProxyFromEnvironment(&http.Request{URL: &url.URL{Scheme: "https", Host: addr}})
	if err != nil || proxyURL == nil {
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}
	return dialViaCONNECT(ctx, proxyURL, addr)
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
