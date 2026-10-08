package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"
)

// fakeClient 表示假 DERP 服务器上的一个已连接客户端，写帧时加锁串行化。
type fakeClient struct {
	mu sync.Mutex
	bw *bufio.Writer
}

func (fc *fakeClient) sendFrame(typ byte, payload []byte) error {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	writeFrame(fc.bw, typ, payload)
	return fc.bw.Flush()
}

// startFakeDERP 启动一个最小化的假 DERP 服务器：
// TLS -> HTTP Upgrade(101) -> ServerKey 帧 -> 读 ClientInfo -> ping 回 pong（延迟 latency）。
// enableForward 为 true 时，还支持客户端间转发：收到 SendPacket(0x04) 后，
// 按其中的目标 key 转发给对应客户端（RecvPacket 0x05），找不到目标则丢弃
// （模拟真实服务器行为），用于测试 probeRelay。
func startFakeDERP(t *testing.T, latency time.Duration, enableForward bool) (string, int) {
	t.Helper()
	var mu sync.Mutex
	clients := make(map[[32]byte]*fakeClient) // 客户端公钥 -> 连接

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "DERP" {
			http.Error(w, "need upgrade", http.StatusBadRequest)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		conn, brw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()

		brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n")
		// ServerKey 帧: 8B magic "DERP🔑" + 32B 公钥（随机非零字节即可，假服务器不校验 ClientInfo）
		fakeKey := make([]byte, 32)
		if _, err := rand.Read(fakeKey); err != nil {
			return
		}
		payload := append([]byte("DERP🔑"), fakeKey...)
		writeFrame(brw.Writer, 0x01, payload)
		if err := brw.Flush(); err != nil {
			return
		}
		// 读 ClientInfo 帧，解析出客户端公钥（payload 前 32 字节）
		ft, p, err := readFrame(brw.Reader)
		if err != nil || ft != 0x02 || len(p) < 32 {
			return
		}
		var ckey [32]byte
		copy(ckey[:], p[:32])
		fc := &fakeClient{bw: brw.Writer}
		mu.Lock()
		clients[ckey] = fc
		mu.Unlock()
		defer func() {
			mu.Lock()
			delete(clients, ckey)
			mu.Unlock()
		}()

		for {
			ft, p, err := readFrame(brw.Reader)
			if err != nil {
				return
			}
			switch ft {
			case 0x12: // ping -> pong
				time.Sleep(latency)
				if err := fc.sendFrame(0x13, p); err != nil {
					return
				}
			case 0x04: // sendpacket: 32B 目标 key + 数据
				if !enableForward || len(p) < 32 {
					continue
				}
				var dst [32]byte
				copy(dst[:], p[:32])
				mu.Lock()
				target := clients[dst]
				mu.Unlock()
				if target == nil {
					continue // 目标不在线则丢弃
				}
				fwd := make([]byte, 0, 32+len(p)-32)
				fwd = append(fwd, ckey[:]...)
				fwd = append(fwd, p[32:]...)
				if err := target.sendFrame(0x05, fwd); err != nil {
					continue
				}
			}
		}
	})
	srv := httptest.NewUnstartedServer(handler)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	u, _ := url.Parse(srv.URL)
	host, portStr, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portStr)
	return host, port
}

func writeFrame(w *bufio.Writer, typ byte, payload []byte) {
	var hdr [5]byte
	hdr[0] = typ
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(payload)))
	w.Write(hdr[:])
	w.Write(payload)
}

func readFrame(r *bufio.Reader) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	ln := binary.BigEndian.Uint32(hdr[1:])
	p := make([]byte, ln)
	if _, err := io.ReadFull(r, p); err != nil {
		return 0, nil, err
	}
	return hdr[0], p, nil
}

func TestProbeDERP(t *testing.T) {
	host, port := startFakeDERP(t, 20*time.Millisecond, false)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	rtt, err := ProbeDERP(ctx, host, port, 3, 5*time.Second, false)
	if err != nil {
		t.Fatalf("探测失败: %v", err)
	}
	if rtt < 15*time.Millisecond || rtt > 2*time.Second {
		t.Fatalf("RTT 不在预期范围: %v", rtt)
	}
	t.Logf("RTT = %v", rtt)
}

func TestProbeDERPNotDERP(t *testing.T) {
	// 普通 HTTPS 服务器（拒绝 Upgrade）应被判定为不可用
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello"))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	host, portStr, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := ProbeDERP(ctx, host, port, 1, 3*time.Second, false); err == nil {
		t.Fatal("期望探测失败，但成功了")
	}
}

func TestProbeDERPConnRefused(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := ProbeDERP(ctx, "127.0.0.1", 1, 1, 2*time.Second, false); err == nil {
		t.Fatal("期望连接被拒绝，但成功了")
	}
}

// TestProxyFromHTTPOnly 验证：只设置 HTTP_PROXY（不设 HTTPS_PROXY）时，
// 探测目标为 https 也能拿到代理地址（Go 标准库不会这样回落，curl 会）。
func TestProxyFromHTTPOnly(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("https_proxy", "")
	t.Setenv("HTTP_PROXY", "proxy:8080") // 无 scheme 也要能解析
	t.Setenv("http_proxy", "")

	pu := proxyFromHTTPOnly()
	if pu == nil || pu.Host != "proxy:8080" {
		t.Fatalf("期望解析出代理 proxy:8080，实际 %v", pu)
	}

	t.Setenv("HTTP_PROXY", "")
	if proxyFromHTTPOnly() != nil {
		t.Fatal("无代理变量时应返回 nil")
	}

	t.Setenv("http_proxy", "http://proxy2:9090")
	pu = proxyFromHTTPOnly()
	if pu == nil || pu.Host != "proxy2:9090" {
		t.Fatalf("期望解析出代理 proxy2:9090，实际 %v", pu)
	}
}

// TestWriteFileAtomic 验证原子写入：内容完整，且不会留下临时文件。
func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/derp.json"
	data := []byte(`{"Regions":{}}` + "\n")
	if err := writeFileAtomic(path, data); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(data) {
		t.Fatalf("内容不一致: %q", got)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != "derp.json" {
			t.Fatalf("残留临时文件: %s", e.Name())
		}
	}
}

// TestProbeRelay 验证 probeRelay：假服务器开启转发时，A 发包 B 必须能收到。
func TestProbeRelay(t *testing.T) {
	host, port := startFakeDERP(t, 5*time.Millisecond, true)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	if err := probeRelay(ctx, addr, true, 5*time.Second); err != nil {
		t.Fatalf("中继转发验证失败: %v", err)
	}
}

// TestProbeRelayNoForward 验证 probeRelay 能检出"不转发"的服务器：
// 假服务器关闭转发时，B 永远收不到包，应在超时后报错（而不是误判通过）。
func TestProbeRelayNoForward(t *testing.T) {
	host, port := startFakeDERP(t, 5*time.Millisecond, false)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	start := time.Now()
	err := probeRelay(ctx, addr, true, 2*time.Second)
	if err == nil {
		t.Fatal("服务器不转发时期望失败，但通过了")
	}
	t.Logf("正确检出不转发的服务器: %v（耗时 %v）", err, time.Since(start).Round(time.Millisecond))
}

// TestProbeDERPWithRelay 走完整 ProbeDERP 流程（含 relayTest=true），
// 确认端到端通过。
func TestProbeDERPWithRelay(t *testing.T) {
	host, port := startFakeDERP(t, 10*time.Millisecond, true)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	rtt, err := ProbeDERP(ctx, host, port, 2, 5*time.Second, true)
	if err != nil {
		t.Fatalf("探测失败: %v", err)
	}
	if rtt <= 0 || rtt > 5*time.Second {
		t.Fatalf("RTT 异常: %v", rtt)
	}
	t.Logf("RTT = %v（含中继验证）", rtt)
}
