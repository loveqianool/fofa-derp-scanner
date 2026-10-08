// derp-scan: 从 FOFA 导出的 DERP 节点资产中，一条命令探测并输出可用的 derpMap。
//
// 流程: 解析 FOFA JSON -> 并发 DERP 协议探测 -> 筛选稳定低延迟节点 ->
// 按延迟排序、重新编号 -> 输出可直接粘贴到 Tailscale ACL derpMap 的 JSON。
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// version 由构建时 -ldflags "-X main.version=..." 注入，默认为 dev。
var version = "dev"

func main() {
	os.Exit(run())
}

func run() int {
	fixArgs() // 必须在 flag.Parse() 之前：某些 Android 设备上 Go 运行时拿不到 argv
	if os.Getenv("DERP_SCAN_DEBUG") != "" {
		debugArgs()
	}
	var (
		input       = flag.String("input", "", "FOFA 导出的 JSON 文件路径（必填）")
		output      = flag.String("output", "derp.json", "输出 derpMap JSON 路径")
		start       = flag.Int("start", 900, "RegionID 起始编号（官方托管限制 900-999）")
		limit       = flag.Int("limit", 50, "最多输出的节点数（按延迟取最低的 N 个），0 表示不限制")
		maxLatency  = flag.Duration("max-latency", 100*time.Millisecond, "保留节点的中位延迟上限")
		samples     = flag.Int("samples", 3, "每个节点 ping 采样次数（全部成功才保留）")
		concurrency = flag.Int("concurrency", 50, "并发探测数")
		timeout     = flag.Duration("timeout", 20*time.Second, "单个节点探测总超时")
		pingTimeout = flag.Duration("ping-timeout", 5*time.Second, "单次 ping 超时")
		relayTest   = flag.Bool("relay-test", false, "额外验证客户端间中继转发（建两个客户端，A 发包 B 收），更严格")
		showVersion = flag.Bool("version", false, "打印版本并退出")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("derp-scan %s\n", version)
		return 0
	}

	// 参数合法性校验：非法值会导致死锁或 panic，提前拦截
	if *concurrency < 1 {
		fmt.Fprintln(os.Stderr, "错误: --concurrency 必须 >= 1")
		return 2
	}
	if *samples < 1 {
		fmt.Fprintln(os.Stderr, "错误: --samples 必须 >= 1")
		return 2
	}
	if *timeout <= 0 || *pingTimeout <= 0 {
		fmt.Fprintln(os.Stderr, "错误: --timeout 和 --ping-timeout 必须 > 0")
		return 2
	}
	// 官方托管硬性限制：自定义 RegionID 只能用 900-999，且一个 Region 只能放 1 台 DERP
	if *start < 900 || *start > 999 {
		fmt.Fprintln(os.Stderr, "错误: --start 必须在 900-999 范围内（官方托管自定义区域 ID 范围）")
		return 2
	}

	// 参数解析 fallback 链：命令行 flag → 环境变量 → 交互式输入。
	// 某些 Android 设备上 argv 会损坏，环境变量和 stdin 是独立的输入通道。
	inputPath := resolveParam(*input, "DERP_SCAN_INPUT", "")
	outputPath := resolveParam(*output, "DERP_SCAN_OUTPUT", "")
	if inputPath == "" && isTerminal() {
		fmt.Print("FOFA JSON 文件路径: ")
		if line, err := readLine(); err == nil {
			inputPath = strings.TrimSpace(line)
		}
	}
	if inputPath == "" {
		fmt.Fprintln(os.Stderr, "错误: 必须指定 --input（或设置 DERP_SCAN_INPUT 环境变量）")
		flag.Usage()
		return 2
	}

	data, err := os.ReadFile(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取输入文件失败: %v\n", err)
		return 1
	}
	assets, err := ParseAssets(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "解析 FOFA 数据失败: %v\n", err)
		return 1
	}
	if len(assets) == 0 {
		fmt.Fprintln(os.Stderr, "没有解析到有效节点（需要 ip + port）")
		return 1
	}
	relayMsg := ""
	if *relayTest {
		relayMsg = "，附加中继转发验证"
	}
	fmt.Printf("解析到 %d 个候选节点，开始探测（并发 %d，每节点 %d 次 ping%s）…\n",
		len(assets), *concurrency, *samples, relayMsg)

	cands := BuildCandidates(assets, *start)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	sem := make(chan struct{}, *concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := make([]Candidate, 0, len(cands))
	done := 0

	for _, c := range cands {
		c := c
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			pctx, cancel := context.WithTimeout(ctx, *timeout)
			defer cancel()

			host := c.Asset.IP
			if c.Asset.Domain != "" {
				host = c.Asset.Domain
			}
			rtt, err := ProbeDERP(pctx, host, c.Asset.Port, *samples, *pingTimeout, *relayTest)

			mu.Lock()
			defer mu.Unlock()
			done++
			label := fmt.Sprintf("%s:%d", host, c.Asset.Port)
			switch {
			case err != nil:
				fmt.Printf("[%d/%d] %-30s 失败: %v\n", done, len(cands), label, shortErr(err))
			case rtt > *maxLatency:
				fmt.Printf("[%d/%d] %-30s %v 太慢（上限 %v），丢弃\n", done, len(cands), label, rtt.Round(time.Millisecond), *maxLatency)
			default:
				c.RTT = rtt
				ok = append(ok, c)
				fmt.Printf("[%d/%d] %-30s 可用 %v\n", done, len(cands), label, rtt.Round(time.Millisecond))
			}
		}()
	}
	wg.Wait()

	if ctx.Err() != nil {
		fmt.Fprintln(os.Stderr, "\n已取消，未写入输出文件。")
		return 1
	}

	if len(ok) == 0 {
		fmt.Fprintln(os.Stderr, "没有可用节点，未生成输出文件。")
		return 1
	}

	// 按延迟取前 N 个：N = min(可用数, --limit, 900-999 范围上限)。
	// 官方托管限制自定义 RegionID 只能用 900-999（最多 100 个 Region），
	// 且一个 Region 只放 1 台 DERP（本工具本来就是 1 Region 1 Node 结构）。
	if n := maxOutput(*start, *limit, len(ok)); len(ok) > n {
		sort.Slice(ok, func(i, j int) bool { return ok[i].RTT < ok[j].RTT })
		fmt.Printf("可用节点 %d 个，取延迟最低的 %d 个（RegionID %d-%d）。\n",
			len(ok), n, *start, *start+n-1)
		ok = ok[:n]
	}

	m := BuildDERPMap(ok, *start)
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "生成 JSON 失败: %v\n", err)
		return 1
	}
	out = append(out, '\n')
	// 原子写入：先写临时文件再 rename，避免 Ctrl+C 等中断留下半截文件
	if err := writeFileAtomic(outputPath, out); err != nil {
		fmt.Fprintf(os.Stderr, "写入输出文件失败: %v\n", err)
		return 1
	}

	fmt.Printf("\n完成：%d/%d 个节点可用（中位延迟 ≤ %v），已按延迟排序并从 %d 重新编号，写入 %s\n",
		len(ok), len(cands), *maxLatency, *start, outputPath)
	fmt.Println("下一步：把该文件中 Regions 下的内容粘贴到 Tailscale ACL 的 derpMap.Regions 里。")
	return 0
}

// writeFileAtomic 原子写入文件：先写同目录临时文件再 rename，
// 避免写入过程中被中断留下半截文件。
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".derp-scan-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // 成功 rename 后删除已不存在，无害
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0644); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// fixArgs 兜底：必须在 flag.Parse() 之前调用。
//
// 1. 某些 Android 设备/ROM 上，Go 程序经 /system/bin/linker64 加载时，
//    argv 在 linker 到 _rt0 的交接中丢失，此时尝试从 /proc/self/cmdline
//    （内核在 execve 时写入，不经过该链路）重建。
// 2. 某些环境会把二进制绝对路径作为 argv[1] 重复插入，导致真实参数整体
//    后移一位（flag.Parse 只看 os.Args[1:]，遇到首个非 flag 参数即停止，
//    后面的 -version/--input 全被吞掉）。检测到 argv[1] 与 argv[0] 指向
//    同一文件时删掉它。
//
// 非 Linux/Android 平台上 /proc 不存在，会静默跳过，无任何影响。
func fixArgs() {
	if len(os.Args) <= 1 {
		if data, err := os.ReadFile("/proc/self/cmdline"); err == nil && len(data) > 0 {
			if args := parseCmdline(data); len(args) > 1 {
				os.Args = args
			}
		}
	}
	// 去掉重复插入的 argv[1]（与 argv[0] 指向同一文件）
	os.Args = dedupArgv(os.Args)
}

// dedupArgv：如果 argv[1] 与 argv[0] 指向同一文件（绝对路径相同），
// 则删掉 argv[1]，让真实参数回到正确位置。否则原样返回。
func dedupArgv(args []string) []string {
	if len(args) >= 3 {
		p0, err0 := filepath.Abs(args[0])
		p1, err1 := filepath.Abs(args[1])
		if err0 == nil && err1 == nil && p0 == p1 {
			return append([]string{args[0]}, args[2:]...)
		}
	}
	return args
}

// resolveParam 按优先级解析参数：命令行 flag 值 → 环境变量 → 默认值。
// flagVal 为空（用户未通过 flag 指定）时才看环境变量。
func resolveParam(flagVal, envKey, def string) string {
	if flagVal != "" {
		return flagVal
	}
	if v := os.Getenv(envKey); v != "" {
		return v
	}
	return def
}

// isTerminal 粗略判断 stdin 是否为终端（可交互输入）。
// 用 /dev/tty 是否可打开来判断，避免引入 x/term 依赖。
func isTerminal() bool {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// readLine 从 stdin 读一行（去掉末尾换行）。
func readLine() (string, error) {
	var line []byte
	buf := make([]byte, 1)
	for {
		n, err := os.Stdin.Read(buf)
		if n > 0 {
			if buf[0] == '\n' {
				break
			}
			line = append(line, buf[0])
		}
		if err != nil {
			break
		}
	}
	if len(line) == 0 {
		return "", fmt.Errorf("no input")
	}
	return strings.TrimRight(string(line), "\r"), nil
}

// debugArgs 打印进程实际拿到的参数信息，用于诊断 argv 丢失问题。
// 设置 DERP_SCAN_DEBUG=1 触发。
func debugArgs() {
	fmt.Fprintf(os.Stderr, "[debug] len(os.Args)=%d\n", len(os.Args))
	for i, a := range os.Args {
		fmt.Fprintf(os.Stderr, "[debug] os.Args[%d]=%q\n", i, a)
	}
	if data, err := os.ReadFile("/proc/self/cmdline"); err != nil {
		fmt.Fprintf(os.Stderr, "[debug] /proc/self/cmdline 读取失败: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "[debug] /proc/self/cmdline=%q\n", parseCmdline(data))
	}
}

// maxOutput 计算最终输出的 Region 数量：
// min(可用节点数, --limit(如设置), 900-999 范围内容量)。
// 官方托管硬性限制自定义 RegionID 只能用 900-999（最多 100 个）。
func maxOutput(start, limit, available int) int {
	maxOut := 999 - start + 1
	if limit > 0 && limit < maxOut {
		maxOut = limit
	}
	if available < maxOut {
		maxOut = available
	}
	return maxOut
}

// parseCmdline 解析 /proc/self/cmdline 的原始字节（以 \0 分隔，末尾也有 \0），
// 返回参数列表。空片段会被丢弃。
func parseCmdline(data []byte) []string {
	parts := strings.Split(string(data), "\x00")
	args := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			args = append(args, p)
		}
	}
	return args
}

// shortErr 把多层 wrapped error 压成最后一句，日志更干净。
func shortErr(err error) string {
	msg := err.Error()
	for i := len(msg) - 1; i >= 0; i-- {
		if msg[i] == ':' && i+2 < len(msg) {
			return msg[i+2:]
		}
	}
	return msg
}
