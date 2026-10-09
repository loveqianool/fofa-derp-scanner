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
	"strconv"
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
		input       = flag.String("input", "", "输入文件：FOFA 导出的 JSON（扫描模式）或 derp-all.json（筛选模式，自动识别）")
		output      = flag.String("output", "derp.json", "输出 derpMap JSON 路径")
		check       = flag.String("check", "", "复检模式：重新探测指定 derp-all.json 中的节点，剔除不可用的并原地更新")
		start       = flag.Int("start", 900, "RegionID 起始编号（官方托管限制 900-999）")
		maxLatency  = flag.Duration("max-latency", 100*time.Millisecond, "保留节点的中位延迟上限")
		samples     = flag.Int("samples", 3, "每个节点 ping 采样次数（全部成功才保留）")
		concurrency = flag.Int("concurrency", 50, "并发探测数")
		timeout     = flag.Duration("timeout", 20*time.Second, "单个节点探测总超时")
		pingTimeout = flag.Duration("ping-timeout", 5*time.Second, "单次 ping 超时")
		stunTimeout = flag.Duration("stun-timeout", 5*time.Second, "STUN UDP 探测超时（STUN 不通的节点会被丢弃，因 Tailscale 不会使用）")
		relayTest   = flag.Bool("relay-test", false, "额外验证客户端间中继转发（建两个客户端，A 发包 B 收），更严格")
		region      = flag.String("region", "", "筛选模式按区域配额选取，如 \"guangzhou:20,hongkong:20\"（省略 :数量 则取该区域全部），逗号分隔多个")
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

	// 复检模式：--check <derp-all.json>，重新探测并原地更新
	if strings.TrimSpace(*check) != "" {
		return runCheck(*check, *start, *maxLatency, *concurrency, *samples, *timeout, *pingTimeout, *stunTimeout, *relayTest)
	}

	// 参数解析 fallback 链：命令行 flag → 环境变量 → 交互式输入。
	// 某些 Android 设备上 argv 会损坏，环境变量和 stdin 是独立的输入通道。
	inputPath := resolveParam(*input, "DERP_SCAN_INPUT", "")
	outputPath := resolveParam(*output, "DERP_SCAN_OUTPUT", "")
	if inputPath == "" && isTerminal() {
		fmt.Print("输入文件路径（FOFA JSON 或 derp-all.json）: ")
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

	// 筛选模式：输入是 derp-all.json（derpMap 格式），不探测，直接按区域配额选取
	if dm, ok := tryParseDERPMap(data); ok {
		quotas, err := parseRegionQuotas(*region)
		if err != nil {
			fmt.Fprintf(os.Stderr, "错误: %v\n", err)
			return 2
		}
		if inputPath == outputPath {
			fmt.Fprintln(os.Stderr, "错误: 筛选模式的输入与输出不能是同一个文件（会丢失未选中的节点）。如需原地剔除不可用节点，请用 --check。")
			return 2
		}
		return runSelect(dm, quotas, *start, inputPath, outputPath)
	}

	// 扫描模式：输入是 FOFA 导出，探测全部可用节点
	if strings.TrimSpace(*region) != "" {
		fmt.Fprintln(os.Stderr, "提示: --region 仅在筛选模式（输入为 derp-all.json）下生效，本次扫描已忽略。")
	}
	assets, err := ParseAssets(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "解析 FOFA 数据失败: %v\n", err)
		return 1
	}
	return runScan(assets, *start, outputPath, *maxLatency, *concurrency, *samples, *timeout, *pingTimeout, *stunTimeout, *relayTest)
}

// probeJob 是一次探测任务。
type probeJob struct {
	label string // 进度显示用，如 "1.2.3.4:443"
	host  string
	port  int
}

// probeResult 是单次探测结果。
type probeResult struct {
	rtt time.Duration
	err error
}

// probeAll 并发探测一批目标，返回与 jobs 一一对应的结果。
// 每个任务完成时实时打印进度；ctx 取消时直接返回已有结果。
func probeAll(ctx context.Context, jobs []probeJob, concurrency, samples int, pingTimeout, timeout, stunTimeout time.Duration, relayTest bool) []probeResult {
	results := make([]probeResult, len(jobs))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	done := 0
	for i := range jobs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			pctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			rtt, err := ProbeDERP(pctx, jobs[i].host, jobs[i].port, samples, pingTimeout, stunTimeout, relayTest)

			mu.Lock()
			results[i] = probeResult{rtt: rtt, err: err}
			done++
			if err != nil {
				fmt.Printf("[%d/%d] %-30s 失败: %v\n", done, len(jobs), jobs[i].label, shortErr(err))
			} else {
				fmt.Printf("[%d/%d] %-30s %v\n", done, len(jobs), jobs[i].label, rtt.Round(time.Millisecond))
			}
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	return results
}

// runScan 扫描模式：探测 FOFA 资产中的全部节点，输出所有可用节点（按延迟排序，带 LatencyMs）。
func runScan(assets []Asset, start int, outputPath string, maxLatency time.Duration, concurrency, samples int, timeout, pingTimeout, stunTimeout time.Duration, relayTest bool) int {
	if len(assets) == 0 {
		fmt.Fprintln(os.Stderr, "没有解析到有效节点（需要 ip + port）")
		return 1
	}
	relayMsg := ""
	if relayTest {
		relayMsg = "，附加中继转发验证"
	}
	fmt.Printf("解析到 %d 个候选节点，开始探测（并发 %d，每节点 %d 次 ping%s）…\n",
		len(assets), concurrency, samples, relayMsg)

	cands := BuildCandidates(assets, start)
	jobs := make([]probeJob, len(cands))
	for i, c := range cands {
		host := c.Asset.IP
		if c.Asset.Domain != "" {
			host = c.Asset.Domain
		}
		jobs[i] = probeJob{label: fmt.Sprintf("%s:%d", host, c.Asset.Port), host: host, port: c.Asset.Port}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	results := probeAll(ctx, jobs, concurrency, samples, pingTimeout, timeout, stunTimeout, relayTest)

	if ctx.Err() != nil {
		fmt.Fprintln(os.Stderr, "\n已取消，未写入输出文件。")
		return 1
	}

	ok := make([]Candidate, 0, len(cands))
	for i, r := range results {
		switch {
		case r.err != nil:
			// 已在 probeAll 中打印失败原因
		case r.rtt > maxLatency:
			fmt.Printf("%-30s %v 太慢（上限 %v），丢弃\n", jobs[i].label, r.rtt.Round(time.Millisecond), maxLatency)
		default:
			c := cands[i]
			c.RTT = r.rtt
			ok = append(ok, c)
		}
	}

	if len(ok) == 0 {
		fmt.Fprintln(os.Stderr, "没有可用节点，未生成输出文件。")
		return 1
	}

	// 按延迟排序，全部输出（不截断）。注意：数量可能超过 900-999 的 100 上限，
	// 这是中间文件（derp-all.json），筛选模式会重新编号并截断到官方限制内。
	sort.Slice(ok, func(i, j int) bool { return ok[i].RTT < ok[j].RTT })

	m := BuildDERPMap(ok, start)
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

	fmt.Printf("\n完成：%d/%d 个节点可用（中位延迟 ≤ %v），已按延迟排序并从 %d 开始编号，写入 %s\n",
		len(ok), len(cands), maxLatency, start, outputPath)
	fmt.Println("下一步：用筛选模式从该文件按区域配额选取节点，例如：")
	fmt.Println("  derp-scan --input " + outputPath + " --output derp.json --region \"guangzhou:20,hongkong:20\"")
	return 0
}

// flatNode 是筛选/复检用的扁平节点（Region + Node）。
type flatNode struct {
	regionName string
	node       Node
}

// flattenDERPMap 把 derpMap 展平为节点列表（按 RegionID 排序，保证确定性）。
func flattenDERPMap(dm *DERPMap) []flatNode {
	keys := make([]int, 0, len(dm.Regions))
	keyOf := make(map[int]string, len(dm.Regions))
	for k := range dm.Regions {
		if id, err := strconv.Atoi(k); err == nil {
			keys = append(keys, id)
			keyOf[id] = k
		}
	}
	sort.Ints(keys)
	var all []flatNode
	for _, id := range keys {
		r := dm.Regions[keyOf[id]]
		for _, n := range r.Nodes {
			all = append(all, flatNode{regionName: r.RegionName, node: n})
		}
	}
	return all
}

// regionDistribution 返回按数量降序的 "区域名 (N个)" 列表，用于零匹配时提示。
func regionDistribution(all []flatNode) []string {
	counts := make(map[string]int)
	for _, f := range all {
		name := f.regionName
		if strings.TrimSpace(name) == "" {
			name = "(未知)"
		}
		counts[name]++
	}
	type kv struct {
		name string
		n    int
	}
	var kvs []kv
	for name, n := range counts {
		kvs = append(kvs, kv{name, n})
	}
	sort.Slice(kvs, func(i, j int) bool {
		if kvs[i].n != kvs[j].n {
			return kvs[i].n > kvs[j].n
		}
		return kvs[i].name < kvs[j].name
	})
	out := make([]string, 0, len(kvs))
	for _, kv := range kvs {
		out = append(out, fmt.Sprintf("%s (%d个)", kv.name, kv.n))
	}
	return out
}

// applyQuotas 按区域配额选取节点：每个配额在未被占用的节点中按区域名匹配，
// 取延迟最低的 Count 个（Count=0 取全部）。返回按配额顺序排列的选中节点。
// 某配额零匹配时返回错误（调用方打印区域分布）。
func applyQuotas(all []flatNode, quotas []RegionQuota) ([]flatNode, error) {
	used := make([]bool, len(all))
	var selected []flatNode
	for _, q := range quotas {
		var idx []int
		for i, f := range all {
			if !used[i] && matchRegion(f.regionName, []string{q.Pattern}) {
				idx = append(idx, i)
			}
		}
		if len(idx) == 0 {
			return nil, fmt.Errorf("区域 %q 没有匹配到节点。", q.Pattern)
		}
		sort.Slice(idx, func(a, b int) bool {
			return latencyMsOrMax(all[idx[a]].node) < latencyMsOrMax(all[idx[b]].node)
		})
		take := len(idx)
		if q.Count > 0 && take > q.Count {
			take = q.Count
		}
		fmt.Printf("区域 %q: %d 个候选，取延迟最低的 %d 个。\n", q.Pattern, len(idx), take)
		for _, i := range idx[:take] {
			used[i] = true
			selected = append(selected, all[i])
		}
	}
	return selected, nil
}

// runSelect 筛选模式：从 derp-all.json 中按区域配额选取节点，不重新探测，
// 重新编号（900-999 范围内）并去掉 LatencyMs 后写入最终输出。
func runSelect(dm *DERPMap, quotas []RegionQuota, start int, inputPath, outputPath string) int {
	all := flattenDERPMap(dm)
	if len(all) == 0 {
		fmt.Fprintln(os.Stderr, "输入的 derpMap 中没有节点。")
		return 1
	}

	// 缺延迟数据时提醒（老版本输出没有 LatencyMs）
	hasLatency := false
	for _, f := range all {
		if f.node.LatencyMs > 0 {
			hasLatency = true
			break
		}
	}
	if !hasLatency {
		fmt.Fprintln(os.Stderr, "提示: 输入文件中没有延迟数据（LatencyMs），\"最低延迟\" 选取将无意义，建议用新版重新扫描生成 derp-all.json。")
	}

	var selected []flatNode
	if len(quotas) == 0 {
		sort.Slice(all, func(i, j int) bool { return latencyMsOrMax(all[i].node) < latencyMsOrMax(all[j].node) })
		selected = all
		fmt.Printf("未指定 --region，选取全部 %d 个节点（按延迟排序）。\n", len(selected))
	} else {
		var err error
		selected, err = applyQuotas(all, quotas)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v文件中实际的区域分布：\n", err)
			for _, s := range regionDistribution(all) {
				fmt.Fprintf(os.Stderr, "  %s\n", s)
			}
			return 1
		}
	}

	if len(selected) == 0 {
		fmt.Fprintln(os.Stderr, "没有选中任何节点。")
		return 1
	}

	// 官方托管限制：RegionID 900-999，按配额顺序截断
	if capacity := 1000 - start; len(selected) > capacity {
		fmt.Printf("提示: RegionID 上限 999，从 %d 起最多 %d 个 Region，超出部分已截断（%d → %d）。\n",
			start, capacity, len(selected), capacity)
		selected = selected[:capacity]
	}

	m := DERPMap{Regions: make(map[string]Region, len(selected))}
	for i, f := range selected {
		rid := start + i
		n := Node{
			Name:             fmt.Sprintf("%d-%s", rid, f.node.HostName),
			RegionID:         rid,
			HostName:         f.node.HostName,
			IPv4:             f.node.IPv4,
			IPv6:             f.node.IPv6,
			DERPPort:         f.node.DERPPort,
			STUNPort:         f.node.STUNPort,
			InsecureForTests: f.node.InsecureForTests,
			// LatencyMs 归零：omitempty 会省略，最终输出干净可直接粘贴到 ACL
		}
		m.Regions[strconv.Itoa(rid)] = Region{
			RegionID:   rid,
			RegionCode: fmt.Sprintf("custom%d", rid),
			RegionName: f.regionName,
			Nodes:      []Node{n},
		}
	}

	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "生成 JSON 失败: %v\n", err)
		return 1
	}
	out = append(out, '\n')
	if err := writeFileAtomic(outputPath, out); err != nil {
		fmt.Fprintf(os.Stderr, "写入输出文件失败: %v\n", err)
		return 1
	}

	fmt.Printf("\n完成：从 %s 的 %d 个节点中选取 %d 个（RegionID %d-%d），写入 %s\n",
		inputPath, len(all), len(selected), start, start+len(selected)-1, outputPath)
	fmt.Println("下一步：把该文件中 Regions 下的内容粘贴到 Tailscale ACL 的 derpMap.Regions 里。")
	return 0
}

// nodeDialHost 取复检时拨号用的主机：优先用 IP（省去 DNS），都没有则用 HostName（域名）。
func nodeDialHost(n Node) string {
	if n.IPv4 != "" {
		return n.IPv4
	}
	if n.IPv6 != "" {
		return n.IPv6
	}
	return n.HostName
}

// runCheck 复检模式：重新探测 derp-all.json 中的每个节点，剔除不可用/太慢的，
// 更新延迟后按延迟重排、重新编号，原地写回。
func runCheck(path string, start int, maxLatency time.Duration, concurrency, samples int, timeout, pingTimeout, stunTimeout time.Duration, relayTest bool) int {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取文件失败: %v\n", err)
		return 1
	}
	dm, ok := tryParseDERPMap(data)
	if !ok {
		fmt.Fprintln(os.Stderr, "错误: --check 需要输入 derpMap 格式的 JSON（如 derp-all.json）。")
		return 2
	}
	all := flattenDERPMap(dm)
	if len(all) == 0 {
		fmt.Fprintln(os.Stderr, "文件中没有节点，无需复检。")
		return 1
	}

	jobs := make([]probeJob, len(all))
	for i, f := range all {
		host := nodeDialHost(f.node)
		jobs[i] = probeJob{label: fmt.Sprintf("%s:%d", host, f.node.DERPPort), host: host, port: f.node.DERPPort}
	}

	relayMsg := ""
	if relayTest {
		relayMsg = "，附加中继转发验证"
	}
	fmt.Printf("复检 %s 中的 %d 个节点（并发 %d%s）…\n", path, len(all), concurrency, relayMsg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	results := probeAll(ctx, jobs, concurrency, samples, pingTimeout, timeout, stunTimeout, relayTest)

	if ctx.Err() != nil {
		fmt.Fprintln(os.Stderr, "\n已取消，未更新文件。")
		return 1
	}

	type okItem struct {
		flatNode
		rtt time.Duration
	}
	var okList []okItem
	for i, r := range results {
		switch {
		case r.err != nil:
			// 已在 probeAll 中打印
		case r.rtt > maxLatency:
			fmt.Printf("%-30s %v 太慢（上限 %v），剔除\n", jobs[i].label, r.rtt.Round(time.Millisecond), maxLatency)
		default:
			n := all[i].node
			n.LatencyMs = r.rtt.Milliseconds()
			okList = append(okList, okItem{flatNode: flatNode{regionName: all[i].regionName, node: n}, rtt: r.rtt})
		}
	}

	if len(okList) == 0 {
		fmt.Fprintln(os.Stderr, "所有节点都不可用，未更新文件。")
		return 1
	}

	sort.Slice(okList, func(i, j int) bool { return okList[i].rtt < okList[j].rtt })

	m := DERPMap{Regions: make(map[string]Region, len(okList))}
	for i, o := range okList {
		rid := start + i
		n := o.node
		n.Name = fmt.Sprintf("%d-%s", rid, n.HostName)
		n.RegionID = rid
		m.Regions[strconv.Itoa(rid)] = Region{
			RegionID:   rid,
			RegionCode: fmt.Sprintf("custom%d", rid),
			RegionName: o.regionName,
			Nodes:      []Node{n},
		}
	}

	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "生成 JSON 失败: %v\n", err)
		return 1
	}
	out = append(out, '\n')
	if err := writeFileAtomic(path, out); err != nil {
		fmt.Fprintf(os.Stderr, "写回文件失败: %v\n", err)
		return 1
	}

	fmt.Printf("\n复检完成：%d/%d 个节点可用，已按延迟重排并原地更新 %s\n", len(okList), len(all), path)
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
