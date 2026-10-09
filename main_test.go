
package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestParseCmdline 验证 /proc/self/cmdline 解析：\0 分隔、末尾 \0、空片段丢弃。
func TestParseCmdline(t *testing.T) {
	got := parseCmdline([]byte("./derp-scan\x00-version\x00--input\x00foo.json\x00"))
	want := []string{"./derp-scan", "-version", "--input", "foo.json"}
	if len(got) != len(want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %q, want %q", got, want)
		}
	}
	// 空输入 / 全空片段
	if got := parseCmdline(nil); len(got) != 0 {
		t.Fatalf("空输入应返回空，got %q", got)
	}
	if got := parseCmdline([]byte("\x00\x00")); len(got) != 0 {
		t.Fatalf("全空片段应返回空，got %q", got)
	}
}

// TestDedupArgv 验证 argv 去重：argv[1] 与 argv[0] 同文件时删掉 argv[1]。
func TestDedupArgv(t *testing.T) {
	// 相对路径 argv[0] + 绝对路径重复的 argv[1]（用户设备上的真实情况）
	got := dedupArgv([]string{"./derp-scan", "/data/data/com.termux/files/home/derp/derp-scan", "-version"})
	// 在测试机上 cwd 不同，Abs("./derp-scan") 不会等于那个绝对路径，所以用同目录构造
	cwd, _ := os.Getwd()
	abs := filepath.Join(cwd, "derp-scan")
	got = dedupArgv([]string{"./derp-scan", abs, "-version", "--input", "x.json"})
	want := []string{"./derp-scan", "-version", "--input", "x.json"}
	if len(got) != len(want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %q, want %q", got, want)
		}
	}
	// 不重复时原样返回
	normal := []string{"./derp-scan", "-version"}
	if got := dedupArgv(normal); len(got) != 2 || got[1] != "-version" {
		t.Fatalf("正常参数不应被改动，got %q", got)
	}
	// argv[1] 是不同文件时不动
	other := []string{"./derp-scan", "/bin/sh", "-version"}
	if got := dedupArgv(other); len(got) != 3 {
		t.Fatalf("不同文件不应去重，got %q", got)
	}
	// 少于 3 个参数时不动
	if got := dedupArgv([]string{"./derp-scan"}); len(got) != 1 {
		t.Fatalf("got %q", got)
	}
}


// TestApplyQuotas 验证按区域配额选取：各取延迟最低的 N 个，配额顺序保留，不重复。
func TestApplyQuotas(t *testing.T) {
	mk := func(region string, latency int64) flatNode {
		return flatNode{regionName: region, node: Node{HostName: region, LatencyMs: latency}}
	}
	all := []flatNode{
		mk("Guangzhou", 50), mk("Guangzhou", 20), mk("Guangzhou", 80),
		mk("Hong Kong", 60), mk("Hong Kong", 10), mk("Hong Kong", 90),
		mk("Shanghai", 30),
	}
	quotas := []RegionQuota{
		{Pattern: "guangzhou", Count: 2},
		{Pattern: "hongkong", Count: 2},
		{Pattern: "shanghai", Count: 5}, // 只有 1 个，全取
	}
	sel, err := applyQuotas(all, quotas)
	if err != nil {
		t.Fatalf("applyQuotas 失败: %v", err)
	}
	if len(sel) != 5 {
		t.Fatalf("应选中 5 个，got %d", len(sel))
	}
	// 配额顺序：先广州（20,50），再香港（10,60），再上海（30）
	want := []int64{20, 50, 10, 60, 30}
	for i, w := range want {
		if sel[i].node.LatencyMs != w {
			t.Errorf("sel[%d] 延迟=%d, want %d", i, sel[i].node.LatencyMs, w)
		}
	}
	// 零匹配应报错
	if _, err := applyQuotas(all, []RegionQuota{{Pattern: "tokyo", Count: 2}}); err == nil {
		t.Error("tokyo 零匹配应报错")
	}
	// 不限量（Count=0）取全部
	sel, err = applyQuotas(all, []RegionQuota{{Pattern: "guangzhou"}})
	if err != nil || len(sel) != 3 {
		t.Fatalf("不限量应取 3 个广州节点，got %d,%v", len(sel), err)
	}
}
