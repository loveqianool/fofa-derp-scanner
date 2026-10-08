
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

// TestMaxOutput 验证 900-999 范围上限与 --limit 的取小逻辑。
func TestMaxOutput(t *testing.T) {
	cases := []struct{ start, limit, avail, want int }{
		{900, 50, 929, 50},   // limit 最小
		{900, 0, 929, 100},   // 不限量时被 900-999 卡到 100
		{900, 0, 30, 30},     // 可用数不足
		{950, 0, 200, 50},    // start=950 时只剩 50 个 ID
		{999, 0, 200, 1},     // 只剩 1 个 ID
		{900, 200, 500, 100}, // limit 超过范围上限仍被卡到 100
		{900, 100, 500, 100}, // limit 恰好等于上限
	}
	for _, c := range cases {
		if got := maxOutput(c.start, c.limit, c.avail); got != c.want {
			t.Errorf("maxOutput(%d,%d,%d)=%d, want %d",
				c.start, c.limit, c.avail, got, c.want)
		}
	}
}
