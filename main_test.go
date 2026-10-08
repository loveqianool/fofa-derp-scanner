
package main

import "testing"

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
