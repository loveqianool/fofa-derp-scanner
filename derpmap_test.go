package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestBuildCandidatesNodeFields 锁定审计后的节点字段规则：
//   - HostName 必须始终有值（derphttp 走代理拨号会拒绝空 HostName），无域名时填 IP
//   - IPv6 地址必须进 IPv6 字段，不能塞进 IPv4（否则客户端静默忽略）
//   - STUNPort 必须为 -1（只验证了 TCP DERP，禁用未经验证的 UDP STUN）
func TestBuildCandidatesNodeFields(t *testing.T) {
	assets := []Asset{
		{IP: "1.1.1.1", Port: 443},
		{IP: "2.2.2.2", Port: 8443, Domain: "a.com"},
		{IP: "2001:db8::1", Port: 443},
	}
	cands := BuildCandidates(assets, 900)
	if len(cands) != 3 {
		t.Fatalf("候选数量错误: %d", len(cands))
	}

	n0 := cands[0].Region.Nodes[0]
	if n0.HostName != "1.1.1.1" {
		t.Errorf("纯 IP 节点 HostName 应为 IP，实际 %q", n0.HostName)
	}
	if n0.IPv4 != "1.1.1.1" {
		t.Errorf("纯 IP 节点 IPv4 错误: %q", n0.IPv4)
	}
	if n0.STUNPort != -1 {
		t.Errorf("STUNPort 应为 -1，实际 %d", n0.STUNPort)
	}

	n1 := cands[1].Region.Nodes[0]
	if n1.HostName != "a.com" {
		t.Errorf("域名节点 HostName 错误: %q", n1.HostName)
	}
	if n1.IPv4 != "" || n1.IPv6 != "" {
		t.Errorf("域名节点不应填 IP 字段: %+v", n1)
	}

	n2 := cands[2].Region.Nodes[0]
	if n2.HostName != "2001:db8::1" {
		t.Errorf("IPv6 节点 HostName 错误: %q", n2.HostName)
	}
	if n2.IPv6 != "2001:db8::1" {
		t.Errorf("IPv6 节点应填 IPv6 字段: %+v", n2)
	}
	if n2.IPv4 != "" {
		t.Errorf("IPv6 地址不能塞进 IPv4 字段: %q", n2.IPv4)
	}
}

// TestDERPMapJSONFields 确认最终 JSON 里关键字段真实存在
// （STUNPort: -1 不能被 omitempty 吃掉，HostName 不能缺席）。
func TestDERPMapJSONFields(t *testing.T) {
	assets := []Asset{{IP: "1.1.1.1", Port: 443}}
	cands := BuildCandidates(assets, 900)
	cands[0].RTT = 10_000_000
	m := BuildDERPMap(cands, 900)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{`"HostName":"1.1.1.1"`, `"STUNPort":-1`, `"DERPPort":443`} {
		if !strings.Contains(s, want) {
			t.Errorf("JSON 缺少 %s，实际: %s", want, s)
		}
	}
}
