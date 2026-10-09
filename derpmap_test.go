package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestBuildCandidatesNodeFields 锁定审计后的节点字段规则：
//   - HostName 必须始终有值（derphttp 走代理拨号会拒绝空 HostName），无域名时填 IP
//   - IPv6 地址必须进 IPv6 字段，不能塞进 IPv4（否则客户端静默忽略）
//   - STUNPort 为 3478（DERP 服务器默认 STUN 端口；探测时会真实验证 STUN 可用性）
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
	if n0.STUNPort != 3478 {
		t.Errorf("STUNPort 应为 3478，实际 %d", n0.STUNPort)
	}

	n1 := cands[1].Region.Nodes[0]
	if n1.HostName != "a.com" {
		t.Errorf("域名节点 HostName 错误: %q", n1.HostName)
	}
	// 域名节点也要写 IPv4/IPv6（双栈写入）：客户端直连用 IP，SNI 用域名
	if n1.IPv4 != "2.2.2.2" {
		t.Errorf("域名节点 IPv4 应为 2.2.2.2，实际 %q", n1.IPv4)
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
// （STUNPort: 3478 不能被 omitempty 吃掉，HostName 不能缺席）。
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
	for _, want := range []string{`"HostName":"1.1.1.1"`, `"STUNPort":3478`, `"DERPPort":443`} {
		if !strings.Contains(s, want) {
			t.Errorf("JSON 缺少 %s，实际: %s", want, s)
		}
	}
}

// TestParseRegionQuotas 验证 --region 配额语法的解析。
func TestParseRegionQuotas(t *testing.T) {
	// 空
	if q, err := parseRegionQuotas(""); err != nil || len(q) != 0 {
		t.Fatalf("空应返回 nil,nil，got %v,%v", q, err)
	}
	// 标准配额
	q, err := parseRegionQuotas("guangzhou:20,hongkong:20,shanghai:20")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(q) != 3 || q[0].Pattern != "guangzhou" || q[0].Count != 20 ||
		q[1].Pattern != "hongkong" || q[1].Count != 20 ||
		q[2].Pattern != "shanghai" || q[2].Count != 20 {
		t.Fatalf("配额解析错误: %+v", q)
	}
	// 省略 :数量 表示不限量
	q, err = parseRegionQuotas("Hong Kong")
	if err != nil || len(q) != 1 || q[0].Pattern != "Hong Kong" || q[0].Count != 0 {
		t.Fatalf("不限量解析错误: %+v,%v", q, err)
	}
	// 非法数量
	if _, err := parseRegionQuotas("hk:abc"); err == nil {
		t.Fatal("hk:abc 应报错")
	}
	if _, err := parseRegionQuotas("hk:-1"); err == nil {
		t.Fatal("hk:-1 应报错")
	}
	if _, err := parseRegionQuotas("hk:"); err == nil {
		t.Fatal("hk: 应报错")
	}
}

// TestTryParseDERPMap 验证 derpMap 中间文件格式的自动识别。
func TestTryParseDERPMap(t *testing.T) {
	// derpMap 格式应被识别
	dmJSON := `{"Regions":{"900":{"RegionID":900,"RegionCode":"custom900","RegionName":"Hong Kong","Nodes":[{"Name":"900-x","RegionID":900,"HostName":"x","DERPPort":443,"LatencyMs":38}]}}}`
	dm, ok := tryParseDERPMap([]byte(dmJSON))
	if !ok || dm == nil {
		t.Fatal("derpMap 应被识别")
	}
	if dm.Regions["900"].Nodes[0].LatencyMs != 38 {
		t.Fatalf("LatencyMs 未解析: %+v", dm.Regions["900"].Nodes[0])
	}
	// FOFA 格式不应被识别为 derpMap
	fofaJSON := `[{"ip":"1.1.1.1","port":443,"city":"Hong Kong"}]`
	if _, ok := tryParseDERPMap([]byte(fofaJSON)); ok {
		t.Fatal("FOFA JSON 不应被识别为 derpMap")
	}
	// 空 Regions 不应被识别
	if _, ok := tryParseDERPMap([]byte(`{"Regions":{}}`)); ok {
		t.Fatal("空 Regions 不应被识别")
	}
	// 非法 JSON
	if _, ok := tryParseDERPMap([]byte(`{xxx`)); ok {
		t.Fatal("非法 JSON 不应被识别")
	}
}

// TestMatchRegion 验证区域名匹配（大小写/空格不敏感）。
func TestMatchRegion(t *testing.T) {
	if !matchRegion("Hong Kong", []string{"hongkong"}) {
		t.Error("hongkong 应匹配 Hong Kong")
	}
	if !matchRegion("Hong Kong", []string{"Hong Kong"}) {
		t.Error("Hong Kong 应匹配自身")
	}
	if matchRegion("Guangzhou", []string{"hongkong"}) {
		t.Error("Guangzhou 不应匹配 hongkong")
	}
	if matchRegion("", []string{"hk"}) {
		t.Error("空城市名不应匹配")
	}
}
