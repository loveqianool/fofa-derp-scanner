package main

import (
	"testing"
)

func TestParseAssetsArray(t *testing.T) {
	data := `[
		{"ip":"1.2.3.4","port":"443","domain":"a.example.com","city":"Beijing"},
		{"ip":"5.6.7.8","port":8443,"city":"Shanghai"},
		{"ip":"9.9.9.9","port":"443"},
		{"ip":"1.2.3.4","port":"443"},
		{"ip":"","port":"443"},
		{"ip":"2.2.2.2"}
	]`
	assets, err := ParseAssets([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	// 去重后 3 个有效（重复的 1.2.3.4:443、缺 ip、缺 port 被跳过）
	if len(assets) != 3 {
		t.Fatalf("期望 3 个资产，得到 %d: %+v", len(assets), assets)
	}
	a := assets[0]
	if a.IP != "1.2.3.4" || a.Port != 443 || a.Domain != "a.example.com" || a.City != "Beijing" {
		t.Fatalf("第一个资产解析错误: %+v", a)
	}
	if assets[1].Port != 8443 || assets[1].Domain != "" {
		t.Fatalf("数字端口/空域名解析错误: %+v", assets[1])
	}
}

func TestParseAssetsJSONLines(t *testing.T) {
	data := "{\"ip\":\"1.1.1.1\",\"port\":443}\n{\"ip\":\"2.2.2.2\",\"port\":\"8443\"}\n"
	assets, err := ParseAssets([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 2 || assets[1].Port != 8443 {
		t.Fatalf("JSON Lines 解析错误: %+v", assets)
	}
}

func TestParseAssetsWrapped(t *testing.T) {
	data := `{"results":[{"ip":"3.3.3.3","port":443}],"size":1}`
	assets, err := ParseAssets([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 1 || assets[0].IP != "3.3.3.3" {
		t.Fatalf("包裹格式解析错误: %+v", assets)
	}
}

func TestParseAssetsSingleObject(t *testing.T) {
	data := `{"ip":"4.4.4.4","port":"443"}`
	assets, err := ParseAssets([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 1 {
		t.Fatalf("单个对象解析错误: %+v", assets)
	}
}

func TestBuildCandidatesAndMap(t *testing.T) {
	assets := []Asset{
		{IP: "1.1.1.1", Port: 443, Domain: "a.com", City: "BJ"},
		{IP: "2.2.2.2", Port: 8443},
	}
	cands := BuildCandidates(assets, 900)
	if len(cands) != 2 || cands[0].Region.RegionID != 900 {
		t.Fatalf("候选构建错误: %+v", cands)
	}
	if cands[0].Region.Nodes[0].HostName != "a.com" || cands[1].Region.Nodes[0].IPv4 != "2.2.2.2" {
		t.Fatalf("HostName/IPv4 选择错误: %+v", cands)
	}
	// 模拟探测结果：第二个更快，排序后应排前面并重新编号
	cands[0].RTT = 80_000_000
	cands[1].RTT = 10_000_000
	m := BuildDERPMap(cands, 900)
	if len(m.Regions) != 2 {
		t.Fatalf("map 构建错误: %+v", m)
	}
	r900 := m.Regions["900"]
	if r900.Nodes[0].IPv4 != "2.2.2.2" || r900.RegionID != 900 {
		t.Fatalf("排序/重编号错误: %+v", r900)
	}
}
