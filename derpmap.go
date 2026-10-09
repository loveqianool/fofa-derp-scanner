package main

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

// DERPMap 是可直接粘贴到 Tailscale ACL derpMap.Regions 中的结构。
type DERPMap struct {
	Regions map[string]Region `json:"Regions"`
}

// Region 对应 derpMap 中的一个 region。
type Region struct {
	RegionID   int    `json:"RegionID"`
	RegionCode string `json:"RegionCode"`
	RegionName string `json:"RegionName"`
	Nodes      []Node `json:"Nodes"`
}

// Node 对应 region 中的一个 DERP 节点。
type Node struct {
	Name             string `json:"Name"`
	RegionID         int    `json:"RegionID"`
	HostName         string `json:"HostName,omitempty"`
	IPv4             string `json:"IPv4,omitempty"`
	IPv6             string `json:"IPv6,omitempty"`
	DERPPort         int    `json:"DERPPort"`
	STUNPort         int    `json:"STUNPort,omitempty"`
	InsecureForTests bool   `json:"InsecureForTests"`
	// LatencyMs 是探测到的中位延迟（毫秒），只用于 derp-all.json 这类中间文件，
	// 方便二次筛选时按延迟排序。最终粘贴到 ACL 的输出会去掉该字段（omitempty）。
	LatencyMs int64 `json:"LatencyMs,omitempty"`
}

// Candidate 是待探测的候选节点：资产 + 探测结果。
type Candidate struct {
	Asset  Asset
	Region Region
	RTT    time.Duration // 中位延迟
}

// BuildCandidates 为每个资产生成候选 region，RegionID 从 start 开始连续编号。
func BuildCandidates(assets []Asset, start int) []Candidate {
	cands := make([]Candidate, 0, len(assets))
	for i, a := range assets {
		rid := start + i
		name := displayName(a)
		node := Node{
			Name: fmt.Sprintf("%d-%s", rid, name),
			RegionID: rid,
			// HostName 必须始终有值：derphttp 走代理拨号时会拒绝空 HostName。
			// 无域名时填 IP 字面量，直连拨号仍走下面的 IPv4/IPv6（强制 IP，不走 DNS）。
			HostName:         name,
			DERPPort:         a.Port,
			STUNPort:         3478, // DERP 服务器默认在 UDP 3478 提供 STUN；探测时会真实验证 STUN 可用性，不可用则丢弃该节点
			InsecureForTests: true,
		}
		// 只要 FOFA 给了 IP，就按地址类型填入对应字段（双栈写入）：
		// 客户端优先用 IPv4/IPv6 直连（免 DNS），TLS SNI 仍用 HostName（域名或 IP）；
		// 避免 IPv6 被误塞进 IPv4 导致客户端忽略。
		if ip := net.ParseIP(a.IP); ip != nil {
			if ip.To4() != nil {
				node.IPv4 = a.IP
			} else {
				node.IPv6 = a.IP
			}
		}
		cands = append(cands, Candidate{
			Asset: a,
			Region: Region{
				RegionID:   rid,
				RegionCode: fmt.Sprintf("custom%d", rid),
				RegionName: a.City,
				Nodes:      []Node{node},
			},
		})
	}
	return cands
}

// BuildDERPMap 按延迟升序排列候选节点，从 start 开始重新连续编号，生成最终 DERPMap。
func BuildDERPMap(cands []Candidate, start int) DERPMap {
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].RTT != cands[j].RTT {
			return cands[i].RTT < cands[j].RTT
		}
		return cands[i].Region.RegionID < cands[j].Region.RegionID
	})
	m := DERPMap{Regions: make(map[string]Region, len(cands))}
	for i, c := range cands {
		rid := start + i
		region := c.Region
		region.RegionID = rid
		region.RegionCode = fmt.Sprintf("custom%d", rid)
		for j := range region.Nodes {
			region.Nodes[j].RegionID = rid
			region.Nodes[j].Name = fmt.Sprintf("%d-%s", rid, displayName(c.Asset))
			region.Nodes[j].LatencyMs = c.RTT.Milliseconds()
		}
		m.Regions[fmt.Sprintf("%d", rid)] = region
	}
	return m
}

func displayName(a Asset) string {
	if a.Domain != "" {
		return a.Domain
	}
	return a.IP
}

// RegionQuota 是 --region 的一条配额："区域名:数量"，如 "hongkong:20"。
// Count 为 0 表示不限量（取该区域全部）。
type RegionQuota struct {
	Pattern string
	Count   int
}

// parseRegionQuotas 解析 --region 参数："gz:20,hk:20" 或 "Hong Kong"（不限量）。
// 模式大小写/空格不敏感（复用 normRegion）。
func parseRegionQuotas(s string) ([]RegionQuota, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var quotas []RegionQuota
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		q := RegionQuota{}
		if i := strings.LastIndex(part, ":"); i >= 0 {
			q.Pattern = strings.TrimSpace(part[:i])
			n, err := strconv.Atoi(strings.TrimSpace(part[i+1:]))
			if err != nil || n < 0 {
				return nil, fmt.Errorf("区域配额格式错误 %q，应为 \"区域名:数量\"，如 \"hongkong:20\"", part)
			}
			q.Count = n
		} else {
			q.Pattern = part
		}
		if q.Pattern == "" {
			return nil, fmt.Errorf("区域名不能为空: %q", part)
		}
		quotas = append(quotas, q)
	}
	return quotas, nil
}

// tryParseDERPMap 尝试把输入解析为 derpMap（中间文件 derp-all.json 的格式）。
// 成功返回 (map, true)；否则返回 (nil, false)，调用方可继续按 FOFA 资产解析。
func tryParseDERPMap(data []byte) (*DERPMap, bool) {
	var m DERPMap
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, false
	}
	for _, r := range m.Regions {
		if len(r.Nodes) > 0 {
			return &m, true
		}
	}
	return nil, false
}

// latencyMsOrMax 取节点的延迟毫秒数，缺失（0）时视为无穷大，排序时沉底。
func latencyMsOrMax(n Node) int64 {
	if n.LatencyMs <= 0 {
		return int64(1) << 62
	}
	return n.LatencyMs
}
