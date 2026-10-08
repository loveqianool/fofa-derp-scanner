package main

import (
	"fmt"
	"net"
	"sort"
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
			STUNPort:         -1, // 只验证了 TCP DERP，禁用未经验证的 UDP STUN（0 会被当作 3478）
			InsecureForTests: true,
		}
		if a.Domain == "" {
			// 无域名：按地址类型填入对应字段，避免 IPv6 被误塞进 IPv4 导致客户端忽略
			if ip := net.ParseIP(a.IP); ip != nil {
				if ip.To4() != nil {
					node.IPv4 = a.IP
				} else {
					node.IPv6 = a.IP
				}
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
