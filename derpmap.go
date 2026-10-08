package main

import (
	"fmt"
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
	DERPPort         int    `json:"DERPPort"`
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
		name := a.Domain
		if name == "" {
			name = a.IP
		}
		node := Node{
			Name:             fmt.Sprintf("%d-%s", rid, name),
			RegionID:         rid,
			DERPPort:         a.Port,
			InsecureForTests: true,
		}
		if a.Domain != "" {
			node.HostName = a.Domain
		} else {
			node.IPv4 = a.IP
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
