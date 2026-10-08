package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// Asset 是从 FOFA 导出数据中解析出的单个节点资产。
type Asset struct {
	IP     string
	Port   int
	Domain string // 可能为空
	City   string // 可能为空
}

// ParseAssets 解析 FOFA 导出的 JSON，兼容多种常见格式：
//   - JSON 数组: [{...}, {...}]
//   - 单个对象: {...}
//   - JSON Lines: 每行一个对象
//   - 包裹对象: {"results": [...]} 或 {"data": [...]}
func ParseAssets(data []byte) ([]Asset, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, fmt.Errorf("输入文件为空")
	}

	var rawAssets []map[string]any

	switch {
	case bytes.HasPrefix(data, []byte("[")):
		if err := json.Unmarshal(data, &rawAssets); err != nil {
			return nil, fmt.Errorf("解析 JSON 数组失败: %w", err)
		}
	case bytes.HasPrefix(data, []byte("{")):
		var obj map[string]any
		if err := json.Unmarshal(data, &obj); err != nil {
			// 可能是 JSON Lines（多行），fallback 到逐行解析
			if lineAssets, lerr := parseJSONLines(data); lerr == nil && len(lineAssets) > 0 {
				rawAssets = lineAssets
				break
			}
			return nil, fmt.Errorf("解析 JSON 对象失败: %w", err)
		}
		// 尝试包裹格式 {"results": [...]} / {"data": [...]}
		if inner, ok := extractWrapped(obj); ok {
			rawAssets = inner
		} else {
			rawAssets = []map[string]any{obj}
		}
	default:
		// 尝试按 JSON Lines 解析
		var err error
		rawAssets, err = parseJSONLines(data)
		if err != nil {
			return nil, err
		}
	}

	assets := make([]Asset, 0, len(rawAssets))
	seen := make(map[string]bool) // 按 ip:port 去重
	for _, raw := range rawAssets {
		ip := strField(raw, "ip")
		port := intField(raw, "port")
		if ip == "" || port <= 0 || port > 65535 {
			continue
		}
		key := ip + ":" + strconv.Itoa(port)
		if seen[key] {
			continue
		}
		seen[key] = true
		assets = append(assets, Asset{
			IP:     ip,
			Port:   port,
			Domain: firstNonEmpty(hostnameFromURL(strField(raw, "host")), strField(raw, "domain")),
			City:   strField(raw, "city"),
		})
	}
	return assets, nil
}

// parseJSONLines 逐行解析 JSON Lines 格式。
func parseJSONLines(data []byte) ([]map[string]any, error) {
	var out []map[string]any
	for _, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal(line, &obj); err != nil {
			return nil, fmt.Errorf("解析 JSON Lines 失败: %w", err)
		}
		out = append(out, obj)
	}
	return out, nil
}

// extractWrapped 尝试从 {"results": [...]} / {"data": [...]} 中提取数组。
func extractWrapped(obj map[string]any) ([]map[string]any, bool) {
	for _, k := range []string{"results", "data", "assets"} {
		v, ok := obj[k]
		if !ok {
			continue
		}
		arr, ok := v.([]any)
		if !ok {
			continue
		}
		out := make([]map[string]any, 0, len(arr))
		for _, item := range arr {
			m, ok := item.(map[string]any)
			if !ok {
				return nil, false
			}
			out = append(out, m)
		}
		return out, true
	}
	return nil, false
}

func strField(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return ""
	}
}

func intField(m map[string]any, key string) int {
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch t := v.(type) {
	case float64:
		return int(t)
	case string:
		n, err := strconv.Atoi(t)
		if err != nil {
			return 0
		}
		return n
	case json.Number:
		n, err := t.Int64()
		if err != nil {
			return 0
		}
		return int(n)
	default:
		return 0
	}
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// hostnameFromURL 从 FOFA 的 host 字段（如 "https://ali-hk.troy-y.org"、
// "https://103.229.126.12:12345"）中提取纯主机名，去掉 scheme、端口和路径。
func hostnameFromURL(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		return h
	}
	return s
}

// normRegion 归一化区域名：小写并去掉空格，使 "HongKong" 能匹配 "Hong Kong"。
func normRegion(s string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(s)), " ", "")
}

// matchRegion 判断城市名是否匹配任一过滤模式（归一化后子串匹配，不区分大小写）。
func matchRegion(city string, patterns []string) bool {
	nc := normRegion(city)
	if nc == "" {
		return false
	}
	for _, p := range patterns {
		if np := normRegion(p); np != "" && strings.Contains(nc, np) {
			return true
		}
	}
	return false
}

// filterByRegion 按区域过滤资产。filter 为逗号分隔的多个模式，任一匹配即保留。
// 空 filter 返回原列表。
func filterByRegion(assets []Asset, filter string) []Asset {
	if strings.TrimSpace(filter) == "" {
		return assets
	}
	patterns := strings.Split(filter, ",")
	out := make([]Asset, 0, len(assets))
	for _, a := range assets {
		if matchRegion(a.City, patterns) {
			out = append(out, a)
		}
	}
	return out
}

// RegionStat 统计某个城市的节点数。
type RegionStat struct {
	City  string
	Count int
}

// listRegions 统计资产中各城市的节点数，按数量降序返回。空城市名记为"(未知)"。
func listRegions(assets []Asset) []RegionStat {
	counts := make(map[string]int)
	for _, a := range assets {
		city := a.City
		if strings.TrimSpace(city) == "" {
			city = "(未知)"
		}
		counts[city]++
	}
	stats := make([]RegionStat, 0, len(counts))
	for city, n := range counts {
		stats = append(stats, RegionStat{City: city, Count: n})
	}
	sort.Slice(stats, func(i, j int) bool {
		if stats[i].Count != stats[j].Count {
			return stats[i].Count > stats[j].Count
		}
		return stats[i].City < stats[j].City
	})
	return stats
}
