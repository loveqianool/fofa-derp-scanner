# derp-scan

从 FOFA 导出的 DERP 节点资产中，一条命令探测并输出**真正可用**的 Tailscale `derpMap`。

这是 [v1 Python 版](#与-v1-的区别)的 Go 重写版：单文件、无依赖（除 Tailscale 官方 DERP 协议库），把原来"导 JSON → 转格式 → Docker 探测 → 手动存 HTML → 提取"的 5 步手工流程收进一个二进制，一次跑完。

[![Docker](https://github.com/loveqianool/fofa-derp-scanner/actions/workflows/docker.yml/badge.svg)](https://github.com/loveqianool/fofa-derp-scanner/actions/workflows/docker.yml)

## 特性

- **真 DERP 协议探测**：TCP 建连 → TLS 握手 → HTTP Upgrade → DERP 握手 → 多次 ping 取中位 RTT，只有完整走通 DERP 协议的节点才会被保留（旧版只测 TLS 握手，会把大量"握手通但不中继"的节点误判为可用）
- **一次跑完**：输入 FOFA 导出的 JSON，直接输出可粘贴进 Tailscale ACL 的 `derp.json`
- **并发探测**：默认 50 并发，2600+ 节点几分钟扫完
- **多格式兼容**：FOFA 网页导出的 JSON 数组 / JSON Lines / `{"results":[...]}` 包裹格式都能解析，按 `ip:port` 自动去重
- **代理支持**：识别 `HTTPS_PROXY`/`HTTP_PROXY`（含 `NO_PROXY`），自动走 HTTP CONNECT 隧道
- **80 端口降级**：端口实际是明文 HTTP 时自动降级为明文 Upgrade 探测

## 快速开始

### 用 Docker（推荐）

```bash
# 1. 在 FOFA 按 body="Tailscale" && body="DERP server" 搜索，导出 JSON，假设为 fofa.json
# 2. 一条命令跑完（把当前目录挂载进去读写文件）
docker run --rm -v $(pwd):/data ghcr.io/loveqianool/fofa-derp-scanner:latest \
  --input /data/fofa.json --output /data/derp.json
```

### 用二进制

到 [Releases](https://github.com/loveqianool/fofa-derp-scanner/releases) 或用 Docker 镜像里的二进制：

```bash
./derp-scan --input fofa.json --output derp.json
```

### 接入 Tailscale

1. 打开 [Tailscale ACL](https://login.tailscale.com/admin/acls/file)
2. 把 `derp.json` 中 `Regions` 下的内容粘贴进 `derpMap.Regions`
3. 保存。客户端会自动选用延迟最低的可用节点，可用 `tailscale status` 查看当前连的是哪个节点。

## 用法

```
Usage of derp-scan:
  -input string        FOFA 导出的 JSON 文件路径（必填）
  -output string       输出 derpMap JSON 路径（默认 "derp.json"）
  -start int           RegionID 起始编号（默认 1000）
  -limit int           最多输出的节点数，按延迟取最低的 N 个（默认 50，0 为不限制）
  -max-latency duration
                       保留节点的中位延迟上限（默认 100ms）
  -samples int         每节点 ping 采样次数，全部成功才保留（默认 3）
  -concurrency int     并发探测数（默认 50）
  -timeout duration    单节点探测总超时（默认 20s）
  -ping-timeout duration
                       单次 ping 超时（默认 5s）
```

示例：

```bash
# 取延迟最低的 100 个，延迟上限放宽到 200ms
./derp-scan --input fofa.json --output derp.json --limit 100 --max-latency 200ms

# 全部可用节点都要
./derp-scan --input fofa.json --output derp.json --limit 0
```

输出示例：

```
解析到 2634 个候选节点，开始探测（并发 50，每节点 3 次 ping）…
[1/2634] 1.2.3.4:443                   可用 38ms
[2/2634] 5.6.7.8:8443                  失败: connection refused
...
可用节点 412 个，按 --limit 取延迟最低的 50 个。

完成：50/2634 个节点可用（中位延迟 ≤ 100ms），已按延迟排序并从 1000 重新编号，写入 derp.json
```

## Docker 镜像

每次 push 到 `main` 分支都会自动构建并推送到 GHCR，提供 amd64/arm64 × gnu/musl 四种镜像：

| Tag | 说明 |
|-----|------|
| `latest` | Debian(gnu) 基，amd64 + arm64 多架构 |
| `musl` | Alpine(musl) 基，amd64 + arm64 多架构 |
| `gnu-amd64` / `gnu-arm64` | Debian 基，单架构 |
| `musl-amd64` / `musl-arm64` | Alpine 基，单架构 |

```bash
# Alpine(musl) 版，镜像更小
docker run --rm -v $(pwd):/data ghcr.io/loveqianool/fofa-derp-scanner:musl \
  --input /data/fofa.json --output /data/derp.json
```

> 二进制是纯静态编译的，不依赖目标系统的 libc，gnu/musl 只是基础镜像的区别。
> 首次推送后如果拉取时提示无权限，到 [Packages](https://github.com/loveqianool?tab=packages) 把该包的可见性改为 Public。

## 工作原理

```
FOFA JSON → 解析去重 → 并发探测 → 筛选 → 排序编号 → derp.json
```

探测（每个节点）：

1. TCP 建连（支持经 `HTTPS_PROXY` 的 CONNECT 隧道）
2. TLS 握手（跳过证书校验，自签证书也能测；ClientHello 带 `http/1.1` ALPN）
3. `GET /derp` + `Upgrade: DERP`，要求 `101 Switching Protocols`
4. DERP 握手（服务端 ServerKey → 客户端 ClientInfo，nacl 加密，声明为 prober）
5. 发送 N 次 ping，取中位 RTT；任一次失败则丢弃该节点

保留条件：全部 ping 成功 **且** 中位延迟 ≤ `--max-latency`。结果按延迟升序、从 `--start` 连续编号，节点带 `InsecureForTests: true`（跳过证书校验，Tailscale 客户端直连即用）。

## 与 v1 的区别

|  | v1 (Python) | v2 (Go, 本版) |
|---|---|---|
| 探测方式 | Docker 跑 derpprober，只测 TLS 握手/UDP | 内置真 DERP 协议 ping |
| 流程 | 5 步手工操作 | 一条命令 |
| 依赖 | Python + Docker + 浏览器插件 | 零依赖单文件 |
| 误判 | 握手通但不中继的节点会被收录 | 只有真能中继的才收录 |

## 本地构建

```bash
go build -o derp-scan .
go test ./...   # 含自建假 DERP 服务器的端到端探测测试
```

```bash
# 本地构建 Docker 镜像（gnu / musl 二选一）
docker build --build-arg BASE_IMAGE=debian:bookworm-slim -t derp-scan .
docker build --build-arg BASE_IMAGE=alpine:3.21 -t derp-scan:musl .
```

## FAQ

**Q: 输出的节点用旧版 Docker derpprober 验证，很多显示失败？**
A: 两个工具标准不同。derpprober 的 tls 探测会校验证书（自签证书直接判失败），而本工具输出的节点都带 `InsecureForTests: true`，Tailscale 客户端会跳过证书校验。以本工具的真 ping 结果和 `tailscale status` 的实际连接为准。

**Q: 扫出来可用节点太少？**
A: 放宽 `--max-latency`（如 `200ms`）或 `--limit 0` 输出全部可用节点。

**Q: 需要走代理？**
A: 设置 `HTTPS_PROXY` 环境变量即可，`NO_PROXY` 也会被遵守。

---

MIT License
