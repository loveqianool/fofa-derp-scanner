# derp-scan

从 FOFA 导出的 DERP 节点资产中，一条命令探测并输出**真正可用**的 Tailscale `derpMap`。

这是 [v1 Python 版](#与-v1-的区别)的 Go 重写版：单文件、无依赖（除 Tailscale 官方 DERP 协议库），把原来"导 JSON → 转格式 → Docker 探测 → 手动存 HTML → 提取"的 5 步手工流程收进一个二进制，一次跑完。

[![Docker](https://github.com/loveqianool/fofa-derp-scanner/actions/workflows/docker.yml/badge.svg)](https://github.com/loveqianool/fofa-derp-scanner/actions/workflows/docker.yml)

## 特性

- **真 DERP 协议探测**：TCP 建连 → TLS 握手 → HTTP Upgrade → DERP 握手 → 多次 ping 取中位 RTT，只有完整走通 DERP 协议的节点才会被保留（旧版只测 TLS 握手，会把大量"握手通但不中继"的节点误判为可用）
- **STUN 必检**：探测时向 UDP 3478 发送 STUN Binding Request（对齐官方 derpprober，支持 IPv4/IPv6 双栈，域名解析出多 IP 时逐个尝试），STUN 不通的节点直接丢弃——Tailscale 客户端靠 STUN 测量 DERP 延迟，STUN 不可用的中继会被客户端忽略（表现为无延迟、永不选用）。输出中 `STUNPort` 为 3478
- **CanPort80 固定 false**：第三方 DERP 基本不开放 80 端口，客户端只用 443 中继 + STUN，避免反复尝试 80 做 captive portal 检测而超时
- **仅 TLS**：Tailscale 生产客户端只用 HTTPS 连接 DERP，因此只保留 TLS 握手成功的节点，明文 HTTP 节点会被丢弃
- **可选的中继转发验证**（`--relay-test`）：在同一服务器上建立两个客户端，A 发包 B 收，验证服务器真正的客户端间转发能力，而不仅是 client↔server 的 ping
- **一次跑完**：输入 FOFA 导出的 JSON，直接输出可粘贴进 Tailscale ACL 的 `derp.json`
- **并发探测**：默认 50 并发，2600+ 节点几分钟扫完
- **多格式兼容**：FOFA 网页导出的 JSON 数组 / JSON Lines / `{"results":[...]}` 包裹格式都能解析，按 `ip:port` 自动去重
- **代理支持**：识别 `HTTPS_PROXY`/`HTTP_PROXY`（含 `NO_PROXY`），自动走 HTTP CONNECT 隧道

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

## 用法（三段式工作流）

工具根据 `--input` 的文件格式自动切换模式：FOFA 导出 → 扫描模式；derp-all.json（derpMap 格式）→ 筛选模式。

```
Usage of derp-scan:
  -input string        输入文件：FOFA 导出的 JSON（扫描模式）或 derp-all.json（筛选模式，自动识别）
  -output string       输出 derpMap JSON 路径（默认 "derp.json"）
  -check string        复检模式：重新探测指定 derp-all.json 中的节点，剔除不可用的并原地更新
  -start int           RegionID 起始编号（官方托管限制 900-999，默认 900）
  -max-latency duration
                       保留节点的中位延迟上限（默认 100ms）
  -samples int         每节点 ping 采样次数，全部成功才保留（默认 3）
  -concurrency int     并发探测数（默认 50）
  -timeout duration    单节点探测总超时（默认 20s）
  -ping-timeout duration
                       单次 ping 超时（默认 5s）
  -stun-timeout duration
                       STUN UDP 探测超时（默认 5s，STUN 不通的节点会被丢弃，因 Tailscale 不会使用）
  -relay-test          额外验证客户端间中继转发（建两个客户端，A 发包 B 收），更严格（默认 false）
  -region string       筛选模式按区域配额选取，如 "guangzhou:20,hongkong:20"（省略 :数量 则取该区域全部），逗号分隔多个
  -version             打印版本并退出
```

### 1. 扫描：FOFA → derp-all.json（全量，无截断）

```bash
./derp-scan --input fofa.json --output derp-all.json
```

输出全部可用节点（按延迟排序，每个节点带 `LatencyMs` 延迟字段，方便后续筛选）。
注意这是中间文件，节点数可能超过 100（RegionID 会超出 999），不要直接粘贴到 ACL。

### 2. 筛选：derp-all.json → derp.json（按区域配额，不重新探测）

```bash
# 20 个广东 + 20 个香港 + 20 个上海，各取延迟最低的，共 60 个
./derp-scan --input derp-all.json --output derp.json --region "guangzhou:20,hongkong:20,shanghai:20"

# 不指定 --region 则取全部（按延迟排序）
./derp-scan --input derp-all.json --output derp.json

# 省略 :数量 表示取该区域全部
./derp-scan --input derp-all.json --output derp.json --region "hongkong"
```

区域名大小写/空格不敏感（`hongkong` 能匹配 `Hong Kong`），写错名字会打印文件实际的区域分布供对照。
输出会重新编号到 900-999（超 100 个自动截断）并去掉 `LatencyMs`，可直接粘贴到 Tailscale ACL。

### 3. 复检：定期剔除 derp-all.json 中的死节点（原地更新）

```bash
./derp-scan --check derp-all.json
```

重新探测每个节点，剔除不可用/超时的，更新延迟后重排并原地写回。全部不可用时不会清空文件。

输出示例（扫描模式）：

```
解析到 2634 个候选节点，开始探测（并发 50，每节点 3 次 ping）…
[1/2634] 1.2.3.4:443                   38ms
[2/2634] 5.6.7.8:8443                  失败: connection refused
...

完成：929/2634 个节点可用（中位延迟 ≤ 100ms），已按延迟排序并从 900 开始编号，写入 derp-all.json
下一步：用筛选模式从该文件按区域配额选取节点，例如：
  derp-scan --input derp-all.json --output derp.json --region "guangzhou:20,hongkong:20"
```

## Docker 镜像

每次 push 到 `main` 分支都会自动构建并推送到 GHCR，Alpine (musl) 基础镜像，提供 amd64/arm64 多架构：

| Tag | 说明 |
|-----|------|
| `latest` | amd64 + arm64 多架构 |
| `amd64` / `arm64` | 单架构 |

```bash
docker run --rm -v $(pwd):/data ghcr.io/loveqianool/fofa-derp-scanner:latest \
  --input /data/fofa.json --output /data/derp.json
```

> 二进制是纯静态编译的，不依赖目标系统的 libc，在 glibc / musl 系统上都能跑。
> 首次推送后如果拉取时提示无权限，到 [Packages](https://github.com/loveqianool?tab=packages) 把该包的可见性改为 Public。

## 发版

打 tag 即自动编译 4 平台（linux amd64/arm64、windows amd64、android arm64）静态二进制并挂到 GitHub Release：

```bash
git tag v2.0.0 && git push origin v2.0.0
```

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

> 官方托管硬性限制：自定义 RegionID 只能用 **900–999**（最多 100 个 Region），且一个 Region 只能放 1 台 DERP。本工具默认 `--start 900`，输出即 1 Region 1 Node 结构；若可用节点超出 900–999 容量会自动截断并提示。

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
# 本地构建 Docker 镜像（多架构）
docker buildx build --platform linux/amd64,linux/arm64 -t derp-scan .
```

## FAQ

**Q: 输出的节点用旧版 Docker derpprober 验证，很多显示失败？**
A: 两个工具标准不同。derpprober 的 tls 探测会校验证书（自签证书直接判失败），而本工具输出的节点都带 `InsecureForTests: true`，Tailscale 客户端会跳过证书校验。以本工具的真 ping 结果和 `tailscale status` 的实际连接为准。

**Q: 扫出来可用节点太少？**
A: 放宽 `--max-latency`（如 `200ms`）。扫描模式默认输出全部可用节点，不再截断。

**Q: `tailscale debug derp` 报 `x509: certificate signed by unknown authority`，节点是不是坏了？**
A: 不是。`debug derp` 的 TLS 配置没看 `InsecureForTests` 字段（源码 `ipn/localapi/debugderp.go` 的 `tlsConfigForNode`），自签名证书一定报错。真实客户端（`derphttp`）会遵循 `InsecureForTests: true` 跳过校验，节点可用。以 `tailscale status` 里是否出现延迟为准。

**Q: 需要走代理？**
A: 设置 `HTTPS_PROXY` 环境变量即可，`NO_PROXY` 也会被遵守。

---

MIT License
