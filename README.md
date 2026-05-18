# Rws - VLESS/Trojan/Shadowsocks proxy

这是参考 `golang` 分支实现的 Rust 版本，支持 VLESS-WS、Trojan-WS 和 Shadowsocks-WS 协议。实现重点是可测试的协议解析、`snafu` 统一错误处理、`Arc<dyn Trait + Send + Sync>` 组合运行期依赖，以及适合生产部署的异步 I/O 边界。

## 功能特性

- VLESS-WS 协议支持
- Trojan-WS 协议支持
- Shadowsocks-WS 协议支持（配合 v2ray-plugin）
- Google DNS-over-HTTPS，失败后回退系统 DNS
- 测速网站域名屏蔽
- 订阅链接生成
- ISP 信息检测
- 哪吒监控集成（v0/v1）
- 自动访问保活（可选）
- Axum + Tokio 异步 WebSocket/TCP 转发
- `snafu` 错误分层，协议、运行时、配置错误边界清晰

## 配置说明

通过环境变量配置：

| 变量名 | 说明 | 默认值 |
| --- | --- | --- |
| `UUID` | 用户 ID（用于认证） | `5efabea4-f6d4-91fd-b8f0-17e004c89c60` |
| `DOMAIN` | 域名（留空则自动获取公网 IP） | 空 |
| `PORT` | 服务端口 | `3000` |
| `WSPATH` | WebSocket 路径 | UUID 前 8 位 |
| `SUB_PATH` | 订阅路径 | `sub` |
| `NAME` | 节点名称前缀 | 空 |
| `AUTO_ACCESS` | 自动访问保活 | `false` |
| `NEZHA_SERVER` | 哪吒监控服务器 | 空 |
| `NEZHA_PORT` | 哪吒 v0 agent 端口；v1 不设置 | 空 |
| `NEZHA_KEY` | 哪吒密钥 | 空 |

## 构建运行

本地运行：

```bash
cargo run --release
```

运行测试：

```bash
cargo test
```

Docker 构建：

```bash
docker build -t rws .
docker run --rm -p 3000:3000 -e UUID=5efabea4-f6d4-91fd-b8f0-17e004c89c60 rws
```

## 获取订阅

服务启动后访问：

```text
http://your-domain:3000/sub
```

订阅内容是 Base64 编码，包含：

- VLESS-WS
- Trojan-WS
- Shadowsocks-WS

## 哪吒监控

v1：

```bash
export NEZHA_SERVER=nz.example.com:8008
export NEZHA_KEY=your_client_secret
```

v0：

```bash
export NEZHA_SERVER=nz.example.com
export NEZHA_PORT=5555
export NEZHA_KEY=your_secret_key
```

`NEZHA_PORT` 为 `443`、`8443`、`2096`、`2087`、`2083`、`2053` 时会自动启用 TLS。

## 架构说明

核心模块：

```text
src/
├── app.rs            # Axum routes、订阅接口、WebSocket 升级和转发
├── config.rs         # 环境变量配置解析
├── dependencies.rs   # Arc<dyn Trait> 依赖组合接口
├── dns.rs            # DoH + 系统 DNS 解析
├── external.rs       # 公网 IP、ISP、保活 HTTP 客户端
├── monitor.rs        # 哪吒 agent 下载、启动、清理
├── policy.rs         # 域名屏蔽策略
├── protocol.rs       # VLESS/Trojan/Shadowsocks 首包解析
├── runtime.rs        # 运行时错误、生产依赖装配、TCP 拨号
└── subscription.rs   # 订阅链接生成
```

运行期依赖通过 `AppDeps` 注入：

```rust
pub struct AppDeps {
    pub resolver: Arc<dyn Resolver>,
    pub policy: Arc<dyn DomainPolicy>,
    pub connector: Arc<dyn OutboundConnector>,
    pub public_ip: Arc<dyn PublicIpProvider>,
    pub isp: Arc<dyn IspProvider>,
    pub keep_alive: Arc<dyn KeepAliveClient>,
    pub monitor: Arc<dyn MonitorAgent>,
}
```

这种结构让协议解析、域名策略、DNS、外部 HTTP 和 TCP 拨号都可以独立测试或替换，便于企业场景接入自定义审计、DNS、限流、配置中心或观测系统。

## 许可证

GPL 3.0 License
