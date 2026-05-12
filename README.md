# PCAP 抓包分析工具

一个面向网络排障场景的 PCAP/PCAPNG 分析工具，目标是把“看包”变成“可执行的排障结论”。
工具将协议解析、规则诊断、根因推断、可视化报告整合为一体，支持本地规则引擎分析，并可按需启用 AI 生成补充结论。

## 产品介绍

这个项目适合以下使用者：
- 网络运维/网络工程师：快速判断是链路问题、策略问题、服务问题，还是应用交互异常
- 系统运维/SRE：在故障窗口内快速拿到“影响范围 + 优先动作”
- 开发/测试团队：对接口失败、DNS 异常、TCP 重传等问题做回放和证据化定位

相比“只看 Wireshark 明细包列表”，这个工具更强调：
- 从包级细节上升到流级/会话级结论（减少人工逐包判断成本）
- 基于规则库自动给出异常识别、严重度和根因方向
- 报告直接服务排障流程（结论、证据、动作建议、命令清单）
- 支持三种分析深度（quick/deep/diagnosis），可按时间压力选择

典型使用流程：
1. 先用 `quick` 进行全局体检，快速找出主异常方向
2. 再用 `deep` 或 `diagnosis` 按 IP/端口/协议/时间窗做定向深挖
3. 导出 HTML/Markdown/JSON 报告，用于跨团队协同和复盘归档

## 1. 当前能力（与代码一致）

### 协议与数据解析
- 支持 `.pcap` / `.pcapng`
- 传输层协议：`TCP` / `UDP` / `ICMP` / `ARP`
- 应用层协议：`DNS` / `HTTP` / `TLS`
- 支持按 IP、端口、协议、时间窗、display filter 做范围分析

### 自动诊断与根因推断
- 自动识别常见异常：
  - TCP 重传率高、RST 异常、握手异常、半开连接、零窗口、乱序等
  - DNS 失败/超时、HTTP 错误、TLS Alert
  - ICMP 不可达/TTL 超时、ARP 异常、流量不对称、突发流量等
- 规则引擎 + 推断引擎联动输出根因方向与优先动作
- 三种分析模式：
  - `quick`：快速体检（默认）
  - `deep`：深度分析（信息更完整）
  - `diagnosis`：故障诊断（输出最完整）

### 报告能力
- 输出格式：`HTML` / `Markdown` / `JSON`
- HTML 报告包含：
  - 管理摘要与关键指标
  - 异常详情（按严重度）
  - 规则命中证据、命令级排查清单
  - 图表（协议分布、流量趋势、RTT 趋势、拓扑等）
- Plotly 默认本地内联（`report.plotly_js_mode: inline`），不依赖 CDN

### 交互与安全清理
- 交互菜单支持：AI 设置、分析新文件、历史记录、目录扫描、知识库查询、程序重置
- 程序重置（菜单 7）会清理敏感信息并恢复初始安全状态：
  - 重置 AI 配置（关闭 AI 并清空 API Key）
  - 清空历史记录
  - 清空报告目录与日志目录
  - 清理 `__pycache__`

## 2. 环境要求

- Python 3.8+
- Wireshark/tshark（必须）
- 安装依赖：

```bash
python -m pip install -r requirements.txt
```

## 3. 安装与初始化

### 1) 安装 tshark
- Windows：安装 Wireshark（包含 tshark）
- Linux：`sudo apt install tshark`
- macOS：`brew install wireshark`

### 2) 配置 tshark 路径（可选但推荐）
如果系统 PATH 找不到 tshark，运行：

```bash
python main.py setup
```

## 4. 使用方式

### 交互模式（推荐）

```bash
python main.py interactive
```

主菜单：
- `0` AI 分析设置
- `1` 分析新文件
- `2` 从历史记录选择
- `3` 扫描目录（支持批量）
- `4` 查看历史记录
- `5` 清空历史记录
- `6` 常见报文错误知识库查询
- `7` 重置程序（敏感信息清理）
- `8` 退出

### 命令行直跑

```bash
python main.py analyze <file_path> [options]
```

常用参数：
- `--mode quick|deep|diagnosis`
- `--scope-ip <ip>`
- `--scope-port <p1,p2,...>`
- `--scope-protocol tcp|udp|icmp|arp|dns|http|tls`
- `--scope-time-start <seconds>`
- `--scope-time-end <seconds>`
- `--scope-display-filter "<tshark_display_filter>"`
- `--all`（忽略 scope，分析全流量）
- `--report-formats html,markdown,json,all`
- `--ai`（本次启用 AI 分析）
- `--no-report`（只分析不出报告）

示例：

```bash
python main.py analyze .\sample.pcap --mode quick --all --report-formats html
python main.py analyze .\sample.pcapng --mode deep --scope-ip 10.190.27.55 --scope-protocol tcp --report-formats html,markdown
python main.py analyze .\sample.pcap --mode diagnosis --scope-display-filter "tcp.flags.reset==1" --ai --report-formats all
```

## 5. 输出位置与文件命名

- 报告默认输出目录：`reports/`
- HTML：`report_<文件名>_<时间戳>.html`
- Markdown：`report_<文件名>_<时间戳>.md`
- JSON：`report_<文件名>_<时间戳>.json` 和 `report_<文件名>_<时间戳>_clean.json`
- 历史记录：`history.json`
- 日志：`logs/analyzer.log`

## 6. AI 分析说明

- AI 为可选功能，未配置时自动回落到本地规则分析
- 交互模式下可在菜单 `0` 配置
- 也支持环境变量覆盖 API Key：
  - `PCAP_AI_API_KEY`
  - `AI_API_KEY`

## 7. 目录结构（简版）

```text
main.py               # 程序入口（interactive / analyze / setup）
core/                 # 报文解析与指标提取
diagnosis/            # 规则、检测、推断、深度分析
report/               # 报告生成与图表
ui/                   # 终端交互菜单与显示
utils/                # 配置、校验、日志、tshark 查找
ai/                   # AI 客户端、Prompt、解析
config.yaml           # 配置文件
requirements.txt      # 依赖列表
```

## 8. 常见问题

### 1) 启动时报未找到 tshark
先执行：

```bash
python main.py setup
```

### 2) 文件太大分析慢
- 用 `quick` 模式先看全局
- 再用 `--scope-ip/--scope-port/--scope-time-*` 缩小范围

### 3) 对外拷贝项目前需要脱敏
在交互菜单执行 `7 重置程序`，可一键清理 AI 配置、历史、报告、日志和缓存。

