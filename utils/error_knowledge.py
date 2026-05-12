"""常见/异常报文错误知识库查询。"""

import re
import unicodedata
from typing import Dict, List, Tuple


_KB: List[Dict] = [
    # ========== 原有核心条目（保留并微调细节） ==========
    {
        "name": "TCP Retransmission",
        "aliases": ["retrans", "重传"],
        "meaning": "发送端重发未被确认的数据段。",
        "causes": [
            "链路丢包/抖动（无线、长距离、拥塞）",
            "中间设备队列溢出或丢弃",
            "接收端处理慢导致丢包/超时",
            "MSS/MTU 不匹配导致分片/丢弃"
        ],
        "scenarios": [
            "高负载、弱网、跨境/跨运营商链路",
            "低速 Wi-Fi、4G/5G 抖动环境",
            "拥塞或排队时 RTT 波动大"
        ],
    },
    {
        "name": "TCP Dup ACK",
        "aliases": ["duplicate ack", "dup ack", "重复ack"],
        "meaning": "接收端连续确认同一序号，表明可能丢包或乱序。",
        "causes": [
            "单个/少量分段丢失，触发快速重传",
            "链路乱序导致误判",
            "接收端缓存/零窗口导致暂停后重发"
        ],
        "scenarios": [
            "无线链路、ECMP 乱序",
            "带宽接近瓶颈时出现排队/丢弃"
        ],
    },
    {
        "name": "TCP Fast Retransmission",
        "aliases": ["fast retrans", "快速重传"],
        "meaning": "收到3个以上 Dup ACK 后的快速重传。",
        "causes": [
            "轻度丢包/乱序触发快速重传",
            "接收端窗口/缓存抖动"
        ],
        "scenarios": ["中等拥塞或间歇丢包场景"],
    },
    {
        "name": "TCP Out-of-Order",
        "aliases": ["ooo", "乱序"],
        "meaning": "报文到达顺序与序列号顺序不一致。",
        "causes": ["ECMP/多路径负载分担", "链路抖动或重传交织", "接收端或中间设备重排序窗口过小"],
        "scenarios": ["多链路/多活出口", "云环境负载分担"],
    },
    {
        "name": "TCP Spurious Retransmission",
        "aliases": ["spurious", "误判重传"],
        "meaning": "ACK 到达较晚导致误以为超时而重传。",
        "causes": ["RTT 激增", "排队/拥塞", "定时器设置过小"],
        "scenarios": ["突发队列积压、链路切换"]
    },
    {
        "name": "TCP ZeroWindow",
        "aliases": ["零窗口"],
        "meaning": "接收端通告窗口为 0，暂无法接收数据。",
        "causes": ["接收端应用消费慢/阻塞", "内存/缓冲区不足", "CPU 过高"],
        "scenarios": ["服务端压力大、应用阻塞/GC/锁等待"]
    },
    {
        "name": "TCP Window Full",
        "aliases": ["窗口满"],
        "meaning": "发送端窗口已满，需等待 ACK 才能继续发送。",
        "causes": ["接收端通告窗口小", "网络延迟/丢包使 ACK 迟到", "流控未调优"],
        "scenarios": ["长 RTT、大对象传输、窗口未调优"]
    },
    {
        "name": "TCP RST",
        "aliases": ["reset", "rst"],
        "meaning": "连接被复位，立即终止。",
        "causes": ["服务端拒绝/端口未监听", "防火墙/IPS 主动拦截", "协议错误或超时"],
        "scenarios": ["访问未开放端口、策略拦截、应用异常退出"]
    },
    {
        "name": "TCP SYN Retransmission",
        "aliases": ["syn retrans", "握手重传"],
        "meaning": "握手 SYN 未获响应而重传。",
        "causes": ["目标不可达/端口未开", "丢包/防火墙丢弃", "SYN 队列溢出"],
        "scenarios": ["服务未启动、ACL 拦截、网络抖动"]
    },
    {
        "name": "PMTU Black Hole",
        "aliases": ["pmtu", "路径mtu", "mtu黑洞", "black hole"],
        "meaning": "路径MTU发现失败导致大包被静默丢弃，连接可建但数据面卡死或重传。",
        "causes": [
            "中间设备丢弃 ICMP Fragmentation Needed (Type3 Code4)",
            "隧道/VPN封装后有效MTU下降但未同步MSS",
            "路径设备MTU配置不一致导致大包跨路径失败"
        ],
        "scenarios": [
            "HTTPS/TLS握手成功但发送较大响应时明显卡顿",
            "跨运营商或跨云专线场景出现间歇性大包失败",
            "变更安全策略后出现仅大报文异常"
        ],
    },
    {
        "name": "ICMP Destination Unreachable",
        "aliases": ["icmp unreachable", "目的不可达"],
        "meaning": "网络/主机/端口/协议不可达反馈。",
        "causes": ["路由不可达", "防火墙丢弃", "端口未监听"],
        "scenarios": ["路由变更、端口关闭、ACL 拦截"]
    },
    {
        "name": "ICMP Time Exceeded",
        "aliases": ["ttl exceeded", "ttl 过期"],
        "meaning": "TTL 用尽，可能有环路或 TTL 设置过小。",
        "causes": ["路由环路", "隧道叠加导致 TTL 耗尽", "TTL 设置过低"],
        "scenarios": ["多跳/隧道环境、异常路由"]
    },
    {
        "name": "TLS Alert",
        "aliases": ["tls handshake fail", "alert"],
        "meaning": "TLS 握手过程中出现告警（如握手失败/未知CA/证书过期）。",
        "causes": ["证书链/信任失败", "协议/套件不兼容", "SNI/ALPN 不匹配"],
        "scenarios": ["跨版本 TLS、代理卸载、证书过期/自签"]
    },
    {
        "name": "HTTP 4xx/5xx",
        "aliases": ["http error", "http 500", "http 404"],
        "meaning": "HTTP 客户端/服务端错误状态。",
        "causes": ["客户端请求异常(4xx)", "服务端故障/过载(5xx)", "上游依赖异常"],
        "scenarios": ["接口变更、权限/认证失败、上游服务不可用"]
    },
    {
        "name": "DNS NXDOMAIN/SERVFAIL",
        "aliases": ["dns error", "nxdomain", "servfail"],
        "meaning": "DNS 响应错误：域名不存在或服务器失败。",
        "causes": ["域名配置错误", "上游 DNS 不可用", "DNSSEC/递归失败"],
        "scenarios": ["域名发布错误、上游不可达、递归链路故障"]
    },
    {
        "name": "UDP No Response",
        "aliases": ["udp noresp", "udp 无响应"],
        "meaning": "发送多包无回包且无 ICMP 错误反馈。",
        "causes": ["服务未监听", "防火墙丢弃回包", "回程路由/非对称导致回包丢失"],
        "scenarios": ["DNS/游戏/VoIP UDP 服务不可达或被拦截"]
    },
    {
        "name": "Broadcast/Multicast Storm",
        "aliases": ["broadcast storm", "组播风暴"],
        "meaning": "短时间内异常高的广播/组播流量，可能引起拥塞或环路。",
        "causes": ["交换机环路/生成树异常", "IGMP Snooping 失效", "恶意/异常主机泛洪"],
        "scenarios": ["二层环路、设备误配置、攻击或故障主机"]
    },

    # ========== 新增：网络层（IP/ICMP/ARP） ==========
    {
        "name": "IP Option Anomaly",
        "aliases": ["ip选项异常", "ip option"],
        "meaning": "IP头包含非必要或敏感选项（如源路由、时间戳），可能是配置错误或攻击探测。",
        "causes": [
            "网络设备误配置启用IP选项",
            "攻击者使用源路由选项探测网络拓扑",
            "老旧系统默认启用不必要的IP选项"
        ],
        "scenarios": [
            "网络安全审计中发现异常探测流量",
            "老旧设备与现代网络互通时的兼容性问题",
            "渗透测试场景下的拓扑探测"
        ],
    },
    {
        "name": "IP Fragment Loss",
        "aliases": ["ip分片丢失", "fragment loss"],
        "meaning": "IP分片报文部分丢失，导致完整报文无法重组。",
        "causes": [
            "链路丢包导致部分分片丢失",
            "防火墙/中间设备丢弃非首片分片",
            "分片重组超时设置过短"
        ],
        "scenarios": [
            "MTU不匹配的跨运营商链路",
            "防火墙策略仅允许首片分片通过",
            "高延迟链路中分片重组超时"
        ],
    },
    {
        "name": "ICMP Redirect",
        "aliases": ["icmp重定向", "redirect"],
        "meaning": "路由器向主机发送重定向报文，告知更优的下一跳路由。",
        "causes": [
            "网络拓扑变更后路由未及时更新",
            "主机默认网关配置不合理",
            "攻击者伪造重定向报文进行路由欺骗"
        ],
        "scenarios": [
            "网络扩容后路由调整阶段",
            "多网关环境中主机路由配置错误",
            "局域网内的路由欺骗攻击"
        ],
    },
    {
        "name": "ARP Flapping",
        "aliases": ["arp抖动", "arp flap"],
        "meaning": "同一IP对应的MAC地址频繁快速变化。",
        "causes": [
            "网络设备（如交换机）端口故障",
            "VRRP/HSRP等网关冗余协议切换",
            "ARP欺骗攻击导致MAC地址频繁更新"
        ],
        "scenarios": [
            "核心交换机冗余切换时",
            "局域网内存在ARP攻击",
            "网络设备硬件故障前兆"
        ],
    },
    {
        "name": "IP Address Conflict",
        "aliases": ["ip地址冲突", "ip conflict"],
        "meaning": "网络中两台设备使用相同IP地址，导致通信异常。",
        "causes": [
            "DHCP地址池分配冲突",
            "静态IP配置与DHCP分配重叠",
            "设备克隆或虚拟机复制导致IP重复"
        ],
        "scenarios": [
            "DHCP服务器配置错误",
            "新增设备静态IP未提前检查",
            "虚拟机批量部署时IP复用"
        ],
    },

    # ========== 新增：传输层（TCP/UDP细粒度） ==========
    {
        "name": "TCP Half-Open Connection",
        "aliases": ["半开连接", "syn_rcvd", "tcp half open"],
        "meaning": "TCP握手完成前（SYN→SYN-ACK后无ACK）或关闭时一方异常断开，连接处于未完成/未关闭状态。",
        "causes": [
            "SYN Flood攻击导致服务端SYN队列溢出",
            "客户端发送SYN后异常退出（如崩溃、网络中断）",
            "中间设备丢弃最终ACK包",
            "服务端处理慢，未及时响应或清理半开连接"
        ],
        "scenarios": [
            "遭受SYN Flood攻击的服务器",
            "客户端网络不稳定频繁断开",
            "高并发下服务端SYN队列配置过小"
        ],
    },
    {
        "name": "TCP RTT Anomaly",
        "aliases": ["tcp rtt异常", "rtt spike"],
        "meaning": "TCP往返时间（RTT）突然激增或持续过高，导致性能下降。",
        "causes": [
            "链路拥塞导致排队延迟增加",
            "中间设备（如路由器）CPU过载",
            "路由切换导致路径变长",
            "无线链路信号干扰"
        ],
        "scenarios": [
            "高峰时段的跨境链路",
            "无线AP覆盖边缘区域",
            "核心路由器故障切换时"
        ],
    },
    {
        "name": "TCP Selective Acknowledgment (SACK) Anomaly",
        "aliases": ["sack异常", "tcp sack"],
        "meaning": "TCP选择性确认（SACK）未启用或使用异常，导致重传效率低。",
        "causes": [
            "两端设备未协商启用SACK",
            "中间设备修改或丢弃SACK选项",
            "操作系统TCP参数配置禁用SACK"
        ],
        "scenarios": [
            "老旧操作系统与现代系统通信",
            "防火墙策略修改TCP选项",
            "高丢包链路中重传效率低下"
        ],
    },
    {
        "name": "TCP Keep-Alive Failure",
        "aliases": ["keep-alive失败", "tcp keepalive"],
        "meaning": "TCP保活报文未获响应，导致连接被异常断开。",
        "causes": [
            "对端设备崩溃或网络中断",
            "中间设备（如防火墙）超时断开空闲连接",
            "保活参数配置不合理（间隔过短/过长）"
        ],
        "scenarios": [
            "长连接应用（如数据库、消息队列）空闲时",
            "防火墙对空闲连接的超时设置过短",
            "服务器异常重启后未通知客户端"
        ],
    },
    {
        "name": "UDP Out-of-Order",
        "aliases": ["udp乱序", "udp ooo"],
        "meaning": "UDP报文到达顺序与发送顺序不一致，应用层需自行处理。",
        "causes": [
            "ECMP/多路径负载分担导致不同报文走不同路径",
            "链路抖动导致部分报文延迟",
            "中间设备队列调度策略"
        ],
        "scenarios": [
            "多链路出口的网络环境",
            "实时音视频传输（如VoIP、视频会议）",
            "云环境中跨可用区通信"
        ],
    },

    # ========== 新增：应用层（HTTP/TLS/DNS/其他协议） ==========
    {
        "name": "HTTP Redirect Loop",
        "aliases": ["http重定向循环", "redirect loop"],
        "meaning": "HTTP请求在多个URL间无限重定向（如A→B→A），导致请求失败。",
        "causes": [
            "Web服务器配置错误（如HTTP/HTTPS强制跳转逻辑冲突）",
            "应用层代码重定向逻辑bug",
            "负载均衡器与后端服务器重定向配置不一致"
        ],
        "scenarios": [
            "网站HTTPS改造后配置错误",
            "应用版本更新后重定向逻辑未同步",
            "多台后端服务器配置不一致"
        ],
    },
    {
        "name": "HTTP Slow Request",
        "aliases": ["http慢请求", "slow http"],
        "meaning": "HTTP请求发送或响应速度极慢，可能导致服务端资源耗尽。",
        "causes": [
            "客户端网络带宽极低",
            "服务端应用处理慢（如数据库查询超时）",
            "Slowloris等慢速攻击"
        ],
        "scenarios": [
            "低带宽客户端访问大文件",
            "服务端数据库性能瓶颈",
            "遭受慢速HTTP攻击"
        ],
    },
    {
        "name": "TLS Version Incompatibility",
        "aliases": ["tls版本不兼容", "tls version"],
        "meaning": "客户端与服务端TLS版本不匹配，导致握手失败。",
        "causes": [
            "老旧客户端仅支持TLS 1.0/1.1，而服务端已禁用",
            "服务端仅支持TLS 1.3，而老旧客户端不支持",
            "中间设备（如代理）不支持高版本TLS"
        ],
        "scenarios": [
            "老旧浏览器访问现代HTTPS网站",
            "服务端安全加固后禁用低版本TLS",
            "老旧代理设备拦截TLS 1.3流量"
        ],
    },
    {
        "name": "TLS SNI Mismatch",
        "aliases": ["sni不匹配", "tls sni"],
        "meaning": "客户端TLS握手中的SNI（服务器名称指示）与服务端期望的不匹配，导致握手失败。",
        "causes": [
            "客户端访问的域名与服务端证书绑定的域名不一致",
            "负载均衡器/反向代理SNI配置错误",
            "攻击者伪造SNI进行探测"
        ],
        "scenarios": [
            "使用IP地址直接访问HTTPS网站",
            "多域名共享IP的虚拟主机配置错误",
            "CDN/反向代理SNI转发配置问题"
        ],
    },
    {
        "name": "DNS Query Timeout",
        "aliases": ["dns查询超时", "dns timeout"],
        "meaning": "DNS请求发送后未在规定时间内收到响应。",
        "causes": [
            "DNS服务器过载或宕机",
            "链路丢包导致DNS请求/响应丢失",
            "防火墙拦截DNS流量",
            "DNS递归解析链路过长"
        ],
        "scenarios": [
            "DNS服务器遭受DDoS攻击",
            "跨运营商DNS解析链路不稳定",
            "企业内部DNS服务器故障"
        ],
    },
    {
        "name": "FTP Passive Mode Failure",
        "aliases": ["ftp被动模式失败", "ftp pasv"],
        "meaning": "FTP被动模式下数据连接建立失败。",
        "causes": [
            "防火墙未开放FTP服务器被动模式端口范围",
            "NAT设备未正确处理FTP被动模式",
            "FTP服务器被动模式端口配置错误"
        ],
        "scenarios": [
            "FTP服务器位于防火墙后",
            "通过NAT访问FTP服务器",
            "FTP服务器安全加固后端口范围未同步"
        ],
    },
    {
        "name": "WebSocket Disconnection",
        "aliases": ["websocket断开", "ws disconnect"],
        "meaning": "WebSocket连接在非预期情况下断开。",
        "causes": [
            "中间设备（如防火墙、负载均衡器）超时断开空闲连接",
            "服务端或客户端应用异常退出",
            "网络中断导致连接断开",
            "TLS握手失败或证书过期"
        ],
        "scenarios": [
            "实时聊天、在线游戏等长连接应用",
            "防火墙对WebSocket连接的超时设置过短",
            "服务器滚动更新时连接断开"
        ],
    },

    # ========== 新增：安全与流量异常 ==========
    {
        "name": "TCP Flag Anomaly",
        "aliases": ["tcp标志位异常", "tcp flag"],
        "meaning": "TCP头标志位组合异常（如SYN+FIN、FIN无ACK），可能是攻击或配置错误。",
        "causes": [
            "攻击者使用异常标志位进行端口扫描（如Xmas扫描、Null扫描）",
            "网络设备TCP/IP协议栈bug",
            "恶意软件发送异常报文"
        ],
        "scenarios": [
            "网络遭受端口扫描攻击",
            "老旧设备协议栈兼容性问题",
            "恶意软件感染的主机"
        ],
    },
    {
        "name": "Traffic Asymmetry",
        "aliases": ["流量不对称", "asymmetric traffic"],
        "meaning": "上下行流量字节数或包数比例严重失衡（如>10:1或<1:10）。",
        "causes": [
            "路由不对称导致上下行走不同路径",
            "NAT设备配置错误导致回包丢失",
            "单向流量攻击（如下行DDoS）",
            "应用层特性（如下载为主的场景）"
        ],
        "scenarios": [
            "多出口网络环境中路由配置错误",
            "遭受下行DDoS攻击",
            "大文件下载场景（正常不对称）"
        ],
    },
    {
        "name": "Port Scan",
        "aliases": ["端口扫描", "port scan", "syn scan"],
        "meaning": "攻击者向目标主机大量端口发送探测包（如SYN），以识别开放端口。",
        "causes": [
            "攻击者进行网络侦察",
            "安全工具的端口扫描测试",
            "误配置的网络监控工具发送大量探测包"
        ],
        "scenarios": [
            "网络遭受攻击前的侦察阶段",
            "企业安全自查的端口扫描",
            "第三方安全评估的渗透测试"
        ],
    },
    {
        "name": "SYN Flood",
        "aliases": ["syn洪水", "syn flood"],
        "meaning": "攻击者发送大量伪造源IP的SYN包，导致服务端SYN队列溢出，无法处理正常连接。",
        "causes": [
            "DDoS攻击",
            "安全测试工具的压力测试",
            "误配置的网络设备发送大量SYN包"
        ],
        "scenarios": [
            "网站或服务遭受DDoS攻击",
            "安全团队进行SYN Flood防护测试",
            "网络设备配置错误导致SYN包风暴"
        ],
    },
    {
        "name": "UDP Flood",
        "aliases": ["udp洪水", "udp flood"],
        "meaning": "攻击者发送大量UDP包到目标主机，导致带宽耗尽或服务端过载。",
        "causes": [
            "DDoS攻击（如DNS放大攻击、NTP放大攻击）",
            "安全测试工具的压力测试",
            "误配置的应用发送大量UDP包"
        ],
        "scenarios": [
            "DNS服务器遭受放大攻击",
            "游戏服务器遭受UDP Flood攻击",
            "安全团队进行UDP Flood防护测试"
        ],
    },
]


def _normalize_text(text: str) -> str:
    """Normalize query text for robust matching."""
    if not text:
        return ""
    value = unicodedata.normalize("NFKC", str(text)).lower().strip()
    value = re.sub(r"[_\-/]+", " ", value)
    value = re.sub(r"\s+", " ", value).strip()

    canonical = {
        "duplicate acknowledgement": "dup ack",
        "duplicate acknowledgment": "dup ack",
        "duplicate ack": "dup ack",
        "dupack": "dup ack",
        "retransmission": "retrans",
        "fast retransmission": "fast retrans",
        "zero window": "zerowindow",
        "zero-window": "zerowindow",
        "zero_window": "zerowindow",
        "tcp zero window": "tcp zerowindow",
    }
    return canonical.get(value, value)


def _compact_text(text: str) -> str:
    return _normalize_text(text).replace(" ", "")


def _infer_category(item: Dict) -> str:
    text = _normalize_text(f"{item.get('name', '')} {' '.join(item.get('aliases', []))}")
    if any(key in text for key in ("http", "tls", "dns", "ftp", "websocket")):
        return "应用层"
    if any(key in text for key in ("icmp", "arp", "ip ", "fragment", "ttl", "redirect", "address conflict")):
        return "网络层"
    if any(key in text for key in ("flood", "storm", "scan", "攻击", "anomaly")):
        return "安全与异常流量"
    if any(key in text for key in ("tcp", "udp", "rtt", "window", "retrans", "ack", "half-open")):
        return "传输层"
    return "综合"


def _infer_severity(item: Dict) -> str:
    text = _normalize_text(f"{item.get('name', '')} {' '.join(item.get('aliases', []))}")
    if any(key in text for key in ("flood", "storm", "syn flood", "udp flood", "port scan", "攻击")):
        return "高"
    if any(
        key in text
        for key in (
            "timeout",
            "rst",
            "reset",
            "half-open",
            "zerowindow",
            "alert",
            "unreachable",
            "ttl",
            "no response",
            "conflict",
        )
    ):
        return "中高"
    return "中"


def _infer_quick_checks(item: Dict) -> List[str]:
    text = _normalize_text(f"{item.get('name', '')} {' '.join(item.get('aliases', []))}")

    if any(key in text for key in ("retrans", "dup ack", "out-of-order", "rtt", "window", "zerowindow")):
        return [
            "检查链路丢包与抖动（ping/mtr）",
            "检查网卡与交换机端口错误/丢弃计数",
            "确认 MTU/MSS 与 TCP 参数是否匹配",
        ]
    if any(key in text for key in ("tls", "https", "sni")):
        return [
            "用 openssl s_client 验证证书链、SNI、协议版本",
            "检查网关/代理是否做 TLS 卸载或改写",
            "核对客户端与服务端 TLS 版本/套件兼容性",
        ]
    if "dns" in text:
        return [
            "用 dig/nslookup 验证解析与 rcode",
            "检查上游 DNS 可达性与递归链路",
            "核对防火墙是否放行 DNS 与返回流量",
        ]
    if any(key in text for key in ("icmp", "arp", "ip ", "fragment", "ttl", "redirect")):
        return [
            "用 traceroute 定位不可达/TTL 异常路径",
            "检查路由、ACL 与网关配置变更",
            "检查二层环路、ARP 冲突与设备告警日志",
        ]
    if any(key in text for key in ("scan", "flood", "storm")):
        return [
            "统计源 IP/端口分布，确认是否攻击流量",
            "检查边界防护策略与限速规则是否生效",
            "必要时临时封禁异常源并保留证据抓包",
        ]
    return [
        "先定位异常出现的时间段与受影响主机",
        "对比正常时段抓包，确认差异点",
        "结合应用日志与网络设备日志交叉验证",
    ]


def _build_search_index() -> List[Tuple[Dict, str, List[str], List[str], List[str]]]:
    """Enrich knowledge items and build search index."""
    index: List[Tuple[Dict, str, List[str], List[str], List[str]]] = []
    for item in _KB:
        item.setdefault("category", _infer_category(item))
        item.setdefault("severity", _infer_severity(item))
        item.setdefault("quick_checks", _infer_quick_checks(item))

        name_norm = _normalize_text(item.get("name", ""))
        alias_norms = [_normalize_text(alias) for alias in item.get("aliases", []) if alias]
        keys = [name_norm] + alias_norms
        compact_keys = [_compact_text(key) for key in keys if key]
        index.append((item, name_norm, alias_norms, keys, compact_keys))
    return index


_KB_INDEX = _build_search_index()


def _score_match(
    query_norm: str,
    query_compact: str,
    name_norm: str,
    alias_norms: List[str],
    keys: List[str],
    compact_keys: List[str],
) -> int:
    score = 0

    if query_norm == name_norm:
        score = max(score, 120)
    if query_norm in alias_norms:
        score = max(score, 116)
    if query_compact and query_compact in compact_keys:
        score = max(score, 112)

    for key, key_compact in zip(keys, compact_keys):
        if not key:
            continue
        if key.startswith(query_norm):
            score = max(score, 92 if key == name_norm else 90)
        if query_norm in key:
            score = max(score, 80 if key == name_norm else 78)
        if query_compact and key_compact.startswith(query_compact):
            score = max(score, 75)
        if query_compact and query_compact in key_compact:
            score = max(score, 70)
        if query_norm.startswith(key) and len(key) >= 3:
            score = max(score, 65)
    return score


def search(term: str) -> List[Dict]:
    """Search knowledge base with normalization and ranked matching."""
    query_norm = _normalize_text(term)
    if not query_norm:
        return []
    query_compact = _compact_text(query_norm)

    scored: List[Tuple[int, str, Dict]] = []
    for item, name_norm, alias_norms, keys, compact_keys in _KB_INDEX:
        score = _score_match(query_norm, query_compact, name_norm, alias_norms, keys, compact_keys)
        if score > 0:
            scored.append((score, item.get("name", ""), item))

    scored.sort(key=lambda x: (-x[0], x[1]))
    return [item for _, _, item in scored]
