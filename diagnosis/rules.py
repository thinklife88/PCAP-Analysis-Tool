"""检测规则库"""
from typing import Optional, Dict, Any
from diagnosis.engine import Anomaly, Severity
from utils.config import get_config
import statistics

class BaseRule:
    """规则基类"""
    def __init__(self):
        self.config = get_config()

    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        raise NotImplementedError

class HighRetransmissionRule(BaseRule):
    """高重传率检测"""
    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        tcp = metrics.get('tcp', {})
        if not tcp:
            return None

        retrans_rate = tcp.get('retrans_rate', 0)
        threshold = self.config.get('analysis.thresholds.retransmission_rate', 0.05)

        if retrans_rate > threshold:
            return Anomaly(
                rule_name="高重传率",
                severity=Severity.HIGH if retrans_rate > 0.1 else Severity.MEDIUM,
                description=f"TCP重传率异常高: {retrans_rate*100:.2f}% (正常 < {threshold*100:.1f}%)",
                evidence=[
                    f"重传包数: {tcp.get('retransmissions', 0)}",
                    f"总TCP包数: {tcp.get('total_tcp', 0)}"
                ],
                affected_flows=[],
                count=tcp.get('retransmissions', 0)
            )
        return None

class HighRSTRateRule(BaseRule):
    """高RST率检测"""
    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        tcp = metrics.get('tcp', {})
        if not tcp:
            return None

        rst_rate = tcp.get('rst_rate', 0)
        threshold = self.config.get('analysis.thresholds.rst_rate', 0.02)

        if rst_rate > threshold:
            return Anomaly(
                rule_name="连接重置异常",
                severity=Severity.HIGH,
                description=f"TCP RST包比例过高: {rst_rate*100:.2f}% (正常 < {threshold*100:.1f}%)",
                evidence=[
                    f"RST包数: {tcp.get('rst', 0)}",
                    f"可能原因: 服务端拒绝连接、防火墙阻断、端口未开放"
                ],
                affected_flows=[],
                count=tcp.get('rst', 0)
            )
        return None

class TCPHandshakeFailureRule(BaseRule):
    """TCP握手失败检测"""
    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        tcp = metrics.get('tcp', {})
        if not tcp:
            return None

        syn = tcp.get('syn', 0)
        syn_ack = tcp.get('syn_ack', 0)
        half_open = tcp.get('half_open_flows', 0)

        if syn > 0 and syn_ack == 0:
            return Anomaly(
                rule_name="TCP握手失败",
                severity=Severity.CRITICAL,
                description=f"检测到 {syn} 个SYN包，但无SYN-ACK响应",
                evidence=[
                    "可能原因: 服务端无响应、网络不可达、防火墙阻断",
                    "建议: 检查目标服务是否运行、网络连通性"
                ],
                affected_flows=[],
                count=syn
            )

        if half_open > 0:
            return Anomaly(
                rule_name="TCP半开连接",
                severity=Severity.HIGH,
                description=f"检测到 {half_open} 个握手未完成的半开连接（收到SYN-ACK但未见ACK）",
                evidence=[
                    "可能原因: 客户端未完成握手、SYN Flood防护、ACK丢包",
                    "建议: 检查客户端重试、查看SYN_RCVD队列、抓包确认ACK是否丢失"
                ],
                affected_flows=[],
                count=half_open
            )

        if syn > 0 and syn_ack > 0:
            ratio = syn_ack / syn
            if ratio < 0.5:
                return Anomaly(
                    rule_name="握手成功率低",
                    severity=Severity.MEDIUM,
                    description=f"握手成功率仅 {ratio*100:.1f}%",
                    evidence=[
                        f"SYN: {syn}, SYN-ACK: {syn_ack}",
                        "可能原因: 服务端负载高、网络丢包"
                    ],
                    affected_flows=[],
                    count=syn - syn_ack
                )
        return None

class NoTrafficRule(BaseRule):
    """无流量检测"""
    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        basic = metrics.get('basic', {})
        total = basic.get('total_packets', 0)

        if total == 0:
            return Anomaly(
                rule_name="无数据包",
                severity=Severity.CRITICAL,
                description="抓包文件中没有数据包",
                evidence=["文件可能损坏或为空"],
                affected_flows=[],
                count=0
            )
        return None

def get_all_rules():
    """获取所有规则"""
    return [
        NoTrafficRule(),
        HighRetransmissionRule(),
        HighRSTRateRule(),
        TCPHandshakeFailureRule(),
        DNSFailureRule(),
        HTTPErrorRule(),
        SlowResponseRule(),
        IcmpUnreachableRule(),
        IcmpTTLExpiredRule(),
        IpOptionAnomalyRule(),
        UdpNoResponseRule(),
        UdpPortUnreachableRule(),
        TcpOutOfOrderRule(),
        TcpHalfOpenRule(),
        TlsHandshakeFailRule(),
        TrafficAsymmetryRule(),
        BroadcastStormRule(),
        PortScanRule()
    ]

class DNSFailureRule(BaseRule):
    """DNS查询失败检测"""
    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        app = metrics.get('application', {})
        dns_count = app.get('dns_total', 0)
        dns_err = app.get('dns_error_rcode', 0)

        if dns_err > 0:
            return Anomaly(
                rule_name="DNS查询失败",
                severity=Severity.MEDIUM if dns_err < 20 else Severity.HIGH,
                description=f"检测到 {dns_err} 个DNS错误响应（NXDOMAIN/SERVFAIL等）",
                evidence=[
                    "可能原因: 上游DNS不可用、域名不存在、解析超时",
                    "建议: 检查DNS服务器可达性，尝试替换上游DNS"
                ],
                affected_flows=[],
                count=dns_err
            )

        if dns_count > 10:  # 至少有10个DNS包才检测
            total = metrics.get('basic', {}).get('total_packets', 1)
            dns_ratio = dns_count / total

            if dns_ratio > 0.3:  # DNS包占比超过30%
                return Anomaly(
                    rule_name="DNS查询异常",
                    severity=Severity.MEDIUM,
                    description=f"DNS查询包占比过高: {dns_ratio*100:.1f}%",
                    evidence=[
                        f"DNS包数: {dns_count}",
                        "可能原因: DNS循环或解析失败重试"
                    ],
                    affected_flows=[],
                    count=dns_count
                )
        return None

class HTTPErrorRule(BaseRule):
    """HTTP错误检测"""
    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        app = metrics.get('application', {})
        http_err = app.get('http_error_responses', 0)
        if http_err > 0:
            return Anomaly(
                rule_name="HTTP错误状态码",
                severity=Severity.MEDIUM if http_err < 50 else Severity.HIGH,
                description=f"检测到 {http_err} 个HTTP 4xx/5xx 错误响应",
                evidence=[
                    "可能原因: 客户端请求异常或服务端故障",
                    "建议: 检查服务端日志与上游依赖，确认错误码来源"
                ],
                affected_flows=[],
                count=http_err
            )
        return None

class SlowResponseRule(BaseRule):
    """慢响应检测"""
    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        perf = metrics.get('performance', {})
        max_interval = perf.get('max_interval', 0)
        tcp = metrics.get('tcp', {})
        cfg = self.config.get('analysis.thresholds', {})
        rtt_high_ms = cfg.get('rtt_high_ms', cfg.get('rtt_threshold_ms', 500))
        interval_high_s = cfg.get('max_interval_s', 5.0)
        avg_rtt = tcp.get('avg_rtt', 0)
        max_rtt = tcp.get('max_rtt', 0)

        evidences = []
        if max_interval > interval_high_s:
            evidences.append(f"全局最大包间隔 {max_interval:.2f}秒")
        if max_rtt and max_rtt*1000 > rtt_high_ms:
            evidences.append(f"TCP RTT 异常，最大RTT {max_rtt*1000:.0f}ms，平均RTT {avg_rtt*1000:.0f}ms (阈值>{rtt_high_ms}ms)")

        if evidences:
            return Anomaly(
                rule_name="响应延迟",
                severity=Severity.MEDIUM if max_interval <= 10 and max_rtt <= 1 else Severity.HIGH,
                description="; ".join(evidences),
                evidence=[
                    "可能原因: 网络延迟高、服务端处理慢、TCP零窗口或队列拥塞",
                    "建议: 检查网络延迟、服务端性能、抓包查看RTT分布"
                ],
                affected_flows=[],
                count=1
            )
        return None


class IcmpUnreachableRule(BaseRule):
    """ICMP目的不可达"""
    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        net = metrics.get('network', {})
        cnt = net.get('icmp_unreachable', 0)
        if cnt > 0:
            return Anomaly(
                rule_name="ICMP目的不可达",
                severity=Severity.HIGH,
                description=f"捕获到 {cnt} 个ICMP目的不可达报文（Type 3）",
                evidence=[
                    "可能原因: 路由不可达、防火墙丢弃、端口未开放",
                    "建议: traceroute定位路径、检查ACL/安全组、确认服务端口监听"
                ],
                affected_flows=[],
                count=cnt
            )
        return None


class IcmpTTLExpiredRule(BaseRule):
    """ICMP超时（TTL过期）"""
    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        net = metrics.get('network', {})
        cnt = net.get('icmp_ttl_expired', 0)
        if cnt > 0:
            return Anomaly(
                rule_name="ICMP超时TTL过期",
                severity=Severity.MEDIUM,
                description=f"捕获到 {cnt} 个ICMP TTL超时报文（Type 11），可能存在路由环路或TTL过小",
                evidence=[
                    "可能原因: 路由环路、TTL配置过小、隧道叠加",
                    "建议: traceroute排查路径，检查路由表和TTL设置"
                ],
                affected_flows=[],
                count=cnt
            )
        return None


class IpOptionAnomalyRule(BaseRule):
    """IP选项异常检测"""
    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        net = metrics.get('network', {})
        cnt = net.get('ip_option_anomaly', 0)
        if cnt > 0:
            return Anomaly(
                rule_name="IP选项异常",
                severity=Severity.MEDIUM,
                description=f"检测到 {cnt} 个带有源路由等异常IP选项的报文",
                evidence=[
                    "可能原因: 配置错误或可疑流量（LSRR/SSRR）",
                    "建议: 丢弃异常选项报文，检查上游设备配置"
                ],
                affected_flows=[],
                count=cnt
            )
        return None


class UdpNoResponseRule(BaseRule):
    """UDP无响应"""
    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        udp = metrics.get('udp', {})
        flows = udp.get('no_response_flows', 0)
        if flows > 0:
            return Anomaly(
                rule_name="UDP无响应",
                severity=Severity.MEDIUM if flows < 10 else Severity.HIGH,
                description=f"检测到 {flows} 个UDP流发送多包但无回包/ICMP错误",
                evidence=[
                    "可能原因: 目标端口未监听、防火墙丢弃、回包路径不通",
                    "建议: 检查目标服务/端口，查看ICMP端口不可达回包是否被阻断"
                ],
                affected_flows=[],
                count=flows
            )
        return None


class UdpPortUnreachableRule(BaseRule):
    """UDP端口不可达"""
    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        net = metrics.get('network', {})
        cnt = net.get('icmp_port_unreachable', 0)
        if cnt > 0:
            return Anomaly(
                rule_name="UDP端口不可达",
                severity=Severity.HIGH,
                description=f"捕获到 {cnt} 个ICMP端口不可达(Type3 Code3) 回包",
                evidence=[
                    "可能原因: UDP目标端口未开放/服务未启动",
                    "建议: 确认端口监听与防火墙放行"
                ],
                affected_flows=[],
                count=cnt
            )
        return None


class TcpOutOfOrderRule(BaseRule):
    """TCP乱序包"""
    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        tcp = metrics.get('tcp', {})
        flows = tcp.get('out_of_order_flows', 0)
        if flows > 0:
            return Anomaly(
                rule_name="TCP乱序包",
                severity=Severity.MEDIUM if flows < 5 else Severity.HIGH,
                description=f"检测到 {flows} 个流存在多于3个乱序包，可能导致性能下降",
                evidence=[
                    "可能原因: 多路径/ECMP导致乱序，RSS/RPS配置，交换机负载分担",
                    "建议: 调整重排序容忍度(tcp_reordering)，检查链路/队列配置"
                ],
                affected_flows=[],
                count=flows
            )
        return None


class TcpHalfOpenRule(BaseRule):
    """TCP半开连接堆积"""
    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        tcp = metrics.get('tcp', {})
        half_open = tcp.get('half_open_flows', 0)
        threshold = self.config.get('analysis.thresholds.half_open_flows', 50)
        if half_open > threshold:
            return Anomaly(
                rule_name="TCP半开连接堆积",
                severity=Severity.CRITICAL,
                description=f"检测到 {half_open} 个SYN_RCVD半开连接，疑似SYN Flood或服务端瓶颈",
                evidence=[
                    "可能原因: SYN洪泛、ACK丢包、SYN队列耗尽",
                    "建议: 检查SYN cookies、加大backlog、排查攻击源"
                ],
                affected_flows=[],
                count=half_open
            )
        return None


class TlsHandshakeFailRule(BaseRule):
    """TLS/SSL握手失败"""
    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        app = metrics.get('application', {})
        alerts = app.get('tls_alerts', 0)
        if alerts > 0:
            return Anomaly(
                rule_name="TLS握手失败",
                severity=Severity.HIGH,
                description=f"检测到 {alerts} 个TLS Alert（如Handshake Failure/Unknown CA）",
                evidence=[
                    "可能原因: 证书校验失败、协议不兼容、SNI/ALPN错误",
                    "建议: 检查证书链、协议版本与加密套件，核对SNI"
                ],
                affected_flows=[],
                count=alerts
            )
        return None


class TrafficAsymmetryRule(BaseRule):
    """流量不对称"""
    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        net = metrics.get('network', {})
        ratio = net.get('asymmetry_ratio', 1)
        threshold = self.config.get('analysis.thresholds.asymmetry_ratio', 10)
        if ratio > threshold:
            return Anomaly(
                rule_name="流量不对称",
                severity=Severity.MEDIUM if ratio < 20 else Severity.HIGH,
                description=f"检测到上下行流量极度不对称（最大比值≈{ratio:.1f}:1）",
                evidence=[
                    "可能原因: 回程路径丢包/阻断、单向抓包、NAT/路由不一致",
                    "建议: 双向抓包比对，检查回程路由与ACL"
                ],
                affected_flows=[],
                count=int(ratio)
            )
        return None


class BroadcastStormRule(BaseRule):
    """广播/组播风暴"""
    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        net = metrics.get('network', {})
        rate = net.get('broadcast_rate', 0)
        threshold = self.config.get('analysis.thresholds.broadcast_rate', 1000)
        if rate > threshold:
            return Anomaly(
                rule_name="广播组播风暴",
                severity=Severity.CRITICAL,
                description=f"1秒内广播/组播包率约 {rate:.1f}，疑似广播风暴",
                evidence=[
                    "可能原因: 环路/IGMP失效/生成树异常",
                    "建议: 检查交换机生成树/IGMP Snooping，定位环路端口"
                ],
                affected_flows=[],
                count=int(rate)
            )
        return None

class PortScanRule(BaseRule):
    """端口扫描检测"""
    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        tcp = metrics.get('tcp', {})
        syn_count = tcp.get('syn', 0)
        total_tcp = tcp.get('total_tcp', 1)
        cfg = self.config.get('analysis.thresholds', {})
        syn_count_threshold = cfg.get('port_scan_syn_count', 100)
        syn_ratio_threshold = cfg.get('port_scan_syn_ratio', 0.8)

        if total_tcp > 0 and syn_count > syn_count_threshold and syn_count / total_tcp > syn_ratio_threshold:
            return Anomaly(
                rule_name="疑似端口扫描",
                severity=Severity.HIGH,
                description=f"检测到大量SYN包: {syn_count}个 ({syn_count/total_tcp*100:.1f}%)",
                evidence=[
                    "可能是端口扫描行为",
                    "建议: 检查源IP是否为恶意扫描"
                ],
                affected_flows=[],
                count=syn_count
            )
        return None
