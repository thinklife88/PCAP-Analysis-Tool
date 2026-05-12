"""增强的检测规则库 - 精确故障定位"""
from collections import Counter, defaultdict
import statistics
from typing import Optional, Dict, Any, List
from diagnosis.engine import Anomaly, Severity
from utils.config import get_config

class BaseRule:
    def __init__(self):
        self.config = get_config()

    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        raise NotImplementedError

class ConnectionFailureRule(BaseRule):
    """连接失败精确检测"""
    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        problem_flows = metrics.get('problem_flows', [])

        handshake_failures = [f for f in problem_flows if any('握手失败' in issue for issue in f['issues'])]

        if handshake_failures:
            evidence = []
            for flow in handshake_failures[:5]:
                evidence.append(
                    f"❌ {flow['src_ip']}:{flow['src_port']} → {flow['dst_ip']}:{flow['dst_port']} "
                    f"(SYN={flow['syn_count']}, 无SYN-ACK响应)"
                )

            return Anomaly(
                rule_name="TCP连接失败",
                severity=Severity.CRITICAL,
                description=f"检测到 {len(handshake_failures)} 个连接无法建立",
                evidence=evidence + [
                    "",
                    "🔍 可能原因:",
                    "  1. 目标服务未启动或端口未监听",
                    "  2. 防火墙阻断了连接请求",
                    "  3. 目标主机不可达或路由问题",
                    "  4. 网络设备ACL规则拦截",
                    "",
                    "📋 排查步骤:",
                    f"  1. 检查目标服务器 {handshake_failures[0]['dst_ip']} 上端口 {handshake_failures[0]['dst_port']} 是否开放",
                    "  2. 在目标服务器执行: netstat -an | grep LISTEN",
                    "  3. 检查防火墙规则: iptables -L 或 firewall-cmd --list-all",
                    "  4. 测试连通性: telnet <目标IP> <端口>",
                    f"  5. 检查源IP {handshake_failures[0]['src_ip']} 到目标的路由"
                ],
                affected_flows=[f"{f['src_ip']}:{f['src_port']}->{f['dst_ip']}:{f['dst_port']}"
                               for f in handshake_failures],
                count=len(handshake_failures)
            )
        return None

class ConnectionResetRule(BaseRule):
    """连接重置精确检测"""
    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        problem_flows = metrics.get('problem_flows', [])

        reset_flows = [f for f in problem_flows if f['rst_count'] > 0]

        if reset_flows:
            evidence = []
            for flow in reset_flows[:5]:
                evidence.append(
                    f"⚠️ {flow['src_ip']}:{flow['src_port']} → {flow['dst_ip']}:{flow['dst_port']} "
                    f"(RST包数={flow['rst_count']})"
                )

            return Anomaly(
                rule_name="连接异常重置",
                severity=Severity.HIGH,
                description=f"检测到 {len(reset_flows)} 个连接被RST重置",
                evidence=evidence + [
                    "",
                    "🔍 可能原因:",
                    "  1. 服务端主动拒绝连接（端口开放但服务拒绝）",
                    "  2. 防火墙或安全设备主动重置连接",
                    "  3. 应用层协议错误导致服务端关闭连接",
                    "  4. 连接超时或资源耗尽",
                    "",
                    "📋 排查步骤:",
                    f"  1. 检查目标服务器 {reset_flows[0]['dst_ip']} 的应用日志",
                    "  2. 查看是否有访问控制策略（如IP白名单）",
                    "  3. 检查防火墙日志，确认是否有拦截记录",
                    "  4. 验证应用层协议是否正确（如HTTP版本、认证信息）",
                    "  5. 检查服务器资源使用情况（CPU、内存、连接数）"
                ],
                affected_flows=[f"{f['src_ip']}:{f['src_port']}->{f['dst_ip']}:{f['dst_port']}"
                               for f in reset_flows],
                count=len(reset_flows)
            )
        return None

class NoResponseRule(BaseRule):
    """单向流量检测"""
    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        problem_flows = metrics.get('problem_flows', [])

        no_response = [f for f in problem_flows if any('单向流量' in issue for issue in f['issues'])]

        if no_response:
            evidence = []
            for flow in no_response[:5]:
                evidence.append(
                    f"📤 {flow['src_ip']}:{flow['src_port']} → {flow['dst_ip']}:{flow['dst_port']} "
                    f"(发送{flow['packet_count']}包，无回包)"
                )

            return Anomaly(
                rule_name="单向流量异常",
                severity=Severity.HIGH,
                description=f"检测到 {len(no_response)} 个流只有发送无回包",
                evidence=evidence + [
                    "",
                    "🔍 可能原因:",
                    "  1. 回包路径不一致（非对称路由）",
                    "  2. 目标主机收到包但无法回复（路由问题）",
                    "  3. 回包被中间设备丢弃",
                    "  4. 抓包位置不对，只能看到单向流量",
                    "",
                    "📋 排查步骤:",
                    f"  1. 在目标服务器 {no_response[0]['dst_ip']} 上同时抓包，确认是否收到请求",
                    "  2. 检查目标服务器的路由表: route -n 或 ip route",
                    f"  3. 检查目标服务器是否能ping通源IP {no_response[0]['src_ip']}",
                    "  4. 检查中间网络设备的路由配置",
                    "  5. 使用traceroute确认去回路径: traceroute <目标IP>"
                ],
                affected_flows=[f"{f['src_ip']}:{f['src_port']}->{f['dst_ip']}:{f['dst_port']}"
                               for f in no_response],
                count=len(no_response)
            )
        return None

class RetransmissionRule(BaseRule):
    """重传异常检测"""
    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        problem_flows = metrics.get('problem_flows', [])

        retrans_flows = [f for f in problem_flows if f['retrans_count'] > 0]

        if retrans_flows:
            # 按重传数量排序
            retrans_flows.sort(key=lambda x: x['retrans_count'], reverse=True)

            evidence = []
            for flow in retrans_flows[:5]:
                retrans_rate = (flow['retrans_count'] / flow['packet_count'] * 100) if flow['packet_count'] > 0 else 0
                evidence.append(
                    f"🔄 {flow['src_ip']}:{flow['src_port']} → {flow['dst_ip']}:{flow['dst_port']} "
                    f"(重传{flow['retrans_count']}包，重传率{retrans_rate:.1f}%)"
                )

            return Anomaly(
                rule_name="数据包重传",
                severity=Severity.MEDIUM,
                description=f"检测到 {len(retrans_flows)} 个流存在重传",
                evidence=evidence + [
                    "",
                    "🔍 可能原因:",
                    "  1. 网络拥塞导致丢包",
                    "  2. 链路质量差（无线网络、长距离传输）",
                    "  3. 中间设备性能瓶颈",
                    "  4. 接收端处理能力不足",
                    "",
                    "📋 排查步骤:",
                    "  1. 检查网络带宽使用情况",
                    "  2. 使用ping测试丢包率: ping -c 100 <目标IP>",
                    "  3. 检查交换机/路由器端口错误计数",
                    "  4. 查看链路利用率和队列丢弃统计",
                    "  5. 检查接收端服务器负载（CPU、内存）"
                ],
                affected_flows=[f"{f['src_ip']}:{f['src_port']}->{f['dst_ip']}:{f['dst_port']}"
                               for f in retrans_flows],
                count=sum(f['retrans_count'] for f in retrans_flows)
            )
        return None

class SlowNetworkRule(BaseRule):
    """网络卡慢检测（高延迟/大包间隔）"""
    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        tcp = metrics.get('tcp', {})
        problem_flows = metrics.get('problem_flows', [])
        slow_flows = [f for f in problem_flows if f.get('max_gap', 0) > 3.0]
        perf = metrics.get('performance', {})
        max_interval = perf.get('max_interval', 0)
        max_rtt = tcp.get('max_rtt', 0)
        avg_rtt = tcp.get('avg_rtt', 0)

        if not slow_flows and max_interval <= 3.0 and max_rtt <= 0.5:
            return None

        evidence = []
        for flow in slow_flows[:5]:
            evidence.append(
                f"🐢 {flow['src_ip']}:{flow['src_port']} → {flow['dst_ip']}:{flow['dst_port']} "
                f"(最大包间隔 {flow['max_gap']:.2f}秒)"
            )
        if max_interval > 3.0:
            evidence.append(f"📊 全局最大包间隔: {max_interval:.2f}秒")
        if max_rtt > 0.5:
            evidence.append(f"⏱ RTT 异常: 最大RTT≈{max_rtt*1000:.0f}ms，平均RTT≈{avg_rtt*1000:.0f}ms")

        evidence += [
            "",
            "🔍 可能原因:",
            "  1. 服务端处理慢（CPU/内存/磁盘IO瓶颈）",
            "  2. 网络链路拥塞，队列积压",
            "  3. TCP零窗口导致发送方等待",
            "  4. 应用层逻辑阻塞（锁、慢查询、GC）",
            "  5. 中间件（代理、负载均衡）处理延迟",
            "",
            "📋 排查步骤:",
            "  1. 检查服务端资源: top / vmstat / iostat",
            "  2. 检查数据库慢查询日志",
            "  3. 检查应用GC日志（Java应用）",
            "  4. 检查中间网络设备队列: show interfaces | include queue",
            "  5. 对比正常时段抓包，定位延迟发生位置",
            "  6. 使用 mtr 持续测试路径延迟",
        ]
        return Anomaly(
            rule_name="网络卡慢/高延迟",
            severity=Severity.HIGH if max_interval > 10.0 or len(slow_flows) > 5 or max_rtt > 1.0 else Severity.MEDIUM,
            description=f"检测到 {len(slow_flows)} 个流存在卡顿/高RTT（包间隔>3秒或RTT>500ms），全局最大间隔{max_interval:.2f}秒，最大RTT≈{max_rtt*1000:.0f}ms",
            evidence=evidence,
            affected_flows=[f"{f['src_ip']}:{f['src_port']}->{f['dst_ip']}:{f['dst_port']}" for f in slow_flows],
            count=len(slow_flows)
        )


class ZeroWindowRule(BaseRule):
    """TCP零窗口检测（接收端缓冲区满）"""
    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        tcp = metrics.get('tcp', {})
        zero_win_total = tcp.get('zero_window', 0)
        zero_win_flows = tcp.get('zero_win_flows', 0)
        problem_flows = metrics.get('problem_flows', [])
        zw_flows = [f for f in problem_flows if f.get('zero_window_count', 0) > 0]

        if zero_win_total == 0:
            return None

        evidence = []
        for flow in zw_flows[:5]:
            evidence.append(
                f"🪟 {flow['src_ip']}:{flow['src_port']} → {flow['dst_ip']}:{flow['dst_port']} "
                f"(零窗口{flow['zero_window_count']}次)"
            )
        evidence += [
            "",
            "🔍 可能原因:",
            "  1. 接收端应用读取数据太慢，接收缓冲区堆满",
            "  2. 接收端系统内存不足，TCP缓冲区被压缩",
            "  3. 接收端CPU过高，无法及时处理数据",
            "  4. 应用层存在阻塞（锁等待、慢处理）",
            "",
            "📋 排查步骤:",
            "  1. 检查接收端内存: free -h",
            "  2. 检查接收端CPU: top -bn1",
            "  3. 调大TCP接收缓冲区: sysctl -w net.ipv4.tcp_rmem='4096 87380 16777216'",
            "  4. 检查应用是否有处理积压（队列长度、线程池状态）",
            "  5. 抓包确认零窗口探测(ZWP)和窗口更新包是否正常",
        ]
        return Anomaly(
            rule_name="TCP零窗口",
            severity=Severity.HIGH,
            description=f"检测到零窗口事件 {zero_win_total} 次，涉及 {zero_win_flows} 个流，接收端缓冲区满",
            evidence=evidence,
            affected_flows=[f"{f['src_ip']}:{f['src_port']}->{f['dst_ip']}:{f['dst_port']}" for f in zw_flows],
            count=zero_win_total
        )


class DupAckPacketLossRule(BaseRule):
    """重复ACK/丢包检测"""
    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        tcp = metrics.get('tcp', {})
        dup_ack_total = tcp.get('dup_ack', 0)
        fast_retrans = tcp.get('fast_retrans', 0)
        problem_flows = metrics.get('problem_flows', [])
        dup_flows = [f for f in problem_flows if f.get('dup_ack_count', 0) >= 3]

        if dup_ack_total < 3:
            return None

        evidence = []
        for flow in dup_flows[:5]:
            evidence.append(
                f"📨 {flow['src_ip']}:{flow['src_port']} → {flow['dst_ip']}:{flow['dst_port']} "
                f"(重复ACK {flow['dup_ack_count']}次，快速重传{flow.get('fast_retrans_count',0)}次)"
            )
        evidence += [
            f"📊 全局重复ACK总数: {dup_ack_total}，快速重传: {fast_retrans}",
            "",
            "🔍 可能原因:",
            "  1. 网络链路存在随机丢包（物理层故障、无线干扰）",
            "  2. 中间设备队列溢出丢包（交换机/路由器过载）",
            "  3. 链路带宽不足导致拥塞丢包",
            "  4. 网卡驱动或硬件问题",
            "",
            "📋 排查步骤:",
            "  1. ping测试丢包率: ping -c 200 -i 0.2 <目标IP>",
            "  2. 检查网卡错误计数: ethtool -S eth0 | grep -i error",
            "  3. 检查交换机端口统计: show interface counters errors",
            "  4. 检查链路利用率是否超过80%",
            "  5. 使用mtr定位丢包节点: mtr --report <目标IP>",
        ]
        return Anomaly(
            rule_name="重复ACK/丢包",
            severity=Severity.HIGH,
            description=f"检测到重复ACK {dup_ack_total} 次（快速重传{fast_retrans}次），疑似链路丢包",
            evidence=evidence,
            affected_flows=[f"{f['src_ip']}:{f['src_port']}->{f['dst_ip']}:{f['dst_port']}" for f in dup_flows],
            count=dup_ack_total
        )


class InterceptionRule(BaseRule):
    """流量拦截检测（防火墙/安全设备/中间人）"""
    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        tcp = metrics.get('tcp', {})
        problem_flows = metrics.get('problem_flows', [])

        # 拦截特征：SYN有响应但立即RST，或握手完成后立即RST，或无数据交换直接FIN
        rst_after_handshake = [
            f for f in problem_flows
            if f.get('rst_count', 0) > 0 and f.get('syn_count', 0) > 0 and f.get('packet_count', 0) < 6
        ]
        # 单向RST（只有RST无数据）
        pure_rst = [
            f for f in problem_flows
            if f.get('rst_count', 0) > 0 and f.get('retrans_count', 0) == 0
            and any('单向' in i or '握手失败' in i for i in f.get('issues', []))
        ]

        intercept_flows = list({
            f"{f['src_ip']}:{f['src_port']}->{f['dst_ip']}:{f['dst_port']}": f
            for f in rst_after_handshake + pure_rst
        }.values())

        if not intercept_flows:
            return None

        evidence = []
        for flow in intercept_flows[:5]:
            evidence.append(
                f"🚫 {flow['src_ip']}:{flow['src_port']} → {flow['dst_ip']}:{flow['dst_port']} "
                f"(SYN={flow['syn_count']}, RST={flow['rst_count']}, 包数={flow['packet_count']})"
            )
        evidence += [
            "",
            "🔍 可能原因:",
            "  1. 防火墙ACL规则主动发送RST拦截连接",
            "  2. 安全设备（IPS/WAF）检测到威胁后重置连接",
            "  3. 负载均衡器健康检查失败后拒绝连接",
            "  4. 中间人设备（透明代理）拦截并重置",
            "  5. 目标端口被安全策略封禁",
            "",
            "📋 排查步骤:",
            "  1. 检查防火墙日志，查找对应IP/端口的拒绝记录",
            "  2. 检查IPS/WAF告警日志",
            "  3. 在防火墙两侧分别抓包，确认RST来源方向",
            "  4. 检查安全组/ACL规则: iptables -L -n -v",
            "  5. 临时关闭防火墙测试: systemctl stop firewalld（测试环境）",
            "  6. 检查是否有透明代理: traceroute <目标IP>",
        ]
        return Anomaly(
            rule_name="流量拦截",
            severity=Severity.CRITICAL,
            description=f"检测到 {len(intercept_flows)} 个连接疑似被防火墙/安全设备拦截（握手后立即RST）",
            evidence=evidence,
            affected_flows=[f"{f['src_ip']}:{f['src_port']}->{f['dst_ip']}:{f['dst_port']}" for f in intercept_flows],
            count=len(intercept_flows)
        )


class FragmentAnomalyRule(BaseRule):
    """IP分片异常检测（分片异常、重组失败、分片长度错误）"""
    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        tcp = metrics.get('tcp', {})
        frag_issue_flows_count = tcp.get('frag_issue_flows', 0)
        problem_flows = metrics.get('problem_flows', [])
        frag_flows = [f for f in problem_flows if f.get('frag_issues')]

        if not frag_flows:
            return None

        evidence = []
        for flow in frag_flows[:5]:
            for issue in flow['frag_issues'][:2]:
                evidence.append(f"🧩 {flow['src_ip']} → {flow['dst_ip']}: {issue}")

        evidence += [
            "",
            "🔍 可能原因:",
            "  1. 路径MTU不一致，分片在传输中丢失",
            "  2. 中间设备不支持IP分片重组（防火墙/NAT设备）",
            "  3. 网络设备修改了数据包长度（隧道封装/解封装错误）",
            "  4. 链路层MTU配置错误（如GRE隧道未调整MSS）",
            "  5. 发送端未正确设置DF位，导致超MTU分片",
            "",
            "📋 排查步骤:",
            "  1. 检测路径MTU: ping -M do -s 1472 <目标IP>（逐步减小直到不分片）",
            "  2. 检查接口MTU配置: ip link show / ifconfig",
            "  3. 启用路径MTU发现: sysctl -w net.ipv4.ip_no_pmtu_disc=0",
            "  4. 检查隧道接口MSS: ip tunnel show",
            "  5. 在中间设备上检查分片重组统计",
            "  6. 调整TCP MSS: iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu",
        ]
        return Anomaly(
            rule_name="IP分片异常",
            severity=Severity.HIGH,
            description=f"检测到 {len(frag_flows)} 个流存在IP分片异常（重组失败或分片长度错误）",
            evidence=evidence,
            affected_flows=[f"{f['src_ip']}:{f['src_port']}->{f['dst_ip']}:{f['dst_port']}" for f in frag_flows],
            count=len(frag_flows)
        )


class PacketLengthAnomalyRule(BaseRule):
    """数据包长度异常检测（长度被篡改/截断/填充）"""
    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        problem_flows = metrics.get('problem_flows', [])
        len_flows = [f for f in problem_flows if f.get('length_anomalies')]

        if not len_flows:
            return None

        evidence = []
        for flow in len_flows[:5]:
            for anomaly in flow['length_anomalies'][:2]:
                evidence.append(f"📏 {flow['src_ip']} → {flow['dst_ip']}: {anomaly}")

        evidence += [
            "",
            "🔍 可能原因:",
            "  1. 中间设备（防火墙/NAT/代理）修改了数据包内容导致长度变化",
            "  2. 网络设备存在Bug，错误修改IP头部长度字段",
            "  3. 隧道封装/解封装过程中长度计算错误",
            "  4. 链路层帧校验错误，数据被截断",
            "  5. 抓包工具捕获不完整（snaplen限制）",
            "",
            "📋 排查步骤:",
            "  1. 在链路两端同时抓包，对比包长度是否一致",
            "  2. 检查中间设备是否有DPI（深度包检测）或内容改写功能",
            "  3. 检查NAT设备的ALG（应用层网关）配置",
            "  4. 验证抓包时snaplen设置: tcpdump -s 0（捕获完整包）",
            "  5. 检查网卡offload设置: ethtool -k eth0 | grep offload",
        ]
        return Anomaly(
            rule_name="数据包长度异常",
            severity=Severity.HIGH,
            description=f"检测到 {len(len_flows)} 个流存在长度关系异常（已排除常见二层开销与TCP可变头长）",
            evidence=evidence,
            affected_flows=[f"{f['src_ip']}:{f['src_port']}->{f['dst_ip']}:{f['dst_port']}" for f in len_flows],
            count=len(len_flows)
        )


class FastRetransmissionRule(BaseRule):
    """快速重传检测（三次重复ACK触发）"""
    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        tcp = metrics.get('tcp', {})
        fast_retrans = tcp.get('fast_retrans', 0)
        problem_flows = metrics.get('problem_flows', [])
        fr_flows = [f for f in problem_flows if f.get('fast_retrans_count', 0) > 0]

        if fast_retrans == 0:
            return None

        evidence = []
        for flow in fr_flows[:5]:
            evidence.append(
                f"⚡ {flow['src_ip']}:{flow['src_port']} → {flow['dst_ip']}:{flow['dst_port']} "
                f"(快速重传{flow['fast_retrans_count']}次)"
            )
        evidence += [
            f"📊 全局快速重传总数: {fast_retrans}",
            "",
            "🔍 可能原因:",
            "  1. 链路存在随机丢包（收到3个重复ACK触发快速重传）",
            "  2. 网络抖动导致乱序，误触发快速重传",
            "  3. 接收端缓冲区不足，部分包被丢弃",
            "",
            "📋 排查步骤:",
            "  1. 检查链路丢包率: ping -c 100 <目标IP>",
            "  2. 检查是否有乱序: 观察抓包中序列号是否连续",
            "  3. 调整重排序容忍度: sysctl -w net.ipv4.tcp_reordering=6",
            "  4. 检查网卡RSS/RPS配置是否导致乱序",
        ]
        return Anomaly(
            rule_name="快速重传",
            severity=Severity.MEDIUM,
            description=f"检测到快速重传 {fast_retrans} 次（三次重复ACK触发），疑似链路丢包或乱序",
            evidence=evidence,
            affected_flows=[f"{f['src_ip']}:{f['src_port']}->{f['dst_ip']}:{f['dst_port']}" for f in fr_flows],
            count=fast_retrans
        )


class EndpointHotspotRule(BaseRule):
    """故障热点端点检测（智能聚类）"""

    @staticmethod
    def _flow_impact_score(flow: Dict[str, Any]) -> float:
        return (
            float(flow.get("retrans_count", 0) or 0) * 2.5
            + float(flow.get("rst_count", 0) or 0) * 4
            + float(flow.get("dup_ack_count", 0) or 0) * 1.5
            + float(flow.get("zero_window_count", 0) or 0) * 3
            + float(flow.get("max_gap", 0) or 0) * 2
            + len(flow.get("issues", []) or []) * 3
        )

    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        flows = metrics.get("problem_flows", []) or []
        if len(flows) < 3:
            return None

        by_endpoint: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for flow in flows:
            endpoint = f"{flow.get('dst_ip', 'unknown')}:{flow.get('dst_port', 0)}"
            by_endpoint[endpoint].append(flow)

        top_endpoint = ""
        top_group: List[Dict[str, Any]] = []
        top_score = -1.0
        for endpoint, group in by_endpoint.items():
            score = sum(self._flow_impact_score(flow) for flow in group)
            if score > top_score:
                top_score = score
                top_endpoint = endpoint
                top_group = group

        if not top_group:
            return None

        unique_clients = {f"{f.get('src_ip', 'unknown')}:{f.get('src_port', 0)}" for f in top_group}
        if len(top_group) < 3 or len(unique_clients) < 3:
            return None

        issue_counter = Counter()
        for flow in top_group:
            for issue in flow.get("issues", []):
                issue_counter[issue] += 1

        dominant_issues = [name for name, _ in issue_counter.most_common(3)]
        evidence = [
            f"🎯 热点端点: {top_endpoint}",
            f"📈 影响会话: {len(top_group)} 条，受影响客户端: {len(unique_clients)} 个",
            "🔎 高频故障特征: " + ("；".join(dominant_issues) if dominant_issues else "无"),
        ]
        for flow in sorted(top_group, key=self._flow_impact_score, reverse=True)[:5]:
            evidence.append(
                f"  - {flow.get('src_ip', 'unknown')}:{flow.get('src_port', 0)} -> "
                f"{flow.get('dst_ip', 'unknown')}:{flow.get('dst_port', 0)} | "
                f"重传={flow.get('retrans_count', 0)}, RST={flow.get('rst_count', 0)}, "
                f"最大间隔={float(flow.get('max_gap', 0) or 0):.2f}s"
            )

        severity = Severity.CRITICAL if len(top_group) >= 8 else Severity.HIGH
        return Anomaly(
            rule_name="故障热点端点",
            severity=severity,
            description=f"同一服务端点 {top_endpoint} 出现集中性异常（{len(top_group)} 条问题流），疑似服务端或策略侧单点故障",
            evidence=evidence,
            affected_flows=[
                f"{f.get('src_ip', 'unknown')}:{f.get('src_port', 0)}->"
                f"{f.get('dst_ip', 'unknown')}:{f.get('dst_port', 0)}"
                for f in top_group[:20]
            ],
            count=len(top_group),
        )


class AdaptiveQualityRule(BaseRule):
    """自适应链路质量检测（动态阈值）"""

    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        dynamic_cfg = self.config.get("analysis.dynamic_threshold", {})
        if not dynamic_cfg.get("enabled", True):
            return None

        tcp = metrics.get("tcp", {}) or {}
        flows = metrics.get("problem_flows", []) or []
        time_baseline = metrics.get("time_baseline", {}) or {}
        if not tcp or not flows:
            return None

        total_tcp = int(tcp.get("total_tcp", 0) or 0)
        retrans_total = int(tcp.get("retransmissions", 0) or 0)
        rst_total = int(tcp.get("rst", 0) or 0)
        if total_tcp <= 0:
            return None

        std_multiplier = float(dynamic_cfg.get("std_multiplier", 2))
        min_windows = int(dynamic_cfg.get("min_windows", 3))
        learning_margin = float(dynamic_cfg.get("learning_margin", 1.15))
        base_retrans = float(self.config.get("analysis.thresholds.retransmission_rate", 0.05))
        base_rst = float(self.config.get("analysis.thresholds.rst_rate", 0.02))

        min_flow_packets = int(dynamic_cfg.get("min_flow_packets", 20))
        flow_retrans_rates = [
            (float(f.get("retrans_count", 0) or 0) / max(int(f.get("packet_count", 0) or 1), 1))
            for f in flows
            if int(f.get("packet_count", 0) or 0) >= min_flow_packets
        ]
        flow_rst_rates = [
            (float(f.get("rst_count", 0) or 0) / max(int(f.get("packet_count", 0) or 1), 1))
            for f in flows
            if int(f.get("packet_count", 0) or 0) >= min_flow_packets
        ]

        # Fallback for fragmented captures where each flow packet count is small.
        if not flow_retrans_rates and not flow_rst_rates:
            flow_retrans_rates = [
                (float(f.get("retrans_count", 0) or 0) / max(int(f.get("packet_count", 0) or 1), 1))
                for f in flows
                if int(f.get("packet_count", 0) or 0) >= 5
            ]
            flow_rst_rates = [
                (float(f.get("rst_count", 0) or 0) / max(int(f.get("packet_count", 0) or 1), 1))
                for f in flows
                if int(f.get("packet_count", 0) or 0) >= 5
            ]

        if not flow_retrans_rates and not flow_rst_rates:
            flow_retrans_rates = [float(tcp.get("retrans_rate", 0) or 0)]
            flow_rst_rates = [float(tcp.get("rst_rate", 0) or 0)]

        retrans_mean = statistics.mean(flow_retrans_rates) if flow_retrans_rates else 0.0
        retrans_std = statistics.pstdev(flow_retrans_rates) if len(flow_retrans_rates) > 1 else 0.0
        rst_mean = statistics.mean(flow_rst_rates) if flow_rst_rates else 0.0
        rst_std = statistics.pstdev(flow_rst_rates) if len(flow_rst_rates) > 1 else 0.0

        adaptive_retrans = max(base_retrans, retrans_mean + std_multiplier * retrans_std)
        adaptive_rst = max(base_rst, rst_mean + std_multiplier * rst_std)

        # Adjust threshold by sample size to reduce false positives on tiny captures.
        if total_tcp < 500:
            adaptive_retrans = max(adaptive_retrans, base_retrans * 1.4)
            adaptive_rst = max(adaptive_rst, base_rst * 1.5)
        elif total_tcp > 5000:
            adaptive_retrans = max(base_retrans * 0.7, adaptive_retrans * 0.9)
            adaptive_rst = max(base_rst * 0.7, adaptive_rst * 0.9)

        adaptive_retrans = min(adaptive_retrans, 0.25)
        adaptive_rst = min(adaptive_rst, 0.15)

        active_window_count = int(time_baseline.get("active_window_count", 0) or 0)
        baseline_used = active_window_count >= min_windows
        learned_retrans = 0.0
        learned_rst = 0.0
        if baseline_used:
            learned_retrans = float(time_baseline.get("retrans_rate_p95", 0) or 0) * learning_margin
            learned_rst = float(time_baseline.get("rst_rate_p95", 0) or 0) * learning_margin
            if learned_retrans > 0:
                adaptive_retrans = max(adaptive_retrans, min(learned_retrans, 0.30))
            if learned_rst > 0:
                adaptive_rst = max(adaptive_rst, min(learned_rst, 0.20))

        current_retrans = float(tcp.get("retrans_rate", 0) or 0)
        current_rst = float(tcp.get("rst_rate", 0) or 0)
        min_retrans_events = max(5, int(total_tcp * 0.003))
        min_rst_events = max(3, int(total_tcp * 0.002))

        triggers: List[str] = []
        if current_retrans > adaptive_retrans and retrans_total >= min_retrans_events:
            triggers.append(
                f"重传率 {current_retrans*100:.2f}% > 自适应阈值 {adaptive_retrans*100:.2f}%"
            )
        if current_rst > adaptive_rst and rst_total >= min_rst_events:
            triggers.append(
                f"RST率 {current_rst*100:.2f}% > 自适应阈值 {adaptive_rst*100:.2f}%"
            )

        spike_windows = time_baseline.get("spike_windows", []) or []
        if baseline_used and spike_windows:
            top_spike = spike_windows[0]
            spike_retrans = float(top_spike.get("retrans_rate", 0) or 0)
            spike_rst = float(top_spike.get("rst_rate", 0) or 0)
            if spike_retrans > adaptive_retrans * 1.3 and retrans_total >= min_retrans_events:
                triggers.append(
                    f"时段突发重传峰值 {spike_retrans*100:.2f}%（窗口#{top_spike.get('index', '?')}）"
                )
            if spike_rst > adaptive_rst * 1.3 and rst_total >= min_rst_events:
                triggers.append(
                    f"时段突发RST峰值 {spike_rst*100:.2f}%（窗口#{top_spike.get('index', '?')}）"
                )

        if not triggers:
            return None

        top_flows = sorted(
            flows,
            key=lambda f: (
                float(f.get("retrans_count", 0) or 0) * 2 + float(f.get("rst_count", 0) or 0) * 4
            ),
            reverse=True,
        )[:5]
        evidence = [
            "📐 动态阈值参数:",
            f"  - 样本TCP包数: {total_tcp}",
            f"  - std_multiplier: {std_multiplier}",
            f"  - 基线阈值: 重传<{base_retrans*100:.2f}%, RST<{base_rst*100:.2f}%",
            f"  - 自适应阈值: 重传<{adaptive_retrans*100:.2f}%, RST<{adaptive_rst*100:.2f}%",
            f"  - 时段学习: {'启用' if baseline_used else '未启用（有效窗口不足）'}",
            f"  - 学习参数: min_windows={min_windows}, learning_margin={learning_margin:.2f}",
            "🚨 触发条件:",
        ] + [f"  - {item}" for item in triggers]
        if baseline_used:
            evidence.append(
                f"  - 时段P95: 重传≈{float(time_baseline.get('retrans_rate_p95', 0) or 0)*100:.2f}%, "
                f"RST≈{float(time_baseline.get('rst_rate_p95', 0) or 0)*100:.2f}%"
            )
            evidence.append(
                f"  - 时段波动: 重传std≈{float(time_baseline.get('retrans_rate_std', 0) or 0)*100:.2f}%, "
                f"RSTstd≈{float(time_baseline.get('rst_rate_std', 0) or 0)*100:.2f}%"
            )
            if spike_windows:
                top_spike = spike_windows[0]
                evidence.append(
                    f"  - 峰值窗口: #{top_spike.get('index', '?')} "
                    f"({float(top_spike.get('start_offset_s', 0) or 0):.1f}s~{float(top_spike.get('end_offset_s', 0) or 0):.1f}s)"
                )
        evidence.append("🔎 受影响高风险流:")
        for flow in top_flows:
            evidence.append(
                f"  - {flow.get('src_ip', 'unknown')}:{flow.get('src_port', 0)} -> "
                f"{flow.get('dst_ip', 'unknown')}:{flow.get('dst_port', 0)} "
                f"(重传={flow.get('retrans_count', 0)}, RST={flow.get('rst_count', 0)}, 包数={flow.get('packet_count', 0)})"
            )

        overshoot = max(
            (current_retrans / adaptive_retrans) if adaptive_retrans > 0 else 0.0,
            (current_rst / adaptive_rst) if adaptive_rst > 0 else 0.0,
        )
        severity = Severity.CRITICAL if overshoot >= 1.8 and len(triggers) >= 2 else Severity.HIGH
        return Anomaly(
            rule_name="自适应链路质量退化",
            severity=severity,
            description="基于动态阈值检测到链路质量显著劣化，超出当前流量结构可接受范围",
            evidence=evidence,
            affected_flows=[
                f"{f.get('src_ip', 'unknown')}:{f.get('src_port', 0)}->"
                f"{f.get('dst_ip', 'unknown')}:{f.get('dst_port', 0)}"
                for f in top_flows
            ],
            count=len(top_flows),
        )


class CrossLayerCascadeRule(BaseRule):
    """跨层级级联故障检测（L3/L4/L7）"""

    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        tcp = metrics.get("tcp", {}) or {}
        net = metrics.get("network", {}) or {}
        app = metrics.get("application", {}) or {}
        flows = metrics.get("problem_flows", []) or []
        if not flows:
            return None

        l3_signals: List[str] = []
        if int(net.get("icmp_unreachable", 0) or 0) > 0:
            l3_signals.append(f"ICMP不可达={net.get('icmp_unreachable', 0)}")
        if float(net.get("asymmetry_ratio", 1) or 1) >= float(
            self.config.get("analysis.thresholds.asymmetry_ratio", 10)
        ):
            l3_signals.append(f"流量不对称≈{float(net.get('asymmetry_ratio', 1) or 1):.1f}:1")
        if int(net.get("icmp_ttl_expired", 0) or 0) > 0:
            l3_signals.append(f"TTL超时={net.get('icmp_ttl_expired', 0)}")

        l4_signals: List[str] = []
        if float(tcp.get("retrans_rate", 0) or 0) >= float(
            self.config.get("analysis.thresholds.retransmission_rate", 0.05)
        ):
            l4_signals.append(f"重传率={float(tcp.get('retrans_rate', 0) or 0)*100:.2f}%")
        if float(tcp.get("rst_rate", 0) or 0) >= float(self.config.get("analysis.thresholds.rst_rate", 0.02)):
            l4_signals.append(f"RST率={float(tcp.get('rst_rate', 0) or 0)*100:.2f}%")
        handshake_fail_count = sum(1 for f in flows if any("握手失败" in issue for issue in f.get("issues", [])))
        if handshake_fail_count > 0:
            l4_signals.append(f"握手失败流={handshake_fail_count}")

        l7_signals: List[str] = []
        if int(app.get("http_error_responses", 0) or 0) > 0:
            l7_signals.append(f"HTTP错误={app.get('http_error_responses', 0)}")
        if int(app.get("dns_error_rcode", 0) or 0) > 0:
            l7_signals.append(f"DNS错误={app.get('dns_error_rcode', 0)}")
        if int(app.get("tls_alerts", 0) or 0) > 0:
            l7_signals.append(f"TLS Alert={app.get('tls_alerts', 0)}")

        layer_count = sum(1 for signals in [l3_signals, l4_signals, l7_signals] if signals)
        if layer_count < 2:
            return None

        severity = Severity.CRITICAL if layer_count == 3 else Severity.HIGH
        evidence = [
            "🧠 跨层级故障链检测：",
            f"  - L3层信号: {'；'.join(l3_signals) if l3_signals else '无'}",
            f"  - L4层信号: {'；'.join(l4_signals) if l4_signals else '无'}",
            f"  - L7层信号: {'；'.join(l7_signals) if l7_signals else '无'}",
            "",
            "📋 建议排障顺序:",
            "  1. 先确认L3/L4连通和回程路径（ICMP/路由/ACL）",
            "  2. 再确认TCP握手与传输完整性（重传/RST/窗口）",
            "  3. 最后核查应用层依赖（DNS/TLS/HTTP）",
        ]

        top_flows = sorted(
            flows,
            key=lambda f: len(f.get("issues", [])) + int(f.get("rst_count", 0) or 0) + int(f.get("retrans_count", 0) or 0),
            reverse=True,
        )[:8]
        return Anomaly(
            rule_name="跨层级故障链",
            severity=severity,
            description=f"检测到 {layer_count} 层同时异常（L3/L4/L7），疑似级联故障而非单点告警",
            evidence=evidence,
            affected_flows=[
                f"{f.get('src_ip', 'unknown')}:{f.get('src_port', 0)}->"
                f"{f.get('dst_ip', 'unknown')}:{f.get('dst_port', 0)}"
                for f in top_flows
            ],
            count=len(top_flows),
        )



class DNSLatencyRule(BaseRule):
    """DNS解析时延异常"""

    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        app = metrics.get("application", {}) or {}
        threshold_ms = float(self.config.get("analysis.thresholds.dns_latency_high_ms", 200))
        p95_ms = float(app.get("dns_latency_p95_ms", 0) or 0)
        avg_ms = float(app.get("dns_latency_avg_ms", 0) or 0)
        samples = int(app.get("dns_latency_samples", 0) or 0)
        slow_count = int(app.get("dns_slow_count", 0) or 0)
        unanswered = int(app.get("dns_unanswered", 0) or 0)

        if samples < 5 and unanswered == 0:
            return None
        if p95_ms < threshold_ms and slow_count == 0 and unanswered == 0:
            return None

        severity = Severity.MEDIUM
        if unanswered >= 10 or p95_ms >= threshold_ms * 4:
            severity = Severity.CRITICAL
        elif unanswered > 0 or p95_ms >= threshold_ms * 2:
            severity = Severity.HIGH

        flows = metrics.get("problem_flows", []) or []
        dns_flows = [
            f for f in flows if int(f.get("dst_port", 0) or 0) == 53 or int(f.get("src_port", 0) or 0) == 53
        ][:8]

        evidence = [
            f"DNS时延样本={samples}, 平均={avg_ms:.1f}ms, P95={p95_ms:.1f}ms",
            f"慢查询(>{threshold_ms:.0f}ms)={slow_count}, 未应答={unanswered}",
            "建议核查本地DNS可达性、上游递归链路与权威DNS响应性能",
        ]
        return Anomaly(
            rule_name="DNS解析时延异常",
            severity=severity,
            description=f"DNS解析时延偏高：P95={p95_ms:.1f}ms，超过阈值{threshold_ms:.0f}ms",
            evidence=evidence,
            affected_flows=[
                f"{f.get('src_ip', 'unknown')}:{f.get('src_port', 0)}->{f.get('dst_ip', 'unknown')}:{f.get('dst_port', 0)}"
                for f in dns_flows
            ],
            count=max(slow_count, unanswered, 1),
        )


class HandshakeLatencyRule(BaseRule):
    """TCP握手时延异常"""

    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        tcp = metrics.get("tcp", {}) or {}
        synack_p95 = float(tcp.get("handshake_synack_p95_ms", 0) or 0)
        ack_p95 = float(tcp.get("handshake_ack_p95_ms", 0) or 0)
        synack_threshold = float(self.config.get("analysis.thresholds.handshake_synack_high_ms", 300))
        ack_threshold = float(self.config.get("analysis.thresholds.handshake_ack_high_ms", 300))

        if synack_p95 <= synack_threshold and ack_p95 <= ack_threshold:
            return None

        flows = metrics.get("problem_flows", []) or []
        delayed = [
            f
            for f in flows
            if float(f.get("handshake_synack_ms", 0) or 0) > synack_threshold
            or float(f.get("handshake_ack_ms", 0) or 0) > ack_threshold
        ]

        evidence = [
            f"SYN->SYN/ACK P95={synack_p95:.1f}ms (阈值={synack_threshold:.0f}ms)",
            f"SYN/ACK->ACK P95={ack_p95:.1f}ms (阈值={ack_threshold:.0f}ms)",
            "握手时延升高常见于链路RTT抖动、策略设备排队或服务器繁忙",
        ]
        severity = (
            Severity.HIGH
            if max(synack_p95 / max(synack_threshold, 1), ack_p95 / max(ack_threshold, 1)) > 2
            else Severity.MEDIUM
        )
        return Anomaly(
            rule_name="TCP握手时延异常",
            severity=severity,
            description="三次握手阶段存在显著时延，连接建立变慢",
            evidence=evidence,
            affected_flows=[
                f"{f.get('src_ip', 'unknown')}:{f.get('src_port', 0)}->{f.get('dst_ip', 'unknown')}:{f.get('dst_port', 0)}"
                for f in delayed[:10]
            ],
            count=max(len(delayed), 1),
        )


class QuickDisconnectRule(BaseRule):
    """握手后快速断开"""

    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        tcp = metrics.get("tcp", {}) or {}
        quick_count = int(tcp.get("quick_disconnect_flows", 0) or 0)
        if quick_count <= 0:
            return None

        flows = metrics.get("problem_flows", []) or []
        candidates = [f for f in flows if bool(f.get("quick_disconnect"))]
        evidence = [
            f"握手后快速断开流={quick_count}",
            "连接建立后短时间即FIN/RST，业务可能在鉴权或协议协商阶段失败",
            "建议重点检查应用日志、TLS握手结果与中间安全策略拦截",
        ]
        return Anomaly(
            rule_name="握手后快速断开",
            severity=Severity.HIGH if quick_count >= 5 else Severity.MEDIUM,
            description="连接建立后快速中断，疑似应用拒绝、鉴权失败或策略拦截",
            evidence=evidence,
            affected_flows=[
                f"{f.get('src_ip', 'unknown')}:{f.get('src_port', 0)}->{f.get('dst_ip', 'unknown')}:{f.get('dst_port', 0)}"
                for f in candidates[:10]
            ],
            count=quick_count,
        )


class HTTPLatencyRule(BaseRule):
    """HTTP首包时延异常"""

    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        app = metrics.get("application", {}) or {}
        threshold_ms = float(self.config.get("analysis.thresholds.http_ttfb_high_ms", 800))
        p95_ms = float(app.get("http_latency_p95_ms", 0) or 0)
        avg_ms = float(app.get("http_latency_avg_ms", 0) or 0)
        samples = int(app.get("http_latency_samples", 0) or 0)
        slow_count = int(app.get("http_slow_count", 0) or 0)

        if samples < 5:
            return None
        if p95_ms < threshold_ms and slow_count == 0:
            return None

        flows = metrics.get("problem_flows", []) or []
        http_flows = [f for f in flows if float(f.get("http_latency_avg_ms", 0) or 0) >= threshold_ms]

        severity = Severity.HIGH if p95_ms >= threshold_ms * 2 else Severity.MEDIUM
        evidence = [
            f"HTTP时延样本={samples}, 平均={avg_ms:.1f}ms, P95={p95_ms:.1f}ms",
            f"慢响应(>{threshold_ms:.0f}ms)={slow_count}",
            "建议排查后端处理耗时、数据库慢查询或网关限流",
        ]
        return Anomaly(
            rule_name="HTTP首包时延异常",
            severity=severity,
            description=f"HTTP响应时延偏高：P95={p95_ms:.1f}ms，超过阈值{threshold_ms:.0f}ms",
            evidence=evidence,
            affected_flows=[
                f"{f.get('src_ip', 'unknown')}:{f.get('src_port', 0)}->{f.get('dst_ip', 'unknown')}:{f.get('dst_port', 0)}"
                for f in http_flows[:10]
            ],
            count=max(slow_count, 1),
        )


class WindowFullPersistentRule(BaseRule):
    """TCP Window Full 持续异常"""

    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        tcp = metrics.get("tcp", {}) or {}
        total_events = int(tcp.get("window_full", 0) or 0)
        flow_count = int(tcp.get("window_full_flows", 0) or 0)
        total_tcp_flows = int(tcp.get("total_tcp_flows", 0) or 0)

        threshold_events = int(self.config.get("analysis.thresholds.window_full_threshold", 30))
        ratio_threshold = float(self.config.get("analysis.thresholds.window_full_flow_ratio", 0.1))
        ratio = (flow_count / total_tcp_flows) if total_tcp_flows > 0 else 0.0

        if total_events < threshold_events and ratio < ratio_threshold:
            return None

        flows = metrics.get("problem_flows", []) or []
        wf_flows = [f for f in flows if int(f.get("window_full_count", 0) or 0) > 0]

        severity = (
            Severity.HIGH
            if total_events >= threshold_events * 2 or ratio >= ratio_threshold * 2
            else Severity.MEDIUM
        )
        evidence = [
            f"Window Full事件={total_events}, 涉及TCP流={flow_count}/{max(total_tcp_flows, 1)} ({ratio*100:.1f}%)",
            f"触发条件：事件>={threshold_events} 或 流占比>={ratio_threshold*100:.1f}%",
            "建议核查接收端处理能力、应用读取速率与主机缓冲配置",
        ]
        return Anomaly(
            rule_name="TCP窗口饱和异常",
            severity=severity,
            description="持续出现Window Full，疑似接收侧处理瓶颈或应用消费不及时",
            evidence=evidence,
            affected_flows=[
                f"{f.get('src_ip', 'unknown')}:{f.get('src_port', 0)}->{f.get('dst_ip', 'unknown')}:{f.get('dst_port', 0)}"
                for f in wf_flows[:10]
            ],
            count=max(total_events, flow_count, 1),
        )


class JitterInstabilityRule(BaseRule):
    """RTT/吞吐抖动异常"""

    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        tcp = metrics.get("tcp", {}) or {}
        baseline = metrics.get("time_baseline", {}) or {}
        rtt_jitter_cv = float(tcp.get("rtt_jitter_cv", baseline.get("rtt_jitter_cv", 0)) or 0)
        throughput_jitter_cv = float(baseline.get("throughput_jitter_cv", 0) or 0)

        rtt_cv_high = float(self.config.get("analysis.thresholds.rtt_jitter_cv_high", 0.6))
        tp_cv_high = float(self.config.get("analysis.thresholds.throughput_jitter_cv_high", 0.8))

        if rtt_jitter_cv < rtt_cv_high and throughput_jitter_cv < tp_cv_high:
            return None

        flows = metrics.get("problem_flows", []) or []
        top_flows = sorted(
            flows,
            key=lambda f: float(f.get("max_gap", 0) or 0) + float(f.get("retrans_count", 0) or 0),
            reverse=True,
        )[:10]

        severity = (
            Severity.HIGH
            if rtt_jitter_cv >= rtt_cv_high * 1.5 and throughput_jitter_cv >= tp_cv_high * 1.5
            else Severity.MEDIUM
        )
        evidence = [
            f"RTT抖动CV={rtt_jitter_cv:.2f} (阈值={rtt_cv_high:.2f})",
            f"吞吐抖动CV={throughput_jitter_cv:.2f} (阈值={tp_cv_high:.2f})",
            "建议核查链路拥塞、QoS整形策略与跨网段路由稳定性",
        ]
        return Anomaly(
            rule_name="链路抖动异常",
            severity=severity,
            description="RTT或吞吐波动显著，链路稳定性下降",
            evidence=evidence,
            affected_flows=[
                f"{f.get('src_ip', 'unknown')}:{f.get('src_port', 0)}->{f.get('dst_ip', 'unknown')}:{f.get('dst_port', 0)}"
                for f in top_flows
            ],
            count=max(len(top_flows), 1),
        )


class SynRetryPressureRule(BaseRule):
    """SYN重试压力"""

    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        flows = metrics.get("problem_flows", []) or []
        min_syn = int(self.config.get("analysis.thresholds.syn_retry_min_count", 3))
        min_flow_count = int(self.config.get("analysis.thresholds.syn_retry_flow_threshold", 3))

        retry_flows = [
            f
            for f in flows
            if int(f.get("syn_count", 0) or 0) >= min_syn and int(f.get("syn_ack_count", 0) or 0) == 0
        ]
        if len(retry_flows) < min_flow_count:
            return None

        src_counter = Counter(f.get("src_ip", "unknown") for f in retry_flows)
        dst_counter = Counter(
            f"{f.get('dst_ip', 'unknown')}:{f.get('dst_port', 0)}" for f in retry_flows
        )
        unique_src = len(src_counter)
        total_syn_retries = sum(int(f.get("syn_count", 0) or 0) for f in retry_flows)

        severity = Severity.HIGH
        if len(retry_flows) >= min_flow_count * 3 or unique_src >= 20:
            severity = Severity.CRITICAL

        evidence = [
            f"SYN重试流={len(retry_flows)}，总SYN重试包={total_syn_retries}",
            f"主要受影响目标={dst_counter.most_common(1)[0][0] if dst_counter else 'unknown'}",
            f"来源主机数={unique_src}，阈值=流数>={min_flow_count}、单流SYN>={min_syn}",
            "该特征常见于服务不可达、ACL静默丢弃、SYN队列压力或SYN Flood。",
        ]
        for flow in retry_flows[:8]:
            evidence.append(
                f"  - {flow.get('src_ip', 'unknown')}:{flow.get('src_port', 0)} -> "
                f"{flow.get('dst_ip', 'unknown')}:{flow.get('dst_port', 0)} | "
                f"SYN={flow.get('syn_count', 0)}, SYN-ACK={flow.get('syn_ack_count', 0)}"
            )

        return Anomaly(
            rule_name="SYN重试压力",
            severity=severity,
            description="连接建立阶段出现明显重试压力，需优先排查服务监听与接入策略。",
            evidence=evidence,
            affected_flows=[
                f"{f.get('src_ip', 'unknown')}:{f.get('src_port', 0)}->"
                f"{f.get('dst_ip', 'unknown')}:{f.get('dst_port', 0)}"
                for f in retry_flows[:20]
            ],
            count=len(retry_flows),
        )


class PMTUBlackholeRule(BaseRule):
    """PMTU黑洞风险"""

    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        tcp = metrics.get("tcp", {}) or {}
        net = metrics.get("network", {}) or {}
        flows = metrics.get("problem_flows", []) or []

        frag_needed = int(net.get("icmp_frag_needed", 0) or 0)
        retrans_rate = float(tcp.get("retrans_rate", 0) or 0)
        frag_issue_flows = int(tcp.get("frag_issue_flows", 0) or 0)
        len_issue_flows = int(tcp.get("length_issue_flows", 0) or 0)

        frag_needed_th = int(self.config.get("analysis.thresholds.pmtud_icmp_frag_needed_threshold", 3))
        retrans_th = float(self.config.get("analysis.thresholds.pmtud_retrans_rate_threshold", 0.05))
        suspect_flow_th = int(self.config.get("analysis.thresholds.pmtud_suspect_flow_threshold", 2))

        suspect_flows = [
            f
            for f in flows
            if int(f.get("final_ack_count", 0) or 0) > 0
            and int(f.get("retrans_count", 0) or 0) >= 2
            and float(f.get("max_gap", 0) or 0) >= 1.5
            and int(f.get("zero_window_count", 0) or 0) == 0
        ]

        direct_signal = frag_needed >= frag_needed_th and retrans_rate >= retrans_th
        indirect_signal = (
            (frag_issue_flows + len_issue_flows) >= suspect_flow_th
            and len(suspect_flows) >= suspect_flow_th
            and retrans_rate >= retrans_th
        )
        if not direct_signal and not indirect_signal:
            return None

        severity = Severity.HIGH
        if (direct_signal and indirect_signal) or frag_needed >= frag_needed_th * 3:
            severity = Severity.CRITICAL

        evidence = [
            f"ICMP Fragmentation Needed={frag_needed}，重传率={retrans_rate*100:.2f}%",
            f"分片异常流={frag_issue_flows}，长度异常流={len_issue_flows}，疑似黑洞流={len(suspect_flows)}",
            "满足特征：握手已完成但数据面重传/卡顿，且出现分片或长度层异常。",
            "建议先做路径MTU探测与MSS钳制验证，排查中间设备是否拦截ICMP PTB。",
        ]
        for flow in suspect_flows[:8]:
            evidence.append(
                f"  - {flow.get('src_ip', 'unknown')}:{flow.get('src_port', 0)} -> "
                f"{flow.get('dst_ip', 'unknown')}:{flow.get('dst_port', 0)} | "
                f"retrans={flow.get('retrans_count', 0)}, gap={float(flow.get('max_gap', 0) or 0):.2f}s"
            )

        return Anomaly(
            rule_name="PMTU黑洞风险",
            severity=severity,
            description="存在路径MTU发现异常风险，可能导致大包数据面卡死或反复重传。",
            evidence=evidence,
            affected_flows=[
                f"{f.get('src_ip', 'unknown')}:{f.get('src_port', 0)}->"
                f"{f.get('dst_ip', 'unknown')}:{f.get('dst_port', 0)}"
                for f in (suspect_flows[:20] if suspect_flows else flows[:20])
            ],
            count=max(frag_needed, len(suspect_flows), 1),
        )


class ARPAnomalyRule(BaseRule):
    """ARP storm/spoof anomaly detection."""

    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        cfg = self.config.get("analysis.thresholds", {}) or {}
        basic = metrics.get("basic", {}) or {}
        network = metrics.get("network", {}) or {}
        protocol = metrics.get("protocol", {}) or {}
        timeline = metrics.get("traffic_timeline", {}) or {}

        arp_total = int(network.get("arp_total", protocol.get("ARP", 0)) or 0)
        duration = float(basic.get("duration", 0) or 0)
        if arp_total <= 0 or duration <= 0:
            return None

        min_packets = int(cfg.get("arp_min_packets", 30) or 30)
        if arp_total < min_packets:
            return None

        window_seconds = float(timeline.get("window_seconds", 1.0) or 1.0)
        if window_seconds <= 0:
            window_seconds = 1.0
        series = timeline.get("series", []) or []

        storm_pps_threshold = float(cfg.get("arp_storm_rate_pps", 60.0) or 60.0)
        storm_window_packets = int(cfg.get("arp_storm_window_packets", 200) or 200)

        storm_windows = []
        for point in series:
            arp_packets = int(point.get("arp_packets", 0) or 0)
            if arp_packets <= 0:
                continue
            arp_pps = arp_packets / window_seconds
            if arp_packets >= storm_window_packets or arp_pps >= storm_pps_threshold:
                storm_windows.append((point, arp_pps))

        conflict_count = int(network.get("arp_ip_mac_conflicts", 0) or 0)
        conflict_examples = network.get("arp_conflict_examples", []) or []

        if not storm_windows and conflict_count <= 0:
            return None

        arp_rate = arp_total / duration if duration > 0 else 0.0
        evidence = [
            f"ARP总包数: {arp_total}, 采样时长: {duration:.1f}s, 平均ARP速率: {arp_rate:.2f} pps",
            (
                f"阈值: storm_pps>={storm_pps_threshold:.1f}, "
                f"storm_window_packets>={storm_window_packets}"
            ),
        ]
        if storm_windows:
            evidence.append(f"ARP突发窗口: {len(storm_windows)} 个")
            for point, arp_pps in storm_windows[:5]:
                evidence.append(
                    "  - 窗口#{idx}: t={start:.1f}s, ARP={count}, 速率={pps:.2f}pps".format(
                        idx=int(point.get("index", 0) or 0),
                        start=float(point.get("time_s", 0) or 0),
                        count=int(point.get("arp_packets", 0) or 0),
                        pps=arp_pps,
                    )
                )
        if conflict_count > 0:
            evidence.append(f"ARP同IP多MAC冲突: {conflict_count} 个")
            for item in conflict_examples[:5]:
                evidence.append(f"  - {item}")

        severity = Severity.MEDIUM
        if conflict_count > 0:
            severity = Severity.CRITICAL
        elif len(storm_windows) >= 3 or arp_rate >= storm_pps_threshold * 1.5:
            severity = Severity.HIGH

        affected = []
        for item in conflict_examples[:10]:
            ip = str(item).split("->", 1)[0].strip()
            if ip:
                affected.append(f"{ip}:arp")

        return Anomaly(
            rule_name="ARP风暴/欺骗风险",
            severity=severity,
            description=(
                f"检测到ARP异常行为（突发窗口={len(storm_windows)}，IP-MAC冲突={conflict_count}），"
                "存在广播风暴或ARP欺骗风险"
            ),
            evidence=evidence,
            affected_flows=affected,
            count=max(len(storm_windows), conflict_count, 1),
        )


class ConnectionLeakRule(BaseRule):
    """Long-lived connection leak detection."""

    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        tcp = metrics.get("tcp", {}) or {}
        problem_flows = metrics.get("problem_flows", []) or []
        flow_analysis = (metrics.get("flow_analysis", {}) or {}).get("flows", {}) or {}
        cfg = self.config.get("analysis.thresholds", {}) or {}

        leak_duration_s = float(cfg.get("connection_leak_duration_s", 120.0) or 120.0)
        leak_min_packets = int(cfg.get("connection_leak_min_packets", 30) or 30)

        leak_flows = [
            flow
            for flow in problem_flows
            if any("连接疑似泄漏" in issue for issue in (flow.get("issues", []) or []))
        ]

        if not leak_flows:
            for flow_key, flow in flow_analysis.items():
                if str(flow.get("protocol", "")).upper() != "TCP":
                    continue
                if not bool(flow.get("handshake_complete", False)):
                    continue
                if int(flow.get("fin_count", 0) or 0) > 0 or int(flow.get("rst_count", 0) or 0) > 0:
                    continue
                if float(flow.get("duration_s", 0) or 0) < leak_duration_s:
                    continue
                if int(flow.get("packets", 0) or 0) < leak_min_packets:
                    continue
                leak_flows.append(
                    {
                        "src_ip": "?",
                        "src_port": 0,
                        "dst_ip": "?",
                        "dst_port": 0,
                        "packet_count": int(flow.get("packets", 0) or 0),
                        "issues": ["连接疑似泄漏（flow_analysis回补）"],
                        "duration_s": float(flow.get("duration_s", 0) or 0),
                        "flow_key": flow_key,
                    }
                )

        leak_count_from_tcp = int(tcp.get("connection_leak_flows", 0) or 0)
        if not leak_flows and leak_count_from_tcp <= 0:
            return None

        evidence = [
            f"疑似泄漏连接数: {max(len(leak_flows), leak_count_from_tcp)}",
            f"判定阈值: duration>={leak_duration_s:.0f}s 且 packets>={leak_min_packets} 且无FIN/RST",
        ]
        for flow in leak_flows[:8]:
            src_ip = flow.get("src_ip", "?")
            src_port = flow.get("src_port", 0)
            dst_ip = flow.get("dst_ip", "?")
            dst_port = flow.get("dst_port", 0)
            duration = float(flow.get("duration_s", 0) or 0)
            packets = int(flow.get("packet_count", 0) or 0)
            flow_key = flow.get("flow_key")
            if flow_key:
                evidence.append(f"  - {flow_key} | 持续={duration:.1f}s, 包数={packets}")
            else:
                evidence.append(
                    f"  - {src_ip}:{src_port} -> {dst_ip}:{dst_port} | 持续={duration:.1f}s, 包数={packets}"
                )

        severity = Severity.HIGH if max(len(leak_flows), leak_count_from_tcp) >= 5 else Severity.MEDIUM
        affected = [
            f"{f.get('src_ip', '?')}:{f.get('src_port', 0)}->{f.get('dst_ip', '?')}:{f.get('dst_port', 0)}"
            for f in leak_flows[:20]
        ]
        return Anomaly(
            rule_name="连接泄漏风险",
            severity=severity,
            description="检测到长生命周期且无正常关闭的连接，可能存在连接泄漏或会话回收异常",
            evidence=evidence,
            affected_flows=affected,
            count=max(len(leak_flows), leak_count_from_tcp, 1),
        )


class TrafficBurstRule(BaseRule):
    """Detect abnormal burst in timeline traffic."""

    @staticmethod
    def _percentile(values: List[float], q: float) -> float:
        if not values:
            return 0.0
        if len(values) == 1:
            return values[0]
        data = sorted(values)
        pos = max(0.0, min(1.0, q)) * (len(data) - 1)
        low = int(pos)
        high = min(low + 1, len(data) - 1)
        if low == high:
            return data[low]
        weight = pos - low
        return data[low] * (1.0 - weight) + data[high] * weight

    def check(self, metrics: Dict[str, Any]) -> Optional[Anomaly]:
        timeline = metrics.get("traffic_timeline", {}) or {}
        series = timeline.get("series", []) or []
        if len(series) < 4:
            return None

        cfg = self.config.get("analysis.thresholds", {}) or {}
        burst_ratio = float(cfg.get("traffic_burst_ratio", 2.5) or 2.5)
        min_burst_pps = float(cfg.get("traffic_burst_min_pps", 120.0) or 120.0)
        min_burst_windows = int(cfg.get("traffic_burst_min_windows", 1) or 1)

        pps_values = [float(point.get("packets_per_sec", 0) or 0) for point in series]
        mbps_values = [float(point.get("throughput_mbps", 0) or 0) for point in series]
        if not pps_values:
            return None

        sorted_pps = sorted(pps_values)
        base_count_pps = max(1, int(len(sorted_pps) * 0.8))
        baseline_pps_samples = sorted_pps[:base_count_pps]
        median_pps = statistics.median(pps_values)
        p95_pps = self._percentile(pps_values, 0.95)
        base_median_pps = statistics.median(baseline_pps_samples)
        base_p95_pps = self._percentile(baseline_pps_samples, 0.95)
        baseline_pps = max(base_median_pps, 1.0)
        trigger_pps = max(base_p95_pps * burst_ratio, base_median_pps * burst_ratio, min_burst_pps)

        sorted_mbps = sorted(mbps_values) if mbps_values else []
        base_count_mbps = max(1, int(len(sorted_mbps) * 0.8)) if sorted_mbps else 0
        baseline_mbps_samples = sorted_mbps[:base_count_mbps] if sorted_mbps else []
        median_mbps = statistics.median(mbps_values) if mbps_values else 0.0
        p95_mbps = self._percentile(mbps_values, 0.95) if mbps_values else 0.0
        base_median_mbps = statistics.median(baseline_mbps_samples) if baseline_mbps_samples else median_mbps
        base_p95_mbps = self._percentile(baseline_mbps_samples, 0.95) if baseline_mbps_samples else p95_mbps
        trigger_mbps = max(base_p95_mbps * burst_ratio, base_median_mbps * burst_ratio, 1.0)

        burst_windows = []
        for point in series:
            pps = float(point.get("packets_per_sec", 0) or 0)
            mbps = float(point.get("throughput_mbps", 0) or 0)
            if pps >= trigger_pps or (p95_mbps > 0 and mbps >= trigger_mbps):
                burst_windows.append(point)

        if len(burst_windows) < min_burst_windows:
            return None

        peak_pps = max(float(point.get("packets_per_sec", 0) or 0) for point in burst_windows)
        overshoot = peak_pps / max(baseline_pps, 1e-6)
        severity = Severity.HIGH if overshoot >= 4.0 or len(burst_windows) >= 3 else Severity.MEDIUM

        evidence = [
            f"时间窗数量: {len(series)}, 突发窗数量: {len(burst_windows)}",
            (
                f"基线: median={median_pps:.2f}pps, p95={p95_pps:.2f}pps, "
                f"trimmed_median={base_median_pps:.2f}pps, trigger={trigger_pps:.2f}pps"
            ),
            (
                f"带宽基线: median={median_mbps:.3f}Mbps, p95={p95_mbps:.3f}Mbps, "
                f"trimmed_median={base_median_mbps:.3f}Mbps, trigger={trigger_mbps:.3f}Mbps"
            ),
            f"峰值速率: {peak_pps:.2f}pps, 相对基线倍数: {overshoot:.2f}x",
        ]
        for point in burst_windows[:8]:
            evidence.append(
                "  - 窗口#{idx} t={time:.1f}s: pps={pps:.2f}, mbps={mbps:.3f}, tcp={tcp}, udp={udp}, arp={arp}".format(
                    idx=int(point.get("index", 0) or 0),
                    time=float(point.get("time_s", 0) or 0),
                    pps=float(point.get("packets_per_sec", 0) or 0),
                    mbps=float(point.get("throughput_mbps", 0) or 0),
                    tcp=int(point.get("tcp_packets", 0) or 0),
                    udp=int(point.get("udp_packets", 0) or 0),
                    arp=int(point.get("arp_packets", 0) or 0),
                )
            )

        return Anomaly(
            rule_name="流量突发异常",
            severity=severity,
            description="检测到流量在时间维度出现突发尖峰，可能引发拥塞、丢包或服务抖动",
            evidence=evidence,
            affected_flows=[],
            count=len(burst_windows),
        )


def get_advanced_rules():
    """返回高级智能规则列表。"""
    return [
        ConnectionFailureRule(),
        ConnectionResetRule(),
        NoResponseRule(),
        RetransmissionRule(),
        SlowNetworkRule(),
        ZeroWindowRule(),
        DupAckPacketLossRule(),
        InterceptionRule(),
        FragmentAnomalyRule(),
        PacketLengthAnomalyRule(),
        FastRetransmissionRule(),
        EndpointHotspotRule(),
        AdaptiveQualityRule(),
        CrossLayerCascadeRule(),
        TrafficBurstRule(),
        ARPAnomalyRule(),
        ConnectionLeakRule(),
        DNSLatencyRule(),
        HandshakeLatencyRule(),
        QuickDisconnectRule(),
        HTTPLatencyRule(),
        WindowFullPersistentRule(),
        JitterInstabilityRule(),
        SynRetryPressureRule(),
        PMTUBlackholeRule(),
    ]
