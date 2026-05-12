"""深度根因推断引擎 - 本地分析大脑"""
from typing import List, Dict, Any
from dataclasses import dataclass
from collections import Counter, defaultdict
from diagnosis.engine import Anomaly

# 模式常量
PATTERN_DATA_RETRANS          = 'data_retrans'
PATTERN_SERVER_DOWN           = 'server_down'
PATTERN_SLOW_NETWORK          = 'slow_network'
PATTERN_ZERO_WINDOW           = 'zero_window'
PATTERN_PACKET_LOSS           = 'packet_loss'
PATTERN_INTERCEPTION          = 'interception'
PATTERN_FRAG_ANOMALY          = 'frag_anomaly'
PATTERN_LENGTH_ANOMALY        = 'length_anomaly'
PATTERN_NETWORK_ISSUE         = 'network_issue'
PATTERN_ICMP_ERROR            = 'icmp_error'
PATTERN_UDP_ISSUE             = 'udp_issue'
PATTERN_TLS_HANDSHAKE_FAIL    = 'tls_handshake_fail'
PATTERN_APPLICATION_ERROR     = 'application_error'
PATTERN_FLOOD_ATTACK          = 'flood_attack'
PATTERN_PMTU_BLACKHOLE        = 'pmtu_blackhole'

@dataclass
class DeepRootCause:
    """深度根因分析结果"""
    summary: str
    root_cause: str
    affected_systems: List[str]
    troubleshooting_steps: List[str]
    prevention: List[str]
    risk_level: str
    confidence: float

class DeepInferenceEngine:
    """深度推断引擎 - 本地分析大脑"""

    def analyze(self, anomalies: List[Anomaly], metrics: Dict[str, Any]) -> DeepRootCause:
        """深度分析"""
        problem_flows = metrics.get('problem_flows', [])
        tcp_metrics = metrics.get('tcp', {})
        basic = metrics.get('basic', {})
        # 记录扩展指标供模式识别使用
        self._metrics_net = metrics.get('network', {})
        self._metrics_udp = metrics.get('udp', {})
        self._metrics_app = metrics.get('application', {})

        aggregation = self._aggregate_flows(problem_flows)
        baseline = self._calculate_baseline(metrics)
        time_pattern = self._analyze_time_pattern(problem_flows, basic)
        correlation = self._analyze_correlation(anomalies, problem_flows)
        pattern = self._identify_pattern(problem_flows, tcp_metrics, aggregation, correlation)

        summary = self._generate_summary(pattern, aggregation, tcp_metrics, time_pattern)
        root_cause = self._generate_root_cause(pattern, aggregation, problem_flows, baseline, correlation)
        affected = self._generate_affected_systems(aggregation, baseline)
        steps = self._generate_troubleshooting(pattern, aggregation, correlation)
        prevention = self._generate_prevention(pattern, baseline)
        risk = self._assess_risk(tcp_metrics, len(problem_flows), baseline, time_pattern)

        return DeepRootCause(
            summary=summary,
            root_cause=root_cause,
            affected_systems=affected,
            troubleshooting_steps=steps,
            prevention=prevention,
            risk_level=risk['level'],
            confidence=risk['confidence']
        )

    def _aggregate_flows(self, flows: List[Dict]) -> Dict[str, Any]:
        """聚合流特征"""
        server_ips = Counter()
        client_ips = Counter()
        flow_groups = defaultdict(list)

        for flow in flows:
            src_port = int(flow.get('src_port') or 0)
            dst_port = int(flow.get('dst_port') or 0)
            src_ip = flow.get('src_ip', 'unknown')
            dst_ip = flow.get('dst_ip', 'unknown')

            # Prefer lower service-like port as server endpoint.
            if dst_port and (src_port == 0 or dst_port <= src_port):
                server_key = f"{dst_ip}:{dst_port}"
                server_ips[server_key] += 1
                client_ips[src_ip] += 1
            else:
                server_key = f"{src_ip}:{src_port}"
                server_ips[server_key] += 1
                client_ips[dst_ip] += 1
            flow_groups[server_key].append(flow)

        return {
            'server_ips': server_ips.most_common(5),
            'client_ips': client_ips.most_common(10),
            'total_flows': len(flows),
            'flow_groups': flow_groups,
            'unique_servers': len(server_ips),
            'unique_clients': len(client_ips)
        }

    def _calculate_baseline(self, metrics: Dict[str, Any]) -> Dict[str, Any]:
        """计算流量基线"""
        tcp = metrics.get('tcp', {})
        problem_flows = metrics.get('problem_flows', [])
        total_flows = metrics.get('flow_analysis', {}).get('total_flows', len(problem_flows))
        problem_ratio = len(problem_flows) / max(total_flows, 1)
        retrans_rate = tcp.get('retrans_rate', 0)
        rst_rate = tcp.get('rst_rate', 0)

        return {
            'problem_ratio': problem_ratio,
            'retrans_baseline': 0.01,
            'rst_baseline': 0.005,
            'retrans_deviation': (retrans_rate - 0.01) / 0.01 if retrans_rate > 0.01 else 0,
            'rst_deviation': (rst_rate - 0.005) / 0.005 if rst_rate > 0.005 else 0,
            'severity': 'critical' if problem_ratio > 0.3 else 'high' if problem_ratio > 0.1 else 'medium'
        }

    def _analyze_time_pattern(self, flows: List[Dict], basic: Dict) -> Dict[str, Any]:
        """时间序列分析"""
        if not flows:
            return {'pattern': 'unknown', 'burst': False, 'density': 0}
        duration = basic.get('duration', 1)
        flow_density = len(flows) / max(duration, 1)
        return {
            'pattern': 'burst' if flow_density > 10 else 'continuous' if flow_density > 1 else 'sporadic',
            'burst': flow_density > 10,
            'density': flow_density
        }

    def _analyze_correlation(self, anomalies: List[Anomaly], flows: List[Dict]) -> Dict[str, Any]:
        """关联分析"""
        correlations = []
        has_handshake_fail = any('握手失败' in a.rule_name for a in anomalies)
        has_high_retrans = any('重传' in a.rule_name for a in anomalies)
        has_rst = any('RST' in a.rule_name or 'RST' in a.description for a in anomalies)
        has_interception = any('拦截' in a.rule_name for a in anomalies)
        has_zero_win = any('零窗口' in a.rule_name for a in anomalies)
        has_slow = any('卡慢' in a.rule_name or '延迟' in a.rule_name for a in anomalies)
        has_frag = any('分片' in a.rule_name for a in anomalies)
        has_length = any('长度' in a.rule_name for a in anomalies)
        has_pmtu = any('PMTU' in a.rule_name or '路径MTU' in a.rule_name for a in anomalies)

        if has_interception:
            correlations.append({'type': 'interception', 'confidence': 0.92, 'reason': '检测到拦截特征：握手后立即RST或单向RST，疑似防火墙/安全设备阻断'})
        if has_handshake_fail and has_rst:
            correlations.append({'type': 'server_unreachable', 'confidence': 0.9, 'reason': '握手失败+RST表明服务端拒绝连接或端口未开放'})
        if has_zero_win and has_slow:
            correlations.append({'type': 'receiver_bottleneck', 'confidence': 0.88, 'reason': '零窗口+卡慢同时出现，接收端处理能力严重不足'})
        if has_high_retrans and not has_handshake_fail:
            correlations.append({'type': 'data_layer_issue', 'confidence': 0.85, 'reason': '握手正常但数据传输重传，表明网络层或应用层问题'})
        if has_pmtu:
            correlations.append({
                'type': 'pmtu_blackhole',
                'confidence': 0.90,
                'reason': '出现PMTU黑洞特征：路径MTU反馈异常，握手后数据面反复重传或卡顿'
            })
        if has_frag:
            correlations.append({'type': 'frag_issue', 'confidence': 0.87, 'reason': 'IP分片异常，路径MTU不一致或中间设备不支持分片重组'})
        if has_length:
            correlations.append({
                'type': 'length_tamper',
                'confidence': 0.85,
                'reason': '数据包长度关系异常（已排除常见二层开销与TCP可变头长），疑似中间设备改写或硬件卸载问题'
            })

        syn_zero = [f for f in flows if f.get('syn_count', 0) == 0]
        if len(syn_zero) == len(flows) and len(flows) > 0:
            correlations.append({'type': 'established_connection_issue', 'confidence': 0.88, 'reason': '所有问题流SYN=0，说明连接已建立，问题在数据传输阶段'})

        return {'correlations': correlations, 'primary_cause': correlations[0]['type'] if correlations else 'unknown'}

    def _identify_pattern(self, flows: List[Dict], tcp: Dict, agg: Dict, correlation: Dict) -> str:
        """智能模式识别 - 覆盖所有故障场景"""
        primary = correlation.get('primary_cause', 'unknown')
        metrics_net = getattr(self, '_metrics_net', {})
        metrics_udp = getattr(self, '_metrics_udp', {})
        metrics_app = getattr(self, '_metrics_app', {})
        _ = agg

        flow_count = max(len(flows), 1)
        retrans_rate = float(tcp.get('retrans_rate', 0) or 0)
        rst_rate = float(tcp.get('rst_rate', 0) or 0)
        dup_ack = int(tcp.get('dup_ack', 0) or 0)
        fast_retrans = int(tcp.get('fast_retrans', 0) or 0)
        slow_flows = int(tcp.get('slow_flows', 0) or 0)
        zero_window = int(tcp.get('zero_window', 0) or 0)
        zero_win_flows = int(tcp.get('zero_win_flows', 0) or 0)
        frag_issue_flows = int(tcp.get('frag_issue_flows', 0) or 0)
        length_issue_flows = int(tcp.get('length_issue_flows', 0) or 0)

        broadcast_rate = float(metrics_net.get('broadcast_rate', 0) or 0)
        asymmetry_ratio = float(metrics_net.get('asymmetry_ratio', 1) or 1)
        icmp_unreachable = int(metrics_net.get('icmp_unreachable', 0) or 0)
        icmp_ttl_expired = int(metrics_net.get('icmp_ttl_expired', 0) or 0)
        icmp_frag_needed = int(metrics_net.get('icmp_frag_needed', 0) or 0)
        icmp_port_unreachable = int(metrics_net.get('icmp_port_unreachable', 0) or 0)

        no_response_udp = int(metrics_udp.get('no_response_flows', 0) or 0)
        tls_alerts = int(metrics_app.get('tls_alerts', 0) or 0)
        http_err = int(metrics_app.get('http_error_responses', 0) or 0)
        dns_err = int(metrics_app.get('dns_error_rcode', 0) or 0)

        scores: Dict[str, float] = {
            PATTERN_DATA_RETRANS: 0.0,
            PATTERN_SERVER_DOWN: 0.0,
            PATTERN_SLOW_NETWORK: 0.0,
            PATTERN_ZERO_WINDOW: 0.0,
            PATTERN_PACKET_LOSS: 0.0,
            PATTERN_INTERCEPTION: 0.0,
            PATTERN_FRAG_ANOMALY: 0.0,
            PATTERN_LENGTH_ANOMALY: 0.0,
            PATTERN_ICMP_ERROR: 0.0,
            PATTERN_UDP_ISSUE: 0.0,
            PATTERN_TLS_HANDSHAKE_FAIL: 0.0,
            PATTERN_APPLICATION_ERROR: 0.0,
            PATTERN_FLOOD_ATTACK: 0.0,
            PATTERN_PMTU_BLACKHOLE: 0.0,
            PATTERN_NETWORK_ISSUE: 0.1,
        }

        if primary == 'pmtu_blackhole':
            scores[PATTERN_PMTU_BLACKHOLE] += 4.5
        if primary == 'interception':
            scores[PATTERN_INTERCEPTION] += 4.0
        if primary == 'server_unreachable':
            scores[PATTERN_SERVER_DOWN] += 4.0
        if primary in ['established_connection_issue', 'data_layer_issue']:
            scores[PATTERN_DATA_RETRANS] += 2.4

        if retrans_rate > 0:
            scores[PATTERN_DATA_RETRANS] += min(retrans_rate / 0.05, 5.0)
        if dup_ack >= 3 or fast_retrans > 0:
            scores[PATTERN_PACKET_LOSS] += 1.6 + min(dup_ack / 10.0, 2.2) + min(fast_retrans / 4.0, 1.6)
        if rst_rate > 0.02:
            scores[PATTERN_INTERCEPTION] += min(rst_rate / 0.02, 2.6)
            scores[PATTERN_SERVER_DOWN] += min(rst_rate / 0.02, 1.8)
        if slow_flows > 0:
            scores[PATTERN_SLOW_NETWORK] += 1.4 + min(slow_flows / max(flow_count, 1) * 4.0, 2.2)
        if zero_window > 0 and zero_win_flows > 0:
            scores[PATTERN_ZERO_WINDOW] += 1.8 + min(zero_win_flows / max(flow_count, 1) * 3.0, 2.0)

        if frag_issue_flows > 0:
            scores[PATTERN_FRAG_ANOMALY] += 1.6 + min(frag_issue_flows / max(flow_count, 1) * 3.6, 2.6)
        if length_issue_flows > 0:
            scores[PATTERN_LENGTH_ANOMALY] += 1.2 + min(length_issue_flows / max(flow_count, 1) * 2.8, 2.2)
        if icmp_frag_needed > 0 and (retrans_rate > 0.03 or frag_issue_flows > 0 or length_issue_flows > 0):
            scores[PATTERN_PMTU_BLACKHOLE] += 2.8 + min(icmp_frag_needed / 4.0, 2.6)

        # 当重传明显主导时，分片/长度异常作为次级线索，不抢占主结论。
        if retrans_rate >= 0.08:
            scores[PATTERN_LENGTH_ANOMALY] *= 0.72
            scores[PATTERN_FRAG_ANOMALY] *= 0.78

        if broadcast_rate > 1000:
            scores[PATTERN_FLOOD_ATTACK] += min(broadcast_rate / 1000.0, 3.0)
        if asymmetry_ratio > 15:
            scores[PATTERN_FLOOD_ATTACK] += min(asymmetry_ratio / 15.0, 2.6)
        if icmp_unreachable > 0 or icmp_ttl_expired > 0:
            scores[PATTERN_ICMP_ERROR] += 1.6 + min((icmp_unreachable + icmp_ttl_expired) / 4.0, 2.0)

        if no_response_udp > 0 or icmp_port_unreachable > 0:
            scores[PATTERN_UDP_ISSUE] += 1.6 + min((no_response_udp + icmp_port_unreachable) / 6.0, 2.0)
        if tls_alerts > 0:
            scores[PATTERN_TLS_HANDSHAKE_FAIL] += 1.8 + min(tls_alerts / 4.0, 2.0)
        if http_err > 0 or dns_err > 0:
            scores[PATTERN_APPLICATION_ERROR] += 1.4 + min((http_err + dns_err) / 10.0, 2.2)

        best_pattern, best_score = max(scores.items(), key=lambda x: x[1])
        if best_score <= 0.15:
            return PATTERN_NETWORK_ISSUE
        return best_pattern

    def _generate_summary(self, pattern: str, agg: Dict, tcp: Dict, time_pattern: Dict) -> str:
        """生成智能摘要"""
        top_server = agg['server_ips'][0] if agg['server_ips'] else ('未知', 0)
        retrans_rate = tcp.get('retrans_rate', 0) * 100
        time_desc = "，呈现突发性故障" if time_pattern['burst'] else ""
        secondary_clues = []
        if int(tcp.get('length_issue_flows', 0) or 0) > 0:
            secondary_clues.append(f"长度异常流 {int(tcp.get('length_issue_flows', 0) or 0)} 条")
        if int(tcp.get('frag_issue_flows', 0) or 0) > 0:
            secondary_clues.append(f"分片异常流 {int(tcp.get('frag_issue_flows', 0) or 0)} 条")
        secondary_desc = f"，次级线索：{'；'.join(secondary_clues)}" if secondary_clues else ""
        if pattern == PATTERN_DATA_RETRANS:
            return (
                f"{top_server[0]}服务端与{agg['unique_clients']}个客户端之间存在严重的TCP重传问题，"
                f"重传率{retrans_rate:.2f}%（正常<5%）{time_desc}{secondary_desc}"
            )
        elif pattern == PATTERN_SERVER_DOWN:
            return f"{top_server[0]}服务端无响应，{agg['unique_clients']}个客户端连接失败{time_desc}"
        elif pattern == PATTERN_SLOW_NETWORK:
            return f"检测到{tcp.get('slow_flows',0)}个流存在严重卡顿，网络或服务端响应延迟过高{time_desc}"
        elif pattern == PATTERN_ZERO_WINDOW:
            return f"检测到零窗口事件{tcp.get('zero_window',0)}次，接收端缓冲区持续满载，数据传输被阻塞{time_desc}"
        elif pattern == PATTERN_PACKET_LOSS:
            return (
                f"检测到重复ACK {tcp.get('dup_ack',0)}次、快速重传{tcp.get('fast_retrans',0)}次，"
                f"链路存在丢包{time_desc}{secondary_desc}"
            )
        elif pattern == PATTERN_INTERCEPTION:
            return f"检测到流量拦截特征，{agg['unique_clients']}个客户端连接被中间设备强制重置{time_desc}"
        elif pattern == PATTERN_PMTU_BLACKHOLE:
            return (
                f"检测到路径MTU黑洞风险，连接建立后数据面出现重传/停顿，"
                f"疑似中间路径MTU与ICMP反馈链路异常{time_desc}"
            )
        elif pattern == PATTERN_FRAG_ANOMALY:
            return f"检测到{tcp.get('frag_issue_flows',0)}个流存在IP分片异常（分片缺失/重组失败/长度错误），数据包无法正确重组{time_desc}"
        elif pattern == PATTERN_LENGTH_ANOMALY:
            return (
                f"检测到{tcp.get('length_issue_flows',0)}个流存在长度关系异常，"
                f"已排除常见二层开销与TCP可变头长影响，疑似中间设备篡改或硬件故障{time_desc}"
            )
        elif pattern == PATTERN_ICMP_ERROR:
            return f"检测到ICMP错误报文（不可达/TTL超时），可能存在路由/防火墙问题{time_desc}"
        elif pattern == PATTERN_UDP_ISSUE:
            return f"检测到UDP无响应或端口不可达，UDP应用（DNS/游戏等）疑似异常{time_desc}"
        elif pattern == PATTERN_TLS_HANDSHAKE_FAIL:
            return f"检测到TLS握手失败/Alert，疑似证书/协议不兼容或加密配置问题{time_desc}"
        elif pattern == PATTERN_APPLICATION_ERROR:
            return f"检测到应用层错误（HTTP 4xx/5xx 或 DNS 错误），业务侧返回异常{time_desc}"
        elif pattern == PATTERN_FLOOD_ATTACK:
            return f"检测到广播/组播风暴或流量不对称，疑似风暴/攻击导致网络拥塞{time_desc}"
        return f"检测到{agg['total_flows']}个问题流，涉及{agg['unique_clients']}个客户端{time_desc}"

    def _generate_root_cause(self, pattern: str, agg: Dict, flows: List[Dict], baseline: Dict, correlation: Dict) -> str:
        """生成根本原因分析"""
        top_server = agg['server_ips'][0] if agg['server_ips'] else ('未知', 0)
        analysis = f"从数据特征判断，问题集中在服务端{top_server[0]}：\n"
        if correlation['correlations']:
            analysis += "**关联分析：**\n"
            for corr in correlation['correlations'][:2]:
                analysis += f"  - {corr['reason']}（置信度{corr['confidence']*100:.0f}%）\n"
        analysis += f"\n**流量特征：**\n  - 问题流占比：{baseline['problem_ratio']*100:.1f}%（{baseline['severity']}）\n"
        analysis += f"  - 涉及{agg['unique_servers']}个服务端口，{agg['unique_clients']}个客户端\n"
        if baseline['retrans_deviation'] > 5:
            analysis += f"  - 重传率超基线{baseline['retrans_deviation']:.1f}倍\n"
        analysis += "\n**可能原因：**\n"
        if pattern == PATTERN_DATA_RETRANS:
            analysis += "  1. 服务端应用处理能力不足\n  2. 服务端网卡丢包\n  3. 中间网络设备拥塞"
        elif pattern == PATTERN_SERVER_DOWN:
            analysis += "  1. 服务未启动\n  2. 端口未监听\n  3. 防火墙阻断"
        elif pattern == PATTERN_SLOW_NETWORK:
            analysis += "  1. 服务端CPU/内存/IO资源瓶颈\n  2. 应用层阻塞（慢查询、GC、锁等待）\n  3. 网络链路拥塞队列积压\n  4. 中间件（代理/LB）处理延迟"
        elif pattern == PATTERN_ZERO_WINDOW:
            analysis += "  1. 接收端应用消费速度远低于发送速度\n  2. 接收端内存不足，TCP缓冲区被压缩\n  3. 接收端CPU过高无法及时处理数据"
        elif pattern == PATTERN_PACKET_LOSS:
            analysis += "  1. 物理链路质量差（光衰、接触不良、无线干扰）\n  2. 中间设备（交换机/路由器）队列溢出\n  3. 链路带宽不足导致拥塞丢包\n  4. 网卡驱动或硬件故障"
        elif pattern == PATTERN_INTERCEPTION:
            analysis += "  1. 防火墙ACL规则拦截特定流量\n  2. 安全设备（IPS/WAF）主动阻断\n  3. 运营商/网络设备对特定端口/协议封锁\n  4. 中间人设备强制重置连接"
        elif pattern == PATTERN_PMTU_BLACKHOLE:
            analysis += "  1. 中间设备丢弃ICMP Fragmentation Needed，PMTUD失效\n  2. 路径MTU小于端点MSS，导致大包在数据面黑洞\n  3. 隧道/VPN封装后有效MTU下降但未同步MSS\n  4. 安全策略对ICMP PTB回包过滤过严"
        elif pattern == PATTERN_FRAG_ANOMALY:
            analysis += "  1. 路径MTU不一致，分片在中间节点被丢弃\n  2. 防火墙/NAT设备不支持IP分片重组\n  3. 网络设备Bug导致分片处理错误\n  4. 发送端MSS协商异常，产生过大数据包"
        elif pattern == PATTERN_LENGTH_ANOMALY:
            analysis += "  1. 中间设备（NAT/代理）修改了数据包但未更新长度字段\n  2. 网卡TSO/GRO/GSO硬件卸载导致长度计算异常\n  3. 网络设备固件Bug\n  4. 链路层帧损坏"
        elif pattern == PATTERN_ICMP_ERROR:
            analysis += "  1. 路由不可达或防火墙丢弃\n  2. TTL 配置过小或路由环路\n  3. 中间设备策略阻断 ICMP"
        elif pattern == PATTERN_UDP_ISSUE:
            analysis += "  1. 目标端口未监听或服务不可达\n  2. 防火墙/ACL 丢弃 UDP 回包\n  3. 回程路径不通或非对称路由"
        elif pattern == PATTERN_TLS_HANDSHAKE_FAIL:
            analysis += "  1. 证书链/信任问题（Unknown CA/过期）\n  2. 协议/套件不兼容（版本或加密套件不匹配）\n  3. SNI/ALPN 错误导致握手中断"
        elif pattern == PATTERN_APPLICATION_ERROR:
            analysis += "  1. 上游服务故障（HTTP 5xx）\n  2. 客户端请求异常（HTTP 4xx）\n  3. DNS 解析失败或上游 DNS 不可用"
        elif pattern == PATTERN_FLOOD_ATTACK:
            analysis += "  1. 广播/组播环路或风暴\n  2. 疑似 DDoS/泛洪导致链路拥塞\n  3. 非对称路由或单向抓包导致流量比例异常"
        else:
            analysis += "  1. 网络链路质量问题\n  2. 中间设备配置异常\n  3. 服务端资源不足"
        return analysis

    def _generate_affected_systems(self, agg: Dict, baseline: Dict) -> List[str]:
        """生成受影响系统"""
        affected = []
        for ip, count in agg['client_ips'][:8]:
            impact = "严重" if count > 50 else "中等" if count > 10 else "轻微"
            affected.append(f"{ip}（{count}个连接，{impact}）")
        if len(agg['client_ips']) > 8:
            affected.append(f"...及其他{len(agg['client_ips'])-8}个客户端")
        return affected

    def _generate_troubleshooting(self, pattern: str, agg: Dict, correlation: Dict) -> List[str]:
        """生成排查步骤"""
        top_server = agg['server_ips'][0][0] if agg['server_ips'] else '未知'
        server_ip = top_server.split(':')[0]
        server_port = top_server.split(':')[-1]
        if pattern == PATTERN_DATA_RETRANS:
            return [
                f"【第一步】检查服务进程：netstat -antp | grep {server_port}",
                "【第二步】检查系统资源：top -bn1 | head -20",
                "【第三步】检查网卡丢包：ethtool -S eth0 | grep drop",
                "【第四步】检查TCP参数：sysctl net.ipv4.tcp_rmem",
                "【第五步】查看应用日志",
                f"【第六步】网络路径测试：mtr -r {server_ip}",
            ]
        elif pattern == PATTERN_SERVER_DOWN:
            return [
                f"【第一步】端口测试：telnet {server_ip} {server_port}",
                "【第二步】检查服务：systemctl status <service>",
                f"【第三步】检查防火墙：iptables -L | grep {server_port}",
                f"【第四步】检查监听：netstat -tlnp | grep {server_port}",
            ]
        elif pattern == PATTERN_SLOW_NETWORK:
            return [
                "【第一步】检查服务端CPU/内存：top -bn1 && free -h",
                "【第二步】检查磁盘IO：iostat -x 1 5",
                "【第三步】检查数据库慢查询日志",
                "【第四步】检查应用线程池/队列积压状态",
                f"【第五步】持续测试路径延迟：mtr --report-cycles 20 {server_ip}",
                "【第六步】对比正常时段抓包，定位延迟发生的具体环节",
            ]
        elif pattern == PATTERN_ZERO_WINDOW:
            return [
                "【第一步】检查接收端内存：free -h && vmstat 1 5",
                "【第二步】检查接收端CPU：top -bn1",
                "【第三步】调大TCP接收缓冲区：sysctl -w net.ipv4.tcp_rmem='4096 87380 16777216'",
                "【第四步】检查应用消费速度，确认是否有处理积压",
                "【第五步】抓包确认零窗口探测(ZWP)后是否有窗口更新",
                "【第六步】检查应用是否存在锁等待或慢处理逻辑",
            ]
        elif pattern == PATTERN_PACKET_LOSS:
            return [
                f"【第一步】ping丢包测试：ping -c 200 -i 0.2 {server_ip}",
                "【第二步】检查网卡错误：ethtool -S eth0 | grep -i 'error\\|drop\\|miss'",
                "【第三步】检查交换机端口错误统计：show interface counters errors",
                f"【第四步】mtr定位丢包节点：mtr --report {server_ip}",
                "【第五步】检查链路利用率是否超过80%",
                "【第六步】检查无线信号强度（如为无线网络）",
            ]
        elif pattern == PATTERN_INTERCEPTION:
            return [
                f"【第一步】确认防火墙规则：iptables -L -n | grep {server_port}",
                "【第二步】检查安全组/ACL配置（云环境）",
                f"【第三步】从不同网络位置测试连通性：telnet {server_ip} {server_port}",
                "【第四步】检查IPS/WAF日志，确认是否有拦截记录",
                "【第五步】抓包对比RST来源（客户端/服务端/中间设备）",
                "【第六步】检查运营商是否对该端口/协议有限制",
            ]
        elif pattern == PATTERN_PMTU_BLACKHOLE:
            return [
                "【第一步】路径MTU探测：ping -M do -s 1472 <目标IP>（逐步减小）",
                "【第二步】检查中间设备是否放行ICMP Type3 Code4（Fragmentation Needed）",
                "【第三步】临时启用MSS钳制验证：--clamp-mss-to-pmtu",
                "【第四步】核查VPN/隧道封装后的实际MTU与接口MTU配置",
                "【第五步】抓包对比大包在客户端/服务端/中间节点的丢失位置",
            ]
        elif pattern == PATTERN_FRAG_ANOMALY:
            return [
                "【第一步】检测路径MTU：ping -M do -s 1472 <目标IP>（逐步减小直到不分片）",
                "【第二步】启用路径MTU发现：sysctl -w net.ipv4.ip_no_pmtu_disc=0",
                "【第三步】检查中间防火墙是否阻断ICMP Type3 Code4（需要分片但DF置位）",
                "【第四步】调整MSS：iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu",
                "【第五步】检查VPN/隧道设备的MTU配置",
                "【第六步】抓包确认分片包的IP_ID和偏移量是否连续",
            ]
        elif pattern == PATTERN_LENGTH_ANOMALY:
            return [
                "【第一步】检查网卡TSO/GSO/GRO是否开启：ethtool -k eth0 | grep offload",
                "【第二步】尝试关闭硬件卸载：ethtool -K eth0 tso off gso off gro off",
                "【第三步】检查中间NAT/代理设备版本和已知Bug",
                "【第四步】在不同网络路径上抓包，对比长度是否一致",
                "【第五步】检查网卡驱动版本，尝试升级驱动",
                "【第六步】检查是否有流量整形/QoS设备修改了数据包",
            ]
        elif pattern == PATTERN_ICMP_ERROR:
            return [
                "【第一步】traceroute <目标IP>，定位不可达/TTL过期节点",
                "【第二步】检查防火墙/ACL是否丢弃ICMP Type3/11",
                "【第三步】确认路由表与下一跳可达性",
                "【第四步】检查TTL/DF设置及隧道叠加情况",
            ]
        elif pattern == PATTERN_UDP_ISSUE:
            return [
                f"【第一步】确认目标服务/端口：nc -u -vz {server_ip} {server_port}",
                "【第二步】在服务端抓包确认是否收到请求",
                "【第三步】检查防火墙/ACL是否允许UDP回包",
                "【第四步】观察是否有ICMP Port Unreachable 回包被丢弃",
            ]
        elif pattern == PATTERN_TLS_HANDSHAKE_FAIL:
            return [
                "【第一步】检查证书链与过期时间：openssl s_client -connect <host:port>",
                "【第二步】核对SNI/ALPN与服务端配置匹配",
                "【第三步】确认协议/套件版本兼容（如 TLS1.2/1.3）",
                "【第四步】查看服务端/反向代理 TLS 日志，排查 Alert 原因",
            ]
        elif pattern == PATTERN_APPLICATION_ERROR:
            return [
                "【第一步】查看HTTP 4xx/5xx日志，定位接口或上游错误",
                "【第二步】检查DNS解析是否稳定，必要时更换上游DNS",
                "【第三步】检查应用依赖（DB/缓存/下游接口）健康",
                "【第四步】对比正常时段请求与响应差异",
            ]
        elif pattern == PATTERN_FLOOD_ATTACK:
            return [
                "【第一步】在交换机/路由器查看接口广播/组播计数与丢弃",
                "【第二步】检查生成树/IGMP Snooping 状态，排查环路",
                "【第三步】限制风暴控制/启用广播抑制",
                "【第四步】若疑似DDoS，启用ACL/限速或接入清洗"
            ]
        return [
            "【第一步】检查网络连通性：ping <目标IP>",
            f"【第二步】检查服务状态：telnet {server_ip} {server_port}",
            "【第三步】检查系统资源：top / free / df",
            "【第四步】查看系统日志：journalctl -xe",
        ]

    def _generate_prevention(self, pattern: str, baseline: Dict) -> List[str]:
        """生成预防措施"""
        if pattern == PATTERN_DATA_RETRANS:
            return [
                "【应用层】优化代码，增加线程数，避免处理阻塞",
                "【系统层】增加TCP缓冲区，启用SACK：sysctl -w net.ipv4.tcp_sack=1",
                "【监控】监控重传率、CPU/内存、网卡丢包",
                "【容量】评估负载，考虑水平扩展",
            ]
        elif pattern == PATTERN_SERVER_DOWN:
            return [
                "【高可用】配置服务自动重启：systemd Restart=always",
                "【负载均衡】部署多实例，避免单点故障",
                "【监控】配置端口存活监控，故障秒级告警",
            ]
        elif pattern == PATTERN_SLOW_NETWORK:
            return [
                "【应用层】优化慢查询，增加缓存，减少阻塞操作",
                "【系统层】调优JVM GC参数，减少STW停顿",
                "【网络层】升级链路带宽，优化QoS策略",
                "【监控】配置P99延迟告警，提前发现性能劣化",
            ]
        elif pattern == PATTERN_ZERO_WINDOW:
            return [
                "【系统层】调大TCP缓冲区：net.ipv4.tcp_rmem / tcp_wmem",
                "【应用层】优化消费速度，增加消费线程",
                "【监控】监控TCP零窗口事件频率",
                "【容量】评估接收端处理能力，考虑扩容",
            ]
        elif pattern == PATTERN_PACKET_LOSS:
            return [
                "【链路层】检查并更换故障光模块/网线",
                "【设备层】升级交换机/路由器固件，扩容链路带宽",
                "【系统层】启用TCP SACK和快速重传优化",
                "【监控】部署链路质量监控（丢包率、误码率）",
            ]
        elif pattern == PATTERN_INTERCEPTION:
            return [
                "【策略层】梳理防火墙/ACL规则，删除过期拦截策略",
                "【变更管理】网络变更前进行连通性测试",
                "【文档】维护网络访问矩阵，明确允许/拒绝策略",
                "【监控】配置连接成功率监控，拦截事件告警",
            ]
        elif pattern == PATTERN_PMTU_BLACKHOLE:
            return [
                "【网络层】统一链路MTU并校验隧道开销，避免超路径MTU大包",
                "【策略层】明确放行ICMP Fragmentation Needed，保证PMTUD有效",
                "【传输层】在边界设备启用MSS钳制作为兜底",
                "【监控】监控ICMP Type3 Code4与大包重传指标，提前预警"
            ]
        elif pattern == PATTERN_FRAG_ANOMALY:
            return [
                "【网络层】统一路径MTU，避免IP分片（推荐MTU 1500或启用PMTUD）",
                "【设备层】确保防火墙允许ICMP Type3 Code4通过",
                "【应用层】调整应用发送缓冲区大小，避免超大包",
                "【监控】监控IP分片计数器，异常时告警",
            ]
        elif pattern == PATTERN_LENGTH_ANOMALY:
            return [
                "【系统层】统一网卡offload配置，避免TSO/GSO引起长度异常",
                "【设备层】升级中间设备固件，修复长度处理Bug",
                "【监控】部署数据包完整性校验监控",
                "【变更】中间设备升级前充分测试数据包转发正确性",
            ]
        elif pattern == PATTERN_ICMP_ERROR:
            return [
                "【网络层】确保ICMP Type3/11不过滤，便于故障反馈",
                "【路由】定期巡检路由表与TTL设置，避免环路",
                "【变更】路径/防火墙变更前做连通性验证"
            ]
        elif pattern == PATTERN_UDP_ISSUE:
            return [
                "【服务】UDP服务上线前做端口连通与ICMP回包校验",
                "【网络】放行必要的ICMP不可达回包以便快速失败",
                "【监控】监控UDP超时/无响应率"
            ]
        elif pattern == PATTERN_TLS_HANDSHAKE_FAIL:
            return [
                "【证书】统一CA与证书续期流程，配置OCSP/CRL",
                "【协议】收敛TLS版本与加密套件，灰度验证",
                "【配置】核对SNI/ALPN，避免多租户混配错误"
            ]
        elif pattern == PATTERN_APPLICATION_ERROR:
            return [
                "【应用】建立4xx/5xx速率告警，快速发现接口异常",
                "【DNS】部署备用DNS与健康检查，降低解析故障影响",
                "【治理】接口契约/依赖健康检查与熔断降级"
            ]
        elif pattern == PATTERN_FLOOD_ATTACK:
            return [
                "【网络】配置广播/组播风暴抑制，优化生成树",
                "【安全】部署DDoS防护或清洗，关键端口限速",
                "【监控】监控上下行流量比例与广播速率，异常告警"
            ]
        return [
            "【监控】部署全面的网络监控体系",
            "【变更管理】网络变更前进行充分测试",
            "【文档】维护网络拓扑和配置文档",
        ]

    def _assess_risk(self, tcp: Dict, flow_count: int, baseline: Dict, time_pattern: Dict) -> Dict[str, Any]:
        """风险评估"""
        score = 0
        retrans_rate = tcp.get('retrans_rate', 0)
        if retrans_rate > 0.3:
            score += 40
        elif retrans_rate > 0.1:
            score += 25
        elif retrans_rate > 0.05:
            score += 15
        if baseline['problem_ratio'] > 0.3:
            score += 30
        elif baseline['problem_ratio'] > 0.1:
            score += 20
        if flow_count > 1000:
            score += 20
        elif flow_count > 500:
            score += 15
        if time_pattern['burst']:
            score += 10
        # 新场景风险加分
        if tcp.get('zero_window', 0) > 0:
            score += 15
        if tcp.get('frag_issue_flows', 0) > 0:
            score += 20
        if tcp.get('length_issue_flows', 0) > 0:
            score += 20
        if tcp.get('slow_flows', 0) > 3:
            score += 15
        if tcp.get('dup_ack', 0) >= 10:
            score += 15
        # 新场景加分
        net = getattr(self, '_metrics_net', {})
        udp = getattr(self, '_metrics_udp', {})
        app = getattr(self, '_metrics_app', {})
        if net.get('icmp_unreachable', 0) > 0 or net.get('icmp_ttl_expired', 0) > 0:
            score += 10
        if net.get('broadcast_rate', 0) > 1000:
            score += 25
        if net.get('asymmetry_ratio', 1) > 15:
            score += 20
        if udp.get('no_response_flows', 0) > 0:
            score += 10
        if app.get('tls_alerts', 0) > 0:
            score += 15
        if app.get('http_error_responses', 0) > 0 or app.get('dns_error_rcode', 0) > 0:
            score += 10
        if score >= 70:
            return {'level': '高', 'confidence': 0.90}
        elif score >= 40:
            return {'level': '中', 'confidence': 0.80}
        return {'level': '低', 'confidence': 0.70}
