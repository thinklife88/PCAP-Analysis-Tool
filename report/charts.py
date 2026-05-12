"""Chart generation helpers for report output."""

import math
import os
import uuid
import zlib
from typing import Any, Dict, List, Optional

import plotly.graph_objects as go
from utils.config import get_config


class ChartGenerator:
    @staticmethod
    def _plotlyjs_mode():
        """
        Plotly JS loading mode.
        - inline/true/1: embed JS for offline viewing
        - cdn: load JS from CDN
        - none/false/0: do not include JS
        """
        offline_env = str(os.getenv("PLOTLY_OFFLINE", "") or "").strip().lower()
        if offline_env in {"1", "true", "yes", "on"}:
            return True
        try:
            mode = str(get_config().get("report.plotly_js_mode", "inline") or "inline").strip().lower()
        except Exception:
            mode = "inline"

        if mode in {"inline", "embed", "true", "1"}:
            return True
        if mode == "cdn":
            return "cdn"
        if mode == "auto":
            return True
        if mode in {"none", "false", "0"}:
            return False
        return True

    @staticmethod
    def generate_plotly_loader(metrics: Dict[str, Any]) -> str:
        """
        Render a tiny hidden figure to guarantee Plotly runtime loading.
        This avoids blank placeholders when the first visible chart is empty.
        Also injects global Plotly config to enable download buttons on all charts.
        """
        _ = metrics
        mode = ChartGenerator._plotlyjs_mode()
        if mode is False:
            return ""
        fig = go.Figure()
        html = fig.to_html(full_html=False, include_plotlyjs=mode)
        return (
            f'<div style="display:none" aria-hidden="true">{html}</div>'
            '<script>'
            'if(typeof Plotly!=="undefined"){'
            'Plotly.setPlotConfig({'
            'modeBarButtonsToAdd:[{'
            'name:"downloadSVG",'
            'title:"Download SVG",'
            'icon:Plotly.Icons.camera,'
            'click:function(el){Plotly.downloadImage(el,{format:"svg",width:1200,height:600,filename:"chart"})}'
            '}],'
            'toImageButtonOptions:{format:"png",width:1200,height:600,filename:"pcap_chart"}'
            '});}'
            '</script>'
        )

    @staticmethod
    def generate_protocol_pie(metrics: Dict[str, Any]) -> str:
        """Transport protocol distribution pie chart."""
        protocol = metrics.get("protocol", {})
        if not protocol:
            return ""

        fig = go.Figure(
            data=[
                go.Pie(
                    labels=list(protocol.keys()),
                    values=list(protocol.values()),
                    hole=0.35,
                )
            ]
        )
        fig.update_layout(title="传输层协议分布", height=420)
        # R-10: 第一个图表负责加载 Plotly JS（cdn → 离线或可按需切换）
        # 使用 "require" 依赖 CDN，但优先 inline 确保离线可用；
        # 若需强制离线，将环境变量 PLOTLY_OFFLINE=1 或改为 include_plotlyjs=True
        return fig.to_html(full_html=False, include_plotlyjs=ChartGenerator._plotlyjs_mode())

    @staticmethod
    def generate_application_protocol_pie(metrics: Dict[str, Any]) -> str:
        """Application protocol distribution pie chart."""
        app_protocol = metrics.get("application_protocol", {})
        if not app_protocol:
            return ""

        fig = go.Figure(
            data=[
                go.Pie(
                    labels=list(app_protocol.keys()),
                    values=list(app_protocol.values()),
                    hole=0.35,
                )
            ]
        )
        fig.update_layout(title="应用层协议分布", height=420)
        return fig.to_html(full_html=False, include_plotlyjs=False)

    @staticmethod
    def generate_top_ips_bar(metrics: Dict[str, Any]) -> str:
        """Top source IP bar chart."""
        top_talkers = metrics.get("top_talkers", {})
        top_src = top_talkers.get("top_src_ips", {})
        if not top_src:
            return ""

        ips = list(top_src.keys())[:10]
        counts = list(top_src.values())[:10]

        fig = go.Figure(data=[go.Bar(x=ips, y=counts)])
        fig.update_layout(
            title="Top 10 源 IP",
            xaxis_title="IP 地址",
            yaxis_title="报文数",
            height=420,
        )
        return fig.to_html(full_html=False, include_plotlyjs=False)

    @staticmethod
    def generate_tcp_metrics_bar(metrics: Dict[str, Any]) -> str:
        """TCP metrics bar chart."""
        tcp = metrics.get("tcp", {})
        if not tcp:
            return ""

        categories = ["SYN", "SYN-ACK", "RST", "FIN", "重传"]
        values = [
            tcp.get("syn", 0),
            tcp.get("syn_ack", 0),
            tcp.get("rst", 0),
            tcp.get("fin", 0),
            tcp.get("retransmissions", 0),
        ]

        fig = go.Figure(data=[go.Bar(x=categories, y=values)])
        fig.update_layout(title="TCP 关键指标", height=420)
        return fig.to_html(full_html=False, include_plotlyjs=False)

    @staticmethod
    def generate_traffic_timeline(metrics: Dict[str, Any]) -> str:
        """Global traffic timeline with throughput, packet rate and TCP quality trends."""
        timeline = metrics.get("traffic_timeline", {}) or {}
        series = timeline.get("series", []) or []
        if not series:
            return ""

        x_axis = [float(point.get("time_s", 0.0) or 0.0) for point in series]
        throughput = [float(point.get("throughput_mbps", 0.0) or 0.0) for point in series]
        pps = [float(point.get("packets_per_sec", 0.0) or 0.0) for point in series]
        retrans_pct = [float(point.get("retrans_rate", 0.0) or 0.0) * 100.0 for point in series]
        rst_pct = [float(point.get("rst_rate", 0.0) or 0.0) * 100.0 for point in series]
        tcp_packets = [int(point.get("tcp_packets", 0) or 0) for point in series]
        udp_packets = [int(point.get("udp_packets", 0) or 0) for point in series]

        fig = go.Figure()
        fig.add_trace(
            go.Scatter(
                x=x_axis,
                y=throughput,
                mode="lines",
                name="吞吐(Mbps)",
                line=dict(color="#2563eb", width=2),
                hovertemplate="时间=%{x:.2f}s<br>吞吐=%{y:.3f} Mbps<extra></extra>",
            )
        )
        fig.add_trace(
            go.Scatter(
                x=x_axis,
                y=pps,
                mode="lines",
                name="包速(pkt/s)",
                line=dict(color="#0f766e", width=2, dash="dot"),
                hovertemplate="时间=%{x:.2f}s<br>包速=%{y:.2f} pkt/s<extra></extra>",
            )
        )
        fig.add_trace(
            go.Scatter(
                x=x_axis,
                y=retrans_pct,
                mode="lines",
                name="重传率(%)",
                yaxis="y2",
                line=dict(color="#ea580c", width=2),
                hovertemplate="时间=%{x:.2f}s<br>重传率=%{y:.2f}%<extra></extra>",
            )
        )
        fig.add_trace(
            go.Scatter(
                x=x_axis,
                y=rst_pct,
                mode="lines",
                name="RST率(%)",
                yaxis="y2",
                line=dict(color="#dc2626", width=2, dash="dash"),
                hovertemplate="时间=%{x:.2f}s<br>RST率=%{y:.2f}%<extra></extra>",
            )
        )
        fig.add_trace(
            go.Bar(
                x=x_axis,
                y=tcp_packets,
                name="TCP包数",
                marker_color="rgba(59,130,246,0.20)",
                hovertemplate="时间=%{x:.2f}s<br>TCP包=%{y}<extra></extra>",
            )
        )
        fig.add_trace(
            go.Bar(
                x=x_axis,
                y=udp_packets,
                name="UDP包数",
                marker_color="rgba(16,185,129,0.20)",
                hovertemplate="时间=%{x:.2f}s<br>UDP包=%{y}<extra></extra>",
            )
        )

        fig.update_layout(
            title="全局流量时间线（吞吐/包速/重传/RST）",
            height=460,
            barmode="overlay",
            xaxis=dict(title="相对时间(s)"),
            yaxis=dict(title="吞吐 & 包速"),
            yaxis2=dict(title="TCP质量(%)", overlaying="y", side="right", rangemode="tozero"),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, x=0),
            margin=dict(l=55, r=55, t=80, b=45),
        )
        return fig.to_html(full_html=False, include_plotlyjs=False)

    @staticmethod
    def generate_rtt_timeline(metrics: Dict[str, Any]) -> str:
        """RTT timeline chart for latency/jitter visibility."""
        timeline = metrics.get("traffic_timeline", {}) or {}
        series = timeline.get("series", []) or []
        if not series:
            return ""

        x_axis = [float(point.get("time_s", 0.0) or 0.0) for point in series]
        avg_rtt_ms = [float(point.get("avg_rtt_ms", 0.0) or 0.0) for point in series]
        if not any(v > 0 for v in avg_rtt_ms):
            return ""

        cfg = metrics.get("config_thresholds", {}) or {}
        rtt_th = float(cfg.get("rtt_high_ms", cfg.get("rtt_threshold_ms", 500)))

        fig = go.Figure()
        fig.add_trace(
            go.Scatter(
                x=x_axis,
                y=avg_rtt_ms,
                mode="lines+markers",
                name="平均RTT(ms)",
                line=dict(color="#f97316", width=2),
                marker=dict(size=5),
                hovertemplate="时间=%{x:.2f}s<br>平均RTT=%{y:.0f}ms<extra></extra>",
            )
        )
        fig.add_hline(
            y=rtt_th,
            line=dict(color="#dc2626", width=1, dash="dash"),
            annotation_text=f"阈值 {rtt_th:.0f}ms",
            annotation_position="top left",
        )
        fig.update_layout(
            title="RTT波动趋势（往返时延）",
            height=420,
            xaxis=dict(title="相对时间(s)"),
            yaxis=dict(title="RTT(ms)", rangemode="tozero"),
            margin=dict(l=55, r=30, t=70, b=45),
        )
        return fig.to_html(full_html=False, include_plotlyjs=False)

    @staticmethod
    def generate_asymmetry_bar(metrics: Dict[str, Any]) -> str:
        """Top endpoint traffic asymmetry bar chart."""
        topology = metrics.get("ip_topology", {}) or {}
        nodes = topology.get("nodes", []) or []
        if not nodes:
            return ""

        ratios: List[Dict[str, float]] = []
        for node in nodes:
            ip = str(node.get("ip", "") or "").strip()
            if not ip:
                continue
            send_packets = float(node.get("send_packets", 0) or 0)
            recv_packets = float(node.get("recv_packets", 0) or 0)
            if send_packets <= 0 or recv_packets <= 0:
                continue
            ratio = max(send_packets / recv_packets, recv_packets / send_packets)
            ratios.append({"ip": ip, "ratio": ratio})

        if not ratios:
            return ""

        top = sorted(ratios, key=lambda row: row["ratio"], reverse=True)[:10]
        x_axis = [row["ip"] for row in top]
        y_axis = [float(row["ratio"]) for row in top]
        fig = go.Figure(
            data=[
                go.Bar(
                    x=x_axis,
                    y=y_axis,
                    marker_color="#0ea5e9",
                    hovertemplate="%{x}<br>不对称比=%{y:.2f}:1<extra></extra>",
                )
            ]
        )
        fig.update_layout(
            title="端点流量不对称比 Top10",
            height=420,
            xaxis=dict(title="IP"),
            yaxis=dict(title="不对称比(:1)", rangemode="tozero"),
            margin=dict(l=55, r=30, t=70, b=60),
        )
        return fig.to_html(full_html=False, include_plotlyjs=False)

    @staticmethod
    def generate_ip_topology(metrics: Dict[str, Any]) -> str:
        """IP communication topology graph."""
        topology = metrics.get("ip_topology", {}) or {}
        nodes = topology.get("nodes", []) or []
        edges = topology.get("edges", []) or []
        if not nodes or not edges:
            return ""

        nodes = nodes[:24]
        node_index = {str(node.get("ip", "")): idx for idx, node in enumerate(nodes) if node.get("ip")}
        filtered_edges = [
            edge
            for edge in edges
            if str(edge.get("src_ip", "")) in node_index and str(edge.get("dst_ip", "")) in node_index
        ][:80]
        if not filtered_edges:
            return ""

        count = len(nodes)
        radius = 1.0
        positions: Dict[str, Any] = {}
        for idx, node in enumerate(nodes):
            ip = str(node.get("ip", ""))
            angle = (2 * math.pi * idx) / max(count, 1)
            positions[ip] = (radius * math.cos(angle), radius * math.sin(angle))

        fig = go.Figure()
        for edge in filtered_edges:
            src_ip = str(edge.get("src_ip", ""))
            dst_ip = str(edge.get("dst_ip", ""))
            if src_ip not in positions or dst_ip not in positions:
                continue
            x0, y0 = positions[src_ip]
            x1, y1 = positions[dst_ip]
            packets = int(edge.get("packets", 0) or 0)
            issue_score = float(edge.get("issue_score", 0.0) or 0.0)
            retrans = int(edge.get("retrans_count", 0) or 0)
            rst = int(edge.get("rst_count", 0) or 0)
            protocol = str(edge.get("dominant_protocol", "OTHER"))

            width = 1.0 + min(packets / 120.0, 5.0)
            color = "#ef4444" if issue_score > 0 else "#94a3b8"
            fig.add_trace(
                go.Scatter(
                    x=[x0, x1],
                    y=[y0, y1],
                    mode="lines",
                    line=dict(width=width, color=color),
                    opacity=0.75,
                    hoverinfo="text",
                    text=(
                        f"{src_ip} -> {dst_ip}<br>"
                        f"包数={packets}, 协议={protocol}<br>"
                        f"重传={retrans}, RST={rst}"
                    ),
                    showlegend=False,
                )
            )

        node_x: List[float] = []
        node_y: List[float] = []
        node_size: List[float] = []
        node_color: List[float] = []
        node_text: List[str] = []
        node_label: List[str] = []
        for node in nodes:
            ip = str(node.get("ip", ""))
            if ip not in positions:
                continue
            x, y = positions[ip]
            total_packets = int(node.get("total_packets", 0) or 0)
            incident_score = float(node.get("incident_score", 0.0) or 0.0)
            node_x.append(x)
            node_y.append(y)
            node_size.append(16 + min(total_packets / 70.0, 24))
            node_color.append(incident_score)
            node_label.append(ip)
            node_text.append(
                f"{ip}<br>总包数={total_packets}<br>"
                f"发送={int(node.get('send_packets', 0) or 0)} / 接收={int(node.get('recv_packets', 0) or 0)}<br>"
                f"异常评分={incident_score:.1f}"
            )

        fig.add_trace(
            go.Scatter(
                x=node_x,
                y=node_y,
                mode="markers+text",
                text=node_label,
                textposition="top center",
                hoverinfo="text",
                hovertext=node_text,
                marker=dict(
                    size=node_size,
                    color=node_color,
                    colorscale="YlOrRd",
                    showscale=True,
                    colorbar=dict(title="异常热度"),
                    line=dict(width=1, color="#0f172a"),
                ),
                showlegend=False,
            )
        )

        fig.update_layout(
            title="IP通信拓扑（边宽=流量，颜色=异常热度）",
            height=560,
            xaxis=dict(visible=False),
            yaxis=dict(visible=False),
            margin=dict(l=20, r=20, t=80, b=20),
            plot_bgcolor="#ffffff",
            paper_bgcolor="#ffffff",
        )
        return fig.to_html(full_html=False, include_plotlyjs=False)

    @staticmethod
    def _flow_score(flow: Dict[str, Any]) -> float:
        syn = int(flow.get("syn_count", 0) or 0)
        syn_ack = int(flow.get("syn_ack_count", 0) or 0)
        final_ack = int(flow.get("final_ack_count", 0) or 0)
        rst = int(flow.get("rst_count", 0) or 0)
        retrans = int(flow.get("retrans_count", 0) or 0)
        dup_ack = int(flow.get("dup_ack_count", 0) or 0)
        zero_window = int(flow.get("zero_window_count", 0) or 0)
        out_of_order = int(flow.get("out_of_order_count", 0) or 0)
        max_gap = float(flow.get("max_gap", 0.0) or 0.0)

        score = rst * 7 + retrans * 4 + dup_ack * 2 + zero_window * 4 + out_of_order * 2 + min(max_gap * 2, 20)
        if syn > 0 and syn_ack == 0:
            score += 40
        if syn_ack > 0 and final_ack == 0:
            score += 30
        return score

    @staticmethod
    def _flow_endpoint(flow: Dict[str, Any]) -> str:
        return (
            f"{flow.get('src_ip', 'unknown')}:{flow.get('src_port', 0)}"
            f" -> {flow.get('dst_ip', 'unknown')}:{flow.get('dst_port', 0)}"
        )

    @staticmethod
    def _flow_identity(flow: Dict[str, Any]) -> str:
        return (
            f"{flow.get('src_ip', 'unknown')}:{flow.get('src_port', 0)}->"
            f"{flow.get('dst_ip', 'unknown')}:{flow.get('dst_port', 0)}|"
            f"{int(flow.get('first_packet_no', 0) or 0)}|"
            f"{int(flow.get('last_packet_no', 0) or 0)}|"
            f"{int(flow.get('packet_count', 0) or 0)}"
        )

    @staticmethod
    def _rank_problem_flows(metrics: Dict[str, Any], limit: int = 10) -> List[Dict[str, Any]]:
        flows = metrics.get("problem_flows", []) or []
        ranked = sorted(flows, key=ChartGenerator._flow_score, reverse=True)
        return ranked[: max(limit, 1)]

    @staticmethod
    def _flow_client_endpoint(flow: Dict[str, Any]) -> str:
        return f"{flow.get('src_ip', 'unknown')}:{flow.get('src_port', 0)}"

    @staticmethod
    def _flow_server_endpoint(flow: Dict[str, Any]) -> str:
        return f"{flow.get('dst_ip', 'unknown')}:{flow.get('dst_port', 0)}"

    @staticmethod
    def _flow_selector_label(flow: Dict[str, Any], index: int) -> str:
        src = ChartGenerator._flow_client_endpoint(flow)
        dst = ChartGenerator._flow_server_endpoint(flow)
        fault = ChartGenerator._flow_fault(flow)
        packet_scope = ChartGenerator._flow_packet_scope(flow)
        return f"流{index + 1} 客户端 {src} -> 服务端 {dst} | {fault} | {packet_scope}"

    @staticmethod
    def _flow_fault(flow: Dict[str, Any]) -> str:
        syn = int(flow.get("syn_count", 0) or 0)
        syn_ack = int(flow.get("syn_ack_count", 0) or 0)
        final_ack = int(flow.get("final_ack_count", 0) or 0)
        rst = int(flow.get("rst_count", 0) or 0)
        retrans = int(flow.get("retrans_count", 0) or 0)
        zero_window = int(flow.get("zero_window_count", 0) or 0)
        out_of_order = int(flow.get("out_of_order_count", 0) or 0)
        max_gap = float(flow.get("max_gap", 0.0) or 0.0)

        if syn > 0 and syn_ack == 0:
            return "握手失败（SYN后无SYN-ACK）"
        if syn_ack > 0 and final_ack == 0:
            return "握手未完成（SYN-ACK后无ACK）"
        if rst > 0 and retrans > 0:
            return "连接重置并伴随重传"
        if rst > 0:
            return "连接被重置（RST）"
        if zero_window > 0:
            return "接收端窗口阻塞"
        if retrans > 0:
            return "传输重传异常"
        if out_of_order > 0:
            return "报文乱序/抖动"
        if max_gap > 3.0:
            return "链路间歇卡顿"
        issues = flow.get("issues", []) or []
        return issues[0] if issues else "未识别具体故障"

    @staticmethod
    def _fault_color(flow: Dict[str, Any]) -> str:
        text = ChartGenerator._flow_fault(flow)
        if "握手失败" in text or "重置" in text:
            return "#dc2626"
        if "阻塞" in text or "重传" in text:
            return "#ea580c"
        return "#ca8a04"

    @staticmethod
    def _truncate_text(text: str, limit: int = 28) -> str:
        if len(text) <= limit:
            return text
        return text[: max(limit - 1, 1)] + "…"

    @staticmethod
    def _flow_packet_scope(flow: Dict[str, Any]) -> str:
        first_no = int(flow.get("first_packet_no", 0) or 0)
        last_no = int(flow.get("last_packet_no", 0) or 0)
        if first_no > 0 and last_no >= first_no:
            return f"包#{first_no}-#{last_no}"
        packet_count = int(flow.get("packet_count", 0) or 0)
        return f"约{packet_count}包" if packet_count > 0 else "未知"

    @staticmethod
    def _flow_evidence_id(flow: Dict[str, Any]) -> str:
        existing = str(flow.get("evidence_id", "") or "").strip()
        if existing:
            return existing
        seed = (
            f"{flow.get('src_ip', '')}:{int(flow.get('src_port', 0) or 0)}->"
            f"{flow.get('dst_ip', '')}:{int(flow.get('dst_port', 0) or 0)}|"
            f"{int(flow.get('packet_count', 0) or 0)}|{int(flow.get('retrans_count', 0) or 0)}|"
            f"{int(flow.get('rst_count', 0) or 0)}"
        )
        return f"EV-{zlib.crc32(seed.encode('utf-8')) & 0xFFFFFFFF:08X}"

    @staticmethod
    def _build_flow_events(flow: Dict[str, Any]) -> List[Dict[str, Any]]:
        dominant_forward = int(flow.get("packets_a_to_b", 0) or 0) >= int(flow.get("packets_b_to_a", 0) or 0)
        data_src = "client" if dominant_forward else "server"
        data_dst = "server" if dominant_forward else "client"
        reverse_src = "server" if data_src == "client" else "client"
        reverse_dst = "client" if data_src == "client" else "server"

        events: List[Dict[str, Any]] = []

        def add_event(
            label: str,
            short: str,
            count: int,
            src_side: str,
            dst_side: str,
            color: str,
            stage: str,
            is_fault: bool = False,
        ) -> None:
            if count <= 0:
                return
            events.append(
                {
                    "label": label,
                    "short": short,
                    "count": int(count),
                    "src": src_side,
                    "dst": dst_side,
                    "color": color,
                    "stage": stage,
                    "is_fault": is_fault,
                }
            )

        syn = int(flow.get("syn_count", 0) or 0)
        syn_ack = int(flow.get("syn_ack_count", 0) or 0)
        ack = int(flow.get("final_ack_count", flow.get("ack_count", 0)) or 0)
        rst = int(flow.get("rst_count", 0) or 0)
        retrans = int(flow.get("retrans_count", 0) or 0)
        zero_win = int(flow.get("zero_window_count", 0) or 0)
        out_of_order = int(flow.get("out_of_order_count", 0) or 0)
        gap = float(flow.get("max_gap", 0.0) or 0.0)
        packet_count = int(flow.get("packet_count", 0) or 0)
        fin_count = int(flow.get("fin_count", 0) or 0)
        data_packets = max(packet_count - (syn + syn_ack + ack + rst + fin_count), 0)

        add_event("客户端发起 SYN", "SYN", syn, "client", "server", "#2563eb", "握手")
        add_event("服务端返回 SYN-ACK", "SYN-ACK", syn_ack, "server", "client", "#0ea5e9", "握手")
        add_event("客户端确认 ACK", "ACK", ack, "client", "server", "#14b8a6", "握手")
        add_event("业务数据传输", "DATA", data_packets, data_src, data_dst, "#16a34a", "数据")
        add_event("连接正常关闭", "FIN", fin_count, reverse_src, reverse_dst, "#64748b", "收尾")

        if syn > 0 and syn_ack == 0:
            add_event("故障：SYN 重试/无响应", "FAULT-SYN", max(syn, 1), "client", "server", "#dc2626", "故障", True)
        elif syn_ack > 0 and ack == 0:
            add_event("故障：握手未完成（ACK缺失）", "FAULT-ACK", max(syn_ack, 1), "client", "server", "#dc2626", "故障", True)
        if rst > 0:
            add_event("故障：连接被重置（RST）", "FAULT-RST", rst, reverse_src, reverse_dst, "#dc2626", "故障", True)
        if retrans > 0:
            add_event("异常：数据重传", "RETRANS", retrans, data_src, data_dst, "#f97316", "故障", True)
        if zero_win > 0:
            add_event("异常：接收端窗口阻塞", "ZERO-WIN", zero_win, data_dst, data_src, "#f59e0b", "故障", True)
        if out_of_order > 0:
            add_event("异常：报文乱序/抖动", "OUT-OF-ORDER", out_of_order, data_src, data_dst, "#f59e0b", "故障", True)
        if gap > 3.0:
            add_event("异常：链路间歇卡顿", "GAP", int(max(gap, 1.0)), data_src, data_dst, "#f59e0b", "故障", True)

        if not events:
            add_event("异常流量被识别", "FAULT", 1, data_src, data_dst, "#dc2626", "故障", True)
        return events[:8]

    @staticmethod
    def _generate_classic_flow_timeline(
        metrics: Dict[str, Any],
        focus_flow: Optional[Dict[str, Any]] = None,
        flow_index: int = 0,
    ) -> str:
        ranked = ChartGenerator._rank_problem_flows(metrics, limit=20)
        if not ranked and not focus_flow:
            return ""

        flow = focus_flow or ranked[0]
        src = ChartGenerator._flow_client_endpoint(flow)
        dst = ChartGenerator._flow_server_endpoint(flow)
        fault_text = ChartGenerator._flow_fault(flow)
        packet_scope = ChartGenerator._flow_packet_scope(flow)
        evidence_id = ChartGenerator._flow_evidence_id(flow)
        events = ChartGenerator._build_flow_events(flow)
        if not events:
            return ""
        fault_start = next((i for i, e in enumerate(events, 1) if e["is_fault"]), 0)
        event_count = len(events)
        x_client = 0.16
        x_server = 0.84
        step_gap = 1.34
        y_positions = [step_gap * (event_count - idx) for idx in range(event_count)]
        y_min = 0.45
        y_max = y_positions[0] + 0.6
        chart_height = max(700, 360 + event_count * 64)
        y_lift = max(0.12, 15.0 / chart_height * (y_max - y_min + 1.35))
        y_top_label = y_positions[0] + 0.92 + y_lift
        flow_tag = f"流{flow_index + 1}"
        src_label = ChartGenerator._truncate_text(src, 28)
        dst_label = ChartGenerator._truncate_text(dst, 28)
        selection_line = ChartGenerator._truncate_text(f"客户端 {src} -> 服务端 {dst}", 66)
        fault_line = ChartGenerator._truncate_text(fault_text, 28)
        meta_line = ChartGenerator._truncate_text(f"{packet_scope} | {evidence_id}", 44)

        def direction_text(event: Dict[str, Any]) -> str:
            return "客户端→服务端" if event["src"] == "client" else "服务端→客户端"

        def event_short_label(event: Dict[str, Any]) -> str:
            if event["count"] <= 1:
                return event["short"]
            return f"{event['short']}×{event['count']}"

        def src_x(event: Dict[str, Any]) -> float:
            return x_client if event["src"] == "client" else x_server

        def dst_x(event: Dict[str, Any]) -> float:
            return x_client if event["dst"] == "client" else x_server

        def event_hover(idx: int, event: Dict[str, Any]) -> str:
            return (
                f"步骤 {idx + 1}<br>"
                f"阶段: {event['stage']}<br>"
                f"事件: {event['label']}<br>"
                f"方向: {direction_text(event)}<br>"
                f"计数: {event['count']}<br>"
                f"包号范围: {packet_scope}<br>"
                f"证据ID: {evidence_id}"
            )

        def build_dynamic_traces(active_idx: int, active_progress: float) -> List[go.Scatter]:
            traces: List[go.Scatter] = []
            for idx, event in enumerate(events):
                y_val = y_positions[idx]
                sx = src_x(event)
                dx = dst_x(event)
                if idx < active_idx:
                    progress = 1.0
                elif idx == active_idx:
                    progress = max(0.0, min(1.0, active_progress))
                else:
                    progress = 0.0

                end_x = sx + (dx - sx) * progress
                visible = progress > 0.0
                opacity = 0.96 if visible else 0.0
                width = 3.4 if progress >= 1.0 else (2.6 if visible else 1.0)
                marker_size = 13 if visible else 0

                hover_txt = event_hover(idx, event)
                traces.append(
                    go.Scatter(
                        x=[sx, end_x],
                        y=[y_val, y_val],
                        mode="lines",
                        line=dict(color=event["color"], width=width),
                        opacity=opacity,
                        hovertemplate="%{customdata}<extra></extra>",
                        customdata=[hover_txt, hover_txt],
                        showlegend=False,
                    )
                )

                traces.append(
                    go.Scatter(
                        x=[end_x],
                        y=[y_val],
                        mode="markers",
                        marker=dict(
                            color=event["color"],
                            size=marker_size,
                            symbol="triangle-right" if dx >= sx else "triangle-left",
                            line=dict(color="#ffffff", width=1),
                            opacity=opacity,
                        ),
                        hovertemplate="%{customdata}<extra></extra>",
                        customdata=[hover_txt],
                        showlegend=False,
                    )
                )
            return traces

        def layout_annotations(current_idx: int) -> List[Dict[str, Any]]:
            if current_idx >= 0:
                current = events[current_idx]
                current_text = f"<b>步骤 {current_idx + 1}/{event_count}：{current['label']}</b>"
                current_color = current["color"]
            else:
                current_text = "<b>点击播放，查看箭头逐步发起过程</b>"
                current_color = "#334155"

            ann: List[Dict[str, Any]] = [
                {
                    "xref": "x",
                    "yref": "y",
                    "x": x_client,
                    "y": y_top_label,
                    "showarrow": False,
                    "text": f"<b>客户端</b><br>{src_label}",
                    "align": "center",
                    "font": {"size": 12, "color": "#1f2937"},
                },
                {
                    "xref": "x",
                    "yref": "y",
                    "x": x_server,
                    "y": y_top_label,
                    "showarrow": False,
                    "text": f"<b>服务端</b><br>{dst_label}",
                    "align": "center",
                    "font": {"size": 12, "color": "#1f2937"},
                },
                {
                    "xref": "paper",
                    "yref": "paper",
                    "x": 0.5,
                    "y": -0.38,
                    "showarrow": False,
                    "xanchor": "center",
                    "yanchor": "top",
                    "align": "center",
                    "font": {"size": 12, "color": "#334155"},
                    "text": (
                        f"当前选择：{flow_tag}<br>{selection_line}<br>"
                        f"故障判定：<b>{fault_line}</b> | {meta_line}"
                    ),
                },
                {
                    "xref": "paper",
                    "yref": "paper",
                    "x": 1,
                    "y": 1.17,
                    "showarrow": False,
                    "xanchor": "right",
                    "align": "right",
                    "font": {"size": 12, "color": "#334155"},
                    "text": "图例：<span style='color:#2563eb'>握手</span> / <span style='color:#16a34a'>数据</span> / "
                    "<span style='color:#f59e0b'>性能异常</span> / <span style='color:#dc2626'>故障</span>",
                },
                {
                    "xref": "x",
                    "yref": "y",
                    "x": 0.5,
                    "y": y_top_label + 0.3,
                    "showarrow": False,
                    "font": {"size": 13, "color": current_color},
                    "text": current_text,
                },
            ]
            if fault_start > 0:
                ann.append(
                    {
                        "xref": "x",
                        "yref": "y",
                        "x": 0.5,
                        "y": y_positions[fault_start - 1] - 0.55,
                        "showarrow": False,
                        "font": {"size": 12, "color": "#dc2626"},
                        "text": f"故障从第 {fault_start} 步开始",
                    }
                )
            return ann

        lane_client = go.Scatter(
            x=[x_client, x_client],
            y=[y_min, y_max],
            mode="lines",
            line=dict(color="#93c5fd", width=4),
            hoverinfo="skip",
            showlegend=False,
        )
        lane_server = go.Scatter(
            x=[x_server, x_server],
            y=[y_min, y_max],
            mode="lines",
            line=dict(color="#86efac", width=4),
            hoverinfo="skip",
            showlegend=False,
        )
        label_trace = go.Scatter(
            x=[0.5] * event_count,
            y=[y + 0.075 + y_lift for y in y_positions],
            mode="text",
            text=[f"{idx + 1}. {event_short_label(event)}" for idx, event in enumerate(events)],
            textfont=dict(size=11, color="#334155"),
            hoverinfo="skip",
            showlegend=False,
        )

        initial_dynamic = build_dynamic_traces(0, 0.0)
        fig = go.Figure(data=[lane_client, lane_server, label_trace] + initial_dynamic)

        if fault_start > 0:
            fig.add_shape(
                type="rect",
                xref="paper",
                yref="y",
                x0=0.04,
                x1=0.96,
                y0=y_min,
                y1=y_positions[fault_start - 1] + 0.42,
                fillcolor="rgba(220, 38, 38, 0.08)",
                line=dict(width=0),
                layer="below",
            )

        trace_start = 3
        trace_count = len(initial_dynamic)
        frame_slices = 2
        frames: List[go.Frame] = [
            go.Frame(
                name="init",
                data=build_dynamic_traces(0, 0.0),
                traces=list(range(trace_start, trace_start + trace_count)),
                layout={"annotations": layout_annotations(-1)},
            )
        ]
        for step_idx in range(event_count):
            for slice_idx in range(1, frame_slices + 1):
                progress = slice_idx / float(frame_slices)
                frames.append(
                    go.Frame(
                        name=f"s{step_idx + 1}_{slice_idx}",
                        data=build_dynamic_traces(step_idx, progress),
                        traces=list(range(trace_start, trace_start + trace_count)),
                        layout={"annotations": layout_annotations(step_idx)},
                    )
                )

        fig.frames = frames
        fig.update_layout(
            title="关键流时序动画",
            height=chart_height,
            xaxis=dict(
                title="通信方向（左：客户端，右：服务端）",
                range=[0.02, 0.98],
                tickmode="array",
                tickvals=[x_client, x_server],
                ticktext=["客户端", "服务端"],
                showgrid=False,
                zeroline=False,
            ),
            yaxis=dict(
                title="交互步骤（自上而下）",
                range=[y_min - 0.2, y_top_label + 0.5],
                tickmode="array",
                tickvals=y_positions,
                ticktext=[str(i) for i in range(1, event_count + 1)],
                showgrid=False,
                zeroline=False,
            ),
            margin=dict(l=90, r=60, t=120, b=360),
            updatemenus=[],
            sliders=[
                {
                    "active": 0,
                    "x": 0.08,
                    "len": 0.9,
                    "y": -0.58,
                    "currentvalue": {"prefix": "当前步骤: "},
                    "steps": (
                        [
                            {
                                "label": "0. 初始",
                                "method": "animate",
                                "args": [
                                    ["init"],
                                    {"frame": {"duration": 0, "redraw": True}, "mode": "immediate"},
                                ],
                            }
                        ]
                        + [
                            {
                                "label": f"{i}. {events[i - 1]['short']}",
                                "method": "animate",
                                "args": [
                                    [f"s{i}_{frame_slices}"],
                                    {"frame": {"duration": 0, "redraw": True}, "mode": "immediate"},
                                ],
                            }
                            for i in range(1, event_count + 1)
                        ]
                    ),
                }
            ],
            annotations=layout_annotations(-1),
        )
        return fig.to_html(full_html=False, include_plotlyjs=False)

    @staticmethod
    def _build_stage_summary(flow: Dict[str, Any]) -> List[Dict[str, str]]:
        syn = int(flow.get("syn_count", 0) or 0)
        syn_ack = int(flow.get("syn_ack_count", 0) or 0)
        ack = int(flow.get("final_ack_count", flow.get("ack_count", 0)) or 0)
        retrans = int(flow.get("retrans_count", 0) or 0)
        zero_win = int(flow.get("zero_window_count", 0) or 0)
        out_of_order = int(flow.get("out_of_order_count", 0) or 0)
        gap = float(flow.get("max_gap", 0.0) or 0.0)
        packet_count = int(flow.get("packet_count", 0) or 0)
        rst = int(flow.get("rst_count", 0) or 0)
        fin_count = int(flow.get("fin_count", 0) or 0)
        data_packets = max(packet_count - (syn + syn_ack + ack + rst + fin_count), 0)

        if syn > 0 and syn_ack == 0:
            hs_short, hs_text, hs_color = "SYN无响应", "握手失败：SYN 后无 SYN-ACK", "#dc2626"
        elif syn_ack > 0 and ack == 0:
            hs_short, hs_text, hs_color = "ACK缺失", "握手未完成：SYN-ACK 后无 ACK", "#dc2626"
        elif syn > 0 or syn_ack > 0 or ack > 0:
            hs_short, hs_text, hs_color = "握手完成", "三次握手可见，连接可建立", "#16a34a"
        else:
            hs_short, hs_text, hs_color = "握手数据不足", "抓包中未观察到完整握手过程", "#94a3b8"

        data_issue_parts: List[str] = []
        if retrans > 0:
            data_issue_parts.append(f"重传 {retrans}")
        if zero_win > 0:
            data_issue_parts.append(f"窗口阻塞 {zero_win}")
        if out_of_order > 0:
            data_issue_parts.append(f"乱序 {out_of_order}")
        if gap > 3.0:
            data_issue_parts.append(f"间歇 {gap:.1f}s")

        if data_issue_parts:
            data_short = ChartGenerator._truncate_text("、".join(data_issue_parts[:2]), 14)
            data_text = "；".join(data_issue_parts)
            data_color = "#f59e0b"
        elif data_packets > 0:
            data_short = f"数据 {data_packets}"
            data_text = f"业务数据可见（约 {data_packets} 包）"
            data_color = "#16a34a"
        else:
            data_short = "无业务数据"
            data_text = "未观察到明显业务数据交换"
            data_color = "#94a3b8"

        fault_text = ChartGenerator._flow_fault(flow)
        fault_color = ChartGenerator._fault_color(flow)
        fault_short = ChartGenerator._truncate_text(fault_text, 14)
        return [
            {"short": hs_short, "text": hs_text, "color": hs_color},
            {"short": data_short, "text": data_text, "color": data_color},
            {"short": fault_short, "text": fault_text, "color": fault_color},
        ]

    @staticmethod
    def _generate_vertical_swimlane_timeline(
        metrics: Dict[str, Any],
        focus_flow: Optional[Dict[str, Any]] = None,
        flow_index: int = 0,
        lane_limit: int = 10,
    ) -> str:
        ranked_all = ChartGenerator._rank_problem_flows(metrics, limit=max(lane_limit, 20))
        if not ranked_all and not focus_flow:
            return ""

        primary_flow = focus_flow or ranked_all[0]
        primary_key = ChartGenerator._flow_identity(primary_flow)
        ranked: List[Dict[str, Any]] = [primary_flow]
        for flow in ranked_all:
            if ChartGenerator._flow_identity(flow) == primary_key:
                continue
            ranked.append(flow)
            if len(ranked) >= lane_limit:
                break

        if not ranked:
            return ""
        primary_src = ChartGenerator._flow_client_endpoint(primary_flow)
        primary_dst = ChartGenerator._flow_server_endpoint(primary_flow)
        primary_fault = ChartGenerator._flow_fault(primary_flow)
        primary_scope = ChartGenerator._flow_packet_scope(primary_flow)
        primary_evidence = ChartGenerator._flow_evidence_id(primary_flow)
        flow_tag = f"流{flow_index + 1}"
        primary_selection = ChartGenerator._truncate_text(f"客户端 {primary_src} -> 服务端 {primary_dst}", 66)
        primary_fault_short = ChartGenerator._truncate_text(primary_fault, 28)
        primary_meta = ChartGenerator._truncate_text(f"{primary_scope} | {primary_evidence}", 44)
        lane_label_limit_1 = 28 if len(ranked) <= 6 else 24
        lane_label_limit_2 = 24 if len(ranked) <= 6 else 20

        lanes: List[Dict[str, Any]] = []
        for idx, flow in enumerate(ranked, 1):
            client_ep = ChartGenerator._flow_client_endpoint(flow)
            server_ep = ChartGenerator._flow_server_endpoint(flow)
            endpoint_full = f"{idx} 客户端 {client_ep} -> 服务端 {server_ep}"
            endpoint_line_1 = ChartGenerator._truncate_text(f"流{idx} 客户端 {client_ep} ->", lane_label_limit_1)
            endpoint_line_2 = ChartGenerator._truncate_text(f"服务端 {server_ep}", lane_label_limit_2)
            lanes.append(
                {
                    "label": endpoint_full,
                    "display_label": (
                        "<span style='display:inline-block;text-align:left;line-height:1.35;'>"
                        f"{endpoint_line_1}<br>{endpoint_line_2}</span>"
                    ),
                    "fault": ChartGenerator._flow_fault(flow),
                    "stages": ChartGenerator._build_stage_summary(flow),
                    "packet_scope": ChartGenerator._flow_packet_scope(flow),
                    "evidence_id": ChartGenerator._flow_evidence_id(flow),
                }
            )

        lane_count = len(lanes)
        lane_gap = 1.24 if lane_count <= 6 else 1.14
        y_positions = [1.0 + lane_gap * (lane_count - idx - 1) for idx in range(lane_count)]
        stage_names = ["握手阶段", "数据阶段", "故障判定"]
        stage_count = len(stage_names)
        chart_height = max(760, 340 + lane_count * 96)

        def guide_trace() -> go.Scatter:
            x: List[Any] = []
            y: List[Any] = []
            for y_pos in y_positions:
                x.extend([0.78, 3.3, None])
                y.extend([y_pos, y_pos, None])
            return go.Scatter(
                x=x,
                y=y,
                mode="lines",
                line=dict(color="#e2e8f0", width=1),
                hoverinfo="skip",
                showlegend=False,
            )

        def progress_line_trace(stage_idx: int) -> go.Scatter:
            x: List[Any] = []
            y: List[Any] = []
            for y_pos in y_positions:
                x.extend(list(range(1, stage_idx + 1)) + [None])
                y.extend([y_pos] * stage_idx + [None])
            return go.Scatter(
                x=x,
                y=y,
                mode="lines",
                line=dict(color="#94a3b8", width=2),
                hoverinfo="skip",
                showlegend=False,
            )

        def progress_point_trace(stage_idx: int) -> go.Scatter:
            x: List[int] = []
            y: List[int] = []
            colors: List[str] = []
            sizes: List[int] = []
            symbols: List[str] = []
            hover: List[str] = []
            for lane_idx, lane in enumerate(lanes):
                y_pos = y_positions[lane_idx]
                for stage in range(1, stage_idx + 1):
                    stage_data = lane["stages"][stage - 1]
                    x.append(stage)
                    y.append(y_pos)
                    colors.append(stage_data["color"])
                    sizes.append(13 if stage < stage_idx else 17)
                    symbols.append("circle" if stage < stage_idx else "diamond")
                    hover.append(
                        f"泳道：{lane['label']}<br>"
                        f"阶段：{stage_names[stage - 1]}<br>"
                        f"状态：{stage_data['text']}<br>"
                        f"故障结论：{lane['fault']}<br>"
                        f"包号范围：{lane['packet_scope']}<br>"
                        f"证据ID：{lane['evidence_id']}"
                    )
            return go.Scatter(
                x=x,
                y=y,
                mode="markers",
                marker=dict(color=colors, size=sizes, symbol=symbols, line=dict(color="#ffffff", width=1)),
                hovertemplate="%{hovertext}<extra></extra>",
                hovertext=hover,
                showlegend=False,
            )

        def stage_text_trace(stage_idx: int) -> go.Scatter:
            if stage_idx <= 0:
                return go.Scatter(
                    x=[],
                    y=[],
                    mode="text",
                    text=[],
                    hoverinfo="skip",
                    showlegend=False,
                )
            return go.Scatter(
                x=[stage_idx + 0.16] * lane_count,
                y=y_positions,
                mode="text",
                text=[ChartGenerator._truncate_text(lane["stages"][stage_idx - 1]["short"], 10) for lane in lanes],
                textposition="middle left",
                textfont=dict(size=11, color="#334155"),
                hoverinfo="skip",
                showlegend=False,
            )

        def frame_annotations(stage_idx: int) -> List[Dict[str, Any]]:
            if stage_idx <= 0:
                phase_text = "准备阶段（点击播放开始）"
            else:
                phase_text = f"{stage_names[stage_idx - 1]}（{stage_idx}/{stage_count}）"
            return [
                {
                    "xref": "paper",
                    "yref": "paper",
                    "x": 0,
                    "y": 1.0,
                    "showarrow": False,
                    "xanchor": "left",
                    "yanchor": "bottom",
                    "align": "left",
                    "font": {"size": 12, "color": "#334155"},
                    "text": (
                        f"覆盖问题流：{lane_count} 条（按影响度排序）　"
                        f"当前阶段：<b>{phase_text}</b>（完整端点见左侧泳道）"
                    ),
                },
                {
                    "xref": "paper",
                    "yref": "paper",
                    "x": 1,
                    "y": 1.10,
                    "showarrow": False,
                    "xanchor": "right",
                    "yanchor": "bottom",
                    "align": "right",
                    "font": {"size": 12, "color": "#334155"},
                    "text": "图例：<span style='color:#16a34a'>正常</span> / "
                    "<span style='color:#f59e0b'>性能异常</span> / "
                    "<span style='color:#dc2626'>故障</span>",
                },
                {
                    "xref": "paper",
                    "yref": "paper",
                    "x": 0.5,
                    "y": -0.15,
                    "showarrow": False,
                    "xanchor": "center",
                    "yanchor": "top",
                    "align": "center",
                    "font": {"size": 12, "color": "#334155"},
                    "text": (
                        f"当前选择：{flow_tag}　{primary_selection}<br>"
                        f"故障判定：<b>{primary_fault_short}</b> | {primary_meta}"
                    ),
                },
            ]

        def stage_highlight(stage_idx: int) -> List[Dict[str, Any]]:
            if stage_idx <= 0:
                return []
            color = "rgba(37, 99, 235, 0.08)" if stage_idx < 3 else "rgba(220, 38, 38, 0.08)"
            return [
                {
                    "type": "rect",
                    "xref": "x",
                    "yref": "paper",
                    "x0": stage_idx - 0.42,
                    "x1": stage_idx + 0.42,
                    "y0": 0,
                    "y1": 1,
                    "fillcolor": color,
                    "line": {"width": 0},
                    "layer": "below",
                }
            ]

        frames: List[go.Frame] = [
            go.Frame(
                name="init",
                data=[progress_line_trace(0), progress_point_trace(0), stage_text_trace(0)],
                traces=[1, 2, 3],
                layout={"annotations": frame_annotations(0), "shapes": stage_highlight(0)},
            )
        ]
        for idx in range(1, stage_count + 1):
            frames.append(
                go.Frame(
                    name=str(idx),
                    data=[progress_line_trace(idx), progress_point_trace(idx), stage_text_trace(idx)],
                    traces=[1, 2, 3],
                    layout={"annotations": frame_annotations(idx), "shapes": stage_highlight(idx)},
                )
            )

        fig = go.Figure(
            data=[guide_trace(), progress_line_trace(0), progress_point_trace(0), stage_text_trace(0)],
            frames=frames,
        )
        fig.update_layout(
            title="纵向多泳道动画（每条问题流独立泳道）",
            height=chart_height,
            xaxis=dict(
                title="诊断阶段",
                autorange=True,
                tickmode="array",
                tickvals=[1, 2, 3],
                ticktext=stage_names,
                showgrid=False,
            ),
            yaxis=dict(
                title="",
                tickmode="array",
                tickvals=y_positions,
                ticktext=[lane["display_label"] for lane in lanes],
                tickfont=dict(size=10 if lane_count >= 8 else 12),
                showgrid=False,
                automargin=True,
            ),
            margin=dict(l=0, r=50, t=120, b=120),
            annotations=frame_annotations(0),
            shapes=stage_highlight(0),
            updatemenus=[],
            sliders=[
                {
                    "active": 0,
                    "x": 0.08,
                    "len": 0.9,
                    "y": -0.22,
                    "currentvalue": {"prefix": "当前阶段: "},
                    "steps": (
                        [
                            {
                                "label": "0. 初始",
                                "method": "animate",
                                "args": [
                                    ["init"],
                                    {"frame": {"duration": 0, "redraw": True}, "mode": "immediate"},
                                ],
                            }
                        ]
                        + [
                            {
                                "label": f"{idx}. {stage_names[idx - 1]}",
                                "method": "animate",
                                "args": [
                                    [str(idx)],
                                    {"frame": {"duration": 0, "redraw": True}, "mode": "immediate"},
                                ],
                            }
                            for idx in range(1, stage_count + 1)
                        ]
                    ),
                }
            ],
        )
        return fig.to_html(full_html=False, include_plotlyjs=False)

    @staticmethod
    def generate_flow_fault_timeline(metrics: Dict[str, Any]) -> str:
        """Render switchable animations: classic timeline and vertical multi-swimlane."""
        ranked_flows = ChartGenerator._rank_problem_flows(metrics, limit=12)
        if not ranked_flows:
            return ""

        scope_mode = str((metrics.get("analysis_scope", {}) or {}).get("mode", "all")).lower()
        enable_selector = scope_mode == "all" and len(ranked_flows) > 1

        block_id = f"flow-anim-{uuid.uuid4().hex[:8]}"
        fn_name = f"toggleFlowAnim_{block_id.replace('-', '_')}"

        classic_views: List[str] = []
        swimlane_views: List[str] = []
        option_rows: List[str] = []
        usable_flows: List[Dict[str, Any]] = []

        if enable_selector:
            for idx, flow in enumerate(ranked_flows):
                classic_block = ChartGenerator._generate_classic_flow_timeline(
                    metrics,
                    focus_flow=flow,
                    flow_index=idx,
                )
                swimlane_block = ChartGenerator._generate_vertical_swimlane_timeline(
                    metrics,
                    focus_flow=flow,
                    flow_index=idx,
                )
                if not classic_block and not swimlane_block:
                    continue
                if not classic_block:
                    classic_block = swimlane_block
                if not swimlane_block:
                    swimlane_block = classic_block

                select_idx = len(usable_flows)
                usable_flows.append(flow)
                label = ChartGenerator._truncate_text(
                    ChartGenerator._flow_selector_label(flow, select_idx),
                    72,
                )
                option_rows.append(f'<option value="{select_idx}">{label}</option>')
                classic_views.append(
                    f'<div id="{block_id}-classic-{select_idx}" class="flow-anim-view" '
                    f'style="display:{"block" if select_idx == 0 else "none"};">{classic_block}</div>'
                )
                swimlane_views.append(
                    f'<div id="{block_id}-swimlane-{select_idx}" class="flow-anim-view" '
                    f'style="display:{"block" if select_idx == 0 else "none"};">{swimlane_block}</div>'
                )

        if not usable_flows:
            enable_selector = False
            primary_flow = ranked_flows[0]
            classic_html = ChartGenerator._generate_classic_flow_timeline(metrics, focus_flow=primary_flow, flow_index=0)
            swimlane_html = ChartGenerator._generate_vertical_swimlane_timeline(
                metrics,
                focus_flow=primary_flow,
                flow_index=0,
            )
            if not classic_html and not swimlane_html:
                return ""
            if not classic_html:
                classic_html = swimlane_html
            if not swimlane_html:
                swimlane_html = classic_html
            classic_views = [f'<div class="flow-anim-view">{classic_html}</div>']
            swimlane_views = [f'<div class="flow-anim-view">{swimlane_html}</div>']

        flow_count = len(classic_views)
        has_selector_js = "true" if enable_selector else "false"

        selector_html = ""
        if enable_selector:
            selector_html = f"""
  <div class="flow-anim-select-row">
    <label for="{block_id}-flow-select" class="flow-anim-label">选择数据流：</label>
    <select id="{block_id}-flow-select" onchange="{fn_name}_selectFlow(this.value)"
      class="flow-anim-select">
      {''.join(option_rows)}
    </select>
  </div>
"""

        classic_content = "".join(classic_views)
        swimlane_content = "".join(swimlane_views)
        hint_text = (
            "当前为全量抓包，可下拉选择指定数据流并播放其交互过程。"
            if enable_selector
            else "可切换查看不同表达方式：时序视角（单关键流）与多泳道视角（多问题流）。"
        )

        return f"""
<style>
  #{block_id}.flow-anim-root {{
    border: 1px solid #e2e8f0;
    border-radius: 12px;
    padding: 10px;
    background: #fff;
    min-width: 0;
  }}
  #{block_id} .flow-anim-toolbar {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
    margin-bottom: 8px;
  }}
  #{block_id} .flow-anim-mode,
  #{block_id} .flow-anim-actions {{
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
    min-width: 0;
  }}
  #{block_id} .flow-anim-actions {{
    justify-content: flex-end;
  }}
  #{block_id} .flow-anim-btn {{
    border: 1px solid #cbd5e1;
    background: #f8fafc;
    color: #334155;
    padding: 6px 10px;
    border-radius: 8px;
    cursor: pointer;
    line-height: 1.2;
    white-space: nowrap;
  }}
  #{block_id} .flow-anim-btn.is-active {{
    border-color: #93c5fd;
    background: #dbeafe;
    color: #1e3a8a;
  }}
  #{block_id} .flow-anim-select-row {{
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
    margin-bottom: 8px;
    min-width: 0;
  }}
  #{block_id} .flow-anim-label {{
    font-size: 12px;
    color: #334155;
    white-space: nowrap;
  }}
  #{block_id} .flow-anim-select {{
    flex: 1 1 320px;
    min-width: 0;
    width: 100%;
    max-width: 100%;
    padding: 6px 8px;
    border: 1px solid #cbd5e1;
    border-radius: 8px;
    background: #fff;
    color: #1f2937;
  }}
  #{block_id} .flow-anim-hint {{
    font-size: 12px;
    color: #64748b;
    margin-bottom: 8px;
    line-height: 1.45;
    word-break: break-word;
  }}
  #{block_id} .flow-anim-panel {{
    min-width: 0;
  }}
  #{block_id} .flow-anim-view {{
    min-width: 0;
  }}
  #{block_id} .flow-anim-view .plotly-graph-div,
  #{block_id} .flow-anim-panel .plotly-graph-div {{
    width: 100% !important;
    max-width: 100% !important;
  }}
  @media (max-width: 920px) {{
    #{block_id} .flow-anim-toolbar {{
      flex-direction: column;
      align-items: stretch;
    }}
    #{block_id} .flow-anim-actions {{
      justify-content: flex-start;
    }}
  }}
  @media (max-width: 680px) {{
    #{block_id} .flow-anim-mode,
    #{block_id} .flow-anim-actions {{
      width: 100%;
    }}
    #{block_id} .flow-anim-btn {{
      flex: 1 1 84px;
      text-align: center;
      padding: 7px 8px;
      white-space: normal;
    }}
    #{block_id} .flow-anim-label {{
      width: 100%;
    }}
    #{block_id} .flow-anim-select {{
      flex-basis: 100%;
    }}
  }}
</style>
<div id="{block_id}" class="flow-anim-root">
  <div class="flow-anim-toolbar">
    <div class="flow-anim-mode">
      <button id="{block_id}-btn-classic" class="flow-anim-btn is-active" onclick="{fn_name}('classic')">时序动画</button>
      <button id="{block_id}-btn-swimlane" class="flow-anim-btn" onclick="{fn_name}('swimlane')">多泳道动画</button>
    </div>
    <div class="flow-anim-actions">
      <button id="{block_id}-btn-play" class="flow-anim-btn is-active" onclick="{fn_name}_play()">播放</button>
      <button id="{block_id}-btn-pause" class="flow-anim-btn" onclick="{fn_name}_pause()">暂停</button>
      <button id="{block_id}-btn-fast" class="flow-anim-btn" onclick="{fn_name}_fast()">快速</button>
      <button id="{block_id}-btn-slow" class="flow-anim-btn is-active" onclick="{fn_name}_slow()">慢速</button>
      <button id="{block_id}-btn-reset" class="flow-anim-btn" onclick="{fn_name}_reset()">重置</button>
    </div>
  </div>
  {selector_html}
  <div class="flow-anim-hint">{hint_text}</div>
  <div id="{block_id}-classic" class="flow-anim-panel">{classic_content}</div>
  <div id="{block_id}-swimlane" class="flow-anim-panel" style="display:none;">{swimlane_content}</div>
</div>
<script>
(function() {{
  var classic = document.getElementById("{block_id}-classic");
  var swimlane = document.getElementById("{block_id}-swimlane");
  var btnClassic = document.getElementById("{block_id}-btn-classic");
  var btnSwimlane = document.getElementById("{block_id}-btn-swimlane");
  var btnPlay = document.getElementById("{block_id}-btn-play");
  var btnPause = document.getElementById("{block_id}-btn-pause");
  var btnFast = document.getElementById("{block_id}-btn-fast");
  var btnSlow = document.getElementById("{block_id}-btn-slow");
  var btnReset = document.getElementById("{block_id}-btn-reset");
  var flowSelect = document.getElementById("{block_id}-flow-select");
  if (!classic || !swimlane || !btnClassic || !btnSwimlane || !btnPlay || !btnPause || !btnFast || !btnSlow || !btnReset) return;

  var hasFlowSelector = {has_selector_js};
  var flowCount = {flow_count};
  var activeFlow = 0;
  var currentMode = "classic";

  function resizePlot(container) {{
    if (!window.Plotly || !container) return;
    var nodes = container.querySelectorAll(".plotly-graph-div");
    for (var i = 0; i < nodes.length; i++) {{
      try {{ window.Plotly.Plots.resize(nodes[i]); }} catch (e) {{}}
    }}
  }}

  function setBtnState(isClassic) {{
    if (isClassic) {{
      btnClassic.classList.add("is-active");
      btnSwimlane.classList.remove("is-active");
    }} else {{
      btnSwimlane.classList.add("is-active");
      btnClassic.classList.remove("is-active");
    }}
  }}

  function getFlowContainer(mode, idx) {{
    if (!hasFlowSelector) {{
      return mode === "classic" ? classic : swimlane;
    }}
    return document.getElementById("{block_id}-" + mode + "-" + idx);
  }}

  function setFlow(idx) {{
    if (!hasFlowSelector) return;
    var parsed = parseInt(idx, 10);
    if (isNaN(parsed) || parsed < 0 || parsed >= flowCount) parsed = 0;
    activeFlow = parsed;
    if (flowSelect && String(flowSelect.value) !== String(activeFlow)) {{
      flowSelect.value = String(activeFlow);
    }}
    for (var i = 0; i < flowCount; i++) {{
      var c = document.getElementById("{block_id}-classic-" + i);
      var s = document.getElementById("{block_id}-swimlane-" + i);
      if (c) c.style.display = i === activeFlow ? "block" : "none";
      if (s) s.style.display = i === activeFlow ? "block" : "none";
    }}
    fitActivePlot();
  }}

  var speedMode = "slow";

  function setSpeedState(mode) {{
    speedMode = mode === "fast" ? "fast" : "slow";
    if (speedMode === "fast") {{
      btnFast.classList.add("is-active");
      btnSlow.classList.remove("is-active");
    }} else {{
      btnSlow.classList.add("is-active");
      btnFast.classList.remove("is-active");
    }}
  }}

  function getActiveContainer() {{
    return getFlowContainer(currentMode, activeFlow);
  }}

  function getActivePlot() {{
    var container = getActiveContainer();
    if (!container) return null;
    return container.querySelector(".plotly-graph-div");
  }}

  function relayoutResponsive(plot) {{
    if (!window.Plotly || !plot || !plot.layout) return;
    var host = plot.parentElement || plot;
    var width = Math.max(320, Math.floor(host.clientWidth || plot.clientWidth || window.innerWidth || 1024));
    var compact = width < 900;
    var tiny = width < 640;
    var isClassicView = currentMode === "classic";
    var annotationY = tiny ? (isClassicView ? -0.44 : -0.44) : (isClassicView ? -0.40 : -0.40);
    var sliderY = tiny ? (isClassicView ? -0.66 : -0.66) : (isClassicView ? -0.58 : -0.58);
    var marginBottom = tiny ? (isClassicView ? 410 : 410) : (isClassicView ? 360 : 360);
    var updates = {{}};

    updates["yaxis.tickfont.size"] = tiny ? 9 : (compact ? 10 : 11);
    updates["xaxis.tickfont.size"] = tiny ? 10 : 11;
    updates["margin.b"] = marginBottom;

    if (plot.layout.annotations && plot.layout.annotations.length >= 1) {{
      updates["annotations[0].font.size"] = tiny ? 10 : 12;
    }}
    if (plot.layout.annotations && plot.layout.annotations.length >= 2) {{
      updates["annotations[1].font.size"] = tiny ? 10 : 12;
    }}
    if (plot.layout.annotations && plot.layout.annotations.length >= 3) {{
      updates["annotations[2].font.size"] = tiny ? 10 : 12;
      updates["annotations[2].y"] = annotationY;
      updates["annotations[2].yanchor"] = "top";
    }}
    if (plot.layout.sliders && plot.layout.sliders.length >= 1) {{
      updates["sliders[0].y"] = sliderY;
      updates["sliders[0].x"] = tiny ? 0.06 : 0.08;
      updates["sliders[0].len"] = tiny ? 0.9 : 0.9;
    }}
    try {{ window.Plotly.relayout(plot, updates); }} catch (e) {{}}
  }}

  function fitActivePlot() {{
    var container = getActiveContainer();
    resizePlot(container);
    var plot = getActivePlot();
    relayoutResponsive(plot);
    resizePlot(container);
  }}

  var resizeTimer = null;
  function scheduleFit() {{
    if (resizeTimer) {{
      clearTimeout(resizeTimer);
    }}
    resizeTimer = setTimeout(function() {{
      fitActivePlot();
    }}, 120);
  }}

  function playOptions() {{
    var isClassicView = currentMode === "classic";
    if (speedMode === "fast") {{
      if (isClassicView) {{
        return {{
          frame: {{ duration: 230, redraw: false }},
          transition: {{ duration: 130, easing: "linear" }},
          fromcurrent: false
        }};
      }}
      return {{
        frame: {{ duration: 860, redraw: true }},
        transition: {{ duration: 200, easing: "linear" }},
        fromcurrent: false
      }};
    }}
    if (isClassicView) {{
      return {{
        frame: {{ duration: 360, redraw: false }},
        transition: {{ duration: 220, easing: "linear" }},
        fromcurrent: false
      }};
    }}
    return {{
      frame: {{ duration: 1120, redraw: true }},
      transition: {{ duration: 260, easing: "linear" }},
      fromcurrent: false
    }};
  }}

  function getPlayableFrames(plot) {{
    if (!plot || !plot._transitionData || !plot._transitionData._frames) return [];
    var frames = plot._transitionData._frames;
    var names = [];
    for (var i = 0; i < frames.length; i++) {{
      var nm = frames[i] && frames[i].name ? String(frames[i].name) : "";
      if (nm && nm !== "init") names.push(nm);
    }}
    return names;
  }}

  function playFromStart() {{
    var plot = getActivePlot();
    if (!plot || !window.Plotly) return;
    var seq = getPlayableFrames(plot);
    if (!seq.length) {{
      window.Plotly.animate(plot, null, playOptions());
      return;
    }}
    window.Plotly.animate(plot, ["init"], {{
      frame: {{ duration: 0, redraw: true }},
      mode: "immediate"
    }});
    setTimeout(function() {{
      window.Plotly.animate(plot, seq, playOptions());
    }}, 20);
  }}

  window["{fn_name}_play"] = function() {{
    playFromStart();
  }};

  window["{fn_name}_pause"] = function() {{
    var plot = getActivePlot();
    if (!plot || !window.Plotly) return;
    window.Plotly.animate(plot, [null], {{
      frame: {{ duration: 0, redraw: false }},
      mode: "immediate"
    }});
  }};

  window["{fn_name}_fast"] = function() {{
    setSpeedState("fast");
    playFromStart();
  }};

  window["{fn_name}_slow"] = function() {{
    setSpeedState("slow");
    playFromStart();
  }};

  window["{fn_name}_reset"] = function() {{
    var plot = getActivePlot();
    if (!plot || !window.Plotly) return;
    window.Plotly.animate(plot, ["init"], {{
      frame: {{ duration: 0, redraw: true }},
      mode: "immediate"
    }});
  }};

  window["{fn_name}_selectFlow"] = function(index) {{
    if (!hasFlowSelector) return;
    setFlow(index);
    window["{fn_name}_reset"]();
  }};

  window["{fn_name}"] = function(mode) {{
    var isClassic = mode !== "swimlane";
    currentMode = isClassic ? "classic" : "swimlane";
    classic.style.display = isClassic ? "block" : "none";
    swimlane.style.display = isClassic ? "none" : "block";
    setBtnState(isClassic);
    scheduleFit();
  }};

  if (window.addEventListener) {{
    window.addEventListener("resize", scheduleFit);
    window.addEventListener("orientationchange", scheduleFit);
  }}

  if (hasFlowSelector) {{
    setFlow(0);
  }}
  setSpeedState("slow");
  window["{fn_name}"]("classic");
  scheduleFit();
}})();
</script>
"""
