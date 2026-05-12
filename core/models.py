"""Core data models used across parser, metrics, and diagnosis layers."""

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class Protocol(str, Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    ARP = "ARP"
    DNS = "DNS"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    TLS = "TLS"
    OTHER = "OTHER"


class PacketInfo(BaseModel):
    """Per-packet normalized model."""

    number: int
    timestamp: float
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    # Backward-compatible protocol field.
    # Kept as transport-layer protocol after this refactor.
    protocol: Protocol

    # New protocol split fields.
    transport_protocol: Protocol = Protocol.OTHER
    application_protocol: Optional[Protocol] = None

    length: int
    tcp_flags: Optional[str] = None
    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None
    tcp_stream_id: Optional[int] = None
    tcp_payload_hex: Optional[str] = None
    tcp_window: Optional[int] = None
    tcp_header_len: Optional[int] = None
    tcp_payload_len: Optional[int] = None
    info: Optional[str] = None

    # IP layer
    ip_header_len: Optional[int] = None
    ip_flags: Optional[str] = None
    ip_frag_offset: Optional[int] = None
    ip_id: Optional[int] = None
    ip_ttl: Optional[int] = None
    ip_total_len: Optional[int] = None
    ip_options: Optional[str] = None

    # TCP RTT
    tcp_rtt: Optional[float] = None

    # ICMP
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None

    # ARP (for storm/spoof diagnostics)
    arp_opcode: Optional[int] = None
    arp_src_ip: Optional[str] = None
    arp_dst_ip: Optional[str] = None
    arp_src_mac: Optional[str] = None
    arp_dst_mac: Optional[str] = None

    # Application layer
    http_is_request: bool = False
    http_is_response: bool = False
    http_response_time: Optional[float] = None
    http_status: Optional[int] = None
    dns_id: Optional[int] = None
    dns_is_response: Optional[bool] = None
    dns_response_time: Optional[float] = None
    dns_rcode: Optional[int] = None
    tls_alert_desc: Optional[str] = None

    # tshark expert flags
    is_retransmission: bool = False
    is_dup_ack: bool = False
    is_zero_window: bool = False
    is_window_full: bool = False
    is_fast_retrans: bool = False
    expert_info: Optional[str] = None


class FlowKey(BaseModel):
    """5-tuple flow key."""

    model_config = ConfigDict(frozen=True)

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str

    def __hash__(self):
        return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol))


class Flow(BaseModel):
    """Flow model."""

    key: FlowKey
    packets: List[PacketInfo] = Field(default_factory=list)
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    total_bytes: int = 0
    packet_count: int = 0


class TCPSession(BaseModel):
    """TCP session model."""

    flow_key: FlowKey
    syn_time: Optional[float] = None
    syn_ack_time: Optional[float] = None
    established_time: Optional[float] = None
    fin_time: Optional[float] = None
    rst_time: Optional[float] = None
    state: str = "INIT"
    retransmissions: int = 0
    zero_windows: int = 0


class AnalysisResult(BaseModel):
    """Overall analysis result."""

    file_path: str
    file_size: int
    total_packets: int
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    duration: Optional[float] = None
    protocol_stats: Dict[str, int] = Field(default_factory=dict)
    top_talkers: Dict[str, int] = Field(default_factory=dict)
    anomalies: List[Dict[str, Any]] = Field(default_factory=list)
    metrics: Dict[str, Any] = Field(default_factory=dict)
