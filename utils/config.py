"""Configuration management with validation and migration support."""

import os
from pathlib import Path
from typing import Any, Dict

import yaml


class ConfigError(Exception):
    pass


class UniqueKeyLoader(yaml.SafeLoader):
    """YAML loader that rejects duplicate keys."""


def _construct_mapping(loader: UniqueKeyLoader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ConfigError(f"Duplicate config key detected: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping
)


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


class Config:
    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = Path(config_path)
        self._config = self._load_config()

    @staticmethod
    def _defaults() -> Dict[str, Any]:
        return {
            "analysis": {
                "batch_size": 10000,
                "timeout_seconds": 3600,
                "max_memory_mb": 1024,
                "memory_packet_bytes_estimate": 350,
                "dynamic_threshold": {
                    "enabled": True,
                    "std_multiplier": 2,
                    "window_seconds": 10,
                    "min_window_packets": 20,
                    "min_flow_packets": 20,
                    "min_windows": 3,
                    "learning_margin": 1.15,
                },
                "quick_ip_guard": {
                    "enabled": True,
                    "file_size_mb_warn": 500,
                    "max_packets": 200000,
                    "adaptive_packets_per_mb": 1200,
                    "adaptive_min_packets": 80000,
                    "adaptive_max_packets": 300000,
                },
                "tcp_payload_backfill": {
                    "enabled": False,
                },
                "thresholds": {
                    "retransmission_rate": 0.05,
                    "rst_rate": 0.02,
                    "rtt_high_ms": 500,
                    "max_interval_s": 5.0,
                    "dns_latency_high_ms": 200,
                    "handshake_synack_high_ms": 300,
                    "handshake_ack_high_ms": 300,
                    "quick_disconnect_s": 2.0,
                    "http_ttfb_high_ms": 800,
                    "window_full_threshold": 30,
                    "window_full_flow_ratio": 0.1,
                    "rtt_jitter_cv_high": 0.6,
                    "throughput_jitter_cv_high": 0.8,
                    "syn_retry_min_count": 3,
                    "syn_retry_flow_threshold": 3,
                    "pmtud_icmp_frag_needed_threshold": 3,
                    "pmtud_retrans_rate_threshold": 0.05,
                    "pmtud_suspect_flow_threshold": 2,
                    "dns_failure_rate": 0.05,
                    "http_error_rate": 0.1,
                    "zero_window_threshold": 10,
                    "connection_leak_duration_s": 120.0,
                    "connection_leak_min_packets": 30,
                    "broadcast_rate": 1000,
                    "arp_min_packets": 30,
                    "arp_storm_rate_pps": 60.0,
                    "arp_storm_window_packets": 200,
                    "asymmetry_ratio": 10,
                    "traffic_burst_ratio": 2.5,
                    "traffic_burst_min_pps": 120.0,
                    "traffic_burst_min_windows": 1,
                    "half_open_flows": 50,
                    "port_scan_syn_count": 100,
                    "port_scan_syn_ratio": 0.8,
                },
            },
            "ai_analysis": {
                "enabled": False,
                "provider": "openai",
                "api_base": "https://api.openai.com/v1",
                "api_key": "",
                "model": "gpt-4o-mini",
                "temperature": 0.3,
                "max_tokens": 4000,
            },
            "history": {"enabled": True, "max_records": 50, "storage_file": "history.json"},
            "logging": {"file": "logs/analyzer.log", "level": "INFO", "max_size_mb": 10, "backup_count": 5},
            "plugins": {"enabled": True, "auto_load": True, "directory": "plugins"},
            "report": {
                "default_format": "html",
                "formats": ["html", "markdown", "json"],
                "include_charts": True,
                "output_dir": "reports",
                "top_n": 10,
                "plotly_js_mode": "inline",
            },
            "tshark": {"path": "", "custom_paths": []},
        }

    @staticmethod
    def _migrate_legacy_config(config: Dict[str, Any]) -> Dict[str, Any]:
        # Legacy releases stored AI fields under analysis.*
        analysis = config.get("analysis", {})
        ai = config.get("ai_analysis", {})

        legacy_ai_keys = {"enabled", "provider", "api_base", "api_key", "model", "temperature", "max_tokens"}
        if isinstance(analysis, dict):
            legacy_ai_data = {k: analysis.get(k) for k in legacy_ai_keys if k in analysis}
            if legacy_ai_data:
                for key, value in legacy_ai_data.items():
                    if key not in ai or ai.get(key) in (None, ""):
                        ai[key] = value
                config["ai_analysis"] = ai
                for key in legacy_ai_keys:
                    analysis.pop(key, None)
                config["analysis"] = analysis

        # rtt_threshold_ms -> rtt_high_ms compatibility
        thresholds = config.get("analysis", {}).get("thresholds", {})
        if "rtt_high_ms" not in thresholds and "rtt_threshold_ms" in thresholds:
            thresholds["rtt_high_ms"] = thresholds["rtt_threshold_ms"]
        return config

    @staticmethod
    def _apply_env_overrides(config: Dict[str, Any]) -> Dict[str, Any]:
        ai_key = os.getenv("PCAP_AI_API_KEY") or os.getenv("AI_API_KEY")
        if ai_key:
            config.setdefault("ai_analysis", {})
            config["ai_analysis"]["api_key"] = ai_key
            config["ai_analysis"]["enabled"] = True
        return config

    def _load_config(self) -> Dict[str, Any]:
        if not self.config_path.exists():
            raise FileNotFoundError(f"Config file not found: {self.config_path}")

        with open(self.config_path, "r", encoding="utf-8") as f:
            raw_data = yaml.load(f, Loader=UniqueKeyLoader)

        if raw_data is None:
            raw_data = {}
        if not isinstance(raw_data, dict):
            raise ConfigError("Config root must be a mapping object")

        raw_data = self._migrate_legacy_config(raw_data)
        config = _deep_merge(self._defaults(), raw_data)
        config = self._apply_env_overrides(config)
        return config

    def get(self, key: str, default=None) -> Any:
        keys = key.split(".")
        value = self._config
        sentinel = object()
        for k in keys:
            if isinstance(value, dict):
                next_value = value.get(k, sentinel)
                if next_value is sentinel:
                    return default
                value = next_value
            else:
                return default
        return value

    def reload(self):
        self._config = self._load_config()


_config_instance = None


def get_config() -> Config:
    global _config_instance
    if _config_instance is None:
        _config_instance = Config()
    return _config_instance
