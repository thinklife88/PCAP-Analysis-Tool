"""Interactive menu module."""

import ipaddress
import json
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.prompt import Confirm, Prompt

from ui.display import console, print_error, print_header, print_info, print_success, print_warning
from utils.ai_config import AIConfig
from utils.config import get_config
from utils.validator import FileValidator


class HistoryManager:
    def __init__(self, history_file: Optional[str] = None):
        cfg = get_config()
        self.enabled = bool(cfg.get("history.enabled", True))
        self.max_records = int(cfg.get("history.max_records", 50) or 50)
        self.history_file = Path(history_file or cfg.get("history.storage_file", "history.json"))
        self.history = self._load_history() if self.enabled else []

    def _load_history(self) -> List[Dict]:
        if not self.enabled:
            return []
        if self.history_file.exists():
            try:
                with open(self.history_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (UnicodeDecodeError, json.JSONDecodeError):
                try:
                    with open(self.history_file, "r", encoding="gbk") as f:
                        return json.load(f)
                except Exception:
                    return []
        return []

    def add_record(self, file_path: str, result_summary: Dict):
        if not self.enabled:
            return
        from datetime import datetime

        record = {
            "file_path": file_path,
            "timestamp": datetime.now().isoformat(),
            "summary": result_summary,
        }
        self.history.insert(0, record)
        self.history = self.history[: self.max_records]
        self._save_history()

    def _save_history(self):
        if not self.enabled:
            return
        self.history_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.history_file, "w", encoding="utf-8") as f:
            json.dump(self.history, f, ensure_ascii=False, indent=2)

    def get_recent(self, n: int = 10) -> List[Dict]:
        if not self.enabled:
            return []
        return self.history[:n]


class Menu:
    def __init__(self):
        self.history_manager = HistoryManager()

    def show_main_menu(self) -> str:
        print_header("PCAP 分析工具 - 主菜单")
        console.print("[0] AI 分析设置")
        console.print("[1] 分析新文件")
        console.print("[2] 从历史记录选择")
        console.print("[3] 扫描目录")
        console.print("[4] 查看历史记录")
        console.print("[5] 清空历史记录")
        console.print("[6] 常见报文错误知识库查询")
        console.print("[7] 重置程序（清理敏感信息便于拷贝外发）")
        console.print("[8] 退出")
        return Prompt.ask("请选择", choices=["0", "1", "2", "3", "4", "5", "6", "7", "8"], default="1")

    def clear_history(self):
        if not self.history_manager.enabled:
            print_info("History feature is disabled in config.")
            return

        if Confirm.ask("\u786e\u8ba4\u5220\u9664\u6240\u6709\u5386\u53f2\u8bb0\u5f55\uff1f", default=False):
            self.history_manager.history = []
            self.history_manager._save_history()
            print_success("\u5386\u53f2\u8bb0\u5f55\u5df2\u6e05\u7a7a")
        else:
            print_info("\u5df2\u53d6\u6d88\u5220\u9664")

    @staticmethod
    def _resolve_path(path_text: str) -> Path:
        path_obj = Path(str(path_text or "").strip() or ".")
        if not path_obj.is_absolute():
            path_obj = Path.cwd() / path_obj
        return path_obj.resolve()

    @staticmethod
    def _is_within(base: Path, target: Path) -> bool:
        try:
            target.resolve().relative_to(base.resolve())
            return True
        except ValueError:
            return False

    @staticmethod
    def _clear_directory_contents(target_dir: Path, truncate_locked: bool = False) -> Dict[str, int]:
        stats = {"removed": 0, "truncated": 0, "errors": 0}
        if not target_dir.exists() or not target_dir.is_dir():
            return stats

        for item in list(target_dir.iterdir()):
            if item.name == ".git":
                continue
            try:
                if item.is_dir():
                    shutil.rmtree(item)
                    stats["removed"] += 1
                else:
                    item.unlink()
                    stats["removed"] += 1
            except PermissionError:
                if truncate_locked and item.is_file():
                    try:
                        item.write_text("", encoding="utf-8")
                        stats["truncated"] += 1
                    except Exception:
                        stats["errors"] += 1
                else:
                    stats["errors"] += 1
            except Exception:
                stats["errors"] += 1
        return stats

    def reset_program(self):
        cfg = get_config()
        workspace = Path.cwd().resolve()

        history_path = self._resolve_path(cfg.get("history.storage_file", "history.json"))
        report_dir = self._resolve_path(cfg.get("report.output_dir", "reports"))
        log_file = self._resolve_path(cfg.get("logging.file", "logs/analyzer.log"))
        log_dir = log_file.parent

        report_files = (
            len([p for p in report_dir.rglob("*") if p.is_file()])
            if report_dir.exists() and report_dir.is_dir()
            else 0
        )
        log_files = (
            len([p for p in log_dir.rglob("*") if p.is_file()])
            if log_dir.exists() and log_dir.is_dir()
            else 0
        )
        pycache_dirs = [p for p in workspace.rglob("__pycache__") if p.is_dir()]

        print_header("程序重置（敏感信息清理）")
        console.print("将执行以下清理动作：")
        console.print("  1. 重置 AI 分析配置为默认安全值（关闭 AI 并清空 API Key）")
        console.print(f"  2. 清空历史记录（内存 {len(self.history_manager.history)} 条 + 文件 {history_path.name}）")
        console.print(f"  3. 清空报告目录：{report_dir}（当前 {report_files} 个文件）")
        console.print(f"  4. 清空日志目录：{log_dir}（当前 {log_files} 个文件）")
        console.print(f"  5. 清理缓存目录 __pycache__（当前 {len(pycache_dirs)} 个）")
        console.print("[yellow]注意：该操作不可撤销。[/yellow]")

        if not Confirm.ask("确认执行重置程序并清理以上内容？", default=False):
            print_info("已取消重置。")
            return

        skipped_paths: List[str] = []
        errors: List[str] = []

        try:
            AIConfig.reset_to_default()
        except Exception as exc:
            errors.append(f"AI config reset failed: {exc}")

        self.history_manager.history = []
        try:
            if self._is_within(workspace, history_path):
                if history_path.exists():
                    history_path.unlink()
            else:
                skipped_paths.append(str(history_path))
        except Exception as exc:
            errors.append(f"history cleanup failed: {exc}")

        report_stats = {"removed": 0, "truncated": 0, "errors": 0}
        try:
            if self._is_within(workspace, report_dir):
                report_stats = self._clear_directory_contents(report_dir, truncate_locked=False)
            else:
                skipped_paths.append(str(report_dir))
        except Exception as exc:
            errors.append(f"report cleanup failed: {exc}")

        log_stats = {"removed": 0, "truncated": 0, "errors": 0}
        try:
            if self._is_within(workspace, log_dir):
                log_stats = self._clear_directory_contents(log_dir, truncate_locked=True)
            else:
                skipped_paths.append(str(log_dir))
        except Exception as exc:
            errors.append(f"log cleanup failed: {exc}")

        pycache_removed = 0
        for cache_dir in pycache_dirs:
            try:
                if self._is_within(workspace, cache_dir):
                    shutil.rmtree(cache_dir)
                    pycache_removed += 1
            except Exception as exc:
                errors.append(f"cache cleanup failed: {cache_dir}: {exc}")

        print_success("程序重置完成。")
        print_info(
            "清理统计："
            f" report_removed={report_stats['removed']},"
            f" log_removed={log_stats['removed']},"
            f" log_truncated={log_stats['truncated']},"
            f" pycache_removed={pycache_removed}"
        )
        if report_stats["errors"] or log_stats["errors"]:
            print_warning(
                f"部分文件清理失败：report_errors={report_stats['errors']}, log_errors={log_stats['errors']}"
            )
        if skipped_paths:
            print_warning("以下路径不在工作目录内，已跳过清理：")
            for item in skipped_paths:
                console.print(f"  - {item}")
        if errors:
            print_warning("发生部分错误：")
            for item in errors:
                console.print(f"  - {item}")

    def query_error(self):
        from utils import error_knowledge

        print_header("常见报文错误知识库查询")
        term = Prompt.ask("请输入关键词(如 Retransmission/Dup ACK/TLS Alert)").strip()
        if not term:
            print_info("未输入关键词")
            return
        results = error_knowledge.search(term)
        if not results:
            print_info("未查询到匹配项")
            return

        for item in results:
            console.print(f"\n[bold cyan]{item['name']}[/bold cyan]")
            meta_parts = []
            if item.get("category"):
                meta_parts.append(f"分类: {item['category']}")
            if item.get("severity"):
                meta_parts.append(f"建议关注级别: {item['severity']}")
            if meta_parts:
                console.print(" | ".join(meta_parts))
            if item.get("meaning"):
                console.print(f"含义: {item['meaning']}")
            if item.get("quick_checks"):
                console.print("快速排查:")
                for check in item["quick_checks"][:3]:
                    console.print(f"  - {check}")
            if item.get("causes"):
                console.print("可能原因:")
                for cause in item["causes"]:
                    console.print(f"  - {cause}")
            if item.get("scenarios"):
                console.print("易发场景:")
                for scene in item["scenarios"]:
                    console.print(f"  - {scene}")

    def get_file_path(self) -> Optional[str]:
        while True:
            file_path = Prompt.ask("请输入 PCAP 文件路径")
            if not file_path:
                return None

            valid, message = FileValidator.validate_file(file_path)
            if valid:
                if "警告" in message:
                    print_info(message)
                    if not Confirm.ask("是否继续？", default=False):
                        continue
                return file_path
            print_error(message)

    def get_directory_path(self) -> Optional[str]:
        while True:
            dir_path = Prompt.ask("请输入需要扫描的目录路径")
            if not dir_path:
                return None
            valid, message = FileValidator.validate_directory(dir_path)
            if valid:
                return dir_path
            print_error(message)

    def select_file_from_directory(self, files: List[Path]) -> Optional[str]:
        print_header(f"发现 {len(files)} 个抓包文件")
        top_n = min(20, len(files))
        for i, path in enumerate(files[:top_n], 1):
            console.print(f"[{i}] {path}")
        if len(files) > top_n:
            console.print(f"... 其余 {len(files) - top_n} 个文件省略显示")
        console.print("[A] 分析全部")
        console.print("[0] 返回")

        choice = Prompt.ask("请选择文件编号", default="0")
        if choice.lower() == "a":
            return "__ALL__"
        if choice == "0":
            return None
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(files):
                return str(files[idx])
        except ValueError:
            pass

        print_error("无效选择")
        return None

    def select_from_history(self) -> Optional[str]:
        if not self.history_manager.enabled:
            print_info("History feature is disabled in config.")
            return None

        recent = self.history_manager.get_recent(10)
        if not recent:
            print_info("\u6682\u65e0\u5386\u53f2\u8bb0\u5f55")
            return None

        print_header("\u6700\u8fd1\u5206\u6790\u6587\u4ef6")
        for i, record in enumerate(recent, 1):
            console.print(f"[{i}] {record['file_path']} ({record['timestamp']})")

        choice = Prompt.ask("\u9009\u62e9\u7f16\u53f7 (0 \u8fd4\u56de)", default="0")
        if choice == "0":
            return None
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(recent):
                return recent[idx]["file_path"]
        except ValueError:
            pass
        print_error("\u65e0\u6548\u9009\u62e9")
        return None

    def select_analysis_mode(self) -> str:
        print_header("选择分析模式")
        console.print("[1] 快速体检 (推荐)")
        console.print("[2] 深度分析")
        console.print("[3] 故障诊断")
        choice = Prompt.ask("请选择", choices=["1", "2", "3"], default="1")
        return {"1": "quick", "2": "deep", "3": "diagnosis"}[choice]

    def select_analysis_scope(self) -> Dict[str, Any]:
        print_header("\u9009\u62e9\u5206\u6790\u8303\u56f4")
        console.print("[1] \u6307\u5b9a\u4e1a\u52a1IP\uff08\u6e90IP\u6216\u76ee\u6807IP\u5339\u914d\uff09")
        console.print("[2] \u5206\u6790\u5168\u90e8")
        console.print("[3] \u9ad8\u7ea7\u8303\u56f4\uff08IP/\u7aef\u53e3/\u534f\u8bae/\u65f6\u95f4\u7a97/\u8fc7\u6ee4\u5668\u53ef\u7ec4\u5408\uff09")
        choice = Prompt.ask("\u8bf7\u9009\u62e9", choices=["1", "2", "3"], default="2")
        if choice == "2":
            return {"mode": "all", "ip": None}

        if choice == "1":
            while True:
                ip_text = Prompt.ask("\u8bf7\u8f93\u5165\u9700\u8981\u5206\u6790\u7684IP").strip()
                if not ip_text:
                    print_error("IP\u4e0d\u80fd\u4e3a\u7a7a\uff0c\u8bf7\u91cd\u65b0\u8f93\u5165")
                    continue
                try:
                    ip_obj = ipaddress.ip_address(ip_text)
                except ValueError:
                    print_error("IP\u683c\u5f0f\u4e0d\u6b63\u786e\uff0c\u8bf7\u8f93\u5165\u5408\u6cd5IPv4/IPv6\u5730\u5740")
                    continue
                return {"mode": "ip", "ip": ip_obj.compressed}

        # Advanced scope (optional composable filters)
        ip_value: Optional[str] = None
        port_values: List[int] = []
        protocol_value: Optional[str] = None
        time_start: Optional[float] = None
        time_end: Optional[float] = None
        display_filter: Optional[str] = None

        ip_text = Prompt.ask("IP\u8fc7\u6ee4\uff08\u53ef\u9009\uff0c\u7559\u7a7a\u8df3\u8fc7\uff09", default="").strip()
        if ip_text:
            try:
                ip_value = ipaddress.ip_address(ip_text).compressed
            except ValueError:
                print_error("IP\u683c\u5f0f\u9519\u8bef\uff0c\u5ffd\u7565IP\u8fc7\u6ee4")
                ip_value = None

        port_text = Prompt.ask("\u7aef\u53e3\u8fc7\u6ee4\uff08\u53ef\u9009\uff0c\u652f\u6301\u9017\u53f7\u5206\u9694\uff09", default="").strip()
        if port_text:
            parsed_ports: List[int] = []
            for token in port_text.split(","):
                token = token.strip()
                if not token:
                    continue
                try:
                    port = int(token)
                    if 1 <= port <= 65535:
                        parsed_ports.append(port)
                except Exception:
                    continue
            port_values = sorted(set(parsed_ports))
            if not port_values:
                print_error("\u7aef\u53e3\u8fc7\u6ee4\u683c\u5f0f\u65e0\u6548\uff0c\u5df2\u5ffd\u7565")

        proto_text = Prompt.ask(
            "\u534f\u8bae\u8fc7\u6ee4\uff08\u53ef\u9009\uff1atcp|udp|icmp|arp|dns|http|tls\uff09",
            default="",
        ).strip().lower()
        if proto_text:
            if proto_text in {"tcp", "udp", "icmp", "arp", "dns", "http", "tls"}:
                protocol_value = proto_text
            elif proto_text == "icmpv6":
                protocol_value = "icmp"
            elif proto_text == "https":
                protocol_value = "tls"
            else:
                print_error("\u534f\u8bae\u503c\u65e0\u6548\uff0c\u5df2\u5ffd\u7565")

        time_start_text = Prompt.ask(
            "\u65f6\u95f4\u7a97\u8d77\u70b9s\uff08\u53ef\u9009\uff0c\u76f8\u5bf9\u6293\u5305\u5f00\u59cb\uff09",
            default="",
        ).strip()
        if time_start_text:
            try:
                time_start = max(0.0, float(time_start_text))
            except Exception:
                print_error("\u65f6\u95f4\u7a97\u8d77\u70b9\u683c\u5f0f\u65e0\u6548\uff0c\u5df2\u5ffd\u7565")
                time_start = None

        time_end_text = Prompt.ask(
            "\u65f6\u95f4\u7a97\u7ec8\u70b9s\uff08\u53ef\u9009\uff0c\u76f8\u5bf9\u6293\u5305\u5f00\u59cb\uff09",
            default="",
        ).strip()
        if time_end_text:
            try:
                time_end = max(0.0, float(time_end_text))
            except Exception:
                print_error("\u65f6\u95f4\u7a97\u7ec8\u70b9\u683c\u5f0f\u65e0\u6548\uff0c\u5df2\u5ffd\u7565")
                time_end = None
        if time_start is not None and time_end is not None and time_end < time_start:
            time_start, time_end = time_end, time_start

        display_filter_text = Prompt.ask(
            "tshark display filter\uff08\u53ef\u9009\uff0c\u4f8b\u5982 tcp.flags.reset==1\uff09",
            default="",
        ).strip()
        if display_filter_text:
            display_filter = display_filter_text

        has_scope = bool(ip_value or port_values or protocol_value or time_start is not None or time_end is not None or display_filter)
        if not has_scope:
            return {"mode": "all", "ip": None}

        mode = "ip" if ip_value and not (port_values or protocol_value or time_start is not None or time_end is not None or display_filter) else "custom"
        return {
            "mode": mode,
            "ip": ip_value,
            "ports": port_values,
            "protocol": protocol_value,
            "time_start": time_start,
            "time_end": time_end,
            "display_filter": display_filter,
        }

    def select_report_formats(self) -> List[str]:
        print_header("选择报告格式")
        console.print("[1] HTML (推荐)")
        console.print("[2] Markdown")
        console.print("[3] JSON")
        console.print("[4] 全部")
        choice = Prompt.ask("请选择", choices=["1", "2", "3", "4"], default="1")

        mapping = {
            "1": ["html"],
            "2": ["markdown"],
            "3": ["json"],
            "4": ["html", "markdown", "json"],
        }
        return mapping[choice]
