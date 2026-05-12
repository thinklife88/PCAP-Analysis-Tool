"""Input validation helpers."""

import os
from pathlib import Path
from typing import Tuple


class ValidationError(Exception):
    pass


class FileValidator:
    VALID_EXTENSIONS = {".pcap", ".pcapng"}
    MAX_FILE_SIZE_WARNING = 500 * 1024 * 1024  # 500 MB

    @staticmethod
    def validate_file(file_path: str) -> Tuple[bool, str]:
        path = Path(file_path)

        if not path.exists():
            return False, f"文件不存在: {file_path}"
        if not path.is_file():
            return False, f"不是有效文件: {file_path}"
        if path.suffix.lower() not in FileValidator.VALID_EXTENSIONS:
            return False, f"不支持的格式: {path.suffix}，仅支持 .pcap/.pcapng"

        size = path.stat().st_size
        if size == 0:
            return False, "文件为空"

        if not os.access(file_path, os.R_OK):
            return False, "文件无读取权限"

        if size > FileValidator.MAX_FILE_SIZE_WARNING:
            return True, f"警告: 文件较大 ({size / 1024 / 1024:.2f} MB)，分析可能较慢"

        return True, "验证通过"

    @staticmethod
    def validate_directory(dir_path: str) -> Tuple[bool, str]:
        path = Path(dir_path)
        if not path.exists():
            return False, f"目录不存在: {dir_path}"
        if not path.is_dir():
            return False, f"不是有效目录: {dir_path}"
        return True, "验证通过"
