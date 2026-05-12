"""日志系统模块"""
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from utils.config import get_config

def setup_logger(name: str = "pcap_analyzer") -> logging.Logger:
    config = get_config()

    logger = logging.getLogger(name)
    level = config.get('logging.level', 'INFO')
    logger.setLevel(getattr(logging, level))

    if logger.handlers:
        return logger

    # 控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_format = logging.Formatter('%(levelname)s: %(message)s')
    console_handler.setFormatter(console_format)

    # 文件处理器
    log_file = Path(config.get('logging.file', 'logs/analyzer.log'))
    log_file.parent.mkdir(parents=True, exist_ok=True)

    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=config.get('logging.max_size_mb', 10) * 1024 * 1024,
        backupCount=config.get('logging.backup_count', 5),
        encoding='utf-8'
    )
    file_handler.setLevel(logging.DEBUG)
    file_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_format)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger
