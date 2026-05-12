"""TShark 路径检测和配置工具"""
import os
import subprocess
from pathlib import Path
from typing import Optional, List
from utils.config import get_config

class TSharkFinder:
    """TShark 查找器"""

    DEFAULT_PATHS = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        r"D:\Wireshark\tshark.exe",
        r"D:\Program Files\Wireshark\tshark.exe",
        r"E:\Wireshark\tshark.exe",
        r"E:\Program Files\Wireshark\tshark.exe",
        r"/usr/bin/tshark",
        r"/usr/local/bin/tshark",
    ]

    @staticmethod
    def find_tshark() -> Optional[str]:
        """查找 tshark 可执行文件"""
        # 1. 检查配置文件中的路径
        config = get_config()
        config_path = config.get('tshark.path', '')
        if config_path and TSharkFinder._verify_tshark(config_path):
            return config_path

        # 2. 检查自定义路径
        custom_paths = config.get('tshark.custom_paths', [])
        for path in custom_paths:
            if TSharkFinder._verify_tshark(path):
                return path

        # 3. 检查默认路径
        for path in TSharkFinder.DEFAULT_PATHS:
            if TSharkFinder._verify_tshark(path):
                return path

        # 4. 检查系统 PATH
        try:
            result = subprocess.run(['tshark', '-v'],
                                  capture_output=True,
                                  timeout=5)
            if result.returncode == 0:
                return 'tshark'
        except:
            pass

        return None

    @staticmethod
    def _verify_tshark(path: str) -> bool:
        """验证 tshark 路径是否有效"""
        if not path:
            return False

        path_obj = Path(path)
        if not path_obj.exists():
            return False

        try:
            result = subprocess.run([str(path_obj), '-v'],
                                  capture_output=True,
                                  timeout=5)
            return result.returncode == 0
        except:
            return False

    @staticmethod
    def search_all_drives() -> List[str]:
        """搜索所有驱动器"""
        found_paths = []

        # Windows: 搜索所有驱动器
        if os.name == 'nt':
            for drive in ['C:', 'D:', 'E:', 'F:', 'G:']:
                possible_paths = [
                    f"{drive}\\Wireshark\\tshark.exe",
                    f"{drive}\\Program Files\\Wireshark\\tshark.exe",
                    f"{drive}\\Program Files (x86)\\Wireshark\\tshark.exe",
                ]
                for path in possible_paths:
                    if TSharkFinder._verify_tshark(path):
                        found_paths.append(path)

        return found_paths

    @staticmethod
    def interactive_setup():
        """交互式配置 tshark 路径"""
        from rich.prompt import Prompt
        from ui.display import console, print_header, print_error, print_success, print_info

        print_header("TShark 配置向导")

        # 尝试自动查找
        print_info("正在搜索 tshark...")
        auto_path = TSharkFinder.find_tshark()

        if auto_path:
            print_success(f"找到 tshark: {auto_path}")
            return auto_path

        # 搜索所有驱动器
        print_info("在所有驱动器中搜索...")
        found_paths = TSharkFinder.search_all_drives()

        if found_paths:
            console.print("\n找到以下 tshark 安装:")
            for i, path in enumerate(found_paths, 1):
                console.print(f"[{i}] {path}")

            choice = Prompt.ask("选择一个路径", choices=[str(i) for i in range(1, len(found_paths)+1)])
            selected_path = found_paths[int(choice)-1]

            # 保存到配置
            TSharkFinder._save_to_config(selected_path)
            print_success(f"已保存配置: {selected_path}")
            return selected_path

        # 手动输入
        print_error("未找到 tshark，请手动输入路径")
        console.print("\n提示:")
        console.print("  - Windows: 通常在 Wireshark 安装目录下")
        console.print("  - 例如: D:\\Wireshark\\tshark.exe")
        console.print("  - 或: D:\\Program Files\\Wireshark\\tshark.exe")

        while True:
            manual_path = Prompt.ask("\n请输入 tshark.exe 完整路径")

            if TSharkFinder._verify_tshark(manual_path):
                TSharkFinder._save_to_config(manual_path)
                print_success(f"验证成功！已保存配置: {manual_path}")
                return manual_path
            else:
                print_error("路径无效或 tshark 无法运行，请重新输入")

    @staticmethod
    def _save_to_config(path: str):
        """保存路径到配置文件"""
        import yaml
        config_file = Path("config.yaml")

        with open(config_file, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)

        if 'tshark' not in config:
            config['tshark'] = {}
        config['tshark']['path'] = path

        with open(config_file, 'w', encoding='utf-8') as f:
            yaml.dump(config, f, allow_unicode=True, default_flow_style=False)
        get_config().reload()
