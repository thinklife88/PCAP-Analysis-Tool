"""AI配置管理模块"""
import yaml
from pathlib import Path
from typing import Dict, Optional
from rich.prompt import Prompt, Confirm
from ui.display import console, print_header, print_success, print_error, print_info

class AIConfig:
    DEFAULT_AI_CONFIG: Dict[str, object] = {
        "enabled": False,
        "provider": "openai",
        "api_base": "https://api.openai.com/v1",
        "api_key": "",
        "model": "gpt-5.4",
        "temperature": 0.3,
        "max_tokens": 4096,
    }
    """AI配置管理器"""

    @staticmethod
    def interactive_setup():
        """交互式AI配置"""
        print_header("AI分析配置向导")

        # 选择AI提供商
        console.print("\n选择AI提供商:")
        console.print("[1] OpenAI")
        console.print("[2] Anthropic (Claude)")
        console.print("[3] Google (Gemini)")
        console.print("[4] Qwen (通义千问)")
        console.print("[5] DeepSeek")
        console.print("[6] 硅基流动 (SiliconFlow)")
        console.print("[7] Ollama (本地部署)")
        console.print("[8] MiniMax")
        console.print("[9] Kimi (月之暗面)")
        console.print("[10] 智谱 (GLM)")
        console.print("[11] 自定义API")

        choice = Prompt.ask("请选择", choices=[str(i) for i in range(1, 12)], default="1")

        provider_map = {
            "1": ("openai", "https://api.openai.com/v1", "gpt-5.4", "OpenAI"),
            "2": ("anthropic", "https://api.anthropic.com", "claude-sonnet-4-6", "Anthropic"),
            "3": ("gemini", "https://generativelanguage.googleapis.com/v1beta", "gemini-3.1-pro", "Google Gemini"),
            "4": ("qwen", "https://dashscope.aliyuncs.com/compatible-mode/v1", "Qwen3.5-27B", "通义千问"),
            "5": ("deepseek", "https://api.deepseek.com/v1", "deepseek-chat", "DeepSeek"),
            "6": ("siliconflow", "https://api.siliconflow.cn/v1", "deepseek-ai/DeepSeek-V3.2", "硅基流动"),
            "7": ("ollama", "http://localhost:11434/v1", "llama2", "Ollama"),
            "8": ("minimax", "https://api.minimax.chat/v1", "MiniMax-M2.5", "MiniMax"),
            "9": ("kimi", "https://api.moonshot.cn/v1", "Kimi-K2.5", "Kimi"),
            "10": ("glm", "https://open.bigmodel.cn/api/paas/v4", "glm-5.1", "智谱GLM"),
            "11": ("custom", "", "", "自定义")
        }

        provider, api_base, model, provider_name = provider_map[choice]

        console.print(f"\n已选择: [cyan]{provider_name}[/cyan]")

        # 自定义配置
        if choice == "11":
            api_base = Prompt.ask("API地址")
            model = Prompt.ask("模型名称")
        else:
            # 允许修改默认配置
            if Confirm.ask(f"使用默认API地址? ({api_base})", default=True):
                pass
            else:
                api_base = Prompt.ask("请输入API地址", default=api_base)

            if Confirm.ask(f"使用默认模型? ({model})", default=True):
                pass
            else:
                model = Prompt.ask("请输入模型名称", default=model)

        # 输入API Key
        console.print(f"\n[yellow]提示: API Key获取方式[/yellow]")
        if choice == "1":
            console.print("  访问: https://platform.openai.com/api-keys")
        elif choice == "2":
            console.print("  访问: https://console.anthropic.com/settings/keys")
        elif choice == "3":
            console.print("  访问: https://makersuite.google.com/app/apikey")
        elif choice == "4":
            console.print("  访问: https://dashscope.console.aliyun.com/apiKey")
        elif choice == "5":
            console.print("  访问: https://platform.deepseek.com/api_keys")
        elif choice == "6":
            console.print("  访问: https://cloud.siliconflow.cn/account/ak")
        elif choice == "7":
            console.print("  本地部署无需API Key，可直接留空")
        elif choice == "8":
            console.print("  访问: https://api.minimax.chat/")
        elif choice == "9":
            console.print("  访问: https://platform.moonshot.cn/console/api-keys")
        elif choice == "10":
            console.print("  访问: https://open.bigmodel.cn/usercenter/apikeys")

        console.print("\n[dim]提示: 输入时不会显示字符（安全保护），直接输入后按回车即可[/dim]")
        api_key = Prompt.ask("API Key (本地模型可留空)", password=True, default="")

        # 保存配置
        AIConfig._save_config(provider, api_base, api_key, model)
        print_success("AI配置已保存！")

        # 测试连接
        if api_key and Confirm.ask("是否测试API连接?"):
            if AIConfig.test_connection():
                print_success("API连接测试成功！")
                if Confirm.ask("是否测试AI模型可用性?"):
                    if AIConfig.test_model_availability():
                        print_success("AI模型可用性测试成功！")
                    else:
                        print_error("AI模型可用性测试失败，请检查模型配置或网络")
            else:
                print_error("API连接测试失败，请检查配置")

    @staticmethod
    def _save_config(provider: str, api_base: str, api_key: str, model: str):
        """保存AI配置"""
        config_file = Path("config.yaml")
        with open(config_file, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)

        config['ai_analysis'] = {
            'enabled': True,
            'provider': provider,
            'api_base': api_base,
            'api_key': api_key,
            'model': model,
            'temperature': 0.3,
            'max_tokens': 4096
        }

        with open(config_file, 'w', encoding='utf-8') as f:
            yaml.dump(config, f, allow_unicode=True, default_flow_style=False)
        from utils.config import get_config
        get_config().reload()

    @staticmethod
    def reset_to_default():
        """Reset AI config to safe defaults and clear API secret."""
        config_file = Path("config.yaml")
        if not config_file.exists():
            raise FileNotFoundError(f"Config file not found: {config_file}")

        with open(config_file, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}
        if not isinstance(config, dict):
            config = {}

        config["ai_analysis"] = dict(AIConfig.DEFAULT_AI_CONFIG)

        with open(config_file, "w", encoding="utf-8") as f:
            yaml.dump(config, f, allow_unicode=True, default_flow_style=False, sort_keys=False)

        from utils.config import get_config
        get_config().reload()

    @staticmethod
    def test_connection() -> bool:
        """测试API连接"""
        try:
            from ai.client import AIClient
            client = AIClient()
            return client.test_connection()
        except Exception as e:
            print_error(f"测试失败: {e}")
            return False

    @staticmethod
    def test_model_availability() -> bool:
        """测试AI模型可用性"""
        try:
            from ai.client import AIClient
            client = AIClient()
            response = client.analyze("你好，你是什么模型？")
            if response and str(response).strip():
                return True
            print_error("模型测试失败：未收到有效响应")
            return False
        except Exception as e:
            print_error(f"模型测试失败: {e}")
            return False

    @staticmethod
    def is_enabled() -> bool:
        """检查AI分析是否启用"""
        from utils.config import get_config
        config = get_config()
        return config.get('ai_analysis.enabled', False)
