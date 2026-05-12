# QUICKSTART（5 分钟上手）

## 1) 安装依赖

```bash
python -m pip install -r requirements.txt
```

确保机器已安装 Wireshark/tshark。

- Windows：安装 Wireshark 后通常会带上 tshark
- Linux：`sudo apt install tshark`
- macOS：`brew install wireshark`

## 2) 首次配置（可选但推荐）

如果程序找不到 tshark，先运行：

```bash
python main.py setup
```

## 3) 先跑一次交互模式（推荐）

```bash
python main.py interactive
```

常用菜单：
- `0` AI 分析设置
- `1` 分析新文件
- `7` 重置程序（清理 AI 配置/历史/报告/日志/缓存）
- `8` 退出

## 4) 命令行最小可用示例

### 快速体检（全流量）

```bash
python main.py analyze .\your.pcap --mode quick --all --report-formats html
```

### 深度分析（按范围）

```bash
python main.py analyze .\your.pcapng --mode deep --scope-ip 10.190.27.55 --scope-protocol tcp --report-formats html,markdown
```

### 故障诊断（可选启用 AI）

```bash
python main.py analyze .\your.pcap --mode diagnosis --scope-display-filter "tcp.flags.reset==1" --ai --report-formats all
```

## 5) 三种模式怎么选

- `quick`：先看全局，速度优先
- `deep`：定位问题细节，信息更完整
- `diagnosis`：输出最全面，适合形成排障闭环

## 6) 输出文件在哪里

默认在 `reports/` 目录下：
- `report_<文件名>_<时间戳>.html`
- `report_<文件名>_<时间戳>.md`
- `report_<文件名>_<时间戳>.json`
- `report_<文件名>_<时间戳>_clean.json`

## 7) 常见排错

### 报错“未找到 tshark”
执行 `python main.py setup`，或把 tshark 加入 PATH。

### 控制台中文显示异常（Windows）
可先执行：

```powershell
chcp 65001 > $null
$env:PYTHONUTF8='1'
```

然后再运行 `python main.py interactive` 或 `python main.py analyze ...`。

### 准备拷贝项目给他人前做脱敏
在交互菜单选择 `7 重置程序`。
