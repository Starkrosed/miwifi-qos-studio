# Xiaomi Router Scheduled QoS Rate Limiter & Web Studio

基于 Linux 的自动化定时网络限速与实时调速控制系统。通过逆向分析小米路由器（MiWiFi）LuCI 协议，实现夜间自动限速、早晨自动恢复，并提供支持手机/电脑端访问的现代 Web 控制面板与 RESTful HTTP API。包含单设备免限标志位（Exemption Flag）机制以及单设备网络波动周期模拟（Network Fluctuation Simulation）。

## 核心特性

- **单设备网络波动周期模拟 (Network Fluctuation Simulation)**：
  - 支持针对局域网内任意单个目标设备（按 MAC 识别）启动网络波动模拟。
  - 上下行速率从最低阶梯平滑爬升至全速，周期性往复循环（阶梯：0.1 Mbps -> 0.4 Mbps -> 1.6 Mbps -> 6.4 Mbps -> 全速）。
  - **动态周期调节**：支持在 Web 界面输入框中动态设置周期（默认 30 秒，可在 5-300 秒间任意调节），亦可通过 API 参数 `period` 传入；代码中预留 `DEFAULT_FLUCTUATION_PERIOD` 与 `DEFAULT_FLUCTUATION_STAGES` 接口便于自定义阶梯值。
  - **一键即刻停止**：点击“停止波动”即可瞬间中断循环并立即将该设备恢复至无限制全速（0 KB/s）。
  - **静默日志优化**：仅在波动启动与停止时记入日志，循环阶段不产生冗余刷屏。
- **单设备放行标志位 (Exemption Flag) 机制**：
  - 🟢 **手动放行 (置 1 免限)**：在 Web 端点击某设备的【放行】，该设备标志位置 **1**，立即解除限速（全速）。在夜间巡检期间，定时任务会自动跳过该设备，保持高速连接。
  - 🐢 **手动限速 (置 0 管控)**：在 Web 端再次点击【限速】，标志位置 **0**，立即恢复限速，继续受定时巡检管控。
  - 🔄 **早晨自动复位**：每天早上定时恢复全速时，系统会自动清空所有设备的放行标志位并停止波动模拟，夜间重新正常进入全员限速管控。
- **开箱即用的实时调速接口**：
  - 🚀 **上传拉满**：一键将所有设备上传速度放开至最大（无限制全速），同时保持下行限速。
  - 🐢 **全员限速**：一键将所有设备上下行限速至预设值（已放行及波动中设备自动跳过）。
  - ⚡ **恢复全速**：一键撤销所有限制，恢复千兆无限制全速，停止所有波动模拟并重置标志位。
  - 📱 **响应式 Web 控制面板**：局域网内手机或电脑浏览器直接访问 `http://<SERVER_IP>:8899` 即可一键操作，实时显示波动进度、档位与在线设备列表。
- **自动鉴权握手**：自动获取路由器动态 Key 与 DeviceId，执行 `SHA256(nonce + SHA256(pwd + key))` 鉴权并维护 `stok` 会话（带自动重试机制与多线程互斥锁）。
- **设备安全白名单**：支持在配置文件中指定永久 MAC 白名单，白名单设备绝不受任何限速影响。

## 文件结构

```
.
├── config.example.json # 路由器参数与限速配置示例文件（复制为 config.json）
├── config.json         # 实际运行配置文件 (包含密码与私有MAC，已被 .gitignore 保护)
├── state.json          # 放行标志位持久化记录 (自动生成，已加 .gitignore)
├── router_qos.py       # 核心调度脚本与内置 HTTP API / Web Studio 服务器
├── qos.log             # 运行日志（自动生成，仅变动时记录，已加 .gitignore）
├── .gitignore          # Git 忽略规则
└── README.md           # 项目文档
```

## 快速上手

### 1. 克隆项目与安装依赖

```bash
git clone https://github.com/<YOUR_USERNAME>/<REPO_NAME>.git
cd <REPO_NAME>

# Python 3 标准库即可运行，无需第三方依赖
python3 --version
```

### 2. 配置参数

复制示例配置文件并填入路由器的管理密码：

```bash
cp config.example.json config.json
nano config.json
```

`config.json` 格式说明：

```json
{
  "router_ip": "192.168.31.1",
  "password": "YOUR_ROUTER_PASSWORD",
  "speed_kb": 13,
  "limit_time": "01:00",
  "restore_time": "06:00",
  "exclude_macs": [
    "AA:BB:CC:DD:EE:01",
    "AA:BB:CC:DD:EE:02"
  ]
}
```

- `router_ip`: 路由器网关 IP（通常为 `192.168.31.1`）
- `password`: 小米路由器 Web 管理密码
- `speed_kb`: 限速目标值（KB/s，13 KB/s 约等于 0.1 Mbps）
- `limit_time`: 夜间开始限速的时间（24 小时制）
- `restore_time`: 早晨恢复全速的时间（24 小时制）
- `exclude_macs`: 永久白名单 MAC 地址列表（大写）

### 3. 启动 Web 控制面板与 API 服务

```bash
python3 router_qos.py --server 8899
```

服务启动后，可在局域网任意浏览器访问：`http://<SERVER_IP>:8899`。

## HTTP API 接口说明

- **Web 控制面板**：`GET http://<SERVER_IP>:8899`
- **单设备开启网络波动模拟**：
  ```http
  GET / POST http://<SERVER_IP>:8899/api/device/fluctuate?mac=AA:BB:CC:DD:EE:01&period=30
  ```
  *可选参数 `stages`：逗号分隔的速率阶梯，例如 `&stages=13,50,200,800,0`*
- **单设备停止网络波动模拟**：
  ```http
  GET / POST http://<SERVER_IP>:8899/api/device/stop_fluctuate?mac=AA:BB:CC:DD:EE:01
  ```
- **单设备放行（标志位置 1，全速免限）**：
  ```http
  GET / POST http://<SERVER_IP>:8899/api/device/exempt?mac=AA:BB:CC:DD:EE:01
  ```
- **单设备限速（标志位置 0，恢复管控）**：
  ```http
  GET / POST http://<SERVER_IP>:8899/api/device/limit?mac=AA:BB:CC:DD:EE:01
  ```
- **上传速度最大化（下行保持限速）**：
  ```http
  GET / POST http://<SERVER_IP>:8899/api/max-upload
  ```
- **全员限速**：
  ```http
  GET / POST http://<SERVER_IP>:8899/api/limit
  ```
- **彻底恢复全速**：
  ```http
  GET / POST http://<SERVER_IP>:8899/api/restore
  ```
- **获取当前设备状态与波动信息**：
  ```http
  GET http://<SERVER_IP>:8899/api/status
  ```

## 命令行用法 (CLI)

```bash
# 查看所有设备当前限速状态、标志位与波动情况
python3 router_qos.py --status

# 单设备开启网络波动模拟 (可指定周期秒数，默认 30 秒)
python3 router_qos.py --fluctuate <MAC地址> [周期秒数]

# 单设备停止网络波动模拟并恢复全速
python3 router_qos.py --stop-fluctuate <MAC地址>

# 单设备手动放行 (标志位置 1，夜间巡检不限速)
python3 router_qos.py --exempt <MAC地址>

# 单设备手动限速 (标志位置 0，恢复夜间限速管控)
python3 router_qos.py --unexempt <MAC地址>

# 把上传速度改成最大（下行保持限速）
python3 router_qos.py --max-upload

# 立即对未放行设备开启限速
python3 router_qos.py --limit

# 立即解除限速（恢复全速，清空标志位，停止波动）
python3 router_qos.py --restore
```

## Systemd 守护进程常驻 (推荐)

创建用户级 systemd 服务文件 `~/.config/systemd/user/net-speed-api.service`：

```ini
[Unit]
Description=Xiaomi Router Net Speed Limit API & Web Server
After=network.target

[Service]
Type=simple
WorkingDirectory=/path/to/project
ExecStart=/usr/bin/python3 /path/to/project/router_qos.py --server 8899
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
```

启用并启动服务：

```bash
systemctl --user daemon-reload
systemctl --user enable --now net-speed-api.service
```

## 定时任务调度 (Crontab)

如不使用后台内置定时器，也可通过系统的 crontab 进行夜间周期调度：

```cron
# 每天凌晨 01:00 开始限速，并在 01:00 - 05:50 期间每 10 分钟扫描一次新接入设备（已放行及波动中设备自动跳过）
0 1 * * * /usr/bin/python3 '/path/to/project/router_qos.py' --limit >> '/path/to/project/qos.log' 2>&1
*/10 1-5 * * * /usr/bin/python3 '/path/to/project/router_qos.py' --limit >> '/path/to/project/qos.log' 2>&1

# 每天早上 06:00 准时恢复全速并清空放行标志位 (取消限速，终止所有波动)
0 6 * * * /usr/bin/python3 '/path/to/project/router_qos.py' --restore >> '/path/to/project/qos.log' 2>&1
```

## License

MIT License