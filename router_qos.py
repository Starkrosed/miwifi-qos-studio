#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Xiaomi Router Scheduled QoS Rate Limiter & Modern Studio Web Interface
Controls bandwidth limits on MiWiFi routers via internal LuCI APIs.
Features:
- Per-device exemption flag (放行标志位)
- Merged online & offline device table (防止休眠设备遗漏)
- Change-only execution & logging (有变动才执行、才记日志，无变动静默)
- Network Fluctuation Simulation (单设备网络波动周期模拟：最低至全速周期阶梯波动)
- High-Performance In-Memory Status Cache (<1ms 状态极速返回，防止高频刷路由)
- Cyber-Minimalist Modern Dashboard UI (Zero-lag DOM 局部增量渲染，不卡顿不掉焦)
"""

import sys
import os
import json
import time
import random
import re
import hashlib
import logging
from datetime import datetime
import urllib.request
import urllib.parse
import mimetypes
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import threading
import subprocess

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "config.json")
STATE_FILE = os.path.join(SCRIPT_DIR, "state.json")
LOG_FILE = os.path.join(SCRIPT_DIR, "qos.log")
WEB_DIR = os.path.join(SCRIPT_DIR, "web")

# ==================== 网络波动参数与接口预设 ====================
DEFAULT_FLUCTUATION_PERIOD = 30  # 默认波动周期 (单位: 秒)
# 波动阶梯速率 (单位: KB/s，从最低到最高，0 代表不限速/全速)
DEFAULT_FLUCTUATION_STAGES = [13, 50, 200, 800, 0]

# 全局路由器操作互斥锁，保证多线程与 Web API 并发安全
router_lock = threading.Lock()

# 状态缓存（避免轮询频繁压垮路由器 LuCI）
_status_cache = {
    "data": None,
    "timestamp": 0
}

def invalidate_status_cache():
    global _status_cache
    _status_cache["timestamp"] = 0

# Setup logging: only log when real changes happen
logger = logging.getLogger("router_qos")
logger.setLevel(logging.INFO)
logger.handlers.clear()

file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(file_handler)

stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(stream_handler)

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg = json.load(f)
                if "state" not in cfg:
                    cfg["state"] = 1
                return cfg
        except Exception as e:
            logger.error(f"读取 config.json 失败: {e}")
    return {
        "router_ip": "192.168.31.1",
        "password": "",
        "state": 1,
        "speed_kb": 13,
        "limit_time": "01:00",
        "restore_time": "06:00",
        "exclude_macs": []
    }

def save_config(cfg):
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        logger.error(f"保存 config.json 失败: {e}")
        return False

def get_system_state():
    cfg = load_config()
    return int(cfg.get("state", 1))

def set_system_state(state_val):
    try:
        state_val = int(state_val)
    except Exception:
        return False, "无效的 state 参数"
    if state_val not in (1, 2, 3):
        return False, "state 仅支持 1 (正常运行), 2 (网页端正常/夜间巡检取消), 3 (全部停机关机)"

    cfg = load_config()
    old_st = cfg.get("state", 1)
    cfg["state"] = state_val
    save_config(cfg)

    desc_map = {
        1: "模式 1 (正常运行: 网页端正常，夜间巡检限速正常开启)",
        2: "模式 2 (仅网页端正常运行，夜间巡检已取消，其余照旧)",
        3: "模式 3 (全部停机关机: 路由器完全恢复全速，停止所有流控与 Web 服务)"
    }
    desc = desc_map.get(state_val, "")
    logger.info(f"[系统模式变动] 运行状态由模式 {old_st} 切换至模式 {state_val}: {desc}")

    if state_val == 3:
        restore_rate_limit()

    return True, desc

def load_state():
    """读取放行标志位状态"""
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"exempt_macs": []}

def save_state(state):
    """保存放行标志位状态"""
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)

def get_exempt_macs():
    st = load_state()
    return set(m.upper() for m in st.get("exempt_macs", []))

def add_exempt_mac(mac):
    mac = mac.upper()
    st = load_state()
    cur = set(m.upper() for m in st.get("exempt_macs", []))
    cur.add(mac)
    st["exempt_macs"] = list(cur)
    save_state(st)
    logger.info(f"[状态变动] 设备 {mac} 放行标志位置 1 (手动放行全速，夜间巡检不限速)")

def remove_exempt_mac(mac):
    mac = mac.upper()
    st = load_state()
    cur = set(m.upper() for m in st.get("exempt_macs", []))
    cur.discard(mac)
    st["exempt_macs"] = list(cur)
    save_state(st)
    logger.info(f"[状态变动] 设备 {mac} 放行标志位置 0 (恢复夜间限速管控)")

def clear_all_exempt_macs():
    st = load_state()
    if st.get("exempt_macs"):
        save_state({"exempt_macs": []})
        logger.info("[状态变动] 全员放行标志位已自动重置归零")
    else:
        save_state({"exempt_macs": []})

class MiWiFiClient:
    def __init__(self, router_ip, password):
        self.router_ip = router_ip
        self.password = password
        self.base_url = f"http://{router_ip}"
        self.token = None

    def login(self):
        login_page_url = f"{self.base_url}/cgi-bin/luci/web/home"
        for attempt in range(1, 4):
            try:
                req = urllib.request.urlopen(login_page_url, timeout=10)
                html = req.read().decode("utf-8", errors="ignore")

                key_match = re.search(r"key:\s*['\"]([^'\"]+)['\"]", html)
                dev_match = re.search(r"deviceId\s*=\s*['\"]([^'\"]+)['\"]", html)
                mode_match = re.search(r"newEncryptMode\s*=\s*parseInt\(['\"](\d+)['\"]\)", html)

                key = key_match.group(1) if key_match else ""
                device_id = dev_match.group(1) if dev_match else ""
                encrypt_mode = int(mode_match.group(1)) if mode_match else 1

                nonce = f"0_{device_id}_{int(time.time())}_{random.randint(0, 9999)}"

                if encrypt_mode == 1:
                    h1 = hashlib.sha256((self.password + key).encode("utf-8")).hexdigest()
                    pwd_hash = hashlib.sha256((nonce + h1).encode("utf-8")).hexdigest()
                else:
                    h1 = hashlib.sha1((self.password + key).encode("utf-8")).hexdigest()
                    pwd_hash = hashlib.sha1((nonce + h1).encode("utf-8")).hexdigest()

                data = urllib.parse.urlencode({
                    "username": "admin",
                    "password": pwd_hash,
                    "logtype": "2",
                    "nonce": nonce
                }).encode("utf-8")

                login_api = f"{self.base_url}/cgi-bin/luci/api/xqsystem/login"
                req = urllib.request.Request(login_api, data=data)
                resp = urllib.request.urlopen(req, timeout=10)
                result = json.loads(resp.read().decode("utf-8"))
                if result.get("code") == 0:
                    self.token = result.get("token")
                    return True
                elif attempt < 3:
                    time.sleep(1)
            except Exception as e:
                if attempt < 3:
                    time.sleep(1)
                else:
                    logger.error(f"Router login error after {attempt} attempts: {e}")
        return False

    def api_get(self, endpoint, params=None):
        if not self.token:
            if not self.login():
                return None
        qs = ""
        if params:
            qs = "?" + urllib.parse.urlencode(params)
        url = f"{self.base_url}/cgi-bin/luci/;stok={self.token}/{endpoint}{qs}"
        try:
            req = urllib.request.urlopen(url, timeout=10)
            return json.loads(req.read().decode("utf-8"))
        except Exception as e:
            logger.error(f"API GET error ({endpoint}): {e}")
            return None

    def api_post(self, endpoint, data=None):
        if not self.token:
            if not self.login():
                return None
        post_bytes = b""
        if data:
            post_bytes = urllib.parse.urlencode(data).encode("utf-8")
        url = f"{self.base_url}/cgi-bin/luci/;stok={self.token}/{endpoint}"
        try:
            req = urllib.request.Request(url, data=post_bytes)
            resp = urllib.request.urlopen(req, timeout=10)
            return json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            logger.error(f"API POST error ({endpoint}): {e}")
            return None

    def get_qos_info(self):
        return self.api_get("api/misystem/qos_info")

    def get_all_devices(self):
        devices_map = {}

        # 1. 从 devicelist 获取路由器记录过的全部设备
        d_info = self.api_get("api/misystem/devicelist")
        if d_info and "list" in d_info:
            for d in d_info["list"]:
                mac = d.get("mac", "").upper()
                if not mac:
                    continue
                ip = ""
                if isinstance(d.get("ip"), list) and d["ip"]:
                    ip = d["ip"][0].get("ip", "")
                elif isinstance(d.get("ip"), str):
                    ip = d.get("ip")
                devices_map[mac] = {
                    "mac": mac,
                    "name": d.get("name") or d.get("origin_name") or "Unknown",
                    "ip": ip,
                    "upmax": 0,
                    "downmax": 0
                }

        # 2. 从 qos_info 读取当前实际的限速规则
        q_info = self.get_qos_info()
        if q_info and "list" in q_info:
            for d in q_info["list"]:
                mac = d.get("mac", "").upper()
                if not mac:
                    continue
                qos = d.get("qos", {})
                upmax = int(float(qos.get("upmax", 0)))
                downmax = int(float(qos.get("downmax", 0)))
                if mac not in devices_map:
                    devices_map[mac] = {
                        "mac": mac,
                        "name": d.get("name") or "Unknown",
                        "ip": d.get("ip", ""),
                        "upmax": upmax,
                        "downmax": downmax
                    }
                else:
                    devices_map[mac]["upmax"] = upmax
                    devices_map[mac]["downmax"] = downmax
                    if d.get("name") and d.get("name") != "Unknown":
                        devices_map[mac]["name"] = d.get("name")
                    if d.get("ip"):
                        devices_map[mac]["ip"] = d.get("ip")

        return devices_map, q_info

    def ensure_qos_enabled(self):
        info = self.get_qos_info()
        if not info:
            return False
        status = info.get("status", {})
        is_on = status.get("on", 0)
        mode = status.get("mode", 0)

        if is_on != 1:
            self.api_get("api/misystem/qos_switch", {"on": 1})

        if mode != 3:
            self.api_get("api/misystem/qos_mode", {"mode": 3})

        return True

    def set_limits(self, limit_list):
        post_data = {"data": json.dumps(limit_list)}
        res = self.api_post("api/misystem/qos_limits", post_data)
        return res and res.get("code") == 0

def create_router_client():
    cfg = load_config()
    return MiWiFiClient(cfg["router_ip"], cfg["password"])

# ==================== 网络波动模拟管理器 ====================
class FluctuationManager:
    """
    负责单设备网络周期波动模拟的后台线程调度器。
    周期性将上下行速率从最低阶梯平滑过渡到最高阶梯(全速)，实现逼真的网络波动。
    严格遵循有变动才记日志的准则，仅在启动和停止时记入日志。
    """
    def __init__(self, client_factory, r_lock):
        self.client_factory = client_factory
        self.router_lock = r_lock
        self.active = {}  # mac -> {thread, stop_event, period, stages, current_step, current_speed, start_time}
        self.lock = threading.Lock()

    def is_fluctuating(self, mac):
        mac = mac.upper()
        with self.lock:
            return mac in self.active

    def get_status(self, mac):
        mac = mac.upper()
        with self.lock:
            item = self.active.get(mac)
            if not item:
                return None
            return {
                "active": True,
                "period": item["period"],
                "stages": item["stages"],
                "current_step": item["current_step"],
                "total_steps": len(item["stages"]),
                "current_speed": item["current_speed"],
                "elapsed": round(time.time() - item["start_time"], 1)
            }

    def start(self, mac, period=None, stages=None):
        mac = mac.upper()
        if period is None:
            period = DEFAULT_FLUCTUATION_PERIOD
        period = max(5, int(period))

        if stages is None:
            stages = DEFAULT_FLUCTUATION_STAGES
        stages = [int(s) for s in stages]
        if not stages:
            stages = DEFAULT_FLUCTUATION_STAGES

        # 如果已有运行中的波动任务，先平稳终止旧任务
        self.stop(mac, log_stop=False)

        stop_event = threading.Event()
        status_info = {
            "period": period,
            "stages": stages,
            "current_step": 0,
            "current_speed": stages[0],
            "start_time": time.time(),
            "stop_event": stop_event
        }

        def _worker():
            step_delay = max(1.0, float(period) / len(stages))
            idx = 0
            while not stop_event.is_set():
                speed = stages[idx % len(stages)]
                with self.lock:
                    if mac in self.active:
                        self.active[mac]["current_step"] = idx % len(stages)
                        self.active[mac]["current_speed"] = speed

                # 下发给路由器执行限速
                with self.router_lock:
                    try:
                        client = self.client_factory()
                        if client.login():
                            client.set_limits([{"mac": mac, "maxup": str(speed), "maxdown": str(speed)}])
                    except Exception as e:
                        logger.error(f"[网络波动异常] 设备 {mac} 阶梯速率设置失败: {e}")

                idx += 1
                if stop_event.wait(step_delay):
                    break

            # 停止循环后，自动恢复全速 (0 KB/s = 不限速)
            with self.router_lock:
                try:
                    client = self.client_factory()
                    if client.login():
                        client.set_limits([{"mac": mac, "maxup": "0", "maxdown": "0"}])
                except Exception as e:
                    logger.error(f"[网络波动恢复] 设备 {mac} 恢复全速失败: {e}")

        t = threading.Thread(target=_worker, name=f"Fluctuation-{mac}", daemon=True)
        status_info["thread"] = t
        with self.lock:
            self.active[mac] = status_info
        t.start()

        invalidate_status_cache()
        logger.info(f"[网络波动] 设备 {mac} 启动网络波动模拟 (周期={period}s, 阶梯={stages})")
        return True

    def stop(self, mac, log_stop=True):
        mac = mac.upper()
        with self.lock:
            item = self.active.pop(mac, None)

        if item:
            item["stop_event"].set()
            item["thread"].join(timeout=3.0)
            invalidate_status_cache()
            if log_stop:
                logger.info(f"[网络波动] 设备 {mac} 停止网络波动模拟并恢复全速")
            return True
        return False

    def stop_all(self):
        with self.lock:
            macs = list(self.active.keys())
        for m in macs:
            self.stop(m, log_stop=True)
        invalidate_status_cache()

fluctuation_manager = FluctuationManager(create_router_client, router_lock)

# ==================== 速率管控业务逻辑 ====================
def apply_rate_limit(up_kb=13, down_kb=13, exclude_macs=None, respect_exempt=True):
    """
    检查所有设备，仅在检测到有状态差异 (if change) 时才下发更新并记录日志！
    无任何变动时静默退出。正在进行波动模拟的设备会自动跳过，不被批量覆写。
    """
    invalidate_status_cache()
    cfg = load_config()
    speed_cfg = cfg.get("speed_kb", 13)
    target_up = up_kb if up_kb is not None else speed_cfg
    target_down = down_kb if down_kb is not None else speed_cfg
    config_excludes = set(m.upper() for m in (exclude_macs or cfg.get("exclude_macs", [])))
    exempt_macs = get_exempt_macs() if respect_exempt else set()

    with router_lock:
        client = MiWiFiClient(cfg["router_ip"], cfg["password"])
        if not client.login():
            return False, []

        client.ensure_qos_enabled()
        devices_map, q_info = client.get_all_devices()
        if not devices_map:
            return False, []

        full_payload = []
        changed_devices = []

        for mac, dev in devices_map.items():
            if fluctuation_manager.is_fluctuating(mac):
                continue

            name = dev["name"]
            ip = dev["ip"]
            cur_up = dev["upmax"]
            cur_down = dev["downmax"]

            # 判断此设备应达到的目标速率
            if mac in config_excludes:
                dev_target_up, dev_target_down = 0, 0
            elif mac in exempt_macs and (target_up > 0 or target_down > 0):
                dev_target_up, dev_target_down = 0, 0
            else:
                dev_target_up, dev_target_down = target_up, target_down

            full_payload.append({
                "mac": mac,
                "maxup": str(dev_target_up),
                "maxdown": str(dev_target_down)
            })

            # 【核心 if(change) 判断】：当前值与目标值不一致，记录变动
            if cur_up != dev_target_up or cur_down != dev_target_down:
                action_desc = "全速 (0 KB/s)" if (dev_target_up == 0 and dev_target_down == 0) else f"限速 (上行 {dev_target_up} KB/s, 下行 {dev_target_down} KB/s)"
                changed_devices.append(f"{name} ({ip}, {mac}) -> {action_desc}")

        # 没有产生任何变动：静默返回，不打扰日志
        if not changed_devices:
            return True, []

        success = client.set_limits(full_payload)
        if success:
            logger.info(f"[限速变动] 检测到 {len(changed_devices)} 台设备状态发生变更:")
            for item in changed_devices:
                logger.info(f"  - {item}")
        else:
            logger.error("Failed to apply rate limits via API.")
        return success, changed_devices

def set_device_limit(mac, up_kb=13, down_kb=13, is_exempt=False):
    """单独控制某一台设备，先终止可能存在的波动模拟"""
    mac = mac.upper()
    fluctuation_manager.stop(mac, log_stop=False)
    invalidate_status_cache()

    cfg = load_config()
    whitelist_macs = set(m.upper() for m in cfg.get("exclude_macs", []))
    if not is_exempt and mac in whitelist_macs:
        return False, f"设备 {mac} 在永久白名单中，受全局保护不可限速"

    with router_lock:
        client = MiWiFiClient(cfg["router_ip"], cfg["password"])
        if not client.login():
            return False, "Router login failed"

        client.ensure_qos_enabled()

        if is_exempt:
            add_exempt_mac(mac)
            target_up, target_down = 0, 0
            action_msg = f"已对设备 {mac} 执行手动放行 (标志位置1，夜间巡检不限速)"
        else:
            remove_exempt_mac(mac)
            speed = up_kb if up_kb is not None else cfg.get("speed_kb", 13)
            target_up, target_down = speed, (down_kb or speed)
            action_msg = f"已对设备 {mac} 执行手动限速 (标志位置0，恢复夜间限速管控)"

        success = client.set_limits([{"mac": mac, "maxup": str(target_up), "maxdown": str(target_down)}])
    return success, action_msg

def set_max_upload():
    """全局上传速度开到最大(0=不限)，下载保持限速(13 KB/s)"""
    cfg = load_config()
    speed = cfg.get("speed_kb", 13)
    return apply_rate_limit(up_kb=0, down_kb=speed, respect_exempt=True)

def set_full_limit(is_scheduled=False):
    """上下行均限速 0.1 Mbps (13 KB/s)，尊重放行名单"""
    cfg = load_config()
    cur_st = int(cfg.get("state", 1))
    if is_scheduled:
        if cur_st == 2:
            logger.info("[系统模式 2] 网页端正常运行，夜间巡检限速已取消，跳过本次巡检。")
            return True, []
        elif cur_st == 3:
            logger.info("[系统模式 3] 系统处于全部关机停机状态，跳过本次巡检。")
            return True, []
    elif cur_st == 3:
        logger.warning("[系统模式 3] 系统当前处于停机状态，跳过限速执行。")
        return False, []

    speed = cfg.get("speed_kb", 13)
    return apply_rate_limit(up_kb=speed, down_kb=speed, respect_exempt=True)

def restore_rate_limit():
    """全面恢复全速(0=不限)并在 06:00 重置清空所有放行标志位，并停止所有设备波动"""
    fluctuation_manager.stop_all()
    clear_all_exempt_macs()
    return apply_rate_limit(up_kb=0, down_kb=0, respect_exempt=False)

def get_status_data(force_refresh=False):
    """
    极速状态获取：
    4秒内重复读取直接使用内存缓存，毫秒级响应，彻底消除前端轮询卡顿！
    内存中动态叠加最新的波动与放行状态，数据始终精准。
    """
    global _status_cache
    now = time.time()

    # 如果有近期缓存且未强制刷新，快速组装返回
    cfg = load_config()
    whitelist_macs = set(m.upper() for m in cfg.get("exclude_macs", []))

    if not force_refresh and _status_cache["data"] and (now - _status_cache["timestamp"] < 4.0):
        cached = _status_cache["data"]
        exempt_macs = get_exempt_macs()
        dev_list = []
        for d in cached.get("list", []):
            mac = d["mac"]
            is_fluc = fluctuation_manager.is_fluctuating(mac)
            fluc_info = fluctuation_manager.get_status(mac) if is_fluc else None
            cur_up = fluc_info["current_speed"] if is_fluc else d["qos"]["upmax"]
            cur_down = fluc_info["current_speed"] if is_fluc else d["qos"]["downmax"]
            dev_list.append({
                "name": d["name"],
                "ip": d["ip"],
                "mac": mac,
                "qos": {"upmax": cur_up, "downmax": cur_down},
                "exempt_flag": 1 if mac in exempt_macs else 0,
                "is_whitelisted": (mac in whitelist_macs),
                "fluctuating": is_fluc,
                "fluctuation_info": fluc_info
            })
        return {
            "status": cached.get("status", {}),
            "band": cached.get("band", {}),
            "list": dev_list,
            "system_state": int(cfg.get("state", 1)),
            "cached": True
        }

    with router_lock:
        client = MiWiFiClient(cfg["router_ip"], cfg["password"])
        if not client.login():
            return _status_cache.get("data")
        devices_map, q_info = client.get_all_devices()
        if not devices_map:
            return _status_cache.get("data")

    exempt_macs = get_exempt_macs()
    dev_list = []
    for mac, d in devices_map.items():
        is_fluc = fluctuation_manager.is_fluctuating(mac)
        fluc_info = fluctuation_manager.get_status(mac) if is_fluc else None
        dev_list.append({
            "name": d["name"],
            "ip": d["ip"],
            "mac": mac,
            "qos": {"upmax": d["upmax"], "downmax": d["downmax"]},
            "exempt_flag": 1 if mac in exempt_macs else 0,
            "is_whitelisted": (mac in whitelist_macs),
            "fluctuating": is_fluc,
            "fluctuation_info": fluc_info
        })

    result = {
        "status": q_info.get("status", {}) if q_info else {"on": 1, "mode": 3},
        "band": q_info.get("band", {}) if q_info else {"upload": 1000, "download": 1000},
        "list": dev_list,
        "system_state": int(cfg.get("state", 1)),
        "cached": False
    }
    _status_cache["data"] = result
    _status_cache["timestamp"] = now
    return result

def print_status():
    data = get_status_data(force_refresh=True)
    if not data:
        print("Failed to query router status.")
        return
    cfg = load_config()
    cur_st = int(cfg.get("state", 1))
    state_names = {
        1: "🟢 模式 1: 正常运行 (Web 控制台与夜间巡检限速全开)",
        2: "🟡 模式 2: 仅网页端正常运行 (夜间巡检限速已取消，其余照旧)",
        3: "🔴 模式 3: 全部停机关机 (恢复全速并停机)"
    }
    print(f"当前系统运行状态: {state_names.get(cur_st, '未知')}")
    status = data.get("status", {})
    band = data.get("band", {})
    devlist = data.get("list", [])
    exempt_macs = get_exempt_macs()

    print("=" * 70)
    print(f"小米路由器 QoS 状态: 开关={'开启' if status.get('on') == 1 else '关闭'}, 模式={status.get('mode')}")
    print(f"外网总带宽: 上传={band.get('upload')} Mbps, 下载={band.get('download')} Mbps")
    print(f"当前放行名单(Flag=1): {list(exempt_macs)}")
    print(f"设备总数: {len(devlist)}")
    print("-" * 70)
    for dev in devlist:
        qos = dev.get("qos", {})
        upmax = qos.get("upmax", 0)
        downmax = qos.get("downmax", 0)
        mac = dev.get("mac", "").upper()
        is_exempt = dev.get("exempt_flag") == 1
        is_whitelisted = dev.get("is_whitelisted", False)
        is_fluc = dev.get("fluctuating")
        fluc_info = dev.get("fluctuation_info")

        if is_whitelisted:
            flag_str = "[🛡️永久白名单]"
        elif is_exempt:
            flag_str = "[🟢已放行 Flag=1]"
        else:
            flag_str = "[⚪受控中 Flag=0]"

        if is_fluc and fluc_info:
            limit_desc = f"🌊 波动中 (当前 {fluc_info['current_speed']} KB/s, 周期 {fluc_info['period']}s)"
        elif upmax == 0 and downmax == 0:
            limit_desc = "不限速 (全速)"
        elif upmax == 0:
            limit_desc = f"上传最大 / 下行限速 {downmax} KB/s"
        else:
            limit_desc = f"上传 {upmax} KB/s / 下行 {downmax} KB/s"

        print(f"{flag_str:<18} 设备: {dev.get('name', 'Unknown'):<16} IP: {dev.get('ip'):<14} MAC: {mac} -> {limit_desc}")
    print("=" * 70)

class QosHttpHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self.request.settimeout(5)

    def _send_bytes(self, content_bytes, content_type="text/html; charset=utf-8", code=200):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(len(content_bytes)))
        self.end_headers()
        self.wfile.write(content_bytes)
        self.close_connection = True

    def _send_json(self, data, code=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self._send_bytes(body, content_type="application/json; charset=utf-8", code=code)

    def _serve_static_file(self, rel_path):
        if rel_path in ("", "/", "/index.html"):
            rel_path = "index.html"
        rel_path = rel_path.lstrip("/")

        # 安全防范路径穿越 (Path Traversal Protection)
        safe_path = os.path.abspath(os.path.join(WEB_DIR, rel_path))
        if not safe_path.startswith(WEB_DIR) or not os.path.isfile(safe_path):
            self._send_json({"code": 404, "msg": f"Static file '{rel_path}' not found"}, 404)
            return

        content_type, _ = mimetypes.guess_type(safe_path)
        if not content_type:
            content_type = "application/octet-stream"
        if content_type.startswith("text/") or content_type in ("application/javascript", "application/json"):
            content_type += "; charset=utf-8"

        try:
            with open(safe_path, "rb") as f:
                data = f.read()
            self._send_bytes(data, content_type=content_type, code=200)
        except Exception as e:
            self._send_json({"code": 500, "msg": f"Failed to read static file: {str(e)}"}, 500)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # 静态资源请求分发
        if not path.startswith("/api/"):
            self._serve_static_file(path)
            return

        # 系统运行状态查询与切换 (1=正常运行, 2=仅网页端正常/夜间巡检取消, 3=全部停机关机)
        if path == "/api/system/state":
            st_param = query.get("state", [None])[0]
            if not st_param:
                cur_st = get_system_state()
                self._send_json({"code": 0, "state": cur_st})
                return
            try:
                st_val = int(st_param)
            except ValueError:
                self._send_json({"code": 1, "message": "Invalid state parameter"}, 400)
                return

            ok, msg = set_system_state(st_val)
            if not ok:
                self._send_json({"code": 1, "message": msg}, 400)
                return

            self._send_json({
                "code": 0,
                "state": st_val,
                "message": msg
            })

            # 若切换为 3 (全部停机关机)，延迟退出服务进程
            if st_val == 3:
                def _do_shutdown():
                    time.sleep(0.8)
                    logger.info("[系统停机] 正在退出 Web API 服务...")
                    try:
                        subprocess.run(["systemctl", "--user", "stop", "net-speed-api.service"], timeout=3)
                    except Exception:
                        pass
                    os._exit(0)
                threading.Thread(target=_do_shutdown, daemon=True).start()
            return

        # 开启网络波动模拟
        if path == "/api/device/fluctuate":
            mac = query.get("mac", [""])[0]
            if not mac:
                self._send_json({"code": 1, "message": "Missing mac parameter"}, 400)
                return
            period = int(query.get("period", [DEFAULT_FLUCTUATION_PERIOD])[0])
            stages_param = query.get("stages", [None])[0]
            stages = [int(s.strip()) for s in stages_param.split(",") if s.strip().isdigit()] if stages_param else None
            ok = fluctuation_manager.start(mac, period=period, stages=stages)
            self._send_json({
                "code": 0 if ok else 1,
                "message": f"已对设备 {mac} 启动网络波动模拟 (周期 {period} 秒)",
                "mac": mac,
                "period": period
            })
            return

        # 停止网络波动模拟
        if path == "/api/device/stop_fluctuate":
            mac = query.get("mac", [""])[0]
            if not mac:
                self._send_json({"code": 1, "message": "Missing mac parameter"}, 400)
                return
            ok = fluctuation_manager.stop(mac)
            self._send_json({
                "code": 0,
                "message": f"已停止设备 {mac} 的网络波动模拟并恢复全速",
                "mac": mac
            })
            return

        # 单设备放行 (Flag=1)
        if path == "/api/device/exempt":
            mac = query.get("mac", [""])[0]
            if not mac:
                self._send_json({"code": 1, "message": "Missing mac parameter"}, 400)
                return
            ok, msg = set_device_limit(mac, is_exempt=True)
            self._send_json({"code": 0 if ok else 1, "message": msg, "mac": mac, "exempt_flag": 1})
            return

        # 单设备限速 (Flag=0)
        if path == "/api/device/limit":
            mac = query.get("mac", [""])[0]
            if not mac:
                self._send_json({"code": 1, "message": "Missing mac parameter"}, 400)
                return
            up = int(query.get("up", [13])[0])
            down = int(query.get("down", [13])[0])
            ok, msg = set_device_limit(mac, up_kb=up, down_kb=down, is_exempt=False)
            self._send_json({"code": 0 if ok else 1, "message": msg, "mac": mac, "exempt_flag": 0})
            return

        # 全局上传拉满
        if path == "/api/max-upload":
            ok, devs = set_max_upload()
            self._send_json({
                "code": 0 if ok else 1,
                "status": "ok" if ok else "error",
                "message": "已将上传速度设为最大 (全速)，下行保持限速 (0.1 Mbps)",
                "devices": devs
            })
            return

        # 全局限速 (跳过 Flag=1 和波动中设备)
        if path == "/api/limit":
            ok, devs = set_full_limit()
            self._send_json({
                "code": 0 if ok else 1,
                "status": "ok" if ok else "error",
                "message": "已对未放行设备执行限速" if devs else "所有设备已处于目标限速状态 (无变更)",
                "devices": devs
            })
            return

        # 全局恢复全速并清空标志位
        if path == "/api/restore":
            ok, devs = restore_rate_limit()
            self._send_json({
                "code": 0 if ok else 1,
                "status": "ok" if ok else "error",
                "message": "已恢复所有设备全速，停止全部波动，全员放行标志位重置归零" if devs else "所有设备已处于全速状态 (无变更)",
                "devices": devs
            })
            return

        # 获取状态（支持 ?refresh=1 强制穿透缓存）
        if path == "/api/status":
            force = query.get("refresh", ["0"])[0] == "1"
            info = get_status_data(force_refresh=force)
            if info:
                self._send_json(info)
            else:
                self._send_json({"code": 1, "msg": "Failed to get router info"}, 500)
            return

        self._send_json({"code": 404, "msg": "Endpoint not found"}, 404)

    def do_POST(self):
        self.do_GET()

    def log_message(self, format, *args):
        pass

def run_server(port=8899):
    if not os.path.isdir(WEB_DIR):
        logger.warning(f"[警告] 前端目录不存在: {WEB_DIR}，请确保 web/ 目录与 router_qos.py 同级。")
    cur_st = get_system_state()
    if cur_st == 3:
        logger.warning("[系统模式 3] 当前配置处于模式 3 (全部关机停机)，Web 服务不启动。如需启动请将 config.json 中 state 改为 1 或 2，或执行: python3 router_qos.py --state 1")
        sys.exit(0)
    server_address = ("0.0.0.0", port)
    httpd = ThreadingHTTPServer(server_address, QosHttpHandler)
    httpd.daemon_threads = True
    logger.info(f"QoS Multi-threaded HTTP API Server listening on http://0.0.0.0:{port} (当前运行模式: {cur_st})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server stopped.")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 router_qos.py [--state [1|2|3] | --max-upload | --limit | --restore | --status | --exempt <MAC> | --unexempt <MAC> | --fluctuate <MAC> [period] | --stop-fluctuate <MAC> | --server [port] | --auto]")
        sys.exit(1)

    cmd = sys.argv[1].lower()
    if cmd == "--state":
        if len(sys.argv) < 3:
            cur_st = get_system_state()
            desc_map = {
                1: "模式 1: 正常运行 (Web 控制台正常，夜间巡检限速正常开启)",
                2: "模式 2: 仅网页端正常运行，夜间巡检取消，其余照旧",
                3: "模式 3: 全部停机关机 (路由器全速，流控与 Web 服务全部停止)"
            }
            print(f"当前系统运行状态: [state = {cur_st}] - {desc_map.get(cur_st, '未知模式')}")
        else:
            try:
                target_st = int(sys.argv[2])
                ok, msg = set_system_state(target_st)
                if ok:
                    print(f"成功切换系统状态: [state = {target_st}] - {msg}")
                    if target_st in (1, 2):
                        try:
                            res = subprocess.run(["systemctl", "--user", "is-active", "net-speed-api.service"], capture_output=True, text=True)
                            if "active" not in res.stdout:
                                subprocess.run(["systemctl", "--user", "start", "net-speed-api.service"])
                                print("已自动唤醒后台 net-speed-api.service 服务。")
                        except Exception:
                            pass
                    elif target_st == 3:
                        try:
                            subprocess.run(["systemctl", "--user", "stop", "net-speed-api.service"])
                            print("已自动停止后台 net-speed-api.service 服务。")
                        except Exception:
                            pass
                else:
                    print(f"切换失败: {msg}")
                    sys.exit(1)
            except ValueError:
                print("错误: state 参数必须是 1, 2 或 3")
                sys.exit(1)
    elif cmd == "--max-upload":
        set_max_upload()
    elif cmd == "--limit":
        set_full_limit(is_scheduled=True)
    elif cmd == "--restore":
        restore_rate_limit()
    elif cmd == "--exempt":
        if len(sys.argv) < 3:
            print("Error: Missing MAC address")
            sys.exit(1)
        set_device_limit(sys.argv[2], is_exempt=True)
    elif cmd == "--unexempt":
        if len(sys.argv) < 3:
            print("Error: Missing MAC address")
            sys.exit(1)
        set_device_limit(sys.argv[2], is_exempt=False)
    elif cmd == "--fluctuate":
        if len(sys.argv) < 3:
            print("Error: Missing MAC address. Usage: python3 router_qos.py --fluctuate <MAC> [period]")
            sys.exit(1)
        mac = sys.argv[2]
        period = int(sys.argv[3]) if len(sys.argv) > 3 else DEFAULT_FLUCTUATION_PERIOD
        print(f"Starting fluctuation on {mac} (period={period}s). Press Ctrl+C to stop.")
        fluctuation_manager.start(mac, period=period)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            fluctuation_manager.stop(mac)
            print("\nFluctuation stopped.")
    elif cmd == "--stop-fluctuate":
        if len(sys.argv) < 3:
            print("Error: Missing MAC address. Usage: python3 router_qos.py --stop-fluctuate <MAC>")
            sys.exit(1)
        mac = sys.argv[2]
        fluctuation_manager.stop(mac)
        print(f"Fluctuation stopped on {mac}.")
    elif cmd == "--status":
        print_status()
    elif cmd == "--server":
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 8899
        run_server(port)
    elif cmd == "--auto":
        cur_st = get_system_state()
        if cur_st == 2:
            logger.info("[系统模式 2] 网页端正常运行，夜间巡检限速已取消，跳过自动调度。")
            return
        elif cur_st == 3:
            logger.info("[系统模式 3] 系统处于全部关机停机状态，跳过自动调度。")
            return
        now_time = datetime.now().strftime("%H:%M")
        cfg = load_config()
        limit_t = cfg.get("limit_time", "01:00")
        restore_t = cfg.get("restore_time", "06:00")
        if limit_t <= now_time < restore_t:
            set_full_limit(is_scheduled=True)
        else:
            restore_rate_limit()
    else:
        print(f"Unknown option: {cmd}")
        sys.exit(1)

if __name__ == "__main__":
    main()