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
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import threading

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "config.json")
STATE_FILE = os.path.join(SCRIPT_DIR, "state.json")
LOG_FILE = os.path.join(SCRIPT_DIR, "qos.log")

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
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {
        "router_ip": "192.168.31.1",
        "password": "",
        "speed_kb": 13,
        "limit_time": "01:00",
        "restore_time": "06:00",
        "exclude_macs": []
    }

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

def set_full_limit():
    """上下行均限速 0.1 Mbps (13 KB/s)，尊重放行名单"""
    cfg = load_config()
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

# ==================== 现代 Cyber-Minimalist 控制台前端 ====================
HTML_PAGE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
<title>MiWiFi QoS Studio · 极速流控中心</title>
<style>
:root {
  --bg-base: #f7f6f2;
  --bg-surface: #ffffff;
  --bg-surface-hover: #fafaf8;
  --border-subtle: #e7e5df;
  --border-hover: #d3cfc7;
  --border-focus: #0284c7;
  --text-main: #1c1917;
  --text-muted: #57534e;
  --text-dim: #78716c;
  --accent-cyan: #0284c7;
  --accent-blue: #2563eb;
  --accent-emerald: #059669;
  --accent-amber: #d97706;
  --accent-rose: #e11d48;
  --accent-violet: #7c3aed;
  --shadow-sm: 0 1px 3px rgba(28, 25, 23, 0.04), 0 1px 2px rgba(28, 25, 23, 0.02);
  --shadow-md: 0 4px 16px -2px rgba(28, 25, 23, 0.05), 0 2px 6px -1px rgba(28, 25, 23, 0.02);
  --shadow-lg: 0 12px 32px -4px rgba(28, 25, 23, 0.08), 0 4px 10px -2px rgba(28, 25, 23, 0.03);
}

* { box-sizing: border-box; margin: 0; padding: 0; -webkit-tap-highlight-color: transparent; }
body {
  background-color: var(--bg-base);
  background-image: 
    radial-gradient(at 0% 0%, rgba(230, 225, 215, 0.55) 0px, transparent 55%),
    radial-gradient(at 100% 100%, rgba(220, 230, 245, 0.55) 0px, transparent 55%);
  color: var(--text-main);
  font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display", "SF Pro Text", "Segoe UI", Roboto, sans-serif;
  min-height: 100vh;
  padding: 24px 16px 50px;
  -webkit-font-smoothing: antialiased;
}

.shell { max-width: 860px; margin: 0 auto; }

/* 头部导航 HUD */
.nav-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 24px;
  padding-bottom: 16px;
  border-bottom: 1px solid var(--border-subtle);
}
.brand-group { display: flex; align-items: center; gap: 12px; }
.brand-logo {
  width: 42px;
  height: 42px;
  background: linear-gradient(135deg, #0284c7, #2563eb);
  border-radius: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
  box-shadow: 0 4px 14px rgba(2, 132, 199, 0.25);
  font-size: 20px;
  color: #fff;
}
.brand-title { font-size: 19px; font-weight: 700; letter-spacing: -0.02em; color: var(--text-main); }
.brand-sub { font-size: 12px; color: var(--text-dim); margin-top: 1px; }

.system-pill {
  display: flex;
  align-items: center;
  gap: 7px;
  background: #ecfdf5;
  border: 1px solid #a7f3d0;
  padding: 6px 13px;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 600;
  color: #047857;
}
.live-dot {
  width: 7px;
  height: 7px;
  background: #10b981;
  border-radius: 50%;
  box-shadow: 0 0 6px #10b981;
  animation: radarPulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
}
@keyframes radarPulse { 0%, 100% { opacity: 1; transform: scale(1); } 50% { opacity: 0.4; transform: scale(0.85); } }

/* 数据 HUD 统计看板 */
.hud-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 12px;
  margin-bottom: 20px;
}
@media (max-width: 600px) {
  .hud-grid { grid-template-columns: repeat(2, 1fr); }
}
.hud-card {
  background: var(--bg-surface);
  border: 1px solid var(--border-subtle);
  border-radius: 14px;
  padding: 14px 14px;
  box-shadow: var(--shadow-sm);
  display: flex;
  flex-direction: column;
  gap: 4px;
  transition: all 0.2s ease;
}
.hud-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-dim); font-weight: 600; }
.hud-value { font-size: 24px; font-weight: 700; color: var(--text-main); font-variant-numeric: tabular-nums; }
.hud-card.active-fluc {
  border-color: #c4b5fd;
  background: linear-gradient(135deg, #faf5ff, #f0f9ff);
  box-shadow: 0 4px 18px rgba(139, 92, 246, 0.12);
}

/* 全局控制中心 */
.deck-card {
  background: var(--bg-surface);
  border: 1px solid var(--border-subtle);
  border-radius: 18px;
  padding: 18px;
  margin-bottom: 24px;
  box-shadow: var(--shadow-md);
}
.deck-title {
  font-size: 12px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--text-dim);
  margin-bottom: 14px;
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.deck-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
}
@media (max-width: 520px) {
  .deck-grid { grid-template-columns: 1fr; }
}

.action-btn {
  position: relative;
  border-radius: 12px;
  padding: 13px 16px;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 12px;
  transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
  text-decoration: none;
  text-align: left;
}
.action-btn:active { transform: scale(0.98); }
.action-btn.loading { opacity: 0.6; pointer-events: none; }
.btn-icon-wrap {
  width: 36px;
  height: 36px;
  border-radius: 10px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 18px;
  flex-shrink: 0;
  color: #fff;
}
.btn-texts { display: flex; flex-direction: column; }
.btn-title { font-size: 14px; font-weight: 600; line-height: 1.25; }
.btn-desc { font-size: 11px; margin-top: 2px; }

.btn-upload {
  background: #f0f9ff;
  border: 1px solid #bae6fd;
}
.btn-upload .btn-icon-wrap { background: #0284c7; }
.btn-upload .btn-title { color: #0369a1; }
.btn-upload .btn-desc { color: #0284c7; }
.btn-upload:hover { background: #e0f2fe; border-color: #38bdf8; box-shadow: 0 4px 14px rgba(2, 132, 199, 0.15); }

.btn-night {
  background: #fffbeb;
  border: 1px solid #fde68a;
}
.btn-night .btn-icon-wrap { background: #d97706; }
.btn-night .btn-title { color: #b45309; }
.btn-night .btn-desc { color: #92400e; }
.btn-night:hover { background: #fef3c7; border-color: #f59e0b; box-shadow: 0 4px 14px rgba(217, 119, 6, 0.15); }

.btn-restore-all {
  grid-column: 1 / -1;
  background: #f0fdf4;
  border: 1px solid #bbf7d0;
}
.btn-restore-all .btn-icon-wrap { background: #059669; }
.btn-restore-all .btn-title { color: #15803d; }
.btn-restore-all .btn-desc { color: #166534; }
.btn-restore-all:hover { background: #dcfce7; border-color: #10b981; box-shadow: 0 4px 14px rgba(5, 150, 105, 0.15); }

/* 搜索与筛选栏 */
.filter-bar {
  display: flex;
  gap: 10px;
  margin-bottom: 16px;
  flex-wrap: wrap;
}
.search-input-wrap {
  position: relative;
  flex: 1;
  min-width: 200px;
}
.search-icon {
  position: absolute;
  left: 12px;
  top: 50%;
  transform: translateY(-50%);
  font-size: 13px;
  color: var(--text-dim);
}
.search-input {
  width: 100%;
  background: var(--bg-surface);
  border: 1px solid var(--border-subtle);
  border-radius: 10px;
  padding: 9px 12px 9px 34px;
  color: var(--text-main);
  font-size: 13px;
  outline: none;
  transition: all 0.2s;
  box-shadow: var(--shadow-sm);
}
.search-input:focus {
  border-color: #0284c7;
  box-shadow: 0 0 0 3px rgba(2, 132, 199, 0.12);
}

.btn-tool {
  background: var(--bg-surface);
  border: 1px solid var(--border-subtle);
  border-radius: 10px;
  padding: 8px 14px;
  color: var(--text-muted);
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 6px;
  transition: all 0.2s;
  box-shadow: var(--shadow-sm);
}
.btn-tool:hover { background: #fafaf9; color: var(--text-main); border-color: var(--border-hover); }
.btn-tool:active { transform: scale(0.96); }

/* 设备卡片网格 */
.device-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(360px, 1fr));
  gap: 16px;
}
@media (max-width: 440px) {
  .device-grid { grid-template-columns: 1fr; }
}

.device-card {
  background: var(--bg-surface);
  border: 1px solid var(--border-subtle);
  border-radius: 16px;
  padding: 16px;
  box-shadow: var(--shadow-sm);
  display: flex;
  flex-direction: column;
  gap: 12px;
  transition: transform 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease;
}
.device-card:hover {
  border-color: var(--border-hover);
  transform: translateY(-2px);
  box-shadow: var(--shadow-lg);
}
.device-card.is-fluctuating {
  border-color: #a78bfa;
  background: #faf5ff;
  box-shadow: 0 8px 24px rgba(139, 92, 246, 0.12);
}

.dev-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
}
.dev-info-left {
  display: flex;
  align-items: center;
  gap: 10px;
  min-width: 0;
}
.dev-avatar {
  width: 40px;
  height: 40px;
  border-radius: 11px;
  background: #f5f4ef;
  border: 1px solid #e7e5df;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 20px;
  flex-shrink: 0;
}
.dev-titles { min-width: 0; }
.dev-name {
  font-size: 15px;
  font-weight: 600;
  color: var(--text-main);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.dev-meta {
  font-size: 11px;
  color: var(--text-dim);
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  margin-top: 2px;
}

/* 徽标组 */
.badges-wrap {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}
.pill {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 3px 9px;
  border-radius: 999px;
  font-size: 11px;
  font-weight: 600;
}
.pill-free { background: #ecfdf5; color: #047857; border: 1px solid #a7f3d0; }
.pill-limit { background: #fff7ed; color: #c2410c; border: 1px solid #fed7aa; }
.pill-exempt { background: #f0f9ff; color: #0369a1; border: 1px solid #bae6fd; }
.pill-whitelist { background: #f5f3ff; color: #6d28d9; border: 1px solid #ddd6fe; box-shadow: 0 1px 4px rgba(109, 40, 217, 0.12); }
.pill-ctrl { background: #f5f5f4; color: #78716c; border: 1px solid #e7e5e4; }
.pill-fluc {
  background: linear-gradient(135deg, #ede9fe, #e0f2fe);
  color: #4338ca;
  border: 1px solid #a5b4fc;
  box-shadow: 0 0 10px rgba(99, 102, 241, 0.2);
}

/* 波动动态可视化 (声波条 + 阶梯管道) */
.fluc-viz-box {
  background: #f8fafc;
  border: 1px solid #e2e8f0;
  border-radius: 12px;
  padding: 10px 12px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.fluc-viz-top {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.eq-bars {
  display: flex;
  align-items: flex-end;
  gap: 3px;
  height: 14px;
}
.eq-bar {
  width: 3px;
  background: linear-gradient(180deg, #0284c7, #6366f1);
  border-radius: 2px;
  animation: barDance 1s ease-in-out infinite alternate;
}
.eq-bar:nth-child(1) { height: 6px; animation-delay: 0.1s; }
.eq-bar:nth-child(2) { height: 12px; animation-delay: 0.3s; }
.eq-bar:nth-child(3) { height: 14px; animation-delay: 0.5s; }
.eq-bar:nth-child(4) { height: 8px; animation-delay: 0.2s; }
.eq-bar:nth-child(5) { height: 11px; animation-delay: 0.4s; }
@keyframes barDance {
  0% { transform: scaleY(0.3); opacity: 0.6; }
  100% { transform: scaleY(1); opacity: 1; }
}

.stages-pipeline {
  display: flex;
  justify-content: space-between;
  align-items: center;
  position: relative;
  padding: 4px 0;
}
.stages-pipeline::before {
  content: '';
  position: absolute;
  top: 50%;
  left: 8px;
  right: 8px;
  height: 2px;
  background: #e2e8f0;
  z-index: 1;
}
.pipe-step {
  position: relative;
  z-index: 2;
  font-size: 10px;
  font-weight: 600;
  padding: 2px 6px;
  border-radius: 6px;
  background: #f1f5f9;
  color: #64748b;
  border: 1px solid #e2e8f0;
  transition: all 0.2s ease;
}
.pipe-step.current {
  background: linear-gradient(135deg, #0284c7, #4f46e5);
  color: #fff;
  border-color: #0284c7;
  box-shadow: 0 2px 10px rgba(2, 132, 199, 0.35);
  transform: scale(1.12);
}

/* 控制按钮组 */
.btn-group-2 {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 8px;
}
.btn-sub-action {
  border-radius: 9px;
  padding: 8px 10px;
  font-size: 12px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.18s ease;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 5px;
}
.btn-sub-action:active { transform: scale(0.96); }
.btn-exempt-opt { background: #f0fdf4; color: #15803d; border: 1px solid #bbf7d0; }
.btn-exempt-opt:hover { background: #dcfce7; }
.btn-limit-opt { background: #fff7ed; color: #c2410c; border: 1px solid #fed7aa; }
.btn-limit-opt:hover { background: #ffedd5; }

/* 网络波动控制舱 */
.fluc-console {
  background: #f8fafc;
  border: 1px solid #e2e8f0;
  border-radius: 12px;
  padding: 10px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.fluc-console-top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 6px;
}
.stepper-wrap {
  display: flex;
  align-items: center;
  background: #ffffff;
  border: 1px solid #cbd5e1;
  border-radius: 8px;
  padding: 2px;
}
.stepper-btn {
  width: 24px;
  height: 24px;
  background: transparent;
  border: none;
  color: #475569;
  font-size: 14px;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 6px;
}
.stepper-btn:hover { background: #f1f5f9; color: #0f172a; }
.stepper-val {
  width: 32px;
  background: transparent;
  border: none;
  color: #0284c7;
  font-weight: 700;
  font-size: 13px;
  text-align: center;
  outline: none;
}
.stepper-unit { font-size: 11px; color: var(--text-dim); margin-right: 6px; }

.quick-pills { display: flex; gap: 4px; }
.quick-pill {
  background: #ffffff;
  border: 1px solid #e2e8f0;
  color: #475569;
  font-size: 11px;
  padding: 3px 7px;
  border-radius: 6px;
  cursor: pointer;
  transition: all 0.15s;
}
.quick-pill:hover { background: #f1f5f9; color: #0f172a; border-color: #cbd5e1; }

.btn-fluc-main {
  width: 100%;
  border: none;
  border-radius: 9px;
  padding: 9px 12px;
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  transition: all 0.2s ease;
}
.btn-fluc-main:active { transform: scale(0.97); }
.btn-fluc-start {
  background: linear-gradient(135deg, #0284c7, #2563eb);
  color: #fff;
  box-shadow: 0 4px 14px rgba(2, 132, 199, 0.25);
}
.btn-fluc-start:hover { filter: brightness(1.06); }
.btn-fluc-stop {
  background: linear-gradient(135deg, #e11d48, #be123c);
  color: #fff;
  box-shadow: 0 4px 14px rgba(225, 29, 72, 0.25);
  animation: stopPulse 2s infinite;
}
@keyframes stopPulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.85; } }

/* 现代浮动 Toast 通知 */
.toast-container {
  position: fixed;
  bottom: 24px;
  left: 50%;
  transform: translateX(-50%);
  z-index: 9999;
  display: flex;
  flex-direction: column;
  gap: 8px;
  pointer-events: none;
}
.toast {
  background: #ffffff;
  border: 1px solid #e2e8f0;
  color: #0f172a;
  padding: 10px 18px;
  border-radius: 12px;
  font-size: 13px;
  font-weight: 600;
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.12);
  display: flex;
  align-items: center;
  gap: 8px;
  animation: toastSlideUp 0.3s cubic-bezier(0.16, 1, 0.3, 1);
  pointer-events: auto;
}
.toast.success { border-color: #a7f3d0; color: #047857; }
.toast.error { border-color: #fecdd3; color: #be123c; }
@keyframes toastSlideUp {
  from { opacity: 0; transform: translateY(16px); }
  to { opacity: 1; transform: translateY(0); }
}

.footer-info {
  margin-top: 32px;
  text-align: center;
  font-size: 12px;
  color: #a8a29e;
  line-height: 1.6;
}
</style>
</head>
<body>
<div class="shell">
  <!-- 头部 HUD -->
  <header class="nav-header">
    <div class="brand-group">
      <div class="brand-logo">⚡</div>
      <div>
        <div class="brand-title">MiWiFi QoS Studio</div>
        <div class="brand-sub">智能路由器流控中心 · 波动仿真与设备精控</div>
      </div>
    </div>
    <div class="system-pill">
      <span class="live-dot"></span>
      <span id="sysStatusText">服务正常 · 8899</span>
    </div>
  </header>

  <!-- 数据看板 HUD -->
  <section class="hud-grid">
    <div class="hud-card">
      <span class="hud-label">在线/已知设备</span>
      <span class="hud-value" id="hudTotal">-</span>
    </div>
    <div class="hud-card">
      <span class="hud-label">手动免限放行</span>
      <span class="hud-value" style="color:#059669;" id="hudExempt">-</span>
    </div>
    <div class="hud-card">
      <span class="hud-label">受控/限速中</span>
      <span class="hud-value" style="color:#d97706;" id="hudLimited">-</span>
    </div>
    <div class="hud-card" id="hudFlucCard">
      <span class="hud-label">网络波动模拟</span>
      <span class="hud-value" style="color:#7c3aed;" id="hudFluc">0</span>
    </div>
  </section>

  <!-- 全局批量控制 Deck -->
  <section class="deck-card">
    <div class="deck-title">
      <span>⚡ 全局快速调度</span>
      <span style="font-size:11px;font-weight:normal;opacity:0.6;">即刻下发至 LuCI 核心</span>
    </div>
    <div class="deck-grid">
      <button class="action-btn btn-upload" onclick="callApi('/api/max-upload', this)">
        <div class="btn-icon-wrap">🚀</div>
        <div class="btn-texts">
          <span class="btn-title">上传开到最大</span>
          <span class="btn-desc">上行解除封顶 (全速) · 下行保持限速</span>
        </div>
      </button>

      <button class="action-btn btn-night" onclick="callApi('/api/limit', this)">
        <div class="btn-icon-wrap">🐢</div>
        <div class="btn-texts">
          <span class="btn-title">全员夜间限速</span>
          <span class="btn-desc">上下行深度限速 0.1M · 跳过已放行</span>
        </div>
      </button>

      <button class="action-btn btn-restore-all" onclick="callApi('/api/restore', this)">
        <div class="btn-icon-wrap">⚡</div>
        <div class="btn-texts">
          <span class="btn-title">恢复所有全速并清空标志位</span>
          <span class="btn-desc">解除全部限速 · 立即停止所有波动 · 标志位清零复位</span>
        </div>
      </button>
    </div>
  </section>

  <!-- 搜索与筛选工具条 -->
  <div class="filter-bar">
    <div class="search-input-wrap">
      <span class="search-icon">🔍</span>
      <input type="text" id="searchInput" class="search-input" placeholder="搜索设备名称、IP 或 MAC..." oninput="handleSearch()">
    </div>
    <button class="btn-tool" onclick="refreshStatus(true)">🔄 刷新设备</button>
  </div>

  <!-- 设备列表容器 (零卡顿增量渲染) -->
  <main id="deviceGrid" class="device-grid">
    <div style="grid-column: 1/-1; text-align:center; padding: 40px; color:#64748b;">正在极速连接路由器...</div>
  </main>

  <footer class="footer-info">
    💡 定时任务在 01:00-06:00 每 10 分钟巡检一次，<strong>严格仅在设备状态产生真实变动时记录日志</strong>。<br>
    🌊 网络波动模拟支持毫秒级平滑梯级循环，点击【停止波动】瞬间恢复千兆全速。
  </footer>
</div>

<div id="toastContainer" class="toast-container"></div>

<script>
let gDevices = [];
let gSearchQuery = '';
let gPollTimer = null;

// 现代化轻量 Toast 提示
function toast(msg, type = 'success') {
  const container = document.getElementById('toastContainer');
  const el = document.createElement('div');
  el.className = 'toast ' + type;
  el.innerHTML = (type === 'success' ? '✅ ' : '⚠️ ') + msg;
  container.appendChild(el);
  setTimeout(() => {
    el.style.opacity = '0';
    el.style.transform = 'translateY(10px)';
    el.style.transition = 'all 0.25s ease';
    setTimeout(() => el.remove(), 250);
  }, 3200);
}

// 统一 API 调用（带乐观按钮加载态，绝不卡死界面）
function callApi(url, btnEl = null) {
  if (btnEl) btnEl.classList.add('loading');
  fetch(url)
    .then(r => r.json())
    .then(data => {
      if (btnEl) btnEl.classList.remove('loading');
      if (data.code === 0) {
        toast(data.message || '操作成功！', 'success');
      } else {
        toast(data.message || '执行失败', 'error');
      }
      refreshStatus(true);
    })
    .catch(err => {
      if (btnEl) btnEl.classList.remove('loading');
      toast('网络异常: ' + err, 'error');
    });
}

function handleSearch() {
  gSearchQuery = document.getElementById('searchInput').value.trim().toLowerCase();
  applyFiltersAndRender();
}

function getDeviceIcon(name) {
  const n = (name || '').toLowerCase();
  if (n.includes('phone') || n.includes('xiaomi') || n.includes('iphone') || n.includes('hbn') || n.includes('al80') || n.includes('huawei')) return '📱';
  if (n.includes('laptop') || n.includes('asus') || n.includes('thinkpad') || n.includes('macbook')) return '💻';
  if (n.includes('desktop') || n.includes('pc') || n.includes('workstation')) return '🖥️';
  return '🌐';
}

function adjustPeriod(safeMac, delta) {
  const el = document.getElementById('period_' + safeMac);
  if (!el) return;
  let val = parseInt(el.value) || 30;
  val = Math.max(5, Math.min(300, val + delta));
  el.value = val;
}

function setQuickPeriod(safeMac, val) {
  const el = document.getElementById('period_' + safeMac);
  if (el) el.value = val;
}

function toggleFluctuate(mac, safeMac, isCurrentlyActive) {
  if (isCurrentlyActive) {
    callApi('/api/device/stop_fluctuate?mac=' + encodeURIComponent(mac));
  } else {
    const el = document.getElementById('period_' + safeMac);
    const period = el ? (parseInt(el.value) || 30) : 30;
    callApi('/api/device/fluctuate?mac=' + encodeURIComponent(mac) + '&period=' + period);
  }
}

// 核心：无感零卡顿 DOM 增量刷新引擎（保留输入框焦点与值，杜绝 innerHTML 粗暴刷白）
function applyFiltersAndRender() {
  const container = document.getElementById('deviceGrid');
  const filtered = gDevices.filter(dev => {
    if (!gSearchQuery) return true;
    const hay = ((dev.name || '') + ' ' + (dev.ip || '') + ' ' + (dev.mac || '')).toLowerCase();
    return hay.includes(gSearchQuery);
  });

  if (filtered.length === 0) {
    container.innerHTML = '<div style="grid-column: 1/-1; text-align:center; padding: 40px; color:#64748b;">未找到匹配的设备</div>';
    return;
  }

  // 移除已经被过滤掉的卡片
  const currentSafeMacs = new Set(filtered.map(d => d.mac.replace(/[^a-zA-Z0-9]/g, '_')));
  Array.from(container.children).forEach(child => {
    if (child.id && child.id.startsWith('card_')) {
      const sm = child.id.replace('card_', '');
      if (!currentSafeMacs.has(sm)) child.remove();
    }
  });

  filtered.forEach(dev => {
    const safeMac = dev.mac.replace(/[^a-zA-Z0-9]/g, '_');
    let card = document.getElementById('card_' + safeMac);
    const isFluc = dev.fluctuating === true;
    const isExempt = dev.exempt_flag === 1;
    const flucInfo = dev.fluctuation_info || {};
    const up = parseFloat(dev.qos?.upmax || 0);
    const down = parseFloat(dev.qos?.downmax || 0);

    // 档位速度文本
    let speedText = '全速 (0 KB/s)';
    let speedPillClass = 'pill-free';
    if (isFluc) {
      speedText = `波动: ${flucInfo.current_speed === 0 ? '全速' : flucInfo.current_speed + ' KB/s'}`;
      speedPillClass = 'pill-fluc';
    } else if (up > 0 || down > 0) {
      speedText = `限速: ${down} KB/s`;
      speedPillClass = 'pill-limit';
    }

    const isWhitelisted = dev.is_whitelisted === true;
    let flagPillHtml = '';
    if (isWhitelisted) {
      flagPillHtml = '<span class="pill pill-whitelist">🛡️ 永久白名单 (免限)</span>';
    } else if (isExempt) {
      flagPillHtml = '<span class="pill pill-exempt">🟢 已放行 (巡检跳过)</span>';
    } else {
      flagPillHtml = '<span class="pill pill-ctrl">⚪ 受控中 (参与管控)</span>';
    }

    if (!card) {
      // 首次创建新卡片
      card = document.createElement('div');
      card.id = 'card_' + safeMac;
      card.className = 'device-card' + (isFluc ? ' is-fluctuating' : '');

      card.innerHTML = `
        <div class="dev-head">
          <div class="dev-info-left">
            <div class="dev-avatar">${getDeviceIcon(dev.name)}</div>
            <div class="dev-titles">
              <div class="dev-name">${dev.name || '未知设备'}</div>
              <div class="dev-meta">${dev.ip || '-'} · ${dev.mac}</div>
            </div>
          </div>
        </div>

        <div class="badges-wrap" id="badges_${safeMac}">
          ${flagPillHtml}
          <span class="pill ${speedPillClass}" id="speedPill_${safeMac}">
            ${speedText}
          </span>
        </div>

        <div id="vizContainer_${safeMac}"></div>

        <div class="btn-group-2">
          <button class="btn-sub-action btn-exempt-opt" onclick="callApi('/api/device/exempt?mac=${encodeURIComponent(dev.mac)}', this)">
            🟢 手动放行
          </button>
          ${isWhitelisted 
            ? '<button class="btn-sub-action" style="opacity:0.5;cursor:not-allowed;" title="白名单设备受全局保护，不可限速" disabled>🛡️ 白名单保护</button>'
            : `<button class="btn-sub-action btn-limit-opt" onclick="callApi('/api/device/limit?mac=${encodeURIComponent(dev.mac)}', this)">🐢 手动限速</button>`
          }
        </div>

        <div class="fluc-console">
          <div class="fluc-console-top">
            <div class="stepper-wrap">
              <button class="stepper-btn" onclick="adjustPeriod('${safeMac}', -5)">−</button>
              <input type="number" id="period_${safeMac}" class="stepper-val" value="${flucInfo.period || 30}" min="5" max="300">
              <span class="stepper-unit">s</span>
              <button class="stepper-btn" onclick="adjustPeriod('${safeMac}', 5)">+</button>
            </div>
            <div class="quick-pills">
              <span class="quick-pill" onclick="setQuickPeriod('${safeMac}', 15)">15s</span>
              <span class="quick-pill" onclick="setQuickPeriod('${safeMac}', 30)">30s</span>
              <span class="quick-pill" onclick="setQuickPeriod('${safeMac}', 60)">60s</span>
            </div>
          </div>
          <button id="flucBtn_${safeMac}" class="btn-fluc-main ${isFluc ? 'btn-fluc-stop' : 'btn-fluc-start'}" onclick="toggleFluctuate('${dev.mac}', '${safeMac}', ${isFluc})">
            ${isFluc ? '🛑 停止波动 (即刻全速)' : '🌊 开启网络波动模拟'}
          </button>
        </div>
      `;
      container.appendChild(card);
    } else {
      // 增量热更新卡片样式和数值（无缝平滑，不闪烁）
      card.className = 'device-card' + (isFluc ? ' is-fluctuating' : '');
      const badgesEl = document.getElementById('badges_' + safeMac);
      if (badgesEl) {
        badgesEl.innerHTML = `
          ${flagPillHtml}
          <span class="pill ${speedPillClass}">
            ${speedText}
          </span>
        `;
      }

      // 更新主按钮
      const flucBtn = document.getElementById('flucBtn_' + safeMac);
      if (flucBtn) {
        flucBtn.className = 'btn-fluc-main ' + (isFluc ? 'btn-fluc-stop' : 'btn-fluc-start');
        flucBtn.innerHTML = isFluc ? '🛑 停止波动 (即刻全速)' : '🌊 开启网络波动模拟';
        flucBtn.onclick = () => toggleFluctuate(dev.mac, safeMac, isFluc);
      }
    }

    // 动态渲染可视化声波阶梯条
    const vizBox = document.getElementById('vizContainer_' + safeMac);
    if (vizBox) {
      if (isFluc) {
        const curStep = flucInfo.current_step || 0;
        const stages = flucInfo.stages || [13, 50, 200, 800, 0];
        const stepLabels = ['13K', '50K', '200K', '800K', '全速'];
        let stepsHtml = '';
        stages.forEach((stg, sIdx) => {
          const isCur = (sIdx === curStep);
          stepsHtml += `<span class="pipe-step ${isCur ? 'current' : ''}">${stepLabels[sIdx] || (stg + 'K')}</span>`;
        });

        vizBox.innerHTML = `
          <div class="fluc-viz-box">
            <div class="fluc-viz-top">
              <span style="font-size:11px;font-weight:700;color:#6d28d9;">🌊 实时波动阶梯 (周期 ${flucInfo.period}s)</span>
              <div class="eq-bars">
                <span class="eq-bar"></span>
                <span class="eq-bar"></span>
                <span class="eq-bar"></span>
                <span class="eq-bar"></span>
                <span class="eq-bar"></span>
              </div>
            </div>
            <div class="stages-pipeline">
              ${stepsHtml}
            </div>
          </div>
        `;
      } else {
        vizBox.innerHTML = '';
      }
    }
  });
}

function updateHUD(list) {
  let exemptCount = 0;
  let limitedCount = 0;
  let flucCount = 0;

  list.forEach(d => {
    if (d.exempt_flag === 1) exemptCount++;
    const isFluc = d.fluctuating === true;
    if (isFluc) flucCount++;
    const up = parseFloat(d.qos?.upmax || 0);
    const down = parseFloat(d.qos?.downmax || 0);
    if (!isFluc && (up > 0 || down > 0)) limitedCount++;
  });

  document.getElementById('hudTotal').textContent = list.length;
  document.getElementById('hudExempt').textContent = exemptCount;
  document.getElementById('hudLimited').textContent = limitedCount;
  document.getElementById('hudFluc').textContent = flucCount;

  const flucCard = document.getElementById('hudFlucCard');
  if (flucCount > 0) flucCard.classList.add('active-fluc');
  else flucCard.classList.remove('active-fluc');
}

function refreshStatus(force = false) {
  fetch('/api/status' + (force ? '?refresh=1' : ''))
    .then(r => r.json())
    .then(data => {
      if (!data || !data.list) return;
      gDevices = data.list;
      updateHUD(gDevices);
      applyFiltersAndRender();

      // 智能自适应轮询：有波动任务时每 2.5 秒无感同步，无波动时每 8 秒心跳轮询
      const anyFluc = gDevices.some(d => d.fluctuating);
      if (gPollTimer) clearTimeout(gPollTimer);
      gPollTimer = setTimeout(() => refreshStatus(false), anyFluc ? 2500 : 8000);
    })
    .catch(() => {
      document.getElementById('sysStatusText').textContent = '连接重试中...';
      if (gPollTimer) clearTimeout(gPollTimer);
      gPollTimer = setTimeout(() => refreshStatus(false), 5000);
    });
}

refreshStatus(true);
</script>
</body>
</html>
"""

class QosHttpHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self.request.settimeout(5)

    def _send_json(self, data, code=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _send_html(self, html_text):
        body = html_text.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path in ("/", "/index.html"):
            self._send_html(HTML_PAGE)
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
    server_address = ("0.0.0.0", port)
    httpd = ThreadingHTTPServer(server_address, QosHttpHandler)
    httpd.daemon_threads = True
    logger.info(f"QoS Multi-threaded HTTP API Server listening on http://0.0.0.0:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server stopped.")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 router_qos.py [--max-upload | --limit | --restore | --status | --exempt <MAC> | --unexempt <MAC> | --fluctuate <MAC> [period] | --stop-fluctuate <MAC> | --server [port] | --auto]")
        sys.exit(1)

    cmd = sys.argv[1].lower()
    if cmd == "--max-upload":
        set_max_upload()
    elif cmd == "--limit":
        set_full_limit()
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
        now_time = datetime.now().strftime("%H:%M")
        cfg = load_config()
        limit_t = cfg.get("limit_time", "01:00")
        restore_t = cfg.get("restore_time", "06:00")
        if limit_t <= now_time < restore_t:
            set_full_limit()
        else:
            restore_rate_limit()
    else:
        print(f"Unknown option: {cmd}")
        sys.exit(1)

if __name__ == "__main__":
    main()