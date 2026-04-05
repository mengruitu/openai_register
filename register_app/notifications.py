import logging
import socket
import threading
import time
from datetime import datetime
from typing import Any, Dict, List

from curl_cffi import requests

logger = logging.getLogger("openai_register")

_fallback_alert_lock = threading.Lock()
_fallback_alert_sent_at: Dict[str, float] = {}


def _monitor_status_text(active_count: int, active_target: int) -> str:
    return "达标" if active_count >= active_target else "未达标"


def build_monitor_dingtalk_message(result: Any) -> str:
    status_text = _monitor_status_text(
        result.active_count,
        result.active_target,
    )
    replenish_text = (
        f"已触发，成功 {result.replenished_count}/{result.register_target}"
        if result.attempted_replenish
        else "未触发"
    )
    return (
        "授权池巡检\n"
        f"主机：{socket.gethostname()}\n"
        f"时间：{result.completed_at.strftime('%m-%d %H:%M:%S')}\n"
        f"状态：{status_text}\n"
        f"A目录：{result.active_count}/{result.active_target}（缺 {result.active_shortage}）\n"
        f"补号：{replenish_text}"
    )


def build_monitor_summary_message(results: List[Any]) -> str:
    if not results:
        return ""

    if len(results) == 1:
        return build_monitor_dingtalk_message(results[0])

    first_result = results[0]
    last_result = results[-1]
    total_replenished = sum(item.replenished_count for item in results)
    total_register_target = sum(
        item.register_target for item in results if item.attempted_replenish
    )
    replenish_rounds = sum(1 for item in results if item.attempted_replenish)
    unmet_rounds = sum(
        1
        for item in results
        if item.active_count < item.active_target
    )
    min_active = min(item.active_count for item in results)
    max_active = max(item.active_count for item in results)
    latest_status = _monitor_status_text(
        last_result.active_count,
        last_result.active_target,
    )

    return (
        "授权池汇总\n"
        f"主机：{socket.gethostname()}\n"
        f"周期：{first_result.completed_at.strftime('%m-%d %H:%M')} ~ {last_result.completed_at.strftime('%m-%d %H:%M')}\n"
        f"巡检轮次：{len(results)}\n"
        f"最新状态：{latest_status}\n"
        f"最新库存：A {last_result.active_count}/{last_result.active_target}（缺 {last_result.active_shortage}）\n"
        f"库存区间：A {min_active} ~ {max_active}\n"
        f"补号轮次：{replenish_rounds}，补号结果：成功 {total_replenished}/{total_register_target}\n"
        f"未达标轮次：{unmet_rounds}"
    )


def send_dingtalk_alert(webhook: str, message: str) -> bool:
    if not webhook:
        return False

    payload = {
        "msgtype": "text",
        "text": {"content": f"CLI变动\n{message}"},
    }
    try:
        resp = requests.post(
            webhook,
            json=payload,
            impersonate="chrome",
            timeout=10,
        )
        return resp.status_code == 200
    except Exception:
        return False


def build_fallback_dingtalk_message(
    primary_provider: str,
    fallback_provider: str,
    thread_id: int,
) -> str:
    return (
        "补号回退提醒\n"
        f"主机：{socket.gethostname()}\n"
        f"时间：{datetime.now().strftime('%m-%d %H:%M:%S')}\n"
        f"线程：{thread_id}\n"
        f"主邮箱服务：{primary_provider}\n"
        f"保底邮箱服务：{fallback_provider}\n"
        "说明：本次注册未走主邮箱服务，已自动切换到保底通道"
    )


def notify_fallback_provider_usage(
    webhook: str,
    *,
    primary_provider: str,
    fallback_provider: str,
    thread_id: int,
    throttle_seconds: int,
) -> bool:
    if not webhook:
        return False

    key = f"{str(primary_provider or '').strip().lower()}->{str(fallback_provider or '').strip().lower()}"
    now_ts = time.time()
    throttle = max(0, int(throttle_seconds))

    with _fallback_alert_lock:
        last_sent_at = _fallback_alert_sent_at.get(key, 0.0)
        if throttle > 0 and now_ts - last_sent_at < throttle:
            return False
        _fallback_alert_sent_at[key] = now_ts

    message = build_fallback_dingtalk_message(
        primary_provider=primary_provider,
        fallback_provider=fallback_provider,
        thread_id=thread_id,
    )
    ok = send_dingtalk_alert(webhook, message)
    if ok:
        return True

    with _fallback_alert_lock:
        if _fallback_alert_sent_at.get(key) == now_ts:
            _fallback_alert_sent_at.pop(key, None)
    return False
