# -*- coding: utf-8 -*-
"""临时邮箱路由与收码逻辑。"""
from __future__ import annotations

import logging
from typing import Any, Optional, Set

from ..mail.cfmail import (
    create_cfmail_mailbox as _create_cfmail_mailbox,
    list_cfmail_message_ids as _list_cfmail_message_ids,
    poll_cfmail_oai_code as _poll_cfmail_oai_code,
)
from ..mail.imap_mail import (
    create_imap_mailbox as _create_imap_mailbox,
    list_imap_message_ids as _list_imap_message_ids,
    poll_imap_oai_code as _poll_imap_oai_code,
)
from ..mail.providers import (
    MAILTM_BASE,
    TempMailbox,
    create_dropmail_mailbox,
    create_hydra_mailbox,
    create_tempmaillol_mailbox,
    create_tempmailio_mailbox,
    list_dropmail_message_ids,
    list_hydra_message_ids,
    list_tempmailio_message_ids,
    list_tempmaillol_message_ids,
    poll_dropmail_oai_code,
    poll_hydra_oai_code,
    poll_tempmailio_oai_code,
    poll_tempmaillol_oai_code,
)

logger = logging.getLogger("openai_register")

# ---------------------------------------------------------------------------
# 临时邮箱路由
# ---------------------------------------------------------------------------

def get_temp_mailbox(
    provider_key: str,
    thread_id: int,
    proxies: Any = None,
    mailtm_base: str = MAILTM_BASE,
) -> Optional[TempMailbox]:
    """根据 provider_key 创建对应的临时邮箱。"""
    mailbox = None
    if provider_key == "mailtm":
        mailbox = create_hydra_mailbox(
            api_base=mailtm_base,
            provider_name="Mail.tm",
            provider_key="mailtm",
            proxies=proxies,
            thread_id=thread_id,
        )
    elif provider_key == "tempmaillol":
        mailbox = create_tempmaillol_mailbox(proxies=proxies, thread_id=thread_id)
    elif provider_key == "tempmailio":
        mailbox = create_tempmailio_mailbox(proxies=proxies, thread_id=thread_id)
    elif provider_key == "dropmail":
        mailbox = create_dropmail_mailbox(proxies=proxies, thread_id=thread_id)
    elif provider_key == "cfmail":
        mailbox = _create_cfmail_mailbox(proxies=proxies, thread_id=thread_id)
    elif provider_key == "imap":
        mailbox = _create_imap_mailbox(proxies=proxies, thread_id=thread_id)
    else:
        logger.error(f"[线程 {thread_id}] [错误] 不支持的临时邮箱服务: {provider_key}")
        return None

    if mailbox:
        provider_desc = provider_key
        if mailbox.provider == "cfmail" and mailbox.config_name:
            provider_desc = f"{provider_key}:{mailbox.config_name}"
        logger.info(
            f"[线程 {thread_id}] [信息] 已绑定临时邮箱服务: {provider_desc}"
        )
        return mailbox

    logger.error(
        f"[线程 {thread_id}] [错误] 临时邮箱服务不可用或创建失败: {provider_key}"
    )
    return None


def get_mailbox_message_snapshot(
    mailbox: TempMailbox, thread_id: int, proxies: Any = None
) -> Set[str]:
    """获取当前邮箱中已有消息的 ID 快照。"""
    try:
        if mailbox.provider == "cfmail":
            return _list_cfmail_message_ids(
                api_base=mailbox.api_base,
                token=mailbox.token,
                email=mailbox.email,
                proxies=proxies,
            )
        if mailbox.provider == "mailtm":
            return list_hydra_message_ids(
                api_base=mailbox.api_base,
                token=mailbox.token,
                proxies=proxies,
            )
        if mailbox.provider == "tempmailio":
            return list_tempmailio_message_ids(email=mailbox.email, proxies=proxies)
        if mailbox.provider == "tempmaillol":
            return list_tempmaillol_message_ids(token=mailbox.token, proxies=proxies)
        if mailbox.provider == "dropmail":
            return list_dropmail_message_ids(
                sid_token=mailbox.sid_token,
                proxies=proxies,
            )
        if mailbox.provider == "imap":
            return _list_imap_message_ids(
                email_addr=mailbox.email,
                auth_code=mailbox.password,
                imap_host=mailbox.api_base,
                proxies=proxies,
            )
    except Exception as exc:
        logger.warning(f"[线程 {thread_id}] [警告] 获取邮箱快照失败: {exc}")

    return set()


def get_oai_code(
    mailbox: TempMailbox,
    thread_id: int,
    proxies: Any = None,
    skip_message_ids: Optional[Set[str]] = None,
    skip_codes: Optional[Set[str]] = None,
) -> str:
    """从临时邮箱中轮询获取 OpenAI 验证码。"""
    if mailbox.provider == "cfmail":
        if not mailbox.token:
            logger.error(
                f"[线程 {thread_id}] [错误] {mailbox.provider} token 为空，无法读取邮件"
            )
            return ""
        return _poll_cfmail_oai_code(
            api_base=mailbox.api_base,
            token=mailbox.token,
            email=mailbox.email,
            thread_id=thread_id,
            proxies=proxies,
            skip_message_ids=skip_message_ids,
            skip_codes=skip_codes,
        )
    if mailbox.provider == "mailtm":
        if not mailbox.token:
            logger.error(
                f"[线程 {thread_id}] [错误] {mailbox.provider} token 为空，无法读取邮件"
            )
            return ""
        return poll_hydra_oai_code(
            api_base=mailbox.api_base,
            token=mailbox.token,
            email=mailbox.email,
            thread_id=thread_id,
            proxies=proxies,
            skip_message_ids=skip_message_ids,
            skip_codes=skip_codes,
        )
    if mailbox.provider == "tempmailio":
        return poll_tempmailio_oai_code(
            email=mailbox.email,
            thread_id=thread_id,
            proxies=proxies,
            skip_message_ids=skip_message_ids,
            skip_codes=skip_codes,
        )
    if mailbox.provider == "tempmaillol":
        if not mailbox.token:
            logger.error(
                f"[线程 {thread_id}] [错误] {mailbox.provider} token 为空，无法读取邮件"
            )
            return ""
        return poll_tempmaillol_oai_code(
            token=mailbox.token,
            email=mailbox.email,
            thread_id=thread_id,
            proxies=proxies,
            skip_message_ids=skip_message_ids,
            skip_codes=skip_codes,
        )
    if mailbox.provider == "dropmail":
        if not mailbox.sid_token:
            logger.error(f"[线程 {thread_id}] [错误] {mailbox.provider} 会话标识为空，无法读取邮件")
            return ""
        return poll_dropmail_oai_code(
            sid_token=mailbox.sid_token,
            email=mailbox.email,
            thread_id=thread_id,
            proxies=proxies,
            skip_message_ids=skip_message_ids,
            skip_codes=skip_codes,
        )
    if mailbox.provider == "imap":
        if not mailbox.password:
            logger.error(
                f"[线程 {thread_id}] [错误] {mailbox.provider} 授权码为空，无法读取邮件"
            )
            return ""
        return _poll_imap_oai_code(
            email_addr=mailbox.email,
            auth_code=mailbox.password,
            imap_host=mailbox.api_base,
            thread_id=thread_id,
            proxies=proxies,
            skip_message_ids=skip_message_ids,
            skip_codes=skip_codes,
        )

    logger.error(
        f"[线程 {thread_id}] [错误] 暂不支持该邮箱服务: {mailbox.provider}"
    )
    return ""

__all__ = [
    "MAILTM_BASE",
    "TempMailbox",
    "get_mailbox_message_snapshot",
    "get_oai_code",
    "get_temp_mailbox",
]
