# -*- coding: utf-8 -*-
"""Cloudflare R2 upload helpers for register-only cleanup."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import logging
import os
import time

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from .config import (
    DEFAULT_R2_PREFIX,
    DEFAULT_R2_RETRY_COUNT,
    DEFAULT_R2_RETRY_DELAY_SECONDS,
)

logger = logging.getLogger("openai_register")


@dataclass(frozen=True)
class R2UploadConfig:
    enabled: bool = False
    account_id: str = ""
    bucket: str = ""
    access_key_id: str = ""
    secret_access_key: str = ""
    prefix: str = DEFAULT_R2_PREFIX
    retry_count: int = DEFAULT_R2_RETRY_COUNT
    retry_delay_seconds: float = DEFAULT_R2_RETRY_DELAY_SECONDS


@dataclass(frozen=True)
class R2UploadFileResult:
    file_path: str
    object_key: str
    attempts: int
    success: bool
    error_message: str = ""


@dataclass(frozen=True)
class R2BatchUploadResult:
    enabled: bool
    attempted: bool
    file_count: int
    uploaded_count: int
    deleted_count: int
    skipped_reason: str = ""
    config_error: str = ""
    uploads: tuple[R2UploadFileResult, ...] = ()
    failures: tuple[R2UploadFileResult, ...] = ()

    @property
    def all_uploaded(self) -> bool:
        return self.attempted and self.file_count > 0 and not self.failures and self.uploaded_count == self.file_count


def build_r2_upload_config_from_args(args: object) -> R2UploadConfig:
    return R2UploadConfig(
        enabled=bool(getattr(args, "r2_enabled", False)),
        account_id=str(getattr(args, "r2_account_id", "") or "").strip(),
        bucket=str(getattr(args, "r2_bucket", "") or "").strip(),
        access_key_id=str(getattr(args, "r2_access_key_id", "") or "").strip(),
        secret_access_key=str(getattr(args, "r2_secret_access_key", "") or "").strip(),
        prefix=str(getattr(args, "r2_prefix", DEFAULT_R2_PREFIX) or "").strip(),
        retry_count=max(0, int(getattr(args, "r2_retry_count", DEFAULT_R2_RETRY_COUNT) or 0)),
        retry_delay_seconds=max(
            0.0,
            float(getattr(args, "r2_retry_delay_seconds", DEFAULT_R2_RETRY_DELAY_SECONDS) or 0.0),
        ),
    )


def build_register_only_object_key(prefix: str, local_date: str, batch_count: int, file_name: str) -> str:
    parts = [part for part in str(prefix or "").strip("/").split("/") if part]
    parts.extend(
        [
            "register-only",
            str(local_date or "").strip(),
            f"count-{max(0, int(batch_count or 0))}",
            os.path.basename(str(file_name or "").strip()),
        ]
    )
    return "/".join(part for part in parts if part)


def validate_r2_upload_config(config: R2UploadConfig) -> list[str]:
    if not config.enabled:
        return []

    errors: list[str] = []
    if not config.account_id:
        errors.append("缺少 r2_account_id")
    if not config.bucket:
        errors.append("缺少 r2_bucket")
    if not config.access_key_id:
        errors.append("缺少 r2_access_key_id")
    if not config.secret_access_key:
        errors.append("缺少 r2_secret_access_key")
    return errors


def _list_json_files(directory: str) -> list[str]:
    if not os.path.isdir(directory):
        return []
    files: list[str] = []
    for name in os.listdir(directory):
        path = os.path.join(directory, name)
        if name.endswith(".json") and os.path.isfile(path):
            files.append(os.path.abspath(path))
    files.sort()
    return files


def _build_r2_endpoint_url(config: R2UploadConfig) -> str:
    return f"https://{config.account_id}.r2.cloudflarestorage.com"


def _build_s3_client(config: R2UploadConfig):
    return boto3.client(
        "s3",
        endpoint_url=_build_r2_endpoint_url(config),
        aws_access_key_id=config.access_key_id,
        aws_secret_access_key=config.secret_access_key,
        region_name="auto",
        config=Config(signature_version="s3v4"),
    )


def _put_json_to_r2(file_path: str, object_key: str, config: R2UploadConfig) -> tuple[bool, str]:
    try:
        client = _build_s3_client(config)
        with open(file_path, "rb") as file_obj:
            client.put_object(
                Bucket=config.bucket,
                Key=object_key,
                Body=file_obj,
                ContentType="application/json",
            )
        return True, ""
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        code = str(err.get("Code") or "").strip()
        message = str(err.get("Message") or "").strip()
        details = [item for item in [f"status={status}" if status else "", f"code={code}" if code else "", message] if item]
        return False, " | ".join(details) or str(exc)
    except BotoCoreError as exc:
        return False, str(exc)
    except Exception as exc:
        return False, str(exc)


def _upload_single_file(file_path: str, object_key: str, config: R2UploadConfig) -> R2UploadFileResult:
    retry_count = max(0, int(config.retry_count))
    retry_delay_seconds = max(0.0, float(config.retry_delay_seconds))
    last_error = ""
    for attempt_index in range(retry_count + 1):
        attempt_number = attempt_index + 1
        success, error_message = _put_json_to_r2(file_path, object_key, config)
        if success:
            return R2UploadFileResult(
                file_path=file_path,
                object_key=object_key,
                attempts=attempt_number,
                success=True,
            )

        last_error = str(error_message or "unknown upload error").strip()
        if attempt_index < retry_count:
            logger.warning(
                "R2 上传失败，准备重试：file=%s key=%s attempt=%s/%s error=%s",
                file_path,
                object_key,
                attempt_number,
                retry_count + 1,
                last_error,
            )
            if retry_delay_seconds > 0:
                time.sleep(retry_delay_seconds)

    return R2UploadFileResult(
        file_path=file_path,
        object_key=object_key,
        attempts=retry_count + 1,
        success=False,
        error_message=last_error or "unknown upload error",
    )


def _delete_uploaded_files(file_paths: list[str]) -> int:
    deleted_count = 0
    for file_path in file_paths:
        if not os.path.exists(file_path):
            deleted_count += 1
            continue
        try:
            os.remove(file_path)
            deleted_count += 1
        except OSError as exc:
            logger.warning("R2 上传成功后删除本地文件失败：file=%s error=%s", file_path, exc)
    return deleted_count


def run_register_only_r2_upload(config: R2UploadConfig, token_dir: str) -> R2BatchUploadResult:
    normalized_token_dir = str(token_dir or "").strip()
    file_paths = _list_json_files(normalized_token_dir)
    file_count = len(file_paths)

    if not config.enabled:
        return R2BatchUploadResult(
            enabled=False,
            attempted=False,
            file_count=file_count,
            uploaded_count=0,
            deleted_count=0,
            skipped_reason="disabled",
        )

    if file_count <= 0:
        return R2BatchUploadResult(
            enabled=True,
            attempted=False,
            file_count=0,
            uploaded_count=0,
            deleted_count=0,
            skipped_reason="empty",
        )

    config_errors = validate_r2_upload_config(config)
    if config_errors:
        return R2BatchUploadResult(
            enabled=True,
            attempted=False,
            file_count=file_count,
            uploaded_count=0,
            deleted_count=0,
            config_error="；".join(config_errors),
        )

    local_date = datetime.now().astimezone().date().isoformat()
    uploads: list[R2UploadFileResult] = []
    failures: list[R2UploadFileResult] = []
    for file_path in file_paths:
        object_key = build_register_only_object_key(
            config.prefix,
            local_date,
            file_count,
            os.path.basename(file_path),
        )
        upload_result = _upload_single_file(file_path, object_key, config)
        if upload_result.success:
            uploads.append(upload_result)
        else:
            failures.append(upload_result)

    if failures:
        return R2BatchUploadResult(
            enabled=True,
            attempted=True,
            file_count=file_count,
            uploaded_count=len(uploads),
            deleted_count=0,
            uploads=tuple(uploads),
            failures=tuple(failures),
        )

    deleted_count = _delete_uploaded_files(file_paths)
    return R2BatchUploadResult(
        enabled=True,
        attempted=True,
        file_count=file_count,
        uploaded_count=len(uploads),
        deleted_count=deleted_count,
        uploads=tuple(uploads),
        failures=(),
    )


__all__ = [
    "DEFAULT_R2_PREFIX",
    "DEFAULT_R2_RETRY_COUNT",
    "DEFAULT_R2_RETRY_DELAY_SECONDS",
    "R2BatchUploadResult",
    "R2UploadConfig",
    "R2UploadFileResult",
    "build_r2_upload_config_from_args",
    "build_register_only_object_key",
    "run_register_only_r2_upload",
    "validate_r2_upload_config",
]
