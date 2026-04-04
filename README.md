# openai_register

`openai_register.py` 是一个面向 OpenAI/ChatGPT 账号池维护的自动化脚本，当前模式已精简为：

- 维护 **A 目录** 账号池
- 库存不足时自动补号
- 使用 `temp-mail.org` 兼容邮箱逻辑
- 默认慢速注册，优先稳定性

## 当前行为

当前巡检/补号逻辑只做这些事：

1. 统计 A 目录账号数量
2. 若低于 `active_min_count`，直接补号到 A 目录
3. 不做删号
4. 不做额度查询
5. 不维护 B 目录

## 目录说明

- `openai_register.py`
  CLI 入口
- `register_app/mail/cfmail.py`
  `temp-mail.org` 兼容邮箱逻辑
- `register_app/registration/flow.py`
  注册主流程
- `register_app/runtime/tasks.py`
  A-only 补号调度
- `register_app/config.py`
  默认配置与配置文件映射
- `register_app/doctor.py`
  环境检查与状态输出
- `register_app/notifications.py`
  钉钉通知

## 快速开始

### 1. 准备配置

复制：

- `monitor_config.example.json` -> `monitor_config.json`
- `cfmail_accounts.example.json` -> `cfmail_accounts.json`

### 2. 单轮补号检测

```bash
python openai_register.py
```

### 3. 持续补号

```bash
python openai_register.py --monitor
```

### 4. 只跑注册

```bash
python openai_register.py --register-only --once
```

### 5. 查看状态

```bash
python openai_register.py --status
```

### 6. 测试邮箱

```bash
python openai_register.py --test-cfmail
```

## monitor_config 关键配置

当前真正有用的字段：

- `active_token_dir`
- `active_min_count`
- `mail_provider`
- `proxy`
- `monitor_interval`
- `register_batch_size`
- `register_openai_concurrency`
- `register_start_delay_seconds`
- `failure_sleep_seconds`
- `dingtalk_webhook`
- `dingtalk_summary_interval`
- `cfmail_profile`
- `cfmail_config`

## 默认节流策略

为降低 `temp-mail.org` 的 429 风险，当前默认已经放慢：

- `register_batch_size = 1`
- `register_openai_concurrency = 1`
- `register_start_delay_seconds = 8.0`
- `failure_sleep_seconds = 20`

邮箱请求节流：

- 创建邮箱最小间隔约 `12s`
- 收件轮询最小间隔约 `6s`
- 命中 `429` 会自动退避重试

## 输出结果

### A 目录 token

巡检补号成功后，token 会直接写入：

- `active_token_dir`

### 注册模式输出目录

`--register-only` 模式下，token 输出到：

- `token_dir`

### 账号汇总

账号密码会追加到：

```text
output/accounts.txt
```

格式：

```text
邮箱----密码----refresh_token
```

## 建议使用方式

长期挂后台：

```bash
python openai_register.py --monitor
```

临时补几个号：

```bash
python openai_register.py --register-only --once
```
