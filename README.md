# openai_register

`openai_register.py` 是一个面向 OpenAI/ChatGPT 账号池维护的自动化脚本，当前模式已精简为：

- 维护 **A 目录** 账号池
- 库存不足时自动补号
- 支持 `temp-mail.org` 兼容邮箱和自建 cfmail worker
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
  `temp-mail.org` / 自建 cfmail worker 邮箱逻辑
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

实际运行统一使用 `monitor_config.json` 和 `cfmail_accounts.json`。

- `monitor_config.example.json` 只是初始化模板，需要内容时再手动参考或复制到 `monitor_config.json`
- `cfmail_accounts.example.json` 只是初始化模板，需要内容时再手动参考或复制到 `cfmail_accounts.json`

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

### 7. cfmail 配置说明

- 默认 temp-mail.org 兼容模式：
  - `worker_domain = web2.temp-mail.org`
  - `email_domain = temp-mail.org`
  - `admin_password = disabled`
- 自建 cfmail worker 模式：
  - 在 `cfmail_accounts.json` 中填写真实的 `worker_domain / email_domain / admin_password`

## systemd 服务模板

当前 `monitor.service` 对应的启动方式：

```ini
ExecStart=/data/openai_register/.venv/bin/python /data/openai_register/openai_register.py --monitor --config /data/openai_register/monitor_config.json
```

注意：旧版参数已经移除，不要再在 service 或 override 里追加：

- `--pool-min-count`
- `--usage-threshold`

修改 unit 后请执行：

```bash
sudo systemctl daemon-reload
sudo systemctl restart openai-register
sudo systemctl status openai-register
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
- `proxy_api_url`
- `proxy_api_scheme`
- `proxy_pool_enabled`
- `proxy_pool_consumer_ttl_seconds`
- `proxy_pool_heartbeat_interval_seconds`
- `proxy_pool_state_path`
- `proxy_pool_consumers_path`
- `proxy_pool_target_multiplier`

补充说明：

- `mail_provider=imap` 继续读取项目根目录 `emails.txt`
- `mail_provider=imap_ms` 读取项目根目录 `ms_emails.txt`
- `ms_emails.txt` 格式为 `邮箱----密码----client_id----refresh_token`
- 也支持扩展格式 `邮箱----密码----client_id----refresh_token----IMAP服务器----端口`

## 共享 IP 池

如果你开启了 `proxy_pool_enabled=true`：

- 所有注册模式共用一个本地文件型代理池
- 程序不再每次注册都直接请求 `proxy_api_url`
- 后台会根据当前所有活跃进程的总线程数持续补货
- 默认目标是保持 `可用 IP >= 2 x 全局线程数`
- 池空且补货失败时，只结束当前线程，不整体降并发

相关配置字段：

- `proxy_api_url`
- `proxy_api_scheme`
- `proxy_pool_enabled`
- `proxy_pool_consumer_ttl_seconds`
- `proxy_pool_heartbeat_interval_seconds`
- `proxy_pool_state_path`
- `proxy_pool_consumers_path`
- `proxy_pool_target_multiplier`

## register-only 收尾上传到 R2

如果你开启了 `r2_enabled=true`，则只有 `--register-only` 会在所有线程自然结束后触发收尾上传：

- 扫描 `token_dir` 下当前现存的全部 JSON
- 按单个 JSON 对象上传到 Cloudflare R2
- 对象 key 结构为 `{r2_prefix}/register-only/{local_date}/count-{N}/{filename}`
- 只有当这一批 JSON 全部上传成功后，才会删除本地 `token_dir` 中对应 JSON
- 任意文件在重试后仍失败，则本地 JSON 全部保留

相关配置字段：

- `r2_enabled`
- `r2_account_id`
- `r2_bucket`
- `r2_access_key_id`
- `r2_secret_access_key`
- `r2_prefix`
- `r2_retry_count`
- `r2_retry_delay_seconds`

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

若同时启用了 `r2_enabled=true`：

- 所有注册线程自然结束后，会上传 `token_dir` 中当下全部 JSON 到 R2
- 全部上传成功后，会自动删除这批本地 JSON
- `output/accounts.txt` 不会上传，也不会删除

当前版本在注册成功后，会直接进入“账号密码重登录”链提取 token，
不再先尝试 continue_url、session cookie、workspace 或 chatgpt session 前置取 token 流程。

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
