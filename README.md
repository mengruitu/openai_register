# openai_register

`openai_register.py` 是一个面向 OpenAI/ChatGPT 账号池维护的自动化脚本，支持注册、双池巡检、额度检查、补号、`cfmail` 热加载和钉钉通知。

这个仓库适合两类场景：

- 持续维护 A/B 两级账号池
- 临时并发补一批新号

## 功能概览

- 自动创建临时邮箱并完成注册流程
- 保存 `id_token`、`access_token`、`refresh_token`、`account_id`
- 维护两级账号池
  - `A`：当前使用中的账号
  - `B`：库存/备用账号
- 巡检账号额度与可用状态
- A/B 库存不足时自动补号
- 支持 `cfmail` 多配置轮询与热加载
- 支持钉钉汇总通知

## 目录说明

- `openai_register.py`
  主入口脚本
- `register_runtime.py`
  巡检、额度查询、补号调度
- `register_auth.py`
  OAuth / token 提取与登录链路
- `register_cfmail.py`
  自建 `cfmail` 相关逻辑
- `register_mailboxes.py`
  第三方临时邮箱逻辑
- `register_notifications.py`
  钉钉通知
- `monitor_config.example.json`
  巡检配置示例
- `cfmail_accounts.example.json`
  `cfmail` 配置示例

## 运行环境

- Python 3.10+
- 依赖见 [requirements.txt](./requirements.txt)

推荐先创建虚拟环境并安装依赖：

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
```

如果你直接用仓库自带脚本部署：

```bash
bash ctl.sh deps
```

## 快速开始

### 1. 准备配置

将以下示例文件复制一份并去掉 `.example`：

- `monitor_config.example.json` -> `monitor_config.json`
- `cfmail_accounts.example.json` -> `cfmail_accounts.json`

然后按你的环境修改：

- `monitor_config.json`
- `cfmail_accounts.json`

最关键的配置项：

- `active_token_dir`
- `token_dir`
- `active_min_count`
- `pool_min_count`
- `usage_threshold`
- `mail_provider`
- `proxy`

### 2. 直接执行一轮巡检

```bash
python openai_register.py
```

默认行为不是无限注册，而是：

1. 巡检 A 目录
2. 巡检 B 目录
3. 从 B 补到 A
4. 如果 A/B 不足，再自动补号

### 3. 持续巡检

```bash
python openai_register.py --monitor
```

### 4. 只跑注册

```bash
python openai_register.py --register-only
```

### 5. 测试 cfmail

```bash
python openai_register.py --test-cfmail
```

## 常用模式

### 单轮巡检

```bash
python openai_register.py
```

### 持续巡检补号

```bash
python openai_register.py --monitor --proxy http://127.0.0.1:7890
```

### 只补一批新号

```bash
python openai_register.py --register-only --once --proxy http://127.0.0.1:7890
```

### 指定 cfmail 配置

```bash
python openai_register.py --monitor --cfmail-profile node1
```

## 巡检逻辑摘要

当前巡检逻辑是：

1. 读取 token 文件
2. 如果 `access_token` 缺失或即将过期，优先尝试用 `refresh_token` 刷新
3. 用最新 `access_token` 查询额度
4. 根据结果决定保留、删除、或跳过

判定原则：

- 已确认失效时删除
  - 例如 `account_deactivated`
  - 或刷新后仍确认登录态失效
- `used_percent >= usage_threshold` 时删除
- 临时查询失败时先保留
  - 例如超时
  - TLS/网络抖动
  - 接口短暂异常
  - 返回结构异常

这意味着：

- `refresh_token` 不是直接用来查额度的
- 它的作用是先换出新的 `access_token`
- 真正查额度时仍然使用 `access_token`

## 输出结果

### Token 文件

注册成功后会生成 `.json` 文件，通常包含：

- `id_token`
- `access_token`
- `refresh_token`
- `account_id`
- `last_refresh`
- `email`
- `type`
- `expired`

### 账号汇总

账号密码会追加到：

```text
output/accounts.txt
```

格式：

```text
邮箱----密码----refresh_token
```

## 配置文件

### `monitor_config.json`

推荐从 [monitor_config.example.json](./monitor_config.example.json) 复制。

核心字段：

- `active_token_dir`
- `token_dir`
- `active_min_count`
- `pool_min_count`
- `usage_threshold`
- `monitor_interval`
- `token_check_workers`
- `curl_timeout`
- `register_batch_size`
- `register_openai_concurrency`
- `dingtalk_webhook`

### `cfmail_accounts.json`

推荐从 [cfmail_accounts.example.json](./cfmail_accounts.example.json) 复制。

支持：

- 多 `cfmail` 配置轮询
- 指定 profile
- 连续失败冷却
- 配置热加载

## 日志说明

当前日志策略偏向“看异常和汇总”：

- 保留删除、失败、补位、补号汇总等关键日志
- 减少正常账号逐条保留日志
- 邮箱轮询不再输出大量 `......`

这样更适合长期挂后台巡检。

## 建议使用方式

长期维护账号池时，推荐：

```bash
python openai_register.py --monitor
```

短时补号时，推荐：

```bash
python openai_register.py --register-only --once
```

## 相关文档

- [monitor_config.example.json](./monitor_config.example.json)：巡检配置示例
- [cfmail_accounts.example.json](./cfmail_accounts.example.json)：`cfmail` 配置示例
