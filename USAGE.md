# openai_register.py 使用文档

## 1. 脚本简介

`openai_register.py` 是一个 **OpenAI/ChatGPT 账号自动注册 + Token 池巡检补号** 脚本，主要能力包括：

- 自动创建临时邮箱
- 自动完成注册流程并提取授权信息
- 将注册得到的 Token 保存为 JSON 文件
- 维护两级账号池：
  - **A 目录**：当前正在使用的账号
  - **B 目录**：库存/备用账号
- 巡检账号额度，自动删除失效或高使用率账号
- 当 A/B 库存不足时，自动触发补号
- 支持钉钉汇总通知
- 支持自建 `cfmail` 邮箱配置热加载

---

## 2. 运行环境

建议环境：

- Python 3.9+
- 已安装依赖：
  - `curl_cffi`

示例安装：

```bash
pip install curl_cffi
```

---

## 3. 默认行为

直接运行：

```bash
python /root/openai_register.py
```

默认不是无限注册，而是：

- 执行 **一轮巡检**
- 检查 A/B 目录中的账号
- 删除无效账号
- 从 B 补充到 A
- 如数量不足则自动注册补号

也就是默认行为等价于"单轮巡检"。

---

## 4. 输出结果

### 4.1 Token JSON 文件

注册成功后，Token 会保存到 `--token-dir` 指定目录，默认：

```text
/data/CLIProxyAPI/auths_pool
```

文件名通常为邮箱名，例如：

```text
abc@example.com.json
```

JSON 内容大致包含：

- `id_token`
- `access_token`
- `refresh_token`
- `account_id`
- `last_refresh`
- `email`
- `type`
- `expired`

### 4.2 账号密码汇总

脚本还会把账号信息追加到当前工作目录下的：

```text
output/accounts.txt
```

每行格式：

```text
邮箱----密码----refresh_token
```

---

## 5. 目录说明

脚本内部把账号池分成两个目录：

### A 目录

当前正在使用的账号目录，默认：

```text
/data/CLIProxyAPI/auths
```

### B 目录

备用库存目录 / 新注册账号保存目录，默认：

```text
/data/CLIProxyAPI/auths_pool
```

巡检逻辑：

1. 清理 A 中失效账号
2. 清理 B 中失效账号
3. 尝试把 B 中可用账号移动到 A
4. 若 A/B 仍不足，则自动注册新账号补到 B
5. 再尝试从 B 补到 A

---

## 6. 支持的邮箱服务

通过 `--mail-provider` 指定：

- `cfmail`（默认，推荐）
- `tempmaillol`
- `mailtm`
- `tempmailio`
- `dropmail`

示例：

```bash
python /root/openai_register.py --mail-provider tempmaillol
```

---

## 7. cfmail 配置

默认配置文件：

```text
<脚本所在目录>/cfmail_accounts.json
```

### 7.1 支持的配置格式

格式一：直接写数组

```json
[
  {
    "name": "node1",
    "worker_domain": "apimail.example.com",
    "email_domain": "example.com",
    "admin_password": "your-password",
    "enabled": true
  }
]
```

格式二：对象包裹 `accounts`

```json
{
  "accounts": [
    {
      "name": "node1",
      "worker_domain": "apimail.example.com",
      "email_domain": "example.com",
      "admin_password": "your-password",
      "enabled": true
    }
  ]
}
```

### 7.2 字段说明

- `name`：配置名称
- `worker_domain`：cfmail 后端域名
- `email_domain`：邮箱域名
- `admin_password`：管理员密码
- `enabled`：是否启用，默认 `true`

### 7.3 cfmail 特性

- 支持多个配置轮询
- `--cfmail-profile auto` 时按顺序轮询
- 某个配置连续失败达到阈值后会进入冷却期，自动跳过
- 配置文件变更后支持**热加载**，无需重启脚本

### 7.4 测试 cfmail 配置

```bash
python /root/openai_register.py --test-cfmail
```

指定代理：

```bash
python /root/openai_register.py --test-cfmail --proxy http://127.0.0.1:7890
```

---

## 8. 命令行参数

### 基础参数

- `--proxy`：代理地址，例如 `http://127.0.0.1:7890`
- `--mail-provider`：邮箱服务提供商
- `--mailtm-api-base`：自定义 Mail.tm API 地址

### 注册循环参数

- `--once`：注册模式只执行一次
- `--sleep-min`：注册循环最短等待秒数，默认 `10`
- `--sleep-max`：注册循环最长等待秒数，默认 `30`
- `--register-only`：只执行注册逻辑，不做 A/B 巡检

### 巡检参数

- `--monitor`：持续巡检
- `--monitor-once`：只执行一轮巡检
- `--monitor-interval`：巡检间隔，默认 `900` 秒
- `--active-token-dir`：A 目录路径
- `--token-dir`：B 目录路径
- `--active-min-count`：A 最少保留数量，默认 `20`
- `--pool-min-count`：B 最少保留数量，默认 `50`
- `--usage-threshold`：账号使用率达到该值后删除，默认 `90`
- `--request-interval`：检测账号时每次请求之间的等待秒数，默认 `2`
- `--curl-timeout`：额度检测超时，默认 `15`
- `--register-batch-size`：补号时每批并发注册数量，默认 `3`

### 钉钉通知参数

- `--dingtalk-webhook`：钉钉机器人地址；留空则不发送
- `--dingtalk-summary-interval`：钉钉汇总间隔，默认 `10800` 秒（3 小时）

### cfmail 参数

- `--cfmail-profile`：指定 cfmail 配置名，默认 `auto`
- `--cfmail-config`：cfmail 配置文件路径
- `--cfmail-worker-domain`：临时指定 worker 域名
- `--cfmail-email-domain`：临时指定邮箱域名
- `--cfmail-admin-password`：临时指定管理员密码
- `--cfmail-profile-name`：临时覆盖配置时使用的名称，默认 `custom`
- `--test-cfmail`：仅测试 cfmail，不执行注册

### 无人值守参数

- `--auto-continue-non-us`：非 US 出口时自动继续执行

---

## 9. 常见用法

### 9.1 默认执行一轮巡检

```bash
python /root/openai_register.py
```

### 9.2 使用代理执行一轮巡检

```bash
python /root/openai_register.py --proxy http://127.0.0.1:7890
```

### 9.3 持续巡检

```bash
python /root/openai_register.py --monitor --proxy http://127.0.0.1:7890
```

### 9.4 持续巡检并自定义阈值

```bash
python /root/openai_register.py \
  --monitor \
  --proxy http://127.0.0.1:7890 \
  --active-min-count 20 \
  --pool-min-count 50 \
  --usage-threshold 90 \
  --monitor-interval 900 \
  --register-batch-size 3
```

### 9.5 只跑注册逻辑，3 线程持续注册

```bash
python /root/openai_register.py --register-only --proxy http://127.0.0.1:7890
```

### 9.6 只跑注册逻辑，每个线程只执行一次

```bash
python /root/openai_register.py --register-only --once --proxy http://127.0.0.1:7890
```

说明：

- 注册模式固定启用 **3 个线程**
- `--once` 表示每个线程只跑一轮，不会无限重试

### 9.7 指定其他邮箱服务

```bash
python /root/openai_register.py --register-only --mail-provider tempmaillol
```

### 9.8 指定某个 cfmail 配置

```bash
python /root/openai_register.py --monitor --cfmail-profile node1
```

### 9.9 临时覆盖 cfmail 配置

```bash
python /root/openai_register.py \
  --register-only \
  --cfmail-worker-domain apimail.example.com \
  --cfmail-email-domain example.com \
  --cfmail-admin-password your-password \
  --cfmail-profile-name custom1
```

注意：上面三个参数必须同时提供，否则脚本会报错。

### 9.10 关闭钉钉通知

```bash
python /root/openai_register.py --monitor --dingtalk-webhook ""
```

---

## 10. 脚本执行逻辑说明

### 10.1 注册模式

启用条件：

- 使用 `--register-only`

行为：

- 启动 3 个线程并发注册
- 每轮成功后保存 Token 和账号密码
- 失败后会额外等待 30 秒再重试
- 若指定 `--once`，则每个线程执行一次后退出

### 10.2 巡检模式

启用条件：

- 默认直接运行
- 或 `--monitor`
- 或 `--monitor-once`

行为：

1. 检查 A 中账号额度
2. 检查 B 中账号额度
3. 删除查询失败或已达到阈值的账号
4. 从 B 向 A 补充账号
5. 若 A/B 不足，启动注册补号
6. 可按周期发送钉钉汇总

---

## 11. 代理与地区判断

脚本会先访问：

```text
https://cloudflare.com/cdn-cgi/trace
```

用于检测出口地区。

规则大致如下：

- `US`：正常继续
- 非 `US`：默认会继续执行
- `CN/HK`：如果没有显式代理，脚本会尝试自动探测本地代理端口

可自动探测的本地端口包括：

- `7890`
- `1080`
- `10809`
- `10808`
- `8888`

---

## 12. 环境变量

脚本也支持通过环境变量提供 cfmail 配置：

- `CFMAIL_CONFIG_PATH`
- `CFMAIL_WORKER_DOMAIN`
- `CFMAIL_EMAIL_DOMAIN`
- `CFMAIL_ADMIN_PASSWORD`
- `CFMAIL_PROFILE_NAME`

当环境变量和配置文件同时存在时，环境变量可覆盖默认配置。

---

## 13. 常见问题

### 13.1 报错：未配置可用的 cfmail 邮箱

原因：

- 默认邮箱服务是 `cfmail`
- 但脚本同目录下的 `cfmail_accounts.json` 中没有有效配置

解决：

- 补充 cfmail 配置文件
- 或改用其他邮箱服务，例如：

```bash
python /root/openai_register.py --mail-provider tempmaillol
```

### 13.2 报错：非 US 节点

建议：

- 使用稳定美国代理
- 或增加 `--auto-continue-non-us` 用于无人值守

### 13.3 账号文件被删除

这是正常巡检行为。以下情况会删除：

- 额度查询失败
- `used_percent >= --usage-threshold`

### 13.4 没有收到验证码

可能原因：

- 临时邮箱服务不稳定
- 当前域名被限制
- 代理质量差

建议：

- 优先使用 `cfmail`
- 或尝试 `tempmaillol`
- 更换代理或降低并发

### 13.5 `unsupported_email` / `registration_disallowed`

通常表示邮箱域名或邮箱提供商被限制。

建议：

- 更换邮箱服务
- 更换 cfmail 域名
- 更换代理出口

---

## 14. 建议使用方式

如果你是长期维护 Token 池，推荐：

```bash
python /openai_register.py \
  --monitor \
  --mail-provider cfmail \
  --active-min-count 20 \
  --pool-min-count 50 \
  --usage-threshold 90 \
  --monitor-interval 900 \
  --register-batch-size 3
```

如果你只是临时补几个账号，推荐：

```bash
python /root/openai_register.py \
  --register-only \
  --once \
  --proxy http://127.0.0.1:7890 \
  --mail-provider cfmail
```

---

## 15. 一句话总结

- **直接运行**：单轮巡检补号
- **`--monitor`**：持续巡检补号
- **`--register-only`**：跳过巡检，直接并发注册
- **`--once`**：只对注册模式生效
- **`--test-cfmail`**：只测试 cfmail 配置
