#!/bin/bash
# -*- coding: utf-8 -*-
# openai_register 一键管理脚本
# 用法: bash ctl.sh {deps|install|start|stop|restart|status|log|uninstall}

set -euo pipefail

SERVICE_NAME="openai-register"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SYSTEMD_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
REQUIREMENTS_FILE="${SCRIPT_DIR}/requirements.txt"
VENV_DIR="${SCRIPT_DIR}/.venv"
VENV_PYTHON="${VENV_DIR}/bin/python"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# 检查 root 权限
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        error "请使用 root 用户运行，或 sudo bash ctl.sh $1"
    fi
}

python_version_ok() {
    local python_bin="$1"
    "$python_bin" - <<'PY' >/dev/null 2>&1
import sys
raise SystemExit(0 if sys.version_info >= (3, 10) else 1)
PY
}

resolve_base_python() {
    local candidate
    for candidate in python3.12 python3.11 python3.10 python3 python; do
        if command -v "$candidate" >/dev/null 2>&1; then
            local resolved
            resolved="$(command -v "$candidate")"
            if python_version_ok "$resolved"; then
                echo "$resolved"
                return 0
            fi
        fi
    done
    return 1
}

create_venv() {
    local base_python="$1"
    if [ -x "$VENV_PYTHON" ] && python_version_ok "$VENV_PYTHON"; then
        return 0
    fi

    info "创建虚拟环境: ${VENV_DIR}"
    if "$base_python" -m venv "$VENV_DIR" >/dev/null 2>&1; then
        return 0
    fi

    warn "python -m venv 不可用，尝试通过 virtualenv 创建虚拟环境"
    "$base_python" -m pip install --upgrade pip virtualenv >/dev/null
    "$base_python" -m virtualenv "$VENV_DIR" >/dev/null
}

bootstrap_runtime_env() {
    local base_python
    base_python="$(resolve_base_python)" || error "未找到 Python 3.10+。请先安装 Python 3.10/3.11/3.12 后再执行。"

    if [ ! -f "$REQUIREMENTS_FILE" ]; then
        error "找不到依赖文件 ${REQUIREMENTS_FILE}"
    fi

    create_venv "$base_python"

    info "升级 pip/setuptools/wheel"
    "$VENV_PYTHON" -m pip install --upgrade pip setuptools wheel

    info "安装/更新项目依赖"
    "$VENV_PYTHON" -m pip install --upgrade -r "$REQUIREMENTS_FILE"
}

resolve_python_bin() {
    if [ -x "$VENV_PYTHON" ] && python_version_ok "$VENV_PYTHON"; then
        echo "$VENV_PYTHON"
        return 0
    fi
    resolve_base_python
}

write_service_file() {
    local python_bin="$1"
    cat > "$SYSTEMD_PATH" <<EOF
[Unit]
# openai_register 持续巡检 / 自动补号服务
Description=openai_register monitor service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${SCRIPT_DIR}
ExecStart=${python_bin} ${SCRIPT_DIR}/openai_register.py --monitor --config ${SCRIPT_DIR}/monitor_config.json
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=openai-register
Environment=LANG=C
Environment=LC_ALL=C
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF
}

# 安装服务
do_install() {
    check_root "install"
    bootstrap_runtime_env
    local python_bin
    python_bin="$(resolve_python_bin)" || error "未找到可用 Python 3.10+"
    if [ ! -f "${SCRIPT_DIR}/openai_register.py" ]; then
        error "找不到 ${SCRIPT_DIR}/openai_register.py"
    fi
    if [ ! -f "${SCRIPT_DIR}/monitor_config.json" ]; then
        warn "未找到 ${SCRIPT_DIR}/monitor_config.json，服务启动前请先准备配置文件"
    fi
    write_service_file "$python_bin"
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    info "服务已安装并设置开机自启"
    info "使用 Python: ${python_bin}"
    info "运行 'bash ctl.sh start' 启动服务"
}

# 安装/更新依赖
do_deps() {
    bootstrap_runtime_env
    info "依赖安装完成 ✓"
    info "虚拟环境 Python: ${VENV_PYTHON}"
}

# 启动
do_start() {
    check_root "start"
    if [ ! -f "$SYSTEMD_PATH" ]; then
        warn "服务尚未安装，先执行安装..."
        do_install
    fi
    systemctl start "$SERVICE_NAME"
    sleep 1
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        info "服务已启动 ✓"
    else
        error "启动失败，请查看日志: bash ctl.sh log"
    fi
}

# 停止
do_stop() {
    check_root "stop"
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    info "服务已停止 ✓"
}

# 重启
do_restart() {
    check_root "restart"
    systemctl restart "$SERVICE_NAME"
    sleep 1
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        info "服务已重启 ✓"
    else
        error "重启失败，请查看日志: bash ctl.sh log"
    fi
}

# 状态
do_status() {
    echo "========================================="
    echo "  openai-register 服务状态"
    echo "========================================="
    systemctl status "$SERVICE_NAME" --no-pager 2>/dev/null || warn "服务未安装或未运行"
    echo ""
    echo "--- 最近 10 条日志 ---"
    journalctl -u "$SERVICE_NAME" -n 10 --no-pager 2>/dev/null || true
}

# 查看日志
do_log() {
    local lines="${1:-50}"
    case "${1:-}" in
        -f|--follow|follow)
            info "实时日志（Ctrl+C 退出）:"
            journalctl -u "$SERVICE_NAME" -f --no-pager
            ;;
        --today|today)
            info "今天的日志:"
            journalctl -u "$SERVICE_NAME" --since today --no-pager
            ;;
        --all|all)
            info "全部日志:"
            journalctl -u "$SERVICE_NAME" --no-pager
            ;;
        *)
            info "最近 ${lines} 条日志:"
            journalctl -u "$SERVICE_NAME" -n "$lines" --no-pager
            ;;
    esac
}

# 卸载服务
do_uninstall() {
    check_root "uninstall"
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    rm -f "$SYSTEMD_PATH"
    systemctl daemon-reload
    info "服务已卸载 ✓"
}

# 帮助信息
do_help() {
    cat << 'EOF'
openai_register 服务管理脚本

用法: bash ctl.sh <命令>

命令:
  deps        创建 .venv 并安装/更新 requirements.txt 中的依赖
  install     安装 systemd 服务并设置开机自启
  start       启动服务
  stop        停止服务
  restart     重启服务
  status      查看服务状态和最近日志
  log         查看最近 50 条日志
  log -f      实时跟踪日志（类似 tail -f）
  log today   查看今天的日志
  log all     查看全部日志
  log 100     查看最近 100 条日志
  uninstall   停止并卸载服务

示例:
  bash ctl.sh deps       # 创建/更新虚拟环境和依赖
  bash ctl.sh install    # 首次部署
  bash ctl.sh start      # 启动
  bash ctl.sh log -f     # 实时看日志
  bash ctl.sh restart    # 改了配置后重启
EOF
}

# 主入口
case "${1:-help}" in
    deps)       do_deps ;;
    install)    do_install ;;
    start)      do_start ;;
    stop)       do_stop ;;
    restart)    do_restart ;;
    status)     do_status ;;
    log)        do_log "${2:-50}" ;;
    uninstall)  do_uninstall ;;
    help|--help|-h) do_help ;;
    *)          error "未知命令: $1\n运行 'bash ctl.sh help' 查看帮助" ;;
esac
