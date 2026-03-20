#!/bin/bash
# -*- coding: utf-8 -*-
# openai_register 一键管理脚本
# 用法: bash ctl.sh {install|start|stop|restart|status|log|uninstall}

set -euo pipefail

SERVICE_NAME="openai-register"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVICE_FILE="${SCRIPT_DIR}/monitor.service"
SYSTEMD_PATH="/etc/systemd/system/${SERVICE_NAME}.service"

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

# 安装服务
do_install() {
    check_root "install"
    if [ ! -f "$SERVICE_FILE" ]; then
        error "找不到 ${SERVICE_FILE}"
    fi
    cp "$SERVICE_FILE" "$SYSTEMD_PATH"
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    info "服务已安装并设置开机自启"
    info "运行 'bash ctl.sh start' 启动服务"
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
  bash ctl.sh install    # 首次部署
  bash ctl.sh start      # 启动
  bash ctl.sh log -f     # 实时看日志
  bash ctl.sh restart    # 改了配置后重启
EOF
}

# 主入口
case "${1:-help}" in
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
