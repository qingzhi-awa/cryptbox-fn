#!/bin/bash
# 重置超级管理员密码（SSH 登录飞牛后执行，无需 SMTP）
# 用法: /var/apps/cryptbox/target/reset-password.sh

set -e

# 脚本位于 target 目录，据此推导应用根目录与数据目录
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_ROOT="$(dirname "$SCRIPT_DIR")"
DB_FILE="${APP_ROOT}/var/app.db"

# 根据系统架构选择二进制
ARCH=$(uname -m)
BIN="${SCRIPT_DIR}/cryptbox-server"
if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
    BIN="${SCRIPT_DIR}/cryptbox-server-arm64"
fi

if [ ! -x "$BIN" ]; then
    echo "错误：找不到可执行文件 $BIN" >&2
    exit 1
fi

if [ ! -f "$DB_FILE" ]; then
    echo "错误：找不到数据库文件 $DB_FILE（应用可能尚未初始化）" >&2
    exit 1
fi

# 输入新密码（不回显）并确认
read -s -p "请输入新的超级管理员密码: " NEW_PASSWORD
echo
read -s -p "请再次输入确认: " CONFIRM
echo

if [ -z "$NEW_PASSWORD" ]; then
    echo "错误：密码不能为空" >&2
    exit 1
fi

if [ "$NEW_PASSWORD" != "$CONFIRM" ]; then
    echo "错误：两次输入的密码不一致" >&2
    exit 1
fi

# 通过标准输入把密码传给重置命令（避免密码出现在命令行）
printf '%s\n' "$NEW_PASSWORD" | DB_DSN="$DB_FILE" "$BIN" -reset-admin
