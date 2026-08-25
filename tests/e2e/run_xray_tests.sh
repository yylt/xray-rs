#!/bin/bash
set -euo pipefail

echo "=========================================="
echo "xray-rs E2E 测试"
echo "=========================================="
echo ""

echo "检查依赖..."
if ! command -v go &> /dev/null; then
    echo "错误: 未安装 Go"
    exit 1
fi

if ! command -v cargo &> /dev/null; then
    echo "错误: 未安装 Cargo"
    exit 1
fi

echo "✓ 依赖检查通过"
echo ""

cd "$(dirname "$0")"

echo "编译测试程序..."
go build -o test_runner . || exit 1
echo "✓ 测试程序编译成功"
echo ""

echo "开始运行测试..."
echo "=========================================="
./test_runner -v

EXIT_CODE=$?

rm -f test_runner
exit $EXIT_CODE
