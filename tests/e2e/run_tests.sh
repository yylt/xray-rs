#!/bin/bash
# 快速测试指南

echo "=========================================="
echo "xray-rs E2E 测试"
echo "=========================================="
echo ""

# 检查依赖
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

# 进入测试目录
cd "$(dirname "$0")"

# 构建测试程序
echo "构建测试程序..."
go build -o test_runner . || exit 1
echo "✓ 测试程序构建成功"
echo ""

# 运行测试
echo "开始运行测试..."
echo "=========================================="
./test_runner -v

# 保存退出码
EXIT_CODE=$?

# 清理
rm -f test_runner

exit $EXIT_CODE
