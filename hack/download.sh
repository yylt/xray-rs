#!/bin/bash

# 定义下载任务数组
# 格式: "url|file-path"
files=(
    "https://raw.githubusercontent.com/fcshark-org/route-list/release/china_ipv4.txt|/opt/china_ipv4.txt"
    "https://raw.githubusercontent.com/fcshark-org/route-list/release/china_list.txt|/opt/china_domain.txt"
    "https://anti-ad.net/domains.txt|/opt/ads.txt"
)

# 日志函数
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# 检查依赖
if ! command -v curl &> /dev/null; then
    log "错误: curl 未安装，请先安装 curl"
    exit 1
fi

# 创建必要的目录
create_directories() {
    for item in "${files[@]}"; do
        filepath="${item#*|}"
        dirpath=$(dirname "$filepath")
        if [ ! -d "$dirpath" ]; then
            mkdir -p "$dirpath"
            log "创建目录: $dirpath"
        fi
    done
}

# 下载文件
download_file() {
    local url="$1"
    local filepath="$2"
    
    log "开始下载: $url -> $filepath"
    
    # 使用 curl 下载，显示进度条
    if curl -L --progress-bar -o "$filepath" "$url" 2>&1; then
        # 检查文件是否下载成功
        if [ -f "$filepath" ] && [ -s "$filepath" ]; then
            log "下载完成: $filepath (大小: $(du -h "$filepath" | cut -f1))"
            return 0
        else
            log "下载失败: 文件为空或不存在"
            return 1
        fi
    else
        log "下载失败: $url"
        return 1
    fi
}

# 主函数
main() {
    log "开始执行下载任务"
    
    # 创建必要的目录
    create_directories
    
    local success_count=0
    local fail_count=0
    
    # 遍历并下载每个文件
    for item in "${files[@]}"; do
        url="${item%|*}"
        filepath="${item#*|}"
        
        if download_file "$url" "$filepath"; then
            ((success_count++))
        else
            ((fail_count++))
        fi
        echo ""
    done
    
    log "下载任务完成 - 成功: $success_count, 失败: $fail_count"
    
    # 根据失败数量返回退出码
    if [ $fail_count -gt 0 ]; then
        exit 1
    else
        exit 0
    fi
}

# 运行主函数
main