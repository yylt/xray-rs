#!/usr/bin/env bash

set -x

go_arch=$1
go_os=$2
project_name=$3

# Make Go -> Rust arch/os mapping
case $go_arch in
    amd64) rust_arch='x86_64' ;;
    arm64) rust_arch='aarch64' ;;
    *) echo "unknown arch: $go_arch" && exit 1 ;;
esac
case $go_os in
    linux) rust_os='linux-musl' ;;
    windows) rust_os='windows' ;;
    android) rust_os='android' ;;
    *) echo "unknown os: $go_os" && exit 1 ;;
esac

# Find artifacts and uncompress in the corresponding directory
DIST_DIR=$(find dist -type d -name "*${go_os}_${go_arch}*")

echo "DIST_DIR: $DIST_DIR"
rm -f ${DIST_DIR}/${project_name}*

find artifacts -type f -wholename "*${rust_arch}*${rust_os}*/${project_name}*" -exec cp {} ${DIST_DIR}/ \;

