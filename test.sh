#!/bin/bash
# 跑 Rules.swift 的测试，不需要 Xcode、不需要安装、不需要 root。
set -euo pipefail
cd "$(dirname "$0")"

mkdir -p build
swiftc -O app/Rules.swift tests/RulesTests.swift -o build/rules-tests
./build/rules-tests
