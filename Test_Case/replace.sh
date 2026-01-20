#!/bin/bash
# 将TeZerphy_Case中的所有py文件中的from Transfer.Config.ST import config替换为from Transfer.Config.Zerphy import config

# 获取脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 计数器
count=0

# 遍历目录下所有.py文件并进行替换
for file in "$SCRIPT_DIR"/*.py; do
    if [ -f "$file" ]; then
        # 检查文件是否包含需要替换的字符串
        if grep -q "from Transfer.Config.ST import config" "$file"; then
            # 使用sed进行原地替换
            sed -i 's/from Transfer\.Config\.ST import config/from Transfer.Config.Zerphy import config/g' "$file"
            echo "已替换: $(basename "$file")"
            ((count++))
        fi
    fi
done

echo "替换完成！共修改了 $count 个文件。"
