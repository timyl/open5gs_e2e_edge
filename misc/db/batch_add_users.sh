#!/bin/bash

# 定义常量
KEY="465B5CE8B199B49FAA5F0A2EE238A6BC"  # 认证密钥 K
OPC="E8ED289DEBA952E4283B54E88E6183CA"  # OPc 值
DNN="internet1"                           # DNN (APN)
SST=1                                     # Slice Service Type
SD="000001"                                    # Slice Differentiator
START=1                                   # IMSI 起始后缀
END=3                                    # IMSI 结束后缀
DB_URI="mongodb://localhost/open5gs"      # MongoDB URI (根据需要调整)

# 确保 open5gs-dbctl 在 PATH 中或指定完整路径
OPEN5GS_DBCTL="./open5gs-dbctl"           # 如果在当前目录运行

# 循环插入用户
for ((i = START; i <= END; i++)); do
    # 生成递增的 IMSI，补齐 15 位
    IMSI=$(printf "001010%09d" "$i")     # 格式化为 001010000000001 到 001010000000010
    echo "Adding IMSI: $IMSI"
    $OPEN5GS_DBCTL --db_uri=$DB_URI add_ue_with_slice "$IMSI" "$KEY" "$OPC" "$DNN" "$SST" "$SD"
    if [ $? -eq 0 ]; then
        echo "Successfully added $IMSI"
        # 修改 AMBR 为 1 Gbps
        $OPEN5GS_DBCTL --db_uri=$DB_URI ambr_speed "$IMSI" 1 3 1 3
        if [ $? -eq 0 ]; then
            echo "Successfully set AMBR to 1 Gbps for $IMSI"
        else
            echo "Failed to set AMBR for $IMSI"
        fi
    else
        echo "Failed to add $IMSI"
    fi
done

echo "Batch insertion completed!"
