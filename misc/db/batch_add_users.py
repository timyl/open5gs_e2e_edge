#!/usr/bin/env python3

import subprocess
import sys

# 定义常量
KEY = "465B5CE8B199B49FAA5F0A2EE238A6BC"  # 认证密钥 K
OPC = "E8ED289DEBA952E4283B54E88E6183CA"  # OPc 值
DNN = "internet1"                           # DNN (APN)
SST = 1                                     # Slice Service Type
SD = "000001"                                    # Slice Differentiator
START = 1                                   # IMSI 起始后缀
END = 10                                    # IMSI 结束后缀
DB_URI = "mongodb://localhost/open5gs"      # MongoDB URI
OPEN5GS_DBCTL = "./open5gs-dbctl"           # open5gs-dbctl 路径

# 批量插入用户
for i in range(START, END + 1):
    # 生成递增的 IMSI，补齐 15 位
    imsi = f"001010{i:09d}"  # 格式化为 001010000000001 到 001010000000010
    print(f"Adding IMSI: {imsi}")
    
    # 构造添加命令
    add_cmd = [
        OPEN5GS_DBCTL,
        "--db_uri=" + DB_URI,
        "add_ue_with_slice",
        imsi,
        KEY,
        OPC,
        DNN,
        str(SST),
        SD
    ]
    
    # 执行添加命令
    result = subprocess.run(add_cmd, capture_output=True, text=True)
    if result.returncode == 0:
        print(f"Successfully added {imsi}")
        # 修改 AMBR 为 1 Gbps
        ambr_cmd = [
            OPEN5GS_DBCTL,
            "--db_uri=" + DB_URI,
            "ambr_speed",
            imsi,
            "1", "3",  # 下行 1 Gbps
            "1", "3"   # 上行 1 Gbps
        ]
        ambr_result = subprocess.run(ambr_cmd, capture_output=True, text=True)
        if ambr_result.returncode == 0:
            print(f"Successfully set AMBR to 1 Gbps for {imsi}")
        else:
            print(f"Failed to set AMBR for {imsi}: {ambr_result.stderr}")
    else:
        print(f"Failed to add {imsi}: {result.stderr}")

print("Batch insertion completed!")
