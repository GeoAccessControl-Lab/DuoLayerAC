#!/bin/bash
# usage:
#   ./start_fabric_zkguard.sh <attribute_count> <org_count> <mode> [sigma] [legal_space_size]
#
# examples:
#   ./start_fabric_zkguard.sh 100 4 up 0.90 1000
#   ./start_fabric_zkguard.sh 1000 25 down
#
# Parameters:
#   attribute_count -> Go constant AttrNum
#   org_count       -> Fabric organization count
#   mode            -> up or down
#   sigma           -> polyLockTargetSigma, default 0.90
#   legal_space_size-> |S_Sigma|, default attribute_count * 10

if [ "$#" -lt 3 ]; then
    echo "Usage: $0 <attribute_count> <org_count> [up|down] [sigma] [legal_space_size]"
    exit 1
fi

ATTR_COUNT=$1
ORG_COUNT=$2
MODE=$3
SIGMA=${4:-0.90}
LEGAL_SPACE_SIZE=${5:-$((ATTR_COUNT * 10))}

if ! [[ "$ATTR_COUNT" =~ ^[1-9][0-9]*$ ]] || \
   ! [[ "$ORG_COUNT" =~ ^[1-9][0-9]*$ ]] || \
   ! [[ "$LEGAL_SPACE_SIZE" =~ ^[1-9][0-9]*$ ]]; then
    echo "attribute_count, org_count and legal_space_size must be positive integers" >&2
    exit 2
fi
if ! awk -v sigma="$SIGMA" 'BEGIN { exit !(sigma > 0.0 && sigma <= 1.0) }'; then
    echo "sigma must be in (0,1]" >&2
    exit 2
fi

SYSTEMINIT_FILE="/root/go/src/github.com/hyperledger/fabric/scripts/fabric-samples/test-network/DuoLayer-client/ipfs-data/systemInit/main.go"
DATARETRIEVE_FILE="/root/go/src/github.com/hyperledger/fabric/scripts/fabric-samples/test-network/DuoLayer-client/ipfs-data/dataRetrieve/main.go"
DATASTORAGE_FILE="/root/go/src/github.com/hyperledger/fabric/scripts/fabric-samples/test-network/DuoLayer-client/ipfs-data/dataStorage/main.go"
UPDATEPOLICY_FILE="/root/go/src/github.com/hyperledger/fabric/scripts/fabric-samples/test-network/DuoLayer-client/ipfs-data/policyUpdate/main.go"
ATTRIBUTEUPDATE_FILE="/root/go/src/github.com/hyperledger/fabric/scripts/fabric-samples/test-network/DuoLayer-client/ipfs-data/attributeUpdate/main.go"
CHAINCODE="/root/go/src/github.com/hyperledger/fabric/scripts/fabric-samples/test-network/DuoLayer-chaincode/main.go"

cd /root/go/src/github.com/hyperledger/fabric/scripts/fabric-samples/test-network || exit 1

replace_int_const() {
    local file=$1
    local name=$2
    local value=$3

    if [ -f "$file" ]; then
        sed -i 's/\('"$name"'\s*=\s*\)[0-9]\+/\1'"$value"'/' "$file"
    else
        echo "文件 $file 不存在"
        exit 1
    fi
}

replace_float_const_if_exists() {
    local file=$1
    local name=$2
    local value=$3

    if [ ! -f "$file" ]; then
        echo "文件 $file 不存在"
        exit 1
    fi

    if grep -q "$name" "$file"; then
        sed -i 's/\('"$name"'\s*=\s*\)[0-9]\+\(\.[0-9]\+\)\?/\1'"$value"'/' "$file"
    fi
}

replace_int_expression_if_exists() {
    local file=$1
    local name=$2
    local value=$3

    if [ ! -f "$file" ]; then
        echo "文件 $file 不存在"
        exit 1
    fi

    if grep -Eq "^[[:space:]]*$name[[:space:]]*=" "$file"; then
        sed -i -E \
            "s|^([[:space:]]*$name[[:space:]]*=[[:space:]]*).*$|\\1$value|" \
            "$file"
    fi
}

if [ "$MODE" = "up" ]; then
    echo "操作模式: $MODE"
    echo "设置属性个数为: $ATTR_COUNT"
    echo "设置组织个数为: $ORG_COUNT"
    echo "设置 Sigma 为: $SIGMA"
    echo "设置合法属性配置空间规模为: $LEGAL_SPACE_SIZE"

    # --------------------------------------------------------------------------
    # 0. 更新 AttrNum
    # --------------------------------------------------------------------------
    replace_int_const "$CHAINCODE" "AttrNum" "$ATTR_COUNT"
    replace_int_const "$SYSTEMINIT_FILE" "AttrNum" "$ATTR_COUNT"
    replace_int_const "$DATARETRIEVE_FILE" "AttrNum" "$ATTR_COUNT"
    replace_int_const "$DATASTORAGE_FILE" "AttrNum" "$ATTR_COUNT"
    replace_int_const "$UPDATEPOLICY_FILE" "AttrNum" "$ATTR_COUNT"
    replace_int_const "$ATTRIBUTEUPDATE_FILE" "AttrNum" "$ATTR_COUNT"

    # --------------------------------------------------------------------------
    # 0.1 更新 Sigma
    # 仅修改客户端中存在 polyLockTargetSigma 的文件。
    # 不修改 polyLockLegalSpaceSize。
    # --------------------------------------------------------------------------
    replace_float_const_if_exists "$SYSTEMINIT_FILE" "polyLockTargetSigma" "$SIGMA"
    replace_float_const_if_exists "$DATASTORAGE_FILE" "polyLockTargetSigma" "$SIGMA"
    replace_float_const_if_exists "$UPDATEPOLICY_FILE" "polyLockTargetSigma" "$SIGMA"
    replace_float_const_if_exists "$ATTRIBUTEUPDATE_FILE" "polyLockTargetSigma" "$SIGMA"

    # --------------------------------------------------------------------------
    # 0.2 更新合法属性配置空间规模。该参数不影响链码电路维度，但会
    #     影响 systemInit、PreResolve、Encaps 和后续策略更新的实际输入。
    # --------------------------------------------------------------------------
    replace_int_expression_if_exists "$SYSTEMINIT_FILE" "polyLockProfileTotal" "$LEGAL_SPACE_SIZE"
    replace_int_expression_if_exists "$DATASTORAGE_FILE" "polyLockLegalSpaceSize" "$LEGAL_SPACE_SIZE"
    replace_int_expression_if_exists "$UPDATEPOLICY_FILE" "polyLockLegalSpaceSize" "$LEGAL_SPACE_SIZE"

    # --------------------------------------------------------------------------
    # 1. 可选编译函数，保留原脚本结构
    # --------------------------------------------------------------------------
    compile_program() {
        local prog_dir=$1
        echo "编译 $prog_dir 程序..."
        cd "$prog_dir" || exit 1
        go build
        if [ $? -ne 0 ]; then
            echo "$prog_dir 编译失败"
            exit 1
        fi
        cd - > /dev/null
    }

    # --------------------------------------------------------------------------
    # 2.1 启动 Fabric 网络
    # --------------------------------------------------------------------------
    echo "设置环境变量..."
    source /root/.bashrc
    export PATH=${PWD}/../bin:$PATH
    export FABRIC_CFG_PATH=$PWD/../config/

    echo "启动网络并创建通道..."
    if ! ./network.sh up createChannel; then
        echo "Error: network.sh up createChannel 失败" >&2
        exit 1
    fi

    # --------------------------------------------------------------------------
    # 2.2 启动额外组织
    # --------------------------------------------------------------------------
    for ((i=4; i<=$ORG_COUNT; i++)); do
        echo "=== 处理 组织$i 的文件 ==="

        cp -a addOrg3 "addOrg$i"
        cp -a scripts/org3-scripts "scripts/org$i-scripts"

        ./replace_orgX.sh -n $i -d "addOrg$i" -p $((20000 + i))
        ./replace_orgX.sh -n $i -d "scripts/org$i-scripts" -p $((20000 + i))

        ./modify_files.sh -m set -n $i -p $((20000 + i))

        echo "拷贝 organizations/peerOrganizations/org1.example.com 到 addOrg$i/compose/docker/peercfg/"
        cp -a "/root/go/src/github.com/hyperledger/fabric/scripts/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com" \
              "/root/go/src/github.com/hyperledger/fabric/scripts/fabric-samples/test-network/addOrg$i/compose/docker/peercfg/"

        echo "启动组织$i..."
        cd "/root/go/src/github.com/hyperledger/fabric/scripts/fabric-samples/test-network/addOrg$i" || exit 1
        ./addOrg$i.sh up
        cd - > /dev/null

        ./replace_orgX.sh -n $i -d "organizations/peerOrganizations/org$i.example.com" -p $((20000 + i))
        sleep 1
    done

    # --------------------------------------------------------------------------
    # 2.3 部署链码
    # --------------------------------------------------------------------------
    echo "部署链码 acmc 到通道 mychannel..."
    if ! ./network.sh deployCC -c mychannel -ccn acmc -ccp ./DuoLayer-chaincode -ccl go; then
        echo "Error: network.sh deployCC 失败" >&2
        exit 1
    fi

    echo "================ SETUP_SUMMARY_BEGIN ================"
    echo "EXPERIMENT=Setup"
    echo "ATTR_NUM=$ATTR_COUNT"
    echo "ORG_COUNT=$ORG_COUNT"
    echo "SIGMA=$SIGMA"
    echo "LEGAL_SPACE_SIZE=$LEGAL_SPACE_SIZE"
    echo "MODE=up"
    echo "STATUS=OK"
    echo "================= SETUP_SUMMARY_END ================="

    exit 0

elif [ "$MODE" = "down" ]; then
    echo "操作模式: $MODE"
    echo "删除操作开始..."

    ./network.sh down >/dev/null 2>&1

    for ((i=4; i<=$ORG_COUNT; i++)); do
        echo "删除组织$i的 Docker 卷..."
        docker volume rm "compose_peer0.org$i.example.com" 2>/dev/null
        ./modify_files.sh -m delete -n $i -p $((20000 + i))
    done

    fabric_containers=$(docker ps -a --filter "name=dev-peer" --filter "name=peer0.org" --filter "name=orderer" --filter "name=cli" -q)
    if [[ -n "$fabric_containers" ]]; then
        docker rm -f $fabric_containers
    else
        echo "未找到 Fabric 相关容器，无需删除。"
    fi

    fabric_volumes=$(docker volume ls | grep -E 'compose|peer0.org' | awk '{print $2}')
    if [[ -n "$fabric_volumes" ]]; then
        echo "将删除以下 Fabric 相关卷："
        echo "$fabric_volumes"
        while read -r volume_name; do
            docker volume rm "$volume_name"
        done <<< "$fabric_volumes"
    else
        echo "未找到 Fabric 相关卷，无需删除。"
    fi

    docker volume prune -f

    for i in $(docker images | grep acmc-1.0 | awk '{print $3}'); do
        docker rmi -f "$i"
    done

    echo "================ SETUP_SUMMARY_BEGIN ================"
    echo "EXPERIMENT=Setup"
    echo "ATTR_NUM=$ATTR_COUNT"
    echo "ORG_COUNT=$ORG_COUNT"
    echo "SIGMA=$SIGMA"
    echo "LEGAL_SPACE_SIZE=$LEGAL_SPACE_SIZE"
    echo "MODE=down"
    echo "STATUS=OK"
    echo "================= SETUP_SUMMARY_END ================="

    echo "删除操作完成。"

else
    echo "无效的操作模式: $MODE"
    echo "可选: up 或 down"
    exit 1
fi
