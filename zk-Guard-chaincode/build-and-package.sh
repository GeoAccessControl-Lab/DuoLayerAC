#!/bin/bash
set -e

NAME="acmc"
GO_VER="1.24.0"

echo "构建链码: $NAME"

# 1. 编译二进制
GOOS=linux GOARCH=amd64 go build -o $NAME -ldflags '-s -w' .

# 2. 生成 vendor
go mod tidy -go=$GO_VER
go mod vendor

# 3. 创建 connection.json
cat > connection.json <<EOF
{
  "address": "0.0.0.0:9999",
  "dial_timeout": "10s",
  "tls_required": false
}
EOF

# 4. 创建 metadata.json
cat > metadata.json <<EOF
{
  "type": "ccaasv2",
  "label": "${NAME}_1.0"
}
EOF

# 5. 打包 code.tar.gz（关键：包含 go.mod + go.sum + main.go + vendor）
echo "打包 code.tar.gz（包含源码和依赖）..."
tar czf code.tar.gz \
    go.mod \
    go.sum \
    main.go \
    $NAME \
    connection.json \
    metadata.json \
    vendor/

# 6. 打包外部安装包
echo "打包 $NAME.tar.gz..."
tar czf $NAME.tar.gz code.tar.gz

# 7. 清理临时文件
rm -rf vendor/ $NAME connection.json metadata.json code.tar.gz

echo "打包完成: $NAME.tar.gz"
echo "   部署命令："
echo "   cd ../test-network"
echo "   export CORE_CHAINCODE_MODE=dev"
echo "   ./network.sh deployCC -ccn $NAME -ccp ../zk-Guard-chaincode -ccl golang"
