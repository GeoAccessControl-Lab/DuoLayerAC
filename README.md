# DuoLayerAC

DuoLayerAC 是面向受控地学数据共享的双层访问控制原型。系统复用 zk-Guard 的
请求级隐私授权能力和 PolyLock 的数据级密码保护能力，在统一属性索引与策略
语义下维护两层状态，并进一步支持策略更新、属性撤销及版本化密钥演化。

本仓库对应学位论文第五章。它不重新定义第三、四章的基础密码原语，而是在系统
层完成接口提升、状态协同和端到端组合。仓库只保留源码、参数、数据样本和实验
脚本；链码包、二进制文件、私钥、证明交换文件、运行时 PolyLock 状态及历史实验
结果均未纳入版本库。

## 研究定位

去中心化数据共享同时存在两个不同层面的授权问题：控制平面需要在不公开具体
用户属性的条件下判断请求是否合法，数据平面需要确保对象密钥只能由当前满足
策略的请求方恢复。若两层独立配置属性和策略，策略更新、属性撤销或对象版本
演化可能造成“链上允许但无法解密”或“链上拒绝但旧密钥状态仍被沿用”的语义
偏差。DuoLayerAC 因此不把两个方案简单串联，而是以统一属性索引、统一策略输入
和显式版本状态组织跨层调用。

系统以 zk-Guard 作为请求级隐私授权机制，以 PolyLock 作为数据级密码保护机制。
同一用户属性配置同时派生零知识证明见证和版本化 PolyLock 密钥；同一对象策略
分别编译为控制平面的策略配置与数据平面的授权根集合。对象根 CID、策略版本和
属性版本作为协同状态参与存储与获取流程，使链上授权、IPFS 对象和密码锁对应到
同一个对象版本。

## 跨层语义与状态不变量

DuoLayerAC 的系统级实现围绕以下不变量组织：

1. **属性一致性**：控制平面承诺与数据平面用户密钥由同一属性配置及其有效版本
   派生；
2. **策略一致性**：策略配置矩阵和 PolyLock 授权根集合由同一业务策略及同一
   合法属性空间产生；
3. **对象一致性**：授权证明、对象元数据和密钥锁绑定同一根 CID 与策略版本；
4. **状态一致性**：策略更新和属性更新均形成显式版本迁移，后续对象访问只使用
   当前有效状态；
5. **判定分工**：zk-Guard 给出请求是否满足策略的确定性判定，PolyLock 决定能否
   恢复对象数据密钥，两者共同完成请求授权与密文可用性的闭环验证。

上述不变量是第五章接口提升、正确性分析和动态更新实验的共同对象。它们不改变
zk-Guard 与 PolyLock 各自的底层密码运算，而是约束两套状态在完整共享流程中的
输入来源、版本关系和执行顺序。

## 协同接口与系统路径

```text
系统初始化
  -> 用户注册与版本化属性密钥生成
  -> 数据存储、统一策略编译与双层对象绑定
  -> 请求证明验证、IPFS 获取、PolyLock 解封装与数据解密
  -> 策略更新 / 属性更新
```

zk-Guard 决定请求是否满足公开配置的授权语义，PolyLock 使满足同一策略且处于
有效属性版本的请求方恢复数据密钥；对象根 CID、策略版本与属性版本把两层状态
连接起来。

| 系统阶段 | 主要处理 | 跨层输出 |
| --- | --- | --- |
| `Setup` | 初始化属性空间、控制平面参数、环格参数和版本状态 | 双层公共参数与初始状态 |
| `UserRegister` | 生成用户承诺、注册证明材料并派生 PolyLock 属性密钥 | 用户标识、承诺与版本化密钥 |
| `DataStorage` | 编译统一策略、封装会话密钥、加密并发布地学对象 | 策略状态、锁、根 CID 与对象版本 |
| `DataRetrieve` | 验证请求证明、获取 IPFS 对象、解封装并认证解密 | 授权结果及恢复对象 |
| `PolicyUpdate` | 更新控制平面配置并刷新数据平面授权根和锁 | 新策略版本与对象绑定状态 |
| `AttributeUpdate` | 更新用户属性承诺并重新派生受影响用户密钥 | 新属性版本与有效用户状态 |

每个阶段同时输出可用于实验统计的局部耗时和端到端耗时，使密码计算、链上处理、
IPFS 交互和更新传播能够在同一测量口径下分解。

## 代码结构

```text
DuoLayerAC/
├── DuoLayer-chaincode/          # Fabric 链码与构建脚本
└── DuoLayer-client/
    ├── ipfs-data/               # 初始化、存储、获取、解密和更新客户端
    ├── polylock-v2/             # 第四章 PolyLock 的 Rust/C/Go 核心
    ├── geodata/                 # 完整 Landsat COG 实验对象
    ├── scripts/chapter05/       # 第五章结果整理脚本
    ├── scripts/chapter06/       # BFR-Det/zk-Guard 轻量性补充实验
    ├── run_attribute_update_sweep.sh
    ├── run_policy_update_sweep.sh
    ├── run_system_level_comparison_sweep.sh
    ├── start_fabric_zkguard.sh
    └── test_ipfs_cluster.sh
```

`DuoLayer-chaincode` 与 `DuoLayer-client` 分别对应链上协同状态和链下端到端
编排；内部仍保留 zk-Guard 与 PolyLock 的机制名称，以明确各密码组件的来源与
职责边界。

## 地学数据对象

端到端实验使用 USGS Landsat Collection 2 Level-2 场景
`LC08_L2SP_002059_20240915_02_T1` 的完整 `QA_PIXEL` COG：

```text
DuoLayer-client/geodata/
  LC08_L2SP_002059_20240915_20240921_02_T1_QA_PIXEL.TIF
```

- 字节数：2,078,283
- SHA-256：`d99dbef34e8c8aa3f062a3e78187752b9728810f5f043d29d0de7547ba5c6e51`
- STAC 元数据：
  <https://planetarycomputer.microsoft.com/api/stac/v1/collections/landsat-c2-l2/items/LC08_L2SP_002059_20240915_02_T1>

数据存储实验对该完整 COG 执行 AES-GCM 加密、PolyLock 会话密钥封装和 IPFS
发布；数据获取实验执行链上授权、IPFS 下载、解封装和认证解密，并以 SHA-256
核验恢复对象。属性与策略由受控地学共享场景中的机构、任务角色、责任区域、
产品级别、使用目的和授权期限等业务维度离散构造，不从影像像元反推。

## 环境与部署布局

- Ubuntu Linux（x86-64）
- Docker 与 Docker Compose
- Hyperledger Fabric 2.x test-network
- Go 1.20 或更高版本
- Rust stable、Cargo 与 cgo
- 应用 zk-Guard MTP 补丁的 Kubo/IPFS

原始自动化脚本按 Fabric samples 的下列布局运行：

```text
fabric-samples/test-network/
├── DuoLayer-chaincode/
└── DuoLayer-client/
```

可将仓库中的两个同名目录复制或符号链接到 `test-network/`，随后在
`DuoLayer-client/` 内执行脚本。

## 功能验证

```bash
cd fabric-samples/test-network/DuoLayer-client

./start_fabric_zkguard.sh 1000 25 down
./start_fabric_zkguard.sh 100 4 up

./test_ipfs_cluster.sh \
  --attr-num 100 \
  --legal-space-size 1000 \
  --target-sigma 0.8 \
  --affected-users 100 \
  --data-object-file geodata/LC08_L2SP_002059_20240915_20240921_02_T1_QA_PIXEL.TIF
```

该流程检查用户注册、对象存储、策略决策与对象恢复、策略更新和属性更新，并输出
各阶段计时以及数据对象名称、字节数和哈希。

## 第五章实验

每个参数点都独立执行网络清理、属性规模写入、Fabric 启动与链码部署，再执行
端到端测量。正式重复次数作为首个参数传入。

```bash
cd fabric-samples/test-network/DuoLayer-client

./run_attribute_update_sweep.sh 10
./run_policy_update_sweep.sh 10

DATA_OBJECT_FILE="$PWD/geodata/LC08_L2SP_002059_20240915_20240921_02_T1_QA_PIXEL.TIF" \
  ./run_system_level_comparison_sweep.sh 10
```

- 属性更新扫描：改变属性全集规模和受影响用户数；
- 策略更新扫描：改变属性规模与策略选择比例，并分解本地编译、锁刷新、IPFS
  发布和链上登记开销；
- 系统级实验：比较用户注册、数据存储、数据获取、策略更新与属性更新的端到端
  时间。

实验变量与学位论文保持一致：属性全集规模用于观察通用策略编译和用户密钥派生
的增长趋势，受影响用户数用于刻画属性撤销的传播范围，策略选择比例用于刻画授权
根集合和锁刷新规模。系统级比较采用相同的 Fabric/IPFS 部署、完整 Landsat COG
对象和一致的计时边界，避免把不同数据载荷或不同网络状态引入方案间对比。

图表数据处理：

```bash
python3 scripts/chapter05/prepare_attribute_update_plot_data.py --help
python3 scripts/chapter05/prepare_policy_update_plot_data.py --help
python3 scripts/chapter05/prepare_system_comparison_plot_data.py --help
```

每轮运行在相应结果目录中生成原始日志、参数清单、逐轮汇总和 `plot_data/*.csv`。
这些派生结果由 `.gitignore` 排除，应由复现实验重新生成。

## 发表情况

本仓库中的访问控制双层架构设计：IEEE Transactions on Consumer Electronics
（TCE，新锐1区、TOP、JCR Q1），2026 年发表。

本仓库用于匿名复现与学术核验，不在仓库地址或文档中标注个人身份信息。
