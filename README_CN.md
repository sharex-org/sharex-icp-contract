# ShareX Vault Backend

这是一个基于Internet Computer (IC)区块链平台的智能合约，用于管理ShareX生态系统中的品牌、商户、设备和交易数据。

## 功能概述

- **权限管理**：实现基于角色的访问控制（Admin、Operator、Merchant、Reader）
- **数据管理**：
  - 国家统计信息管理
  - 品牌注册与查询
  - 商户信息管理
  - 设备管理
  - 交易数据上传与查询
- **资源管理**：cycles余额监控和管理
- **合约升级**：支持合约升级与回滚
- **统计功能**：提供各种统计数据查询接口

## 技术特点

- 使用`ic_stable_structures`实现稳定内存存储，确保升级时数据不会丢失
- 细粒度权限控制，保障数据安全
- 全面的操作日志记录，便于审计和调试
- 支持加密数据存储，保护敏感信息
- 完整的资源监控机制，防止系统资源耗尽

## 部署指南

### 前提条件

- 安装 [dfx](https://internetcomputer.org/docs/current/developer-docs/build/install-upgrade-remove)（Internet Computer SDK）
- 安装 Rust 和 Cargo

### 部署步骤

1. 克隆仓库
   ```
   git clone <repository-url>
   cd sharex-vault-backend
   ```

2. 启动本地开发网络
   ```
   dfx start --background
   ```

3. 部署合约
   ```
   dfx deploy
   ```

## 使用指南

### 初始化

合约部署后，部署者自动成为管理员（Admin角色）。管理员可以为其他用户分配角色。

### 角色管理

- **管理员(Admin)**：可以执行所有操作，包括分配角色和升级合约
- **运营者(Operator)**：可以注册国家、品牌、商户和设备
- **商户(Merchant)**：可以上传交易数据
- **读取者(Reader)**：只能查询数据

### 基本操作流程

1. 管理员分配角色
2. 运营者注册国家
3. 运营者注册品牌
4. 运营者注册商户
5. 运营者注册设备
6. 商户上传交易数据
7. 用户查询数据

### API示例

#### 分配角色
```bash
dfx canister call sharex-vault-backend assign_role '(principal "<principal-id>", variant { Operator })'
```

#### 注册国家
```bash
dfx canister call sharex-vault-backend register_country '("JP")'
```

#### 注册品牌
```bash
dfx canister call sharex-vault-backend register_partner '("0001", "PowerNow", "JP", "SX12345", "充电宝服务", "PowerBank")'
```

#### 注册商户
```bash
dfx canister call sharex-vault-backend register_merchant '("加密的商户名称", "M001", null, "JP", "TOKYO", null, null, "SX67890")'
```

#### 注册设备
```bash
dfx canister call sharex-vault-backend register_device '("D001", "PowerBank", "0001", "M001")'
```

#### 上传交易数据
```bash
dfx canister call sharex-vault-backend upload_transaction_batch '("D001", "2023-06-01", vec { record { user_id_encrypted = opt "加密的用户ID"; sharex_id_encrypted = null; transaction_amount_encrypted = opt "加密的金额"; timestamp = 1685577600000000000; additional_data = null } })'
```

#### 查询统计数据
```bash
dfx canister call sharex-vault-backend get_stats
```

## 安全考虑

- 敏感数据应在客户端加密后再上传
- 定期监控cycles余额，防止资源耗尽
- 权限管理应严格控制，特别是Admin角色
- 合约升级前应充分测试新版本

## 升级流程

1. 管理员调用`prepare_upgrade`函数
2. 使用dfx执行升级
   ```bash
   dfx canister install sharex-vault-backend --mode upgrade
   ```
3. 管理员调用`complete_upgrade`函数，提供新版本号
   ```bash
   dfx canister call sharex-vault-backend complete_upgrade '("1.1.0")'
   ```
4. 如需回滚，管理员可调用`rollback_upgrade`函数
   ```bash
   dfx canister call sharex-vault-backend rollback_upgrade
   ```

## 数据结构

### 国家信息 (CountryInfo)
- iso2: ISO2国家代码
- timestamp: 注册时间戳

### 品牌信息 (PartnerInfo)
- partner_code: 品牌代码
- partner_name: 品牌名称
- iso2: ISO2国家代码
- verification: 认证编号
- description: 描述信息
- business_type: 业务类型
- timestamp: 注册时间戳

### 商户信息 (MerchantInfo)
- merchant_name_encrypted: 加密的商户名称
- merchant_id: 商户ID
- description_encrypted: 加密的描述（可选）
- iso2: 国家代码
- location_id: 位置ID
- location_encrypted: 加密的位置信息（可选）
- merchant_type_encrypted: 加密的商户类型（可选）
- verification: 认证编号
- timestamp: 注册时间戳

### 设备信息 (DeviceInfo)
- device_id: 设备ID
- device_type: 设备类型
- partner_code: 品牌代码
- merchant_id: 商户ID
- timestamp: 注册时间戳

### 交易信息
- BasicTransactionInfo: 基本信息（设备哈希、日期、订单数量）
- TransactionDetail: 交易详情（加密的用户ID、ShareX ID、交易金额等）
- TransactionBatch: 交易批次（基本信息、详情列表、批次时间戳）

## 贡献指南

欢迎提交问题和改进建议。请遵循以下步骤：

1. Fork仓库
2. 创建功能分支
3. 提交修改
4. 推送到分支
5. 创建Pull Request

## 许可证

[MIT](LICENSE)