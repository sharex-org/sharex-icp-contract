# ShareX Vault Backend

This is a smart contract based on the Internet Computer (IC) blockchain platform, designed to manage brands, merchants, devices, and transaction data in the ShareX ecosystem.

## Features Overview

- **Permission Management**: Role-based access control (Admin, Operator, Merchant, Reader)
- **Data Management**:
  - Country statistics management
  - Brand registration and querying
  - Merchant information management
  - Device management
  - Transaction data uploading and querying
- **Resource Management**: Cycles balance monitoring and management
- **Contract Upgrade**: Support for contract upgrades and rollbacks
- **Statistics**: Various statistical data query interfaces

## Technical Highlights

- Uses `ic_stable_structures` for stable memory storage, ensuring data persistence during upgrades
- Fine-grained permission control for data security
- Comprehensive operation logging for auditing and debugging
- Support for encrypted data storage to protect sensitive information
- Complete resource monitoring mechanism to prevent system resource depletion

## Deployment Guide

### Prerequisites

- Install [dfx](https://internetcomputer.org/docs/current/developer-docs/build/install-upgrade-remove) (Internet Computer SDK)
- Install Rust and Cargo

### Deployment Steps

1. Clone the repository
   ```
   git clone <repository-url>
   cd sharex-vault-backend
   ```

2. Start the local development network
   ```
   dfx start --background
   ```

3. Deploy the contract
   ```
   dfx deploy
   ```

## Usage Guide

### Initialization

After deployment, the deployer automatically becomes an administrator (Admin role). Administrators can assign roles to other users.

### Role Management

- **Admin**: Can perform all operations, including role assignment and contract upgrades
- **Operator**: Can register countries, brands, merchants, and devices
- **Merchant**: Can upload transaction data
- **Reader**: Can only query data

### Basic Operation Flow

1. Admin assigns roles
2. Operator registers countries
3. Operator registers brands
4. Operator registers merchants
5. Operator registers devices
6. Merchant uploads transaction data
7. Users query data

### API Examples

#### Assign Role
```bash
dfx canister call sharex-vault-backend assign_role '(principal "<principal-id>", variant { Operator })'
```

#### Register Country
```bash
dfx canister call sharex-vault-backend register_country '("JP")'
```

#### Register Brand
```bash
dfx canister call sharex-vault-backend register_partner '("0001", "PowerNow", "JP", "SX12345", "Power Bank Service", "PowerBank")'
```

#### Register Merchant
```bash
dfx canister call sharex-vault-backend register_merchant '("Encrypted Merchant Name", "M001", null, "JP", "TOKYO", null, null, "SX67890")'
```

#### Register Device
```bash
dfx canister call sharex-vault-backend register_device '("D001", "PowerBank", "0001", "M001")'
```

#### Upload Transaction Data
```bash
dfx canister call sharex-vault-backend upload_transaction_batch '("D001", "2023-06-01", vec { record { user_id_encrypted = opt "encrypted_user_id"; sharex_id_encrypted = null; transaction_amount_encrypted = opt "encrypted_amount"; timestamp = 1685577600000000000; additional_data = null } })'
```

#### Query Statistics
```bash
dfx canister call sharex-vault-backend get_stats
```

## Security Considerations

- Sensitive data should be encrypted on the client side before uploading
- Regularly monitor cycles balance to prevent resource depletion
- Role management should be strictly controlled, especially the Admin role
- New versions should be thoroughly tested before contract upgrades

## Upgrade Process

1. Admin calls the `prepare_upgrade` function
2. Use dfx to perform the upgrade
   ```bash
   dfx canister install sharex-vault-backend --mode upgrade
   ```
3. Admin calls the `complete_upgrade` function with the new version number
   ```bash
   dfx canister call sharex-vault-backend complete_upgrade '("1.1.0")'
   ```
4. For rollback, admin can call the `rollback_upgrade` function
   ```bash
   dfx canister call sharex-vault-backend rollback_upgrade
   ```

## Data Structures

### Country Information (CountryInfo)
- iso2: ISO2 country code
- timestamp: Registration timestamp

### Brand Information (PartnerInfo)
- partner_code: Brand code
- partner_name: Brand name
- iso2: ISO2 country code
- verification: Certification number
- description: Description
- business_type: Business type
- timestamp: Registration timestamp

### Merchant Information (MerchantInfo)
- merchant_name_encrypted: Encrypted merchant name
- merchant_id: Merchant ID
- description_encrypted: Encrypted description (optional)
- iso2: Country code
- location_id: Location ID
- location_encrypted: Encrypted location information (optional)
- merchant_type_encrypted: Encrypted merchant type (optional)
- verification: Certification number
- timestamp: Registration timestamp

### Device Information (DeviceInfo)
- device_id: Device ID
- device_type: Device type
- partner_code: Brand code
- merchant_id: Merchant ID
- timestamp: Registration timestamp

### Transaction Information
- BasicTransactionInfo: Basic information (device hash, date, order count)
- TransactionDetail: Transaction details (encrypted user ID, ShareX ID, transaction amount, etc.)
- TransactionBatch: Transaction batch (basic info, details list, batch timestamp)

## Contribution Guidelines

Issues and improvement suggestions are welcome. Please follow these steps:

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

[MIT](LICENSE)