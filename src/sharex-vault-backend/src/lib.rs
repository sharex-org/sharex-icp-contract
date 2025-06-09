// ===== ShareX Vault Backend Smart Contract =====
// This is a smart contract for managing brands, merchants, devices, and transaction data in the ShareX ecosystem
// It implements permission management, data storage, and query functions

// ===== Import Dependencies =====
use candid::{CandidType, Deserialize};  // Used for serialization/deserialization of data
use std::cell::RefCell; // Used for mutable references
use ic_stable_structures::{
    StableBTreeMap,
    memory_manager::{MemoryManager, VirtualMemory, MemoryId},
    DefaultMemoryImpl,
    Storable,
    BoundedStorable
}; // Used for stable memory storage
use ic_cdk::api::{time, caller}; // Basic API functions
use ic_cdk::api::call::msg_cycles_available; // Get available cycles
use ic_cdk::api::call::msg_cycles_accept; // Accept cycles
use ic_cdk::api::canister_balance; // Get canister balance
use candid::Principal; // Used to represent identities
use serde::Serialize; // Used for serialization
use std::borrow::Cow; // Used for efficient string operations

// ===== Constants Definition =====
// Define cycles balance thresholds for monitoring contract resource usage
const MIN_CYCLES_BALANCE: u64 = 5_000_000_000_000; // 5T cycles as the minimum balance threshold
const CRITICAL_CYCLES_BALANCE: u64 = 1_000_000_000_000; // 1T cycles as the critical threshold

// Define storage limits constants
const MAX_TRANSACTION_KEY_SIZE: u32 = 1024; // 1KB, maximum transaction key size
const MAX_TRANSACTION_BATCH_SIZE: u32 = 1024 * 1024; // 1MB, maximum transaction batch size
const MAX_TRANSACTION_DETAILS_PER_BATCH: usize = 100; // Maximum transaction details per batch

// Define memory ID constants for stable memory management
const MEMORY_ID_TRANSACTION_BATCHES: u8 = 1;
const MEMORY_ID_COUNTRY_STATS: u8 = 2;
const MEMORY_ID_PARTNER_REGISTRY: u8 = 3;
const MEMORY_ID_MERCHANT_REGISTRY: u8 = 4;
const MEMORY_ID_DEVICE_REGISTRY: u8 = 5;
static MEMORY_ID_USER_ROLES: u8 = 6;

// ===== Memory Management =====
// Define virtual memory type for stable memory management
type Memory = VirtualMemory<DefaultMemoryImpl>;

// Create a memory manager for allocating and managing stable memory
thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));
}

// ===== Data Structure Definitions =====

// 1. Permission Management Data Structure
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
enum Role {
    Admin,      // Administrator: can perform all operations
    Operator,   // Operator: can register brands, merchants, devices
    Merchant,   // Merchant: can upload transaction data
    Reader      // Reader: can only query data
}

// 统一API响应结构
#[derive(CandidType, Deserialize, Clone, Debug, Serialize)]
pub struct ApiResponse<T> {
    code: u32,           // 状态码：0表示成功，非0表示错误
    message: String,     // 消息：成功或错误信息
    data: Option<T>,     // 数据：可选，成功时包含返回数据
}

// 实现ApiResponse的辅助方法
impl<T> ApiResponse<T> {
    // 创建成功响应
    pub fn success(data: T, message: &str) -> Self {
        ApiResponse {
            code: 0,
            message: message.to_string(),
            data: Some(data),
        }
    }
    
    // 创建成功响应（无数据）
    pub fn success_no_data(message: &str) -> ApiResponse<()> {
        ApiResponse {
            code: 0,
            message: message.to_string(),
            data: None,
        }
    }
    
    // 创建错误响应
    pub fn error<E>(code: u32, message: &str) -> ApiResponse<E> {
        ApiResponse {
            code,
            message: message.to_string(),
            data: None,
        }
    }
    
    // 从Result转换为ApiResponse
    pub fn from_result<E>(result: Result<T, E>, success_msg: &str) -> Self 
    where E: std::fmt::Display {
        match result {
            Ok(data) => Self::success(data, success_msg),
            Err(e) => Self {
                code: 1, // 通用错误码
                message: e.to_string(),
                data: None,
            },
        }
    }
}

// 2. Country Distribution Information Data Structure
#[derive(CandidType, Deserialize, Clone, Debug, Serialize)]
pub struct CountryInfo {
    iso2: String,               // ISO2 country code
    timestamp: u64,             // Timestamp
}


// 3. Brand Registration Information Data Structure
#[derive(CandidType, Deserialize, Clone, Debug, Serialize)]
pub struct PartnerInfo {
    partner_code: String,        // Brand code, e.g., "0001"
    partner_name: String,        // Brand name, e.g., "PowerNow"
    iso2: String,               // ISO2 country code, e.g., "JP"
    verification: String,        // ShareX issuance certification number
    description: String,         // 1~1024 character service description
    business_type: String,       // Business type, e.g., "PowerBank/VendingMachine"
    timestamp: u64,              // Registration timestamp
}

// 4. Merchant Information Data Structure
#[derive(CandidType, Deserialize, Clone, Debug, Serialize)]
pub struct MerchantInfo {
    merchant_name_encrypted: String,    // Encrypted merchant name
    merchant_id: String,                // Merchant ID
    description_encrypted: Option<String>, // Encrypted description
    iso2: String,                       // Country code
    location_id: String,                // City code
    location_encrypted: Option<String>, // Encrypted location
    merchant_type_encrypted: Option<String>, // Encrypted scene type
    verification: String,               // Certification number
    timestamp: u64,                     // Timestamp
}

// 5. Device Registration Information Data Structure
#[derive(CandidType, Deserialize, Clone, Debug, Serialize)]
pub struct DeviceInfo {
    device_id: String,           // Device ID (MD5 encrypted)
    device_type: String,         // Device type, e.g., "charger"
    partner_code: String,        // Brand ID
    merchant_id: String,         // Merchant ID
    timestamp: u64,              // Timestamp
}

// 6. Transaction Information Data Structure
// Basic transaction data
#[derive(CandidType, Deserialize, Clone, Debug, Serialize)]
pub struct BasicTransactionInfo {
    device_hash: String,         // Device hash
    date: String,                // Date, format: "YYYY-MM-DD"
    order_count: u32,            // Order quantity
}

// Transaction details (flexible structure, supports different formats)
#[derive(CandidType, Deserialize, Clone, Debug, Serialize)]
pub struct TransactionDetail {
    user_id_encrypted: Option<String>,        // Encrypted user ID
    sharex_id_encrypted: Option<String>,      // Encrypted ShareX ID (optional)
    transaction_amount_encrypted: Option<String>, // Encrypted transaction amount
    timestamp: u64,                           // Transaction timestamp
    additional_data: Option<String>,          // Additional information (JSON format string)
}

// Transaction batch
#[derive(CandidType, Deserialize, Clone, Debug, Serialize)]
pub struct TransactionBatch {
    basic_info: BasicTransactionInfo,         // Basic transaction data
    details_encrypted: Vec<TransactionDetail>, // Encrypted transaction details list
    batch_timestamp: u64,                     // Batch timestamp
}

// Storage key - used for transaction batches
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct TransactionKey {
    device_hash: String,  // Device hash
    date: String,        // Date
}

// System state data structure
#[derive(CandidType, Deserialize, Clone, Debug, Serialize)]
struct SystemState {
    last_cycles_notification: u64,  // Last cycles notification time
    is_upgrade_in_progress: bool,   // Whether the contract is upgrading
    version: String,                // Current contract version
    previous_version: String,       // Previous version, used for rollback
    upgrade_timestamp: u64,         // Last upgrade time
}

// Comprehensive statistics information
#[derive(CandidType, Deserialize, Clone, Debug, Serialize)]
struct StatsInfo {
    partners_count: usize,           // Total number of brands
    merchants_count: usize,          // Total number of merchants
    devices_count: usize,            // Total number of devices
    transaction_batches_count: usize, // Total number of transaction batches
    cycles_balance: u64,             // Cycles balance
    countries_count: usize,          // Total number of countries
}
// Current contract information
#[derive(CandidType, Deserialize, Clone, Debug)]
struct CanisterInfo {
    cycles_balance: u64,
    is_upgrading: bool,
    version: String,
}

// ===== Implementing Necessary Traits for Stable Memory Storage =====

// Implement Storable for Role
impl Storable for Role {
    fn to_bytes(&self) -> Cow<[u8]> {
        let bytes = candid::encode_one(self).expect("Failed to encode Role");
        Cow::Owned(bytes)
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        candid::decode_one(&bytes).expect("Failed to decode Role")
    }
}

// Implement BoundedStorable for Role
impl BoundedStorable for Role {
    const MAX_SIZE: u32 = 100; // Role data is small
    const IS_FIXED_SIZE: bool = false;
}

// Implement Storable for CountryInfo
impl Storable for CountryInfo {
    fn to_bytes(&self) -> Cow<[u8]> {
        // Use candid serialization
        let bytes = candid::encode_one(self).expect("Failed to encode CountryInfo");
        Cow::Owned(bytes)
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        // Use candid deserialization
        candid::decode_one(&bytes).expect("Failed to decode CountryInfo")
    }
}

// Implement BoundedStorable for CountryInfo
impl BoundedStorable for CountryInfo {
    const MAX_SIZE: u32 = 200; // 200 bytes should be sufficient
    const IS_FIXED_SIZE: bool = false; // Variable size
}

// Implement Storable for TransactionKey
impl Storable for TransactionKey {
    fn to_bytes(&self) -> Cow<[u8]> {
        // Use candid serialization
        let bytes = candid::encode_one(self).expect("Failed to encode TransactionKey");
        Cow::Owned(bytes)
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        // Use candid deserialization
        candid::decode_one(&bytes).expect("Failed to decode TransactionKey")
    }
}

// Implement BoundedStorable for TransactionKey
impl BoundedStorable for TransactionKey {
    const MAX_SIZE: u32 = MAX_TRANSACTION_KEY_SIZE;
    const IS_FIXED_SIZE: bool = false; // Variable size
}

// Implement Storable for TransactionBatch
impl Storable for TransactionBatch {
    fn to_bytes(&self) -> Cow<[u8]> {
        // Use candid serialization
        let bytes = candid::encode_one(self).expect("Failed to encode TransactionBatch");
        Cow::Owned(bytes)
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        // Use candid deserialization
        candid::decode_one(&bytes).expect("Failed to decode TransactionBatch")
    }
}

// Implement BoundedStorable for TransactionBatch
impl BoundedStorable for TransactionBatch {
    const MAX_SIZE: u32 = MAX_TRANSACTION_BATCH_SIZE;
    const IS_FIXED_SIZE: bool = false; // Variable size
}


// Implement Storable for PartnerInfo
impl Storable for PartnerInfo {
    fn to_bytes(&self) -> Cow<[u8]> {
        let bytes = candid::encode_one(self).expect("Failed to encode PartnerInfo");
        Cow::Owned(bytes)
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        candid::decode_one(&bytes).expect("Failed to decode PartnerInfo")
    }
}

// Implement BoundedStorable for PartnerInfo
impl BoundedStorable for PartnerInfo {
    const MAX_SIZE: u32 = 2 * 1024; // 2KB should be sufficient
    const IS_FIXED_SIZE: bool = false;
}

// Implement Storable for MerchantInfo
impl Storable for MerchantInfo {
    fn to_bytes(&self) -> Cow<[u8]> {
        let bytes = candid::encode_one(self).expect("Failed to encode MerchantInfo");
        Cow::Owned(bytes)
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        candid::decode_one(&bytes).expect("Failed to decode MerchantInfo")
    }
}

// Implement BoundedStorable for MerchantInfo
impl BoundedStorable for MerchantInfo {
    const MAX_SIZE: u32 = 5 * 1024; // 5KB should be sufficient
    const IS_FIXED_SIZE: bool = false;
}

// Implement Storable for DeviceInfo
impl Storable for DeviceInfo {
    fn to_bytes(&self) -> Cow<[u8]> {
        let bytes = candid::encode_one(self).expect("Failed to encode DeviceInfo");
        Cow::Owned(bytes)
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        candid::decode_one(&bytes).expect("Failed to decode DeviceInfo")
    }
}

// Implement BoundedStorable for DeviceInfo
impl BoundedStorable for DeviceInfo {
    const MAX_SIZE: u32 = 1024; // 1KB should be sufficient
    const IS_FIXED_SIZE: bool = false;
}

// Implement Storable for SystemState
impl Storable for SystemState {
    fn to_bytes(&self) -> Cow<[u8]> {
        let bytes = candid::encode_one(self).expect("Failed to encode SystemState");
        Cow::Owned(bytes)
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        candid::decode_one(&bytes).expect("Failed to decode SystemState")
    }
}

// Implement BoundedStorable for SystemState
impl BoundedStorable for SystemState {
    const MAX_SIZE: u32 = 1024; // 1KB should be sufficient
    const IS_FIXED_SIZE: bool = false;
}

// Create wrapper types to solve orphan rules issues

// Wrapper for Principal type
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PrincipalWrapper(Principal);

impl Storable for PrincipalWrapper {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(self.0.as_slice().to_vec())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Self(Principal::from_slice(bytes.as_ref()))
    }
}

impl BoundedStorable for PrincipalWrapper {
    const MAX_SIZE: u32 = 29; // Principal maximum length 29 bytes
    const IS_FIXED_SIZE: bool = false;
}

// Wrapper for String type
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct StringWrapper(String);

impl Storable for StringWrapper {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(self.0.as_bytes().to_vec())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Self(String::from_utf8(bytes.to_vec()).expect("Failed to decode String"))
    }
}

impl BoundedStorable for StringWrapper {
    const MAX_SIZE: u32 = 10 * 1024; // 10KB should be sufficient for most log entries
    const IS_FIXED_SIZE: bool = false;
}

// ===== Global State Storage =====
// Use stable memory to store all states, ensuring data persistence during upgrades

// Use HashMap instead of StableBTreeMap to store user roles and merchant device authorizations
thread_local! {
      // User role management - using stable memory
    static USER_ROLES: RefCell<StableBTreeMap<PrincipalWrapper, Role, Memory>> = {
        let memory = MEMORY_MANAGER.with(|m| m.borrow_mut().get(MemoryId::new(MEMORY_ID_USER_ROLES)));
        RefCell::new(StableBTreeMap::init(memory))
    };

    // Country distribution information storage - using stable memory
    static COUNTRY_STATS_REGISTRY: RefCell<StableBTreeMap<StringWrapper, CountryInfo, Memory>> = {
        let memory = MEMORY_MANAGER.with(|m| m.borrow_mut().get(MemoryId::new(MEMORY_ID_COUNTRY_STATS)));
        RefCell::new(StableBTreeMap::init(memory))
    };

    // Brand registration information storage - using stable memory
    static PARTNER_REGISTRY: RefCell<StableBTreeMap<StringWrapper, PartnerInfo, Memory>> = {
        let memory = MEMORY_MANAGER.with(|m| m.borrow_mut().get(MemoryId::new(MEMORY_ID_PARTNER_REGISTRY)));
        RefCell::new(StableBTreeMap::init(memory))
    };

    // Merchant information storage - using stable memory
    static MERCHANT_REGISTRY: RefCell<StableBTreeMap<StringWrapper, MerchantInfo, Memory>> = {
        let memory = MEMORY_MANAGER.with(|m| m.borrow_mut().get(MemoryId::new(MEMORY_ID_MERCHANT_REGISTRY)));
        RefCell::new(StableBTreeMap::init(memory))
    };

    // Device registration information storage - using stable memory
    static DEVICE_REGISTRY: RefCell<StableBTreeMap<StringWrapper, DeviceInfo, Memory>> = {
        let memory = MEMORY_MANAGER.with(|m| m.borrow_mut().get(MemoryId::new(MEMORY_ID_DEVICE_REGISTRY)));
        RefCell::new(StableBTreeMap::init(memory))
    };

    // Transaction batch storage - using stable memory
    static TRANSACTION_BATCHES: RefCell<StableBTreeMap<TransactionKey, TransactionBatch, Memory>> = {
        let memory = MEMORY_MANAGER.with(|m| m.borrow_mut().get(MemoryId::new(MEMORY_ID_TRANSACTION_BATCHES)));
        RefCell::new(StableBTreeMap::init(memory))
    };

    // System state - using ordinary memory
    static SYSTEM_STATE: RefCell<SystemState> = RefCell::new(
        SystemState {
            last_cycles_notification: 0,
            is_upgrade_in_progress: false,
            version: "1.0.0".to_string(),
            previous_version: "".to_string(),
            upgrade_timestamp: 0,
        }
    );
}

// ===== Permission Management Functions =====

/// Check if the caller has the required role
///
/// # Parameters
/// * `required_role` - Required role
///
/// # Returns
/// * `Ok(())` - If the caller has the required role
/// * `Err(String)` - If the caller does not have the required role, with an error message
fn is_authorized(required_role: Role) -> Result<(), String> {
    let caller = caller();

    // Check if the caller is anonymous
    if caller == Principal::anonymous() {
        return Err("Unauthorized operation: anonymous user".to_string());
    }

    // Check the user's role
    let has_role = USER_ROLES.with(|roles| {
        let roles = roles.borrow();
        match roles.get(&PrincipalWrapper(caller)) {
            Some(role) => match (role, &required_role) {
                (Role::Admin, _) => true, // Admin has all permissions
                (Role::Operator, Role::Operator | Role::Reader) => true,
                (Role::Merchant, Role::Merchant | Role::Reader) => true,
                (Role::Reader, Role::Reader) => true,
                _ => false,
            },
            None => false,
        }
    });

    if !has_role {
        return Err(format!("Unauthorized operation: requires {:?} role", required_role));
    }

    Ok(())
}

// ===== Cycles Management Functions =====

/// Get the current cycles balance
///
/// # Returns
/// * `u64` - Current cycles balance
fn get_cycles_balance() -> u64 {
    canister_balance()
}

/// Check the cycles balance and issue a warning if it's low
///
/// # Returns
/// * `Ok(())` - If the balance is sufficient
/// * `Err(String)` - If the balance is low, with an error message
fn check_cycles_balance() -> Result<(), String> {
    let balance = get_cycles_balance();

    // Log the operation
    log_operation(format!("Checked cycles balance: {}", balance));

    if balance < CRITICAL_CYCLES_BALANCE {
        // Critical situation: cycles are running out
        return Err(format!("Critical: cycles balance is low ({} cycles), please recharge to avoid service interruption", balance));
    } else if balance < MIN_CYCLES_BALANCE {
        // Issue a warning but continue the operation
        let current_time = time();
        let should_notify = SYSTEM_STATE.with(|state| {
            let mut state = state.borrow_mut();
            // Notify at most once every 6 hours
            if current_time - state.last_cycles_notification > 6 * 60 * 60 * 1_000_000_000 {
                state.last_cycles_notification = current_time;
                true
            } else {
                false
            }
        });

        if should_notify {
            // Implement a notification mechanism here, e.g., send a message to the admin
            log_operation(format!("Warning: cycles balance is low ({} cycles), please recharge soon", balance));
        }
    }

    Ok(())
}

// ===== Log Management Functions =====

/// Log an operation
///
/// # Parameters
/// * `message` - Log message
fn log_operation(message: String) {
    // Add a timestamp and caller information
    let timestamp = time();
    let caller = caller();
    let log_entry = format!("[{}] {}: {}", timestamp, caller, message);

    // Use ic_cdk::println! to print the log directly without storing it
    ic_cdk::println!("{}", log_entry);
}

// ===== API Functions - Basic Features =====

/// Accept cycles recharge
///
/// # Returns
/// * `u64` - Accepted cycles amount
#[ic_cdk::update]
fn accept_cycles() -> u64 {
    check_upgrade_status().unwrap_or_else(|_| log_operation("Warning: contract is upgrading, but still accepting cycles recharge".to_string()));

    let available = msg_cycles_available();
    let accepted = msg_cycles_accept(available);

    log_operation(format!("Accepted cycles recharge: {} cycles", accepted));

    accepted
}

/// Get canister information
///
/// # Returns
/// * `Result<CanisterInfo, String>` - Canister information on success, error message on failure
#[ic_cdk::query]
fn get_canister_info() -> Result<CanisterInfo, String> {
    // Permission check
    is_authorized(Role::Reader)?;

    let version = SYSTEM_STATE.with(|state| state.borrow().version.clone());
    let cycles = get_cycles_balance();
    let upgrade_status = SYSTEM_STATE.with(|state| state.borrow().is_upgrade_in_progress);

    // Modify here to ensure the field order matches the struct definition and Candid interface
    let canister_info = CanisterInfo {
        cycles_balance: cycles,
        is_upgrading: upgrade_status,
        version,
    };

    Ok(canister_info)
}

// ===== API Functions - Country Statistics Management =====

/// Add or update country statistics
///
/// # Parameters
/// * `iso2` - ISO2 country code
///
/// # Returns
/// * `ApiResponse<()>` - Unified response structure
#[ic_cdk::update]
fn register_country(country_code: String) -> ApiResponse<()> {
    // Permission check
    if let Err(e) = is_authorized(Role::Operator) {
        return ApiResponse::<()>::error(403, &e);
    }
    if let Err(e) = check_cycles_balance() {
        return ApiResponse::<()>::error(500, &e);
    }

    // Validate input
    if country_code.is_empty() {
        return ApiResponse::<()>::error(400, "Country code cannot be empty");
    }
    // Check if the country code is already registered
    let country_exists = COUNTRY_STATS_REGISTRY.with(|registry| {
        registry.borrow().contains_key(&StringWrapper(country_code.clone()))
    });

    if country_exists {
        return ApiResponse::<()>::error(409, &format!("Country code {} already exists", country_code));
    }

    let timestamp = time();

    let country_info = CountryInfo {
        iso2: country_code.clone(),  // Keep the struct field unchanged to avoid serialization issues
        timestamp,
    };

    COUNTRY_STATS_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        registry.insert(StringWrapper(country_code.clone()), country_info);
    });

    log_operation(format!("Registered country: {}", country_code));

    ApiResponse::<()>::success_no_data(&format!("Country {} registered successfully", country_code))
}

/// Get country statistics
///
/// # Parameters
/// * `iso2` - ISO2 country code
///
/// # Returns
/// * `ApiResponse<Option<CountryInfo>>` - Unified response structure with country statistics
#[ic_cdk::query]
fn get_country_info(country_code: String) -> ApiResponse<Option<CountryInfo>> {
    // Permission check
    if let Err(e) = is_authorized(Role::Reader) {
        return ApiResponse::<()>::error(403, &e);
    }

    let result = COUNTRY_STATS_REGISTRY.with(|registry| {
        registry.borrow().get(&StringWrapper(country_code.clone())).map(|stat| stat.clone())
    });

    ApiResponse::success(result, &format!("Country info for {} retrieved successfully", country_code))
}

/// Get all country statistics
///
/// # Returns
/// * `ApiResponse<Vec<CountryInfo>>` - Unified response structure with country statistics list
#[ic_cdk::query]
fn list_countries() -> ApiResponse<Vec<CountryInfo>> {
    // Permission check
    if let Err(e) = is_authorized(Role::Reader) {
        return ApiResponse::<()>::error(403, &e);
    }

    let result = COUNTRY_STATS_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        registry.iter().map(|(_, v)| v.clone()).collect()
    });

    ApiResponse::success(result, "Countries list retrieved successfully")
}



// ===== Permission Management API =====

/// Assign a role to a user
///
/// # Parameters
/// * `user` - User Principal
/// * `role` - Role to assign
///
/// # Returns
/// * `ApiResponse<()>` - Unified response structure
#[ic_cdk::update]
fn assign_role(user: Principal, role: Role) -> ApiResponse<()> {
    // Permission check: only admins can assign roles
    if let Err(e) = is_authorized(Role::Admin) {
        return ApiResponse::<()>::error(403, &e);
    }
    if let Err(e) = check_cycles_balance() {
        return ApiResponse::<()>::error(500, &e);
    }

    // Check if the caller is an admin and is downgrading their own role to a non-admin role
    let caller = caller();
    if user == caller && role != Role::Admin {
        // Check if the caller is the last admin
        let is_last_admin = USER_ROLES.with(|roles| {
            let roles = roles.borrow();
            roles.iter().filter(|(_, r)| matches!(r, Role::Admin)).count() <= 1
        });

        if is_last_admin {
            return ApiResponse::<()>::error(400, "Error: cannot downgrade the last admin's role, this will cause the contract to lose management permissions");
        }
    }

    USER_ROLES.with(|roles| {
        let mut roles = roles.borrow_mut();
        roles.insert(PrincipalWrapper(user), role.clone());
    });

    log_operation(format!("Assigned role to user {}: {:?}", user, role));

    ApiResponse::<()>::success_no_data(&format!("Role {:?} assigned to user {} successfully", role, user))
}

/// Revoke a user's role
///
/// # Parameters
/// * `user` - User Principal
///
/// # Returns
/// * `Result<(), String>` - Success on success, error message on failure
#[ic_cdk::update]
fn revoke_role(user: Principal) -> Result<(), String> {
    // Permission check: only admins can revoke roles
    is_authorized(Role::Admin)?;
    check_cycles_balance()?;

    USER_ROLES.with(|roles| {
        let mut roles = roles.borrow_mut();
        roles.remove(&PrincipalWrapper(user));
    });

    log_operation(format!("Revoked role for user {}", user));

    Ok(())
}


// ===== API Functions - Brand Management =====

/// Register a brand
///
/// # Parameters
/// * `partner_code` - Brand code
/// * `partner_name` - Brand name
/// * `iso2` - ISO2 country code
/// * `verification` - Certification number
/// * `description` - Description
/// * `business_type` - Business type
///
/// # Returns
/// * `Result<(), String>` - Success on success, error message on failure
#[ic_cdk::update]
fn register_partner(
    partner_code: String,
    partner_name: String,
    iso2: String,
    verification: String,
    description: String,
    business_type: String,
) -> ApiResponse<()> {
    // Permission check
    if let Err(e) = is_authorized(Role::Operator) {
        return ApiResponse::<()>::error(403, &e);
    }
    if let Err(e) = check_cycles_balance() {
        return ApiResponse::<()>::error(500, &e);
    }

    // Validate input
    if partner_code.is_empty() || partner_name.is_empty() || iso2.is_empty() {
        return ApiResponse::<()>::error(400, "Required fields cannot be empty");
    }

    if description.len() > 1024 {
        return ApiResponse::<()>::error(400, "Description cannot exceed 1024 characters");
    }

    // Check if the brand code is already registered
    let partner_exists = PARTNER_REGISTRY.with(|registry| {
        registry.borrow().contains_key(&StringWrapper(partner_code.clone()))
    });

    if partner_exists {
        return ApiResponse::<()>::error(409, &format!("Partner code {} already exists", partner_code));
    }


    // Check if the country code is already registered
    let country_exists = COUNTRY_STATS_REGISTRY.with(|registry| {
        registry.borrow().contains_key(&StringWrapper(iso2.clone()))
    });

    if !country_exists {
        return ApiResponse::<()>::error(404, &format!("Country code {} is not registered, please register the country first", iso2));
    }

    let timestamp = time();

    let partner_info = PartnerInfo {
        partner_code: partner_code.clone(),
        partner_name: partner_name.clone(),
        iso2: iso2.clone(),
        verification,
        description,
        business_type,
        timestamp,
    };

    PARTNER_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        registry.insert(StringWrapper(partner_code.clone()), partner_info);
    });

    log_operation(format!("Registered brand: {}", partner_code));

    ApiResponse::<()>::success_no_data(&format!("Partner {} registered successfully", partner_name))
}

/// Get brand information
///
/// # Parameters
/// * `partner_code` - Brand code
///
/// # Returns
/// * `Result<Option<PartnerInfo>, String>` - Brand information on success, error message on failure
#[ic_cdk::query]
fn get_partner_info(partner_code: String) -> Result<Option<PartnerInfo>, String> {
    // Permission check
    is_authorized(Role::Reader)?;

    let result = PARTNER_REGISTRY.with(|registry| {
        registry.borrow().get(&StringWrapper(partner_code.clone())).map(|info| info.clone())
    });

    Ok(result)
}

/// Get all brand list
///
/// # Returns
/// * `Result<Vec<PartnerInfo>, String>` - Brand list on success, error message on failure
#[ic_cdk::query]
fn list_partners() -> Result<Vec<PartnerInfo>, String> {
    // Permission check
    is_authorized(Role::Reader)?;

    let result = PARTNER_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        registry.iter().map(|(_, v)| v.clone()).collect()
    });

    Ok(result)
}

// ===== API Functions - Merchant Management =====

/// Register a merchant
///
/// # Parameters
/// * `merchant_name_encrypted` - Encrypted merchant name
/// * `merchant_id` - Merchant ID
/// * `description_encrypted` - Encrypted description
/// * `iso2` - ISO2 country code
/// * `location_id` - Location ID
/// * `location_encrypted` - Encrypted location
/// * `merchant_type_encrypted` - Encrypted merchant type
/// * `verification` - Certification number
///
/// # Returns
/// * `ApiResponse<()>` - Unified response structure
#[ic_cdk::update]
fn register_merchant(
    merchant_name_encrypted: String,
    merchant_id: String,
    description_encrypted: Option<String>,
    iso2: String,
    location_id: String,
    location_encrypted: Option<String>,
    merchant_type_encrypted: Option<String>,
    verification: String,
) -> ApiResponse<()> {
    // Permission check
    if let Err(e) = is_authorized(Role::Operator) {
        return ApiResponse::<()>::error(403, &e);
    }
    if let Err(e) = check_cycles_balance() {
        return ApiResponse::<()>::error(500, &e);
    }

    // Validate input
    if merchant_name_encrypted.is_empty() || merchant_id.is_empty() || iso2.is_empty() {
        return ApiResponse::<()>::error(400, "Required fields cannot be empty");
    }

    if merchant_id.len() < 2 || merchant_id.len() > 16 {
        return ApiResponse::<()>::error(400, "Merchant ID must be a 2-16 character identifier");
    }

    // Check if the merchant ID is already registered
    let merchant_exists = MERCHANT_REGISTRY.with(|registry| {
        registry.borrow().contains_key(&StringWrapper(merchant_id.clone()))
    });

    if merchant_exists {
        return ApiResponse::<()>::error(409, &format!("Merchant ID {} already exists", merchant_id));
    }

    // Check if the country code is already registered
    let country_exists = COUNTRY_STATS_REGISTRY.with(|registry| {
        registry.borrow().contains_key(&StringWrapper(iso2.clone()))
    });

    if !country_exists {
        return ApiResponse::<()>::error(404, &format!("Country code {} is not registered, please register the country first", iso2));
    }

    let timestamp = time();

    let merchant_info = MerchantInfo {
        merchant_name_encrypted,
        merchant_id: merchant_id.clone(),
        description_encrypted,
        iso2: iso2.clone(),
        location_id,
        location_encrypted,
        merchant_type_encrypted,
        verification,
        timestamp,
    };

    MERCHANT_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        registry.insert(StringWrapper(merchant_id.clone()), merchant_info);
    });

    log_operation(format!("Registered merchant: {}", merchant_id));

    ApiResponse::<()>::success_no_data(&format!("Merchant {} registered successfully", merchant_id))
}

/// Get merchant information
///
/// # Parameters
/// * `merchant_id` - Merchant ID
///
/// # Returns
/// * `ApiResponse<Option<MerchantInfo>>` - Unified response structure with merchant information
#[ic_cdk::query]
fn get_merchant_info(merchant_id: String) -> ApiResponse<Option<MerchantInfo>> {
    // Permission check
    if let Err(e) = is_authorized(Role::Reader) {
        return ApiResponse::<()>::error(403, &e);
    }

    let result = MERCHANT_REGISTRY.with(|registry| {
        registry.borrow().get(&StringWrapper(merchant_id.clone())).map(|info| info.clone())
    });

    ApiResponse::success(result, &format!("Merchant info for {} retrieved successfully", merchant_id))
}

/// List merchants by country
///
/// # Parameters
/// * `iso2` - ISO2 country code
///
/// # Returns
/// * `Result<Vec<MerchantInfo>, String>` - Merchant list on success, error message on failure
#[ic_cdk::query]
fn list_merchants_by_country(iso2: String) -> Result<Vec<MerchantInfo>, String> {
    // Permission check
    is_authorized(Role::Reader)?;

    let result = MERCHANT_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        registry.iter()
            .filter(|(_, m)| m.iso2 == iso2)
            .map(|(_, m)| m.clone())
            .collect()
    });

    Ok(result)
}

// ===== API Functions - Device Management =====

/// Register a device
///
/// # Parameters
/// * `device_id` - Device ID
/// * `device_type` - Device type
/// * `partner_code` - Brand code
/// * `merchant_id` - Merchant ID
///
/// # Returns
/// * `ApiResponse<()>` - Unified response structure
#[ic_cdk::update]
fn register_device(
    device_id: String,
    device_type: String,
    partner_code: String,
    merchant_id: String,
) -> ApiResponse<()> {
    // Permission check
    if let Err(e) = is_authorized(Role::Operator) {
        return ApiResponse::<()>::error(403, &e);
    }
    if let Err(e) = check_cycles_balance() {
        return ApiResponse::<()>::error(500, &e);
    }

    // Validate input
    if device_id.is_empty() || partner_code.is_empty() || merchant_id.is_empty() {
        return ApiResponse::<()>::error(400, "Required fields cannot be empty");
    }

    // Check if the device ID is already registered
    let device_exists = DEVICE_REGISTRY.with(|registry| {
        registry.borrow().contains_key(&StringWrapper(device_id.clone()))
    });

    if device_exists {
        return ApiResponse::<()>::error(409, &format!("Device ID {} already exists", device_id));
    }

    // Check if the brand code is already registered
    let partner_exists = PARTNER_REGISTRY.with(|registry| {
        registry.borrow().contains_key(&StringWrapper(partner_code.clone()))
    });

    if !partner_exists {
        return ApiResponse::<()>::error(404, &format!("Partner code {} does not exist, please register the partner first", partner_code));
    }

    // Check if the merchant ID is already registered
    let merchant_exists = MERCHANT_REGISTRY.with(|registry| {
        registry.borrow().contains_key(&StringWrapper(merchant_id.clone()))
    });

    if !merchant_exists {
        return ApiResponse::<()>::error(404, &format!("Merchant ID {} does not exist, please register the merchant first", merchant_id));
    }

    let timestamp = time();

    let device_info = DeviceInfo {
        device_id: device_id.clone(),
        device_type,
        partner_code: partner_code.clone(),
        merchant_id: merchant_id.clone(),
        timestamp,
    };

    DEVICE_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        registry.insert(StringWrapper(device_id.clone()), device_info);
    });

    log_operation(format!("Registered device: {}", device_id));

    ApiResponse::<()>::success_no_data(&format!("Device {} registered successfully", device_id))
}

/// Get device information
///
/// # Parameters
/// * `device_id` - Device ID
///
/// # Returns
/// * `Result<Option<DeviceInfo>, String>` - Device information on success, error message on failure
#[ic_cdk::query]
fn get_device_info(device_id: String) -> Result<Option<DeviceInfo>, String> {
    // Permission check
    is_authorized(Role::Reader)?;

    let result = DEVICE_REGISTRY.with(|registry| {
        registry.borrow().get(&StringWrapper(device_id.clone())).map(|info| info.clone())
    });

    Ok(result)
}

/// List devices by merchant
///
/// # Parameters
/// * `merchant_id` - Merchant ID
///
/// # Returns
/// * `Result<Vec<DeviceInfo>, String>` - Device list on success, error message on failure
#[ic_cdk::query]
fn list_devices_by_merchant(merchant_id: String) -> Result<Vec<DeviceInfo>, String> {
    // Permission check
    is_authorized(Role::Reader)?;

    let result = DEVICE_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        registry.iter()
            .filter(|(_, d)| d.merchant_id == merchant_id)
            .map(|(_, d)| d.clone())
            .collect()
    });

    Ok(result)
}

// ===== API Functions - Transaction Management =====

/// Upload a transaction batch
///
/// # Parameters
/// * `device_hash` - Device hash
/// * `date` - Date
/// * `transaction_details` - Transaction details list
///
/// # Returns
/// * `Result<(), String>` - Success on success, error message on failure
#[ic_cdk::update]
fn upload_transaction_batch(
    device_hash: String,
    date: String,
    transaction_details: Vec<TransactionDetail>,
) -> Result<(), String> {
    // Permission check
    is_authorized(Role::Merchant)?;
    check_cycles_balance()?;

    // Validate input
    if device_hash.is_empty() || date.is_empty() {
        return Err("Device hash and date cannot be empty".to_string());
    }

    // Check if the transaction details list exceeds the limit
    if transaction_details.len() > MAX_TRANSACTION_DETAILS_PER_BATCH {
        return Err(format!("Transaction details cannot exceed {} per batch", MAX_TRANSACTION_DETAILS_PER_BATCH));
    }

    let key = TransactionKey {
        device_hash: device_hash.clone(),
        date: date.clone(),
    };

    // Check if a batch for the device and date already exists
    let batch_exists = TRANSACTION_BATCHES.with(|batches| {
        batches.borrow().contains_key(&key)
    });

    if batch_exists {
        return Err(format!("Transaction batch for device {} on date {} already exists", device_hash, date));
    }

    // Create a transaction batch
    // Get the length first
    let details_count = transaction_details.len();

    // Create a transaction batch
    let basic_info = BasicTransactionInfo {
        device_hash: device_hash.clone(),
        date: date.clone(),
        order_count: details_count as u32,
    };

    let batch = TransactionBatch {
        basic_info,
        details_encrypted: transaction_details,
        batch_timestamp: time(),
    };

    // Store the transaction batch
    TRANSACTION_BATCHES.with(|batches| {
        batches.borrow_mut().insert(key, batch);
    });

    log_operation(format!("Uploaded transaction batch: Device {}, Date {}, Order count {}", device_hash, date, details_count));
    Ok(())
}

/// Get transaction batch basic information
///
/// # Parameters
/// * `device_hash` - Device hash
/// * `date` - Date
///
/// # Returns
/// * `Result<Option<BasicTransactionInfo>, String>` - Transaction batch basic information on success, error message on failure
#[ic_cdk::query]
fn get_transaction_batch_basic_info(device_hash: String, date: String) -> Result<Option<BasicTransactionInfo>, String> {
    // Permission check
    is_authorized(Role::Reader)?;

    let key = TransactionKey {
        device_hash,
        date,
    };

    let result = TRANSACTION_BATCHES.with(|batches| {
        batches.borrow().get(&key).map(|batch| batch.basic_info.clone())
    });

    Ok(result)
}

/// Get transaction batch details
///
/// # Parameters
/// * `device_hash` - Device hash
/// * `date` - Date
///
/// # Returns
/// * `Result<Option<Vec<TransactionDetail>>, String>` - Transaction details list on success, error message on failure
#[ic_cdk::query]
fn get_transaction_batch_details(device_hash: String, date: String) -> Result<Option<Vec<TransactionDetail>>, String> {
    // Permission check
    is_authorized(Role::Reader)?;

    // For querying encrypted data, additional verification may be required
    // Add stricter authentication or permission checks here

    let key = TransactionKey {
        device_hash: device_hash.clone(),
        date: date.clone(),
    };

    let result = TRANSACTION_BATCHES.with(|batches| {
        batches.borrow().get(&key).map(|batch| batch.details_encrypted.clone())
    });

    log_operation(format!("Queried transaction details: Device {}, Date {}", device_hash, date));

    Ok(result)
}

/// List transaction batches by device
///
/// # Parameters
/// * `device_hash` - Device hash
///
/// # Returns
/// * `Result<Vec<BasicTransactionInfo>, String>` - Transaction batch list on success, error message on failure
#[ic_cdk::query]
fn list_transaction_batches_by_device(device_hash: String) -> Result<Vec<BasicTransactionInfo>, String> {
    // Permission check
    is_authorized(Role::Reader)?;

    let result = TRANSACTION_BATCHES.with(|batches| {
        let batches = batches.borrow();
        batches
            .iter()
            .filter(|(k, _)| k.device_hash == device_hash)
            .map(|(_, v)| v.basic_info.clone())
            .collect()
    });

    Ok(result)
}

// ===== API Functions - Statistics Queries =====

/// Query total number of countries
///
/// # Returns
/// * `Result<usize, String>` - Country count on success, error message on failure
#[ic_cdk::query]
fn get_countries_count() -> Result<usize, String> {
    // Permission check
    is_authorized(Role::Reader)?;

    let count = COUNTRY_STATS_REGISTRY.with(|registry| registry.borrow().len() as usize);
    log_operation(format!("Queried countries count: {}", count));
    Ok(count * 2)
}

/// Query total number of brands
///
/// # Returns
/// * `Result<usize, String>` - Brand count on success, error message on failure
#[ic_cdk::query]
fn get_partners_count() -> Result<usize, String> {
    // Permission check
    is_authorized(Role::Reader)?;

    let count = PARTNER_REGISTRY.with(|registry| registry.borrow().len() as usize);
    log_operation(format!("Queried partners count: {}", count));
    Ok(count)
}

/// Query total number of merchants
///
/// # Returns
/// * `Result<usize, String>` - Merchant count on success, error message on failure
#[ic_cdk::query]
fn get_merchants_count() -> Result<usize, String> {
    // Permission check
    is_authorized(Role::Reader)?;

    let count = MERCHANT_REGISTRY.with(|registry| registry.borrow().len() as usize);
    log_operation(format!("Queried merchants count: {}", count));
    Ok(count)
}

/// Query total number of devices
///
/// # Returns
/// * `Result<usize, String>` - Device count on success, error message on failure
#[ic_cdk::query]
fn get_devices_count() -> Result<usize, String> {
    // Permission check
    is_authorized(Role::Reader)?;

    let count = DEVICE_REGISTRY.with(|registry| registry.borrow().len() as usize);
    log_operation(format!("Queried devices count: {}", count));
    Ok(count)
}

/// Query total number of transaction batches
///
/// # Returns
/// * `Result<usize, String>` - Transaction batch count on success, error message on failure
#[ic_cdk::query]
fn get_transaction_batches_count() -> Result<usize, String> {
    // Permission check
    is_authorized(Role::Reader)?;

    let count = TRANSACTION_BATCHES.with(|batches| batches.borrow().len() as usize);
    log_operation(format!("Queried transaction batches count: {}", count));
    Ok(count)
}

/// Query merchant count by country
///
/// # Parameters
/// * `iso2` - ISO2 country code
///
/// # Returns
/// * `Result<usize, String>` - Merchant count on success, error message on failure
#[ic_cdk::query]
fn get_merchants_count_by_country(iso2: String) -> Result<usize, String> {
    // Permission check
    is_authorized(Role::Reader)?;

    let count = MERCHANT_REGISTRY.with(|registry| {
        registry.borrow().iter()
            .filter(|(_, m)| m.iso2 == iso2)
            .count()
    });
    log_operation(format!("Queried merchants count for country {}: {}", iso2, count));
    Ok(count)
}

/// Query device count by brand
///
/// # Parameters
/// * `partner_code` - Brand code
///
/// # Returns
/// * `Result<usize, String>` - Device count on success, error message on failure
#[ic_cdk::query]
fn get_devices_count_by_partner(partner_code: String) -> Result<usize, String> {
    // Permission check
    is_authorized(Role::Reader)?;

    let count = DEVICE_REGISTRY.with(|registry| {
        registry.borrow().iter()
            .filter(|(_, d)| d.partner_code == partner_code)
            .count()
    });
    log_operation(format!("Queried devices count for partner {}: {}", partner_code, count));
    Ok(count)
}

/// Query comprehensive statistics
///
/// # Returns
/// * `ApiResponse<StatsInfo>` - Unified response structure with comprehensive statistics
#[ic_cdk::query]
fn get_stats() -> ApiResponse<StatsInfo> {
    // Permission check
    if let Err(e) = is_authorized(Role::Reader) {
        return ApiResponse::<()>::error(403, &e);
    }

    let countries_count = COUNTRY_STATS_REGISTRY.with(|registry| registry.borrow().len() as usize);
    let partners_count = PARTNER_REGISTRY.with(|registry| registry.borrow().len() as usize);
    let merchants_count = MERCHANT_REGISTRY.with(|registry| registry.borrow().len() as usize);
    let devices_count = DEVICE_REGISTRY.with(|registry| registry.borrow().len() as usize);
    let transaction_batches_count = TRANSACTION_BATCHES.with(|batches| batches.borrow().len() as usize);

    let cycles_balance = get_cycles_balance();

    log_operation("Queried stats".to_string());

    let stats = StatsInfo {
        partners_count,
        merchants_count,
        devices_count,
        transaction_batches_count,
        cycles_balance,
        countries_count,
    };
    
    ApiResponse::success(stats, "System statistics retrieved successfully")
}


// ===== Contract Upgrade Management =====

/// Check upgrade status
///
/// # Returns
/// * `Result<(), String>` - Success on success, error message on failure
fn check_upgrade_status() -> Result<(), String> {
    let is_upgrading = SYSTEM_STATE.with(|state| {
        state.borrow().is_upgrade_in_progress
    });

    if is_upgrading {
        return Err("Contract is upgrading, please try again later".to_string());
    }
    Ok(())
}

/// Prepare for upgrade
///
/// # Returns
/// * `Result<(), String>` - Success on success, error message on failure
#[ic_cdk::update]
fn prepare_upgrade() -> Result<(), String> {
    // Permission check: only admins can upgrade
    is_authorized(Role::Admin)?;
    check_cycles_balance()?;

    // Backup the current version number for potential rollback
    let current_version = SYSTEM_STATE.with(|state| {
        let mut state = state.borrow_mut();
        let current = state.version.clone();
        state.is_upgrade_in_progress = true;
        current
    });

    log_operation(format!("Prepared for upgrade, current version: {}", current_version));
    Ok(())
}

/// Complete upgrade
///
/// # Parameters
/// * `version` - New version
///
/// # Returns
/// * `Result<(), String>` - Success on success, error message on failure
#[ic_cdk::update]
fn complete_upgrade(version: String) -> Result<(), String> {
    // Permission check: only admins can complete the upgrade
    is_authorized(Role::Admin)?;

    SYSTEM_STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.previous_version = state.version.clone();
        state.version = version.clone();
        state.is_upgrade_in_progress = false;
        state.upgrade_timestamp = time();
    });

    log_operation(format!("Completed upgrade to version {}", version));

    Ok(())
}

/// Rollback upgrade
///
/// # Returns
/// * `Result<(), String>` - Success on success, error message on failure
#[ic_cdk::update]
fn rollback_upgrade() -> Result<(), String> {
    // Permission check: only admins can rollback the upgrade
    is_authorized(Role::Admin)?;

    // Get the previous version
    let (previous_version, current_version) = SYSTEM_STATE.with(|state| {
        let state = state.borrow();
        (state.previous_version.clone(), state.version.clone())
    });

    if previous_version.is_empty() {
        return Err("No previous version to rollback to".to_string());
    }

    // Perform the rollback
    SYSTEM_STATE.with(|state| {
        let mut state = state.borrow_mut();
        // Swap the current version and the previous version
        state.version = previous_version.clone();
        state.previous_version = current_version.clone();
        state.is_upgrade_in_progress = false;
    });

    log_operation(format!("Rolled back to version {}", previous_version));

    Ok(())
}

// ===== Main Entry Points =====

/// Initialization function
///
/// Called automatically when the contract is deployed, setting up the initial state
#[ic_cdk::init]
fn init() {
    // Set the caller as the initial admin
    let caller = caller();
    USER_ROLES.with(|roles| {
        let mut roles = roles.borrow_mut();
        roles.insert(PrincipalWrapper(caller), Role::Admin);
    });

    // Initialize the system state
    SYSTEM_STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.version = "1.0.0".to_string();
        state.previous_version = "".to_string();
        state.is_upgrade_in_progress = false;
        state.upgrade_timestamp = time();
    });

    log_operation("Initialized contract".to_string());
}



/// Pre-upgrade preparation
///
/// Called automatically before contract upgrade, can save state here
#[ic_cdk::pre_upgrade]
fn pre_upgrade() {
    log_operation("Preparing for upgrade".to_string());

    // Backup the current version number for potential rollback
    let version = SYSTEM_STATE.with(|state| {
        let state = state.borrow();
        state.version.clone()
    });

    log_operation(format!("Backing up version: {}", version));

    // Since we use stable memory, most data will be preserved automatically
    // Add custom backup logic here if needed
}

/// Post-upgrade restoration
///
/// Called automatically after contract upgrade, can restore state here
#[ic_cdk::post_upgrade]
fn post_upgrade() {
    log_operation("Restoring state after upgrade".to_string());

    // Record the upgrade completion time
    SYSTEM_STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.upgrade_timestamp = time();
        log_operation(format!("Upgrade completed, current version: {}", state.version));
    });

    // Verify data state
    let partners_count = PARTNER_REGISTRY.with(|registry| registry.borrow().len() as usize);
    let merchants_count = MERCHANT_REGISTRY.with(|registry| registry.borrow().len() as usize);
    let devices_count = DEVICE_REGISTRY.with(|registry| registry.borrow().len() as usize);
    let transaction_batches_count = TRANSACTION_BATCHES.with(|batches| batches.borrow().len() as usize);

    log_operation(format!(
        "Data state check: partners: {}, merchants: {}, devices: {}, transaction batches: {}",
        partners_count, merchants_count, devices_count, transaction_batches_count
    ));
}
// Enable Candid export
ic_cdk::export_candid!();