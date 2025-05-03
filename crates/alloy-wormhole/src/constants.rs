use alloy_primitives::U256;

/// The salt byte for generating the magic burn address.
pub const MAGIC_ADDRESS: u8 = 0xfe;

/// The salt byte for computing for nullifier.
pub const MAGIC_NULLIFIER: u8 = 0x01;

/// The salt for Proof-of-Work condition on the secret.
pub const MAGIC_POW: u8 = 0x02;

/// The exponent for Proof-of-Work condition on the secret.
pub const POW_LOG_DIFFICULTY: u8 = 24;

/// The u256 Proof-of-Work condition on the secret.
/// 2 ** [POW_LOG_DIFFICULTY] = 16 777 216
pub const POW_DIFFICULTY_U256: U256 = U256::from_limbs([0x1000000, 0x0, 0x0, 0x0]);

/// The maximum allowed value of the Wormhole deposit.
/// 32 * 10**18 wei = 32 ether
pub const MAX_DEPOSIT: U256 = U256::from_limbs([0xbc16d674ec800000, 0x1, 0x0, 0x0]);

/// The transaction type of the Wormhole transaction
pub const WORMHOLE_TX_TYPE: u8 = 5;
