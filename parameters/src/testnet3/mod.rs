// Copyright (C) 2019-2023 Aleo Systems Inc.
// This file is part of the snarkVM library.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

pub mod genesis;
pub use genesis::*;

pub mod powers;
pub use powers::*;
use crate::macros::get_dir;

const REMOTE_URL: &str = "https://s3-us-west-1.amazonaws.com/testnet3.parameters";

// Degrees
impl_mobile_local!(Degree15, "resources/", "powers-of-beta-15", "usrs");
impl_mobile_local!(Degree16, "resources/", "powers-of-beta-16", "usrs");
impl_mobile_local!(Degree17, "resources/", "powers-of-beta-17", "usrs");
impl_mobile_local!(Degree18, "resources/", "powers-of-beta-18", "usrs");
impl_mobile_local!(Degree19, "resources/", "powers-of-beta-19", "usrs");
impl_mobile_local!(Degree20, "resources/", "powers-of-beta-20", "usrs");
impl_mobile_local!(Degree21, "resources/", "powers-of-beta-21", "usrs");
impl_mobile_local!(Degree22, "resources/", "powers-of-beta-22", "usrs");
impl_mobile_local!(Degree23, "resources/", "powers-of-beta-23", "usrs");
impl_mobile_local!(Degree24, "resources/", "powers-of-beta-24", "usrs");
impl_mobile_local!(Degree25, "resources/", "powers-of-beta-25", "usrs");
impl_mobile_local!(Degree26, "resources/", "powers-of-beta-26", "usrs");
impl_mobile_local!(Degree27, "resources/", "powers-of-beta-27", "usrs");
impl_mobile_local!(Degree28, "resources/", "powers-of-beta-28", "usrs");

// Shifted Degrees
impl_mobile_local!(ShiftedDegree15, "resources/", "shifted-powers-of-beta-15", "usrs");
impl_mobile_local!(ShiftedDegree16, "resources/", "shifted-powers-of-beta-16", "usrs");
impl_mobile_local!(ShiftedDegree17, "resources/", "shifted-powers-of-beta-17", "usrs");
impl_mobile_local!(ShiftedDegree18, "resources/", "shifted-powers-of-beta-18", "usrs");
impl_mobile_local!(ShiftedDegree19, "resources/", "shifted-powers-of-beta-19", "usrs");
impl_mobile_local!(ShiftedDegree20, "resources/", "shifted-powers-of-beta-20", "usrs");
impl_mobile_local!(ShiftedDegree21, "resources/", "shifted-powers-of-beta-21", "usrs");
impl_mobile_local!(ShiftedDegree22, "resources/", "shifted-powers-of-beta-22", "usrs");
impl_mobile_local!(ShiftedDegree23, "resources/", "shifted-powers-of-beta-23", "usrs");
impl_mobile_local!(ShiftedDegree24, "resources/", "shifted-powers-of-beta-24", "usrs");
impl_mobile_local!(ShiftedDegree25, "resources/", "shifted-powers-of-beta-25", "usrs");
impl_mobile_local!(ShiftedDegree26, "resources/", "shifted-powers-of-beta-26", "usrs");
impl_mobile_local!(ShiftedDegree27, "resources/", "shifted-powers-of-beta-27", "usrs");

// Powers of Beta Times Gamma * G
impl_local!(Gamma, "resources/", "powers-of-beta-gamma", "usrs");
// Negative Powers of Beta in G2
impl_local!(NegBeta, "resources/", "neg-powers-of-beta", "usrs");
// Negative Powers of Beta in G2
impl_local!(BetaH, "resources/", "beta-h", "usrs");

// BondPublic
// impl_remote!(BondPublicProver, REMOTE_URL, "resources/", "bond_public", "prover");
impl_local!(BondPublicVerifier, "resources/", "bond_public", "verifier");
// // UnbondPublic
// impl_remote!(UnbondPublicProver, REMOTE_URL, "resources/", "unbond_public", "prover");
impl_local!(UnbondPublicVerifier, "resources/", "unbond_public", "verifier");
// // UnbondDelegatorAsValidator
// impl_remote!(UnbondDelegatorAsValidatorProver, REMOTE_URL, "resources/", "unbond_delegator_as_validator", "prover");
impl_local!(UnbondDelegatorAsValidatorVerifier, "resources/", "unbond_delegator_as_validator", "verifier");
// // ClaimUnbondPublic
// impl_remote!(ClaimUnbondPublicProver, REMOTE_URL, "resources/", "claim_unbond_public", "prover");
impl_local!(ClaimUnbondPublicVerifier, "resources/", "claim_unbond_public", "verifier");
// // SetValidatorState
// impl_remote!(SetValidatorStateProver, REMOTE_URL, "resources/", "set_validator_state", "prover");
impl_local!(SetValidatorStateVerifier, "resources/", "set_validator_state", "verifier");
// // TransferPrivate
// impl_remote!(TransferPrivateProver, REMOTE_URL, "resources/", "transfer_private", "prover");
impl_local!(TransferPrivateVerifier, "resources/", "transfer_private", "verifier");
// // TransferPublic
// impl_remote!(TransferPublicProver, REMOTE_URL, "resources/", "transfer_public", "prover");
impl_local!(TransferPublicVerifier, "resources/", "transfer_public", "verifier");
// // TransferPrivateToPublic
// impl_remote!(TransferPrivateToPublicProver, REMOTE_URL, "resources/", "transfer_private_to_public", "prover");
impl_local!(TransferPrivateToPublicVerifier, "resources/", "transfer_private_to_public", "verifier");
// // TransferPublicToPrivate
// impl_remote!(TransferPublicToPrivateProver, REMOTE_URL, "resources/", "transfer_public_to_private", "prover");
impl_local!(TransferPublicToPrivateVerifier, "resources/", "transfer_public_to_private", "verifier");
// // Join
// impl_remote!(JoinProver, REMOTE_URL, "resources/", "join", "prover");
impl_local!(JoinVerifier, "resources/", "join", "verifier");
// // Split
// impl_remote!(SplitProver, REMOTE_URL, "resources/", "split", "prover");
impl_local!(SplitVerifier, "resources/", "split", "verifier");
// // FeePrivate
// impl_remote!(FeePrivateProver, REMOTE_URL, "resources/", "fee_private", "prover");
impl_local!(FeePrivateVerifier, "resources/", "fee_private", "verifier");
// // FeePublic
// impl_remote!(FeePublicProver, REMOTE_URL, "resources/", "fee_public", "prover");
impl_local!(FeePublicVerifier, "resources/", "fee_public", "verifier");

impl_mobile_local!(BondPublicProver, "resources/", "bond_public", "prover");
// impl_mobile_local!(BondPublicVerifier, "resources/", "bond_public", "verifier");
impl_mobile_local!(UnbondPublicProver, "resources/", "unbond_public", "prover");
// impl_mobile_local!(UnbondPublicVerifier, "resources/", "unbond_public", "verifier");
impl_mobile_local!(UnbondDelegatorAsValidatorProver, "resources/", "unbond_delegator_as_validator", "prover");
// impl_mobile_local!(UnbondDelegatorAsValidatorVerifier, "resources/", "unbond_delegator_as_validator", "verifier");
impl_mobile_local!(ClaimUnbondPublicProver, "resources/", "claim_unbond_public", "prover");
// impl_mobile_local!(ClaimUnbondPublicVerifier, "resources/", "claim_unbond_public", "verifier");
impl_mobile_local!(SetValidatorStateProver, "resources/", "set_validator_state", "prover");
// impl_mobile_local!(SetValidatorStateVerifier, "resources/", "set_validator_state", "verifier");
impl_mobile_local!(TransferPrivateProver, "resources/", "transfer_private", "prover");
// impl_mobile_local!(TransferPrivateVerifier, "resources/", "transfer_private", "verifier");
impl_mobile_local!(TransferPublicProver, "resources/", "transfer_public", "prover");
// impl_mobile_local!(TransferPublicVerifier, "resources/", "transfer_public", "verifier");
impl_mobile_local!(TransferPrivateToPublicProver, "resources/", "transfer_private_to_public", "prover");
// impl_mobile_local!(TransferPrivateToPublicVerifier, "resources/", "transfer_private_to_public", "verifier");
impl_mobile_local!(TransferPublicToPrivateProver, "resources/", "transfer_public_to_private", "prover");
// impl_mobile_local!(TransferPublicToPrivateVerifier, "resources/", "transfer_public_to_private", "verifier");
impl_mobile_local!(JoinProver, "resources/", "join", "prover");
// impl_mobile_local!(JoinVerifier, "resources/", "join", "verifier");
impl_mobile_local!(SplitProver, "resources/", "split", "prover");
// impl_mobile_local!(SplitVerifier, "resources/", "split", "verifier");
impl_mobile_local!(FeePrivateProver, "resources/", "fee_private", "prover");
// impl_mobile_local!(FeePrivateVerifier, "resources/", "fee_private", "verifier");
impl_mobile_local!(FeePublicProver, "resources/", "fee_public", "prover");
// impl_mobile_local!(FeePublicVerifier, "resources/", "fee_public", "verifier");

#[macro_export]
macro_rules! insert_credit_keys {
    ($map:ident, $type:ident<$network:ident>, $variant:ident) => {{
        paste::paste! {
            let string = stringify!([<$variant:lower>]);
            $crate::insert_key!($map, string, $type<$network>, ("bond_public", $crate::testnet3::[<BondPublic $variant>]::load_bytes()));
            $crate::insert_key!($map, string, $type<$network>, ("unbond_public", $crate::testnet3::[<UnbondPublic $variant>]::load_bytes()));
            $crate::insert_key!($map, string, $type<$network>, ("unbond_delegator_as_validator", $crate::testnet3::[<UnbondDelegatorAsValidator $variant>]::load_bytes()));
            $crate::insert_key!($map, string, $type<$network>, ("claim_unbond_public", $crate::testnet3::[<ClaimUnbondPublic $variant>]::load_bytes()));
            $crate::insert_key!($map, string, $type<$network>, ("set_validator_state", $crate::testnet3::[<SetValidatorState $variant>]::load_bytes()));
            $crate::insert_key!($map, string, $type<$network>, ("transfer_private", $crate::testnet3::[<TransferPrivate $variant>]::load_bytes()));
            $crate::insert_key!($map, string, $type<$network>, ("transfer_public", $crate::testnet3::[<TransferPublic $variant>]::load_bytes()));
            $crate::insert_key!($map, string, $type<$network>, ("transfer_private_to_public", $crate::testnet3::[<TransferPrivateToPublic $variant>]::load_bytes()));
            $crate::insert_key!($map, string, $type<$network>, ("transfer_public_to_private", $crate::testnet3::[<TransferPublicToPrivate $variant>]::load_bytes()));
            $crate::insert_key!($map, string, $type<$network>, ("join", $crate::testnet3::[<Join $variant>]::load_bytes()));
            $crate::insert_key!($map, string, $type<$network>, ("split", $crate::testnet3::[<Split $variant>]::load_bytes()));
            $crate::insert_key!($map, string, $type<$network>, ("fee_private", $crate::testnet3::[<FeePrivate $variant>]::load_bytes()));
            $crate::insert_key!($map, string, $type<$network>, ("fee_public", $crate::testnet3::[<FeePublic $variant>]::load_bytes()));
        }
    }};
}

#[macro_export]
macro_rules! insert_key {
    ($map:ident, $string:tt, $type:ident<$network:ident>, ($name:tt, $circuit_key:expr)) => {{
        // Load the circuit key bytes.
        let key_bytes: Vec<u8> = $circuit_key.expect(&format!("Failed to load {} bytes", $string));
        // Recover the circuit key.
        let key = $type::<$network>::from_bytes_le(&key_bytes[1..]).expect(&format!("Failed to recover {}", $string));
        // Insert the circuit key.
        $map.insert($name.to_string(), std::sync::Arc::new(key));
    }};
}

// Inclusion
impl_mobile_local!(InclusionProver, "resources/", "inclusion", "prover");
impl_mobile_local!(InclusionVerifier, "resources/", "inclusion", "verifier");

/// The function name for the inclusion circuit.
pub const TESTNET3_INCLUSION_FUNCTION_NAME: &str = "inclusion";

lazy_static! {
    pub static ref INCLUSION_PROVING_KEY: Vec<u8> =
        InclusionProver::load_bytes().expect("Failed to load inclusion proving key");
    pub static ref INCLUSION_VERIFYING_KEY: Vec<u8> =
        InclusionVerifier::load_bytes().expect("Failed to load inclusion verifying key");
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;
    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    fn test_load_bytes() {
        Degree16::load_bytes().expect("Failed to load degree 16");
        Degree17::load_bytes().expect("Failed to load degree 17");
        Degree18::load_bytes().expect("Failed to load degree 18");
        Degree19::load_bytes().expect("Failed to load degree 19");
        Degree20::load_bytes().expect("Failed to load degree 20");
        BondPublicVerifier::load_bytes().expect("Failed to load bond_public verifier");
        UnbondPublicVerifier::load_bytes().expect("Failed to load unbond_public verifier");
        UnbondDelegatorAsValidatorVerifier::load_bytes()
            .expect("Failed to load unbond_delegator_as_validator verifier");
        ClaimUnbondPublicVerifier::load_bytes().expect("Failed to load claim_unbond_public verifier");
        SetValidatorStateVerifier::load_bytes().expect("Failed to load set_validator_state verifier");
        TransferPrivateVerifier::load_bytes().expect("Failed to load transfer_private verifier");
        TransferPublicVerifier::load_bytes().expect("Failed to load transfer_public verifier");
        TransferPrivateToPublicVerifier::load_bytes().expect("Failed to load transfer_private_to_public verifier");
        TransferPublicToPrivateVerifier::load_bytes().expect("Failed to load transfer_public_to_private verifier");
        FeePrivateProver::load_bytes().expect("Failed to load fee_private prover");
        FeePrivateVerifier::load_bytes().expect("Failed to load fee_private verifier");
        FeePublicProver::load_bytes().expect("Failed to load fee_public prover");
        FeePublicVerifier::load_bytes().expect("Failed to load fee_public verifier");
        InclusionProver::load_bytes().expect("Failed to load inclusion prover");
        InclusionVerifier::load_bytes().expect("Failed to load inclusion verifier");
    }
}
