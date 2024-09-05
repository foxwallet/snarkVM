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

/// The restrictions list as a JSON-compatible string.
pub const RESTRICTIONS_LIST: &str = include_str!("./resources/restrictions.json");

const REMOTE_URL: &str = "https://parameters.aleo.org/mainnet";

impl_mobile_local!(Degree15, "resources/", "powers-of-beta-15", "usrs");
impl_mobile_local!(Degree16, "resources/", "powers-of-beta-16", "usrs");
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
impl_mobile_local!(Gamma, "resources/", "powers-of-beta-gamma", "usrs");
// Negative Powers of Beta in G2
impl_mobile_local!(NegBeta, "resources/", "neg-powers-of-beta", "usrs");
// Negative Powers of Beta in G2
impl_mobile_local!(BetaH, "resources/", "beta-h", "usrs");

// BondPublic
impl_mobile_local!(BondPublicProver, "resources/", "bond_public", "prover");
impl_mobile_local!(BondPublicVerifier, "resources/", "bond_public", "verifier");
// BondValidator
impl_mobile_local!(BondValidatorProver, "resources/", "bond_validator", "prover");
impl_mobile_local!(BondValidatorVerifier, "resources/", "bond_validator", "verifier");
// UnbondPublic
impl_mobile_local!(UnbondPublicProver, "resources/", "unbond_public", "prover");
impl_mobile_local!(UnbondPublicVerifier, "resources/", "unbond_public", "verifier");
// ClaimUnbondPublic
impl_mobile_local!(ClaimUnbondPublicProver, "resources/", "claim_unbond_public", "prover");
impl_mobile_local!(ClaimUnbondPublicVerifier, "resources/", "claim_unbond_public", "verifier");
// SetValidatorState
impl_mobile_local!(SetValidatorStateProver, "resources/", "set_validator_state", "prover");
impl_mobile_local!(SetValidatorStateVerifier, "resources/", "set_validator_state", "verifier");
// TransferPrivate
impl_mobile_local!(TransferPrivateProver, "resources/", "transfer_private", "prover");
impl_mobile_local!(TransferPrivateVerifier, "resources/", "transfer_private", "verifier");
// TransferPublic
impl_mobile_local!(TransferPublicProver, "resources/", "transfer_public", "prover");
impl_mobile_local!(TransferPublicVerifier, "resources/", "transfer_public", "verifier");
// TransferPublicAsSigner
impl_mobile_local!(TransferPublicAsSignerProver, "resources/", "transfer_public_as_signer", "prover");
impl_mobile_local!(TransferPublicAsSignerVerifier, "resources/", "transfer_public_as_signer", "verifier");
// TransferPrivateToPublic
impl_mobile_local!(TransferPrivateToPublicProver, "resources/", "transfer_private_to_public", "prover");
impl_mobile_local!(TransferPrivateToPublicVerifier, "resources/", "transfer_private_to_public", "verifier");
// TransferPublicToPrivate
impl_mobile_local!(TransferPublicToPrivateProver, "resources/", "transfer_public_to_private", "prover");
impl_mobile_local!(TransferPublicToPrivateVerifier, "resources/", "transfer_public_to_private", "verifier");
// Join
impl_mobile_local!(JoinProver, "resources/", "join", "prover");
impl_mobile_local!(JoinVerifier, "resources/", "join", "verifier");
// Split
impl_mobile_local!(SplitProver, "resources/", "split", "prover");
impl_mobile_local!(SplitVerifier, "resources/", "split", "verifier");
// FeePrivate
impl_mobile_local!(FeePrivateProver, "resources/", "fee_private", "prover");
impl_mobile_local!(FeePrivateVerifier, "resources/", "fee_private", "verifier");
// FeePublic
impl_mobile_local!(FeePublicProver, "resources/", "fee_public", "prover");
impl_mobile_local!(FeePublicVerifier, "resources/", "fee_public", "verifier");

#[macro_export]
macro_rules! insert_credit_keys {
    ($map:ident, $type:ident<$network:ident>, $variant:ident) => {{
        paste::paste! {
            let string = stringify!([<$variant:lower>]);
            $crate::insert_key!($map, string, $type<$network>, ("bond_public", $crate::mainnet::[<BondPublic $variant>]::load_bytes()));
            $crate::insert_key!($map, string, $type<$network>, ("bond_validator", $crate::mainnet::[<BondValidator $variant>]::load_bytes()));
            $crate::insert_key!($map, string, $type<$network>, ("unbond_public", $crate::mainnet::[<UnbondPublic $variant>]::load_bytes()));
            $crate::insert_key!($map, string, $type<$network>, ("claim_unbond_public", $crate::mainnet::[<ClaimUnbondPublic $variant>]::load_bytes()));
            $crate::insert_key!($map, string, $type<$network>, ("set_validator_state", $crate::mainnet::[<SetValidatorState $variant>]::load_bytes()));
            $crate::insert_key!($map, string, $type<$network>, ("transfer_private", $crate::mainnet::[<TransferPrivate $variant>]::load_bytes()));
            $crate::insert_key!($map, string, $type<$network>, ("transfer_public", $crate::mainnet::[<TransferPublic $variant>]::load_bytes()));
            $crate::insert_key!($map, string, $type<$network>, ("transfer_public_as_signer", $crate::mainnet::[<TransferPublicAsSigner $variant>]::load_bytes()));
            $crate::insert_key!($map, string, $type<$network>, ("transfer_private_to_public", $crate::mainnet::[<TransferPrivateToPublic $variant>]::load_bytes()));
            $crate::insert_key!($map, string, $type<$network>, ("transfer_public_to_private", $crate::mainnet::[<TransferPublicToPrivate $variant>]::load_bytes()));
            $crate::insert_key!($map, string, $type<$network>, ("join", $crate::mainnet::[<Join $variant>]::load_bytes()));
            $crate::insert_key!($map, string, $type<$network>, ("split", $crate::mainnet::[<Split $variant>]::load_bytes()));
            $crate::insert_key!($map, string, $type<$network>, ("fee_private", $crate::mainnet::[<FeePrivate $variant>]::load_bytes()));
            $crate::insert_key!($map, string, $type<$network>, ("fee_public", $crate::mainnet::[<FeePublic $variant>]::load_bytes()));
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
pub const NETWORK_INCLUSION_FUNCTION_NAME: &str = "inclusion";

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
        BondValidatorVerifier::load_bytes().expect("Failed to load bond_validator verifier");
        UnbondPublicVerifier::load_bytes().expect("Failed to load unbond_public verifier");
        ClaimUnbondPublicVerifier::load_bytes().expect("Failed to load claim_unbond_public verifier");
        SetValidatorStateVerifier::load_bytes().expect("Failed to load set_validator_state verifier");
        TransferPrivateVerifier::load_bytes().expect("Failed to load transfer_private verifier");
        TransferPublicVerifier::load_bytes().expect("Failed to load transfer_public verifier");
        TransferPublicAsSignerVerifier::load_bytes().expect("Failed to load transfer_public_as_signer verifier");
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
