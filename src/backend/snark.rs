use super::ZkpBackend;
use crate::utils::error_handling::ZkpError;
use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::crh::constraints::CRHSchemeGadget;
use ark_crypto_primitives::crh::sha256::constraints::{Sha256Gadget, UnitVar};
use ark_ff::ToConstraintField;
use ark_groth16::Groth16;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::rngs::OsRng;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

// ===== Key directory configuration =====
// Allows persisting/rehydrating proving and verifying keys for SNARK circuits.
static SNARK_KEY_DIR: OnceLock<Option<PathBuf>> = OnceLock::new();

fn get_key_dir() -> Option<PathBuf> {
    if let Some(dir) = SNARK_KEY_DIR.get() {
        return dir.clone();
    }
    let env_dir = env::var("LIBZKP_SNARK_KEY_DIR").ok().map(PathBuf::from);
    SNARK_KEY_DIR.get_or_init(|| env_dir.clone());
    env_dir
}

fn key_paths(prefix: &str) -> Option<(PathBuf, PathBuf)> {
    get_key_dir().map(|dir| {
        (
            dir.join(format!("{}_pk.bin", prefix)),
            dir.join(format!("{}_vk.bin", prefix)),
        )
    })
}

fn load_pk_vk(
    pk_path: &Path,
    vk_path: &Path,
) -> Result<
    Option<(
        ark_groth16::ProvingKey<Bn254>,
        ark_groth16::VerifyingKey<Bn254>,
    )>,
    String,
> {
    if !pk_path.exists() || !vk_path.exists() {
        return Ok(None);
    }

    let pk_bytes = fs::read(pk_path)
        .map_err(|e| format!("failed to read proving key {}: {:?}", pk_path.display(), e))?;
    let vk_bytes = fs::read(vk_path).map_err(|e| {
        format!(
            "failed to read verifying key {}: {:?}",
            vk_path.display(),
            e
        )
    })?;

    let pk = ark_groth16::ProvingKey::<Bn254>::deserialize_uncompressed(&pk_bytes[..])
        .map_err(|e| format!("failed to deserialize proving key: {:?}", e))?;
    let vk = ark_groth16::VerifyingKey::<Bn254>::deserialize_uncompressed(&vk_bytes[..])
        .map_err(|e| format!("failed to deserialize verifying key: {:?}", e))?;

    Ok(Some((pk, vk)))
}

fn persist_pk_vk(
    pk: &ark_groth16::ProvingKey<Bn254>,
    vk: &ark_groth16::VerifyingKey<Bn254>,
    pk_path: &Path,
    vk_path: &Path,
) -> Result<(), String> {
    if let Some(parent) = pk_path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            format!(
                "failed to create key directory {}: {:?}",
                parent.display(),
                e
            )
        })?;
    }
    if let Some(parent) = vk_path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            format!(
                "failed to create key directory {}: {:?}",
                parent.display(),
                e
            )
        })?;
    }

    let mut pk_buf = Vec::new();
    pk.serialize_uncompressed(&mut pk_buf)
        .map_err(|e| format!("failed to serialize proving key: {:?}", e))?;
    fs::write(pk_path, &pk_buf)
        .map_err(|e| format!("failed to write proving key {}: {:?}", pk_path.display(), e))?;

    let mut vk_buf = Vec::new();
    vk.serialize_uncompressed(&mut vk_buf)
        .map_err(|e| format!("failed to serialize verifying key: {:?}", e))?;
    fs::write(vk_path, &vk_buf).map_err(|e| {
        format!(
            "failed to write verifying key {}: {:?}",
            vk_path.display(),
            e
        )
    })?;

    Ok(())
}

pub fn set_snark_key_dir(path: &str) -> Result<(), ZkpError> {
    if path.is_empty() {
        return Err(ZkpError::ConfigError(
            "SNARK key directory cannot be empty".to_string(),
        ));
    }
    if UNIVERSAL_SETUP.get().is_some() || MEMBERSHIP_SETUP.get().is_some() {
        return Err(ZkpError::ConfigError(
            "SNARK setup is already initialized; set LIBZKP_SNARK_KEY_DIR before first proof"
                .to_string(),
        ));
    }

    let requested = PathBuf::from(path);
    let stored = SNARK_KEY_DIR.get_or_init(|| Some(requested.clone()));
    if let Some(existing) = stored {
        if existing != &requested {
            return Err(ZkpError::ConfigError(format!(
                "SNARK key directory already set to {}; new value {} rejected",
                existing.display(),
                requested.display()
            )));
        }
    }

    // Keep environment variable in sync for child processes/tools.
    env::set_var("LIBZKP_SNARK_KEY_DIR", &requested);
    Ok(())
}

pub fn is_snark_initialized() -> bool {
    UNIVERSAL_SETUP.get().is_some() || MEMBERSHIP_SETUP.get().is_some()
}

#[derive(Clone)]
struct EqualityCircuit {
    a: Option<u64>,
    b: Option<u64>,
    pub hash_input: Option<[u8; 32]>,
}

impl ConstraintSynthesizer<Fr> for EqualityCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Allocate witnesses for a and b as field elements
        let a_var = FpVar::<Fr>::new_witness(cs.clone(), || {
            self.a
                .map(Fr::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let b_var = FpVar::<Fr>::new_witness(cs.clone(), || {
            self.b
                .map(Fr::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Enforce a == b
        a_var.enforce_equal(&b_var)?;

        // Convert 'a' to little-endian bits and constrain higher bits to zero (only 64-bit used)
        let mut a_bits_le = a_var.to_bits_le()?; // length ~= 254
                                                 // Keep exactly 64 LSBs for hashing input
        let a_bits_le_64: Vec<Boolean<Fr>> = a_bits_le.drain(0..64).collect();
        // Remaining higher bits must be zero to represent a 64-bit integer faithfully
        for bit in a_bits_le.into_iter() {
            bit.enforce_equal(&Boolean::FALSE)?;
        }

        // Build 8 LE bytes from the 64 LSBits
        let mut a_bytes_le: Vec<UInt8<Fr>> = Vec::with_capacity(8);
        for chunk in a_bits_le_64.chunks(8) {
            a_bytes_le.push(UInt8::<Fr>::from_bits_le(chunk));
        }

        // Compute SHA-256 over the 8-byte LE encoding of 'a'
        let digest_var = Sha256Gadget::<Fr>::evaluate(&UnitVar::default(), &a_bytes_le)?; // DigestVar
        let digest_bytes = digest_var.to_bytes_le()?; // Vec<UInt8<Fr>> length 32

        // Public input: expected 32-byte commitment
        let expected_commitment = self
            .hash_input
            .ok_or(SynthesisError::AssignmentMissing)?
            .to_vec();
        let expected_commitment_bytes =
            UInt8::<Fr>::new_input_vec(cs.clone(), expected_commitment.as_slice())?;

        // Enforce digest == expected_commitment (byte-wise)
        for (d, e) in digest_bytes.iter().zip(expected_commitment_bytes.iter()) {
            d.enforce_equal(e)?;
        }

        Ok(())
    }
}

pub struct SnarkBackend;

static UNIVERSAL_SETUP: OnceLock<
    Result<
        (
            ark_groth16::ProvingKey<Bn254>,
            ark_groth16::VerifyingKey<Bn254>,
        ),
        String,
    >,
> = OnceLock::new();

// ===== ZK Set Membership (one-out-of-N with hidden index/value) =====
// Public inputs: 32 bytes commitment (SHA-256 of 8-byte LE value), K set values, K is_real flags (0/1)
// Witness: value (u64), selection bits sel[0..K-1] (one-hot)
// Constraints:
//  - Each sel[i] is boolean
//  - sum(sel[i]) == 1
//  - For all i: sel[i] <= is_real[i]
//  - sum_i sel[i] * (value - set[i]) == 0
//  - SHA256(value_le_8) == commitment (32 bytes)

pub const MAX_SET_SIZE: usize = 64;

#[derive(Clone)]
struct MembershipCircuit {
    // Witness
    value: Option<u64>,
    sel: Vec<Option<bool>>, // length MAX_SET_SIZE
    // Public inputs
    set_values: Vec<u64>, // length MAX_SET_SIZE
    is_real: Vec<bool>,   // length MAX_SET_SIZE
    commitment: Option<[u8; 32]>,
}

impl ConstraintSynthesizer<Fr> for MembershipCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Allocate witness for value
        let value_var = FpVar::<Fr>::new_witness(cs.clone(), || {
            self.value
                .map(Fr::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Enforce value is 64-bit: keep 64 LSBs, higher bits zero
        let mut value_bits_le = value_var.to_bits_le()?;
        let value_bits_64: Vec<Boolean<Fr>> = value_bits_le.drain(0..64).collect();
        for bit in value_bits_le.into_iter() {
            bit.enforce_equal(&Boolean::FALSE)?;
        }

        // Build 8 little-endian bytes from 64 bits
        let mut value_bytes_le: Vec<UInt8<Fr>> = Vec::with_capacity(8);
        for chunk in value_bits_64.chunks(8) {
            value_bytes_le.push(UInt8::<Fr>::from_bits_le(chunk));
        }

        // SHA-256(value_le_8)
        let digest_var = Sha256Gadget::<Fr>::evaluate(&UnitVar::default(), &value_bytes_le)?;
        let digest_bytes = digest_var.to_bytes_le()?; // 32 bytes

        // Public input: expected commitment (32 bytes)
        let expected_commitment = self.commitment.ok_or(SynthesisError::AssignmentMissing)?;
        let expected_commitment_bytes =
            UInt8::<Fr>::new_input_vec(cs.clone(), &expected_commitment)?;
        for (d, e) in digest_bytes.iter().zip(expected_commitment_bytes.iter()) {
            d.enforce_equal(e)?;
        }

        // Public inputs: set values and is_real flags
        if self.set_values.len() != MAX_SET_SIZE || self.is_real.len() != MAX_SET_SIZE {
            return Err(SynthesisError::Unsatisfiable);
        }

        let mut set_vars: Vec<FpVar<Fr>> = Vec::with_capacity(MAX_SET_SIZE);
        for v in self.set_values.into_iter() {
            set_vars.push(FpVar::<Fr>::new_input(cs.clone(), || Ok(Fr::from(v)))?);
        }
        let mut is_real_bools: Vec<Boolean<Fr>> = Vec::with_capacity(MAX_SET_SIZE);
        for b in self.is_real.into_iter() {
            is_real_bools.push(Boolean::new_input(cs.clone(), || Ok(b))?);
        }

        // Witness: selection bits
        if self.sel.len() != MAX_SET_SIZE {
            return Err(SynthesisError::Unsatisfiable);
        }
        let mut sel_bools: Vec<Boolean<Fr>> = Vec::with_capacity(MAX_SET_SIZE);
        for bit in self.sel.into_iter() {
            sel_bools.push(Boolean::new_witness(cs.clone(), || {
                bit.ok_or(SynthesisError::AssignmentMissing)
            })?);
        }

        // Enforce booleanity and one-hot (sum == 1)
        let mut sum_sel = FpVar::<Fr>::zero();
        for (i, sel_i) in sel_bools.iter().enumerate() {
            // booleanity is inherent, but ensure by sel_i * (1 - sel_i) == 0
            let sel_fp: FpVar<Fr> = sel_i.clone().into();
            sum_sel += sel_fp.clone();

            // sel[i] <= is_real[i]  => sel[i] * (1 - is_real[i]) == 0
            let is_real_fp: FpVar<Fr> = is_real_bools[i].clone().into();
            let one_minus_is_real = FpVar::<Fr>::one() - is_real_fp;
            (sel_fp * one_minus_is_real).enforce_equal(&FpVar::<Fr>::zero())?;
        }
        sum_sel.enforce_equal(&FpVar::<Fr>::one())?;

        // sum_i sel[i] * (value - set[i]) == 0
        let mut acc = FpVar::<Fr>::zero();
        for i in 0..MAX_SET_SIZE {
            let sel_fp: FpVar<Fr> = sel_bools[i].clone().into();
            acc += sel_fp * (value_var.clone() - set_vars[i].clone());
        }
        acc.enforce_equal(&FpVar::<Fr>::zero())?;

        Ok(())
    }
}

static MEMBERSHIP_SETUP: OnceLock<
    Result<
        (
            ark_groth16::ProvingKey<Bn254>,
            ark_groth16::VerifyingKey<Bn254>,
        ),
        String,
    >,
> = OnceLock::new();

fn get_membership_setup() -> &'static Result<
    (
        ark_groth16::ProvingKey<Bn254>,
        ark_groth16::VerifyingKey<Bn254>,
    ),
    String,
> {
    MEMBERSHIP_SETUP.get_or_init(SnarkBackend::load_or_generate_membership_setup)
}

impl SnarkBackend {
    fn load_or_generate_membership_setup() -> Result<
        (
            ark_groth16::ProvingKey<Bn254>,
            ark_groth16::VerifyingKey<Bn254>,
        ),
        String,
    > {
        if let Some((pk_path, vk_path)) = key_paths("membership") {
            match load_pk_vk(&pk_path, &vk_path)? {
                Some(pair) => return Ok(pair),
                None => {
                    let pair = Self::generate_membership_setup()?;
                    if let Err(e) = persist_pk_vk(&pair.0, &pair.1, &pk_path, &vk_path) {
                        // Production safety: avoid writing to stderr from a library.
                        // Persistence failures are non-fatal; callers can still use in-memory keys.
                        let _ = e;
                    }
                    return Ok(pair);
                }
            }
        }
        Self::generate_membership_setup()
    }

    fn generate_membership_setup() -> Result<
        (
            ark_groth16::ProvingKey<Bn254>,
            ark_groth16::VerifyingKey<Bn254>,
        ),
        String,
    > {
        let rng = &mut OsRng;
        let dummy = MembershipCircuit {
            value: Some(0),
            sel: vec![Some(false); MAX_SET_SIZE],
            set_values: vec![0u64; MAX_SET_SIZE],
            is_real: vec![false; MAX_SET_SIZE],
            commitment: Some([0u8; 32]),
        };
        Groth16::<Bn254>::circuit_specific_setup(dummy, rng)
            .map_err(|e| format!("setup failed: {:?}", e))
    }

    fn get_universal_setup() -> &'static Result<
        (
            ark_groth16::ProvingKey<Bn254>,
            ark_groth16::VerifyingKey<Bn254>,
        ),
        String,
    > {
        UNIVERSAL_SETUP.get_or_init(Self::load_or_generate_equality_setup)
    }

    fn load_or_generate_equality_setup() -> Result<
        (
            ark_groth16::ProvingKey<Bn254>,
            ark_groth16::VerifyingKey<Bn254>,
        ),
        String,
    > {
        if let Some((pk_path, vk_path)) = key_paths("equality") {
            match load_pk_vk(&pk_path, &vk_path)? {
                Some(pair) => return Ok(pair),
                None => {
                    let pair = Self::generate_equality_setup()?;
                    if let Err(e) = persist_pk_vk(&pair.0, &pair.1, &pk_path, &vk_path) {
                        // Production safety: avoid writing to stderr from a library.
                        // Persistence failures are non-fatal; callers can still use in-memory keys.
                        let _ = e;
                    }
                    return Ok(pair);
                }
            }
        }
        Self::generate_equality_setup()
    }

    fn generate_equality_setup() -> Result<
        (
            ark_groth16::ProvingKey<Bn254>,
            ark_groth16::VerifyingKey<Bn254>,
        ),
        String,
    > {
        let rng = &mut OsRng;
        let dummy_circuit = EqualityCircuit {
            a: Some(0),
            b: Some(0),
            hash_input: Some([0; 32]),
        };
        Groth16::<Bn254>::circuit_specific_setup(dummy_circuit, rng)
            .map_err(|e| format!("setup failed: {:?}", e))
    }

    pub fn prove_equality_zk(a: u64, b: u64, hash_input: [u8; 32]) -> Vec<u8> {
        if a != b {
            return vec![];
        }

        let circuit = EqualityCircuit {
            a: Some(a),
            b: Some(b),
            hash_input: Some(hash_input),
        };

        let setup = match Self::get_universal_setup() {
            Ok(pair) => pair,
            Err(_) => return vec![],
        };
        let rng = &mut OsRng;
        let proof = match Groth16::<Bn254>::prove(&setup.0, circuit, rng) {
            Ok(p) => p,
            Err(_) => return vec![],
        };

        let mut bytes = Vec::new();
        if proof.serialize_uncompressed(&mut bytes).is_err() {
            return vec![];
        }
        bytes
    }

    pub fn verify_equality_zk(proof_data: &[u8], hash_input: &[u8]) -> bool {
        let proof = match ark_groth16::Proof::<Bn254>::deserialize_uncompressed(proof_data) {
            Ok(p) => p,
            Err(_) => return false,
        };

        let setup = match Self::get_universal_setup() {
            Ok(pair) => pair,
            Err(_) => return false,
        };
        let pvk = match Groth16::<Bn254>::process_vk(&setup.1) {
            Ok(pvk) => pvk,
            Err(_) => return false,
        };

        if hash_input.len() != 32 {
            return false;
        }

        // Public inputs must match `UInt8::new_input_vec` packing:
        // bytes are packed into one or more field elements via `ToConstraintField`.
        let public_inputs: Vec<Fr> = match ToConstraintField::<Fr>::to_field_elements(hash_input) {
            Some(v) => v,
            None => return false,
        };

        Groth16::<Bn254>::verify_with_processed_vk(&pvk, &public_inputs, &proof).unwrap_or(false)
    }

    pub fn prove_membership_zk(value: u64, set: Vec<u64>, commitment: [u8; 32]) -> Vec<u8> {
        if set.is_empty() || set.len() > MAX_SET_SIZE {
            return vec![];
        }

        // Find index
        let pos = match set.iter().position(|&x| x == value) {
            Some(i) => i,
            None => return vec![],
        };

        // Prepare fixed-size inputs
        let mut set_values = vec![0u64; MAX_SET_SIZE];
        let mut is_real = vec![false; MAX_SET_SIZE];
        for (i, &v) in set.iter().enumerate() {
            set_values[i] = v;
            is_real[i] = true;
        }
        let mut sel = vec![Some(false); MAX_SET_SIZE];
        sel[pos] = Some(true);

        let circuit = MembershipCircuit {
            value: Some(value),
            sel,
            set_values,
            is_real,
            commitment: Some(commitment),
        };

        let setup = match get_membership_setup() {
            Ok(pair) => pair,
            Err(_) => return vec![],
        };
        let rng = &mut OsRng;
        let proof = match Groth16::<Bn254>::prove(&setup.0, circuit, rng) {
            Ok(p) => p,
            Err(_) => return vec![],
        };

        let mut bytes = Vec::new();
        if proof.serialize_uncompressed(&mut bytes).is_err() {
            return vec![];
        }
        bytes
    }

    pub fn verify_membership_zk(proof_data: &[u8], set: &[u64], commitment: &[u8]) -> bool {
        if set.is_empty() || set.len() > MAX_SET_SIZE {
            return false;
        }
        if commitment.len() != 32 {
            return false;
        }

        let proof = match ark_groth16::Proof::<Bn254>::deserialize_uncompressed(proof_data) {
            Ok(p) => p,
            Err(_) => return false,
        };

        let setup = match get_membership_setup() {
            Ok(pair) => pair,
            Err(_) => return false,
        };
        let pvk = match Groth16::<Bn254>::process_vk(&setup.1) {
            Ok(pvk) => pvk,
            Err(_) => return false,
        };

        // Build public inputs:
        // - commitment bytes packed into field elements (UInt8::new_input_vec)
        // - MAX_SET_SIZE set values (FpVar inputs)
        // - MAX_SET_SIZE is_real flags (Boolean inputs as 0/1 field elements)
        let mut public_inputs: Vec<Fr> =
            match ToConstraintField::<Fr>::to_field_elements(commitment) {
                Some(v) => v,
                None => return false,
            };
        // set values (padded)
        for i in 0..MAX_SET_SIZE {
            let v = if i < set.len() { set[i] } else { 0u64 };
            public_inputs.push(Fr::from(v));
        }
        // is_real flags
        for i in 0..MAX_SET_SIZE {
            let flag = if i < set.len() { 1u64 } else { 0u64 };
            public_inputs.push(Fr::from(flag));
        }

        Groth16::<Bn254>::verify_with_processed_vk(&pvk, &public_inputs, &proof).unwrap_or(false)
    }
}

impl ZkpBackend for SnarkBackend {
    fn prove(data: &[u8]) -> Vec<u8> {
        if data.len() != 48 {
            return vec![];
        }
        let a_bytes: [u8; 8] = match data[0..8].try_into() {
            Ok(arr) => arr,
            Err(_) => return vec![],
        };
        let b_bytes: [u8; 8] = match data[8..16].try_into() {
            Ok(arr) => arr,
            Err(_) => return vec![],
        };
        let hash_input: [u8; 32] = match data[16..48].try_into() {
            Ok(arr) => arr,
            Err(_) => return vec![],
        };
        let a = u64::from_le_bytes(a_bytes);
        let b = u64::from_le_bytes(b_bytes);

        Self::prove_equality_zk(a, b, hash_input)
    }

    fn verify(proof: &[u8], data: &[u8]) -> bool {
        Self::verify_equality_zk(proof, data)
    }
}
