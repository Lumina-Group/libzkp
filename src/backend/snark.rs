use super::ZkpBackend;
use crate::utils::encoding::read_u64_le;
use crate::utils::error_handling::ZkpError;
use ark_bn254::{Bn254, Fr};
use ark_ff::{AdditiveGroup, PrimeField};
use ark_groth16::Groth16;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

// ===== Key directory configuration =====
static SNARK_KEY_DIR_OVERRIDE: Mutex<Option<PathBuf>> = Mutex::new(None);

fn get_key_dir() -> Option<PathBuf> {
    if let Ok(guard) = SNARK_KEY_DIR_OVERRIDE.lock() {
        if let Some(ref p) = *guard {
            return Some(p.clone());
        }
    }
    env::var("LIBZKP_SNARK_KEY_DIR").ok().map(PathBuf::from)
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

type SnarkKeyPair = (
    ark_groth16::ProvingKey<Bn254>,
    ark_groth16::VerifyingKey<Bn254>,
);

fn load_or_generate_setup<G>(prefix: &str, generate: G) -> Result<SnarkKeyPair, String>
where
    G: FnOnce() -> Result<SnarkKeyPair, String>,
{
    if let Some((pk_path, vk_path)) = key_paths(prefix) {
        match load_pk_vk(&pk_path, &vk_path)? {
            Some(pair) => return Ok(pair),
            None => {
                let pair = generate()?;
                if let Err(e) = persist_pk_vk(&pair.0, &pair.1, &pk_path, &vk_path) {
                    let _ = e;
                }
                return Ok(pair);
            }
        }
    }
    generate()
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
    let mut guard = SNARK_KEY_DIR_OVERRIDE
        .lock()
        .map_err(|_| ZkpError::ConfigError("SNARK key directory lock poisoned".to_string()))?;
    if let Some(existing) = guard.as_ref() {
        if existing != &requested {
            return Err(ZkpError::ConfigError(format!(
                "SNARK key directory already set to {}; new value {} rejected",
                existing.display(),
                requested.display()
            )));
        }
    } else {
        *guard = Some(requested.clone());
    }
    Ok(())
}

pub fn is_snark_initialized() -> bool {
    UNIVERSAL_SETUP.get().is_some() || MEMBERSHIP_SETUP.get().is_some()
}

// ===== MiMC-5 hash function =====
// MiMC-5 over BN254 Fr field.
// S-box: f(x) = x^5 (valid since gcd(5, p-1) = 1 for BN254).
// Rounds: 110 (>= ceil(log_5(p)) = ceil(254/2.322) ≈ 110).
// Round constants derived deterministically from SHA-256 of "libzkp_mimc_v1:{i}".

pub const MIMC_ROUNDS: usize = 110;

static MIMC_CONSTANTS: OnceLock<Box<[Fr; MIMC_ROUNDS]>> = OnceLock::new();

fn get_mimc_constants() -> &'static [Fr; MIMC_ROUNDS] {
    MIMC_CONSTANTS.get_or_init(|| {
        let mut constants = Box::new([Fr::ZERO; MIMC_ROUNDS]);
        for i in 0..MIMC_ROUNDS {
            let mut hasher = Sha256::new();
            hasher.update(b"libzkp_mimc_v1:");
            hasher.update(&(i as u64).to_le_bytes());
            let hash = hasher.finalize();
            constants[i] = Fr::from_le_bytes_mod_order(&hash);
        }
        constants
    })
}

/// Compute MiMC-5 hash of a u64 value natively (for commitment generation).
pub fn mimc_hash_native(value: u64) -> Fr {
    let constants = get_mimc_constants();
    let mut x = Fr::from(value);
    for &c in constants.iter() {
        let t = x + c;
        let t2 = t * t;
        let t4 = t2 * t2;
        x = t4 * t;
    }
    x
}

/// Serialize an Fr element to 32 bytes (canonical little-endian).
pub fn fr_to_commitment(f: Fr) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(32);
    f.serialize_uncompressed(&mut bytes)
        .expect("Fr serialization is infallible");
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes[..32]);
    arr
}

/// Deserialize 32 bytes to an Fr element.
fn fr_from_commitment(bytes: &[u8]) -> Option<Fr> {
    if bytes.len() != 32 {
        return None;
    }
    Fr::deserialize_uncompressed(bytes).ok()
}

/// Compute MiMC-5 in-circuit using FpVar arithmetic (3 constraints per round).
fn mimc_hash_circuit(x_init: FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    let constants = get_mimc_constants();
    let mut x = x_init;
    for &c in constants.iter() {
        let c_var = FpVar::constant(c);
        // t = x + c (linear combination, zero constraints)
        let t: FpVar<Fr> = x + c_var;
        // t^2 (1 constraint)
        let t2: FpVar<Fr> = t.clone() * &t;
        // t^4 (1 constraint)
        let t4: FpVar<Fr> = t2.clone() * &t2;
        // t^5 = t^4 * t (1 constraint)
        x = t4 * t;
    }
    Ok(x)
}

// ===== Equality Circuit =====
// Proves: MiMC5(a) == commitment AND a == b
// Witness: a, b
// Public: commitment (Fr)
// Constraints: ~332 (1 equality + 330 MiMC + 1 commit check)

#[derive(Clone)]
struct EqualityCircuit {
    a: Option<u64>,
    b: Option<u64>,
    pub commitment: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for EqualityCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
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

        // Compute MiMC5(a) in-circuit
        let hash_var = mimc_hash_circuit(a_var)?;

        // Public input: expected commitment (single Fr element)
        let commitment_var = FpVar::<Fr>::new_input(cs.clone(), || {
            self.commitment.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Enforce hash == commitment
        hash_var.enforce_equal(&commitment_var)?;

        Ok(())
    }
}

pub struct SnarkBackend;

static UNIVERSAL_SETUP: OnceLock<Result<SnarkKeyPair, String>> = OnceLock::new();

static MEMBERSHIP_SETUP: OnceLock<Result<SnarkKeyPair, String>> = OnceLock::new();

fn get_membership_setup() -> &'static Result<SnarkKeyPair, String> {
    MEMBERSHIP_SETUP.get_or_init(SnarkBackend::load_or_generate_membership_setup)
}

impl SnarkBackend {
    fn load_or_generate_membership_setup() -> Result<SnarkKeyPair, String> {
        // Use "_mimc" suffix to avoid loading stale SHA-256 based keys
        load_or_generate_setup("membership_mimc", || Self::generate_membership_setup())
    }

    fn generate_membership_setup() -> Result<SnarkKeyPair, String> {
        let rng = &mut OsRng;
        let dummy = MembershipCircuit {
            value: Some(0),
            sel: vec![Some(false); MAX_SET_SIZE],
            set_values: vec![0u64; MAX_SET_SIZE],
            is_real: vec![false; MAX_SET_SIZE],
            commitment: Some(Fr::ZERO),
        };
        Groth16::<Bn254>::circuit_specific_setup(dummy, rng)
            .map_err(|e| format!("setup failed: {:?}", e))
    }

    fn get_universal_setup() -> &'static Result<SnarkKeyPair, String> {
        UNIVERSAL_SETUP.get_or_init(Self::load_or_generate_equality_setup)
    }

    fn load_or_generate_equality_setup() -> Result<SnarkKeyPair, String> {
        load_or_generate_setup("equality_mimc", || Self::generate_equality_setup())
    }

    fn generate_equality_setup() -> Result<SnarkKeyPair, String> {
        let rng = &mut OsRng;
        let dummy_circuit = EqualityCircuit {
            a: Some(0),
            b: Some(0),
            commitment: Some(Fr::ZERO),
        };
        Groth16::<Bn254>::circuit_specific_setup(dummy_circuit, rng)
            .map_err(|e| format!("setup failed: {:?}", e))
    }

    /// Prove equality: MiMC5(a) == commitment AND a == b.
    /// `hash_input` must be `fr_to_commitment(mimc_hash_native(a))`.
    pub fn prove_equality_zk(a: u64, b: u64, hash_input: [u8; 32]) -> Vec<u8> {
        if a != b {
            return vec![];
        }

        let commitment_fr = match fr_from_commitment(&hash_input) {
            Some(f) => f,
            None => return vec![],
        };

        let circuit = EqualityCircuit {
            a: Some(a),
            b: Some(b),
            commitment: Some(commitment_fr),
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

    /// Verify an equality proof. `hash_input` must be the 32-byte MiMC commitment.
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

        let commitment_fr = match fr_from_commitment(hash_input) {
            Some(f) => f,
            None => return false,
        };

        // Public input ordering matches generate_constraints: [commitment]
        let public_inputs = vec![commitment_fr];

        Groth16::<Bn254>::verify_with_processed_vk(&pvk, &public_inputs, &proof).unwrap_or(false)
    }

    /// Prove set membership: MiMC5(value) == commitment AND value ∈ set.
    /// `commitment` must be `fr_to_commitment(mimc_hash_native(value))`.
    pub fn prove_membership_zk(value: u64, set: Vec<u64>, commitment: [u8; 32]) -> Vec<u8> {
        if set.is_empty() || set.len() > MAX_SET_SIZE {
            return vec![];
        }

        let commitment_fr = match fr_from_commitment(&commitment) {
            Some(f) => f,
            None => return vec![],
        };

        let pos = match set.iter().position(|&x| x == value) {
            Some(i) => i,
            None => return vec![],
        };

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
            commitment: Some(commitment_fr),
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

    /// Verify a membership proof. `commitment` must be the 32-byte MiMC commitment.
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

        let commitment_fr = match fr_from_commitment(commitment) {
            Some(f) => f,
            None => return false,
        };

        // Public input ordering matches generate_constraints:
        // [commitment, set[0], ..., set[MAX_SET_SIZE-1], is_real[0], ..., is_real[MAX_SET_SIZE-1]]
        let mut public_inputs: Vec<Fr> = vec![commitment_fr];
        for i in 0..MAX_SET_SIZE {
            let v = if i < set.len() { set[i] } else { 0u64 };
            public_inputs.push(Fr::from(v));
        }
        for i in 0..MAX_SET_SIZE {
            let flag = if i < set.len() { 1u64 } else { 0u64 };
            public_inputs.push(Fr::from(flag));
        }

        Groth16::<Bn254>::verify_with_processed_vk(&pvk, &public_inputs, &proof).unwrap_or(false)
    }
}

// ===== ZK Set Membership circuit =====
// Proves: MiMC5(value) == commitment AND value ∈ {set[0..real_len]}
// Public inputs: commitment (Fr), set_values[MAX_SET_SIZE], is_real[MAX_SET_SIZE]
// Witness: value (Fr), sel[MAX_SET_SIZE] (one-hot boolean)

pub const MAX_SET_SIZE: usize = 64;

#[derive(Clone)]
struct MembershipCircuit {
    value: Option<u64>,
    sel: Vec<Option<bool>>,
    set_values: Vec<u64>,
    is_real: Vec<bool>,
    commitment: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for MembershipCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Witness: value as field element
        let value_var = FpVar::<Fr>::new_witness(cs.clone(), || {
            self.value
                .map(Fr::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Compute MiMC5(value) in-circuit (330 constraints)
        let hash_var = mimc_hash_circuit(value_var.clone())?;

        // Public input: commitment (single Fr)
        let commitment_var = FpVar::<Fr>::new_input(cs.clone(), || {
            self.commitment.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Enforce MiMC5(value) == commitment (1 constraint)
        hash_var.enforce_equal(&commitment_var)?;

        if self.set_values.len() != MAX_SET_SIZE || self.is_real.len() != MAX_SET_SIZE {
            return Err(SynthesisError::Unsatisfiable);
        }

        // Public inputs: set values
        let mut set_vars: Vec<FpVar<Fr>> = Vec::with_capacity(MAX_SET_SIZE);
        for v in self.set_values.into_iter() {
            set_vars.push(FpVar::<Fr>::new_input(cs.clone(), || Ok(Fr::from(v)))?);
        }

        // Public inputs: is_real flags
        let mut is_real_bools: Vec<Boolean<Fr>> = Vec::with_capacity(MAX_SET_SIZE);
        for b in self.is_real.into_iter() {
            is_real_bools.push(Boolean::new_input(cs.clone(), || Ok(b))?);
        }

        if self.sel.len() != MAX_SET_SIZE {
            return Err(SynthesisError::Unsatisfiable);
        }

        // Witness: selection bits (one-hot)
        let mut sel_bools: Vec<Boolean<Fr>> = Vec::with_capacity(MAX_SET_SIZE);
        for bit in self.sel.into_iter() {
            sel_bools.push(Boolean::new_witness(cs.clone(), || {
                bit.ok_or(SynthesisError::AssignmentMissing)
            })?);
        }

        // Enforce booleanity and one-hot (sum == 1)
        let mut sum_sel = FpVar::<Fr>::zero();
        for (i, sel_i) in sel_bools.iter().enumerate() {
            let sel_fp: FpVar<Fr> = sel_i.clone().into();
            sum_sel += sel_fp.clone();

            // sel[i] <= is_real[i]
            let is_real_fp: FpVar<Fr> = is_real_bools[i].clone().into();
            let one_minus_is_real = FpVar::<Fr>::one() - is_real_fp;
            (sel_fp * one_minus_is_real).enforce_equal(&FpVar::<Fr>::zero())?;
        }
        sum_sel.enforce_equal(&FpVar::<Fr>::one())?;

        // Enforce value ∈ set: sum_i sel[i] * (value - set[i]) == 0
        let mut acc = FpVar::<Fr>::zero();
        for i in 0..MAX_SET_SIZE {
            let sel_fp: FpVar<Fr> = sel_bools[i].clone().into();
            acc += sel_fp * (value_var.clone() - set_vars[i].clone());
        }
        acc.enforce_equal(&FpVar::<Fr>::zero())?;

        Ok(())
    }
}

impl ZkpBackend for SnarkBackend {
    fn prove(data: &[u8]) -> Vec<u8> {
        if data.len() != 48 {
            return vec![];
        }
        let a = match read_u64_le(data, 0) {
            Some(v) => v,
            None => return vec![],
        };
        let b = match read_u64_le(data, 8) {
            Some(v) => v,
            None => return vec![],
        };
        let hash_input: [u8; 32] = match data[16..48].try_into() {
            Ok(arr) => arr,
            Err(_) => return vec![],
        };

        Self::prove_equality_zk(a, b, hash_input)
    }

    fn verify(proof: &[u8], data: &[u8]) -> bool {
        Self::verify_equality_zk(proof, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mimc_hash_deterministic() {
        let h1 = mimc_hash_native(42);
        let h2 = mimc_hash_native(42);
        assert_eq!(h1, h2);
        assert_ne!(mimc_hash_native(42), mimc_hash_native(43));
    }

    #[test]
    fn fr_commitment_roundtrip() {
        let f = mimc_hash_native(123);
        let bytes = fr_to_commitment(f);
        let f2 = fr_from_commitment(&bytes).unwrap();
        assert_eq!(f, f2);
    }

    #[test]
    fn groth16_equality_roundtrip() {
        let commitment = fr_to_commitment(mimc_hash_native(42));
        let proof = SnarkBackend::prove_equality_zk(42, 42, commitment);
        assert!(!proof.is_empty(), "proof generation failed");
        assert!(SnarkBackend::verify_equality_zk(&proof, &commitment));
        let wrong = fr_to_commitment(mimc_hash_native(99));
        assert!(!SnarkBackend::verify_equality_zk(&proof, &wrong));
    }
}
