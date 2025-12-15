use super::proof::TvcSystem;
use super::signal::{TemporalCode, Waveform};
use crate::utils::error_handling::ZkpResult;
use lazy_static::lazy_static;
use pyo3::prelude::*;
use std::sync::Mutex;

lazy_static! {
    static ref TVC_SYSTEM: Mutex<TvcSystem> = Mutex::new(TvcSystem::setup());
}

#[pyfunction]
pub fn tvc_simulate_transmission(s: u64, t: u64, fps: u32) -> PyResult<(Vec<f32>, u64, u64)> {
    let code = TemporalCode::new(s, t);
    let waveform = code.encode(fps);
    // Simulate transmission and decode
    let decoded = waveform.decode().map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
    Ok((waveform.frames, decoded.s, decoded.t))
}

#[pyfunction]
pub fn tvc_prove_reception(
    s: u64,
    t: u64,
    current_time: u64,
    tolerance: u64,
) -> PyResult<(Vec<u8>, Vec<u8>)> {
    let system = TVC_SYSTEM.lock().unwrap();
    let code = TemporalCode::new(s, t);
    
    // In a real scenario, 's' and 't' would come from the decoded waveform.
    // The prover (user) proves they know 's' and 't' that form a valid commitment
    // and that 't' is close to 'current_time'.
    
    system.prove(&code, current_time, tolerance)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
}

#[pyfunction]
pub fn tvc_verify_reception(
    proof: Vec<u8>,
    public_inputs: Vec<u8>,
) -> PyResult<bool> {
    let system = TVC_SYSTEM.lock().unwrap();
    system.verify(&proof, &public_inputs)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
}
