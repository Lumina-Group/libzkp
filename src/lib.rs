pub mod advanced;
pub mod backend;
pub mod proof;
pub mod utils;

#[cfg(feature = "python")]
mod python_api;

#[cfg(feature = "python")]
use pyo3::prelude::*;

#[cfg(feature = "python")]
#[pymodule]
fn libzkp(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    python_api::register_module(py, m)
}
