use criterion::{black_box, criterion_group, criterion_main, Criterion};
use libzkp::zkp_backends::{BackendRegistry, ZKPBackend};
use libzkp::zkp_backends::bulletproofs_backend::BulletproofsBackend;
use libzkp::circuits::generic_circuit::{GenericCircuitCompiler, CircuitTemplates};
use libzkp::circuits::set_membership::SetMembershipProver;
use std::time::Duration;

fn benchmark_range_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("range_proof");
    group.measurement_time(Duration::from_secs(10));
    
    let backend = BulletproofsBackend::new();
    let compiler = GenericCircuitCompiler::new();
    
    group.bench_function("prove_range_0_100", |b| {
        b.iter(|| {
            let circuit_desc = CircuitTemplates::range_proof(0, 100);
            let circuit = compiler.compile_circuit(&circuit_desc).unwrap();
            let compiled = backend.compile_circuit(&circuit).unwrap();
            
            let public_inputs = r#"{"values": [], "parameters": {"min": 0, "max": 100}}"#;
            let private_inputs = r#"{"values": [42], "blindings": ["deadbeef"]}"#;
            
            backend.prove(
                &compiled,
                public_inputs.as_bytes(),
                private_inputs.as_bytes(),
            ).unwrap()
        })
    });
    
    group.bench_function("verify_range_0_100", |b| {
        let circuit_desc = CircuitTemplates::range_proof(0, 100);
        let circuit = compiler.compile_circuit(&circuit_desc).unwrap();
        let compiled = backend.compile_circuit(&circuit).unwrap();
        
        let public_inputs = r#"{"values": [], "parameters": {"min": 0, "max": 100}}"#;
        let private_inputs = r#"{"values": [42], "blindings": ["deadbeef"]}"#;
        
        let (proof, commitment) = backend.prove(
            &compiled,
            public_inputs.as_bytes(),
            private_inputs.as_bytes(),
        ).unwrap();
        
        b.iter(|| {
            backend.verify(
                black_box(&compiled),
                black_box(&proof),
                black_box(&commitment),
            ).unwrap()
        })
    });
    
    group.finish();
}

fn benchmark_set_membership(c: &mut Criterion) {
    let mut group = c.benchmark_group("set_membership");
    group.measurement_time(Duration::from_secs(10));
    
    // Create sets of different sizes
    let sizes = [10, 100, 1000];
    
    for &size in &sizes {
        let elements: Vec<Vec<u8>> = (0..size)
            .map(|i| format!("element_{}", i).into_bytes())
            .collect();
        
        let prover = SetMembershipProver::from_elements(elements.clone());
        
        group.bench_function(&format!("prove_membership_size_{}", size), |b| {
            b.iter(|| {
                prover.prove_membership(black_box(&elements[0]))
            })
        });
        
        if let Some((circuit, witness)) = prover.prove_membership(&elements[0]) {
            group.bench_function(&format!("verify_membership_size_{}", size), |b| {
                b.iter(|| {
                    prover.verify_membership(black_box(&circuit), black_box(&witness))
                })
            });
        }
    }
    
    group.finish();
}

fn benchmark_batch_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_operations");
    group.measurement_time(Duration::from_secs(15));
    
    let backend = BulletproofsBackend::new();
    let compiler = GenericCircuitCompiler::new();
    
    let batch_sizes = [1, 5, 10, 20];
    
    for &batch_size in &batch_sizes {
        let mut compiled_circuits = Vec::new();
        let mut public_inputs = Vec::new();
        let mut private_inputs = Vec::new();
        
        for i in 0..batch_size {
            let circuit_desc = CircuitTemplates::range_proof(0, 100);
            let circuit = compiler.compile_circuit(&circuit_desc).unwrap();
            let compiled = backend.compile_circuit(&circuit).unwrap();
            compiled_circuits.push(compiled);
            
            let pub_input = format!(r#"{{"values": [], "parameters": {{"min": 0, "max": 100}}}}"#);
            let priv_input = format!(r#"{{"values": [{}], "blindings": ["deadbeef"]}}"#, 10 + i);
            
            public_inputs.push(pub_input.into_bytes());
            private_inputs.push(priv_input.into_bytes());
        }
        
        let public_refs: Vec<&[u8]> = public_inputs.iter().map(|v| v.as_slice()).collect();
        let private_refs: Vec<&[u8]> = private_inputs.iter().map(|v| v.as_slice()).collect();
        
        group.bench_function(&format!("batch_prove_size_{}", batch_size), |b| {
            b.iter(|| {
                backend.prove_batch(
                    black_box(&compiled_circuits),
                    black_box(&public_refs),
                    black_box(&private_refs),
                ).unwrap()
            })
        });
        
        let (proofs, commitments) = backend.prove_batch(
            &compiled_circuits,
            &public_refs,
            &private_refs,
        ).unwrap();
        
        group.bench_function(&format!("batch_verify_size_{}", batch_size), |b| {
            b.iter(|| {
                backend.verify_batch(
                    black_box(&compiled_circuits),
                    black_box(&proofs),
                    black_box(&commitments),
                ).unwrap()
            })
        });
    }
    
    group.finish();
}

criterion_group!(
    benches,
    benchmark_range_proof,
    benchmark_set_membership,
    benchmark_batch_operations
);
criterion_main!(benches);