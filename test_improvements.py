#!/usr/bin/env python3
"""Test script to verify the improvements made to the libzkp library."""

import libzkp
import time
import hashlib

def test_stark_backend():
    """Test the improved STARK backend implementation."""
    print("\n=== Testing STARK Backend (Improvement Proof) ===")
    
    # Test valid improvement
    try:
        proof = libzkp.prove_improvement(10, 20)
        is_valid = libzkp.verify_improvement(proof, 10)
        print(f"✓ Valid improvement proof: {is_valid}")
        assert is_valid
    except Exception as e:
        print(f"✗ Failed to create/verify improvement proof: {e}")
        return False
    
    # Test invalid improvement (new <= old)
    try:
        proof = libzkp.prove_improvement(20, 10)
        print("✗ Should have failed for invalid improvement")
        return False
    except ValueError as e:
        print(f"✓ Correctly rejected invalid improvement: {e}")
    
    return True

def test_parallel_verification():
    """Test the improved parallel verification."""
    print("\n=== Testing Parallel Verification ===")
    
    # Create multiple proofs
    proofs = []
    
    # Range proof
    range_proof = libzkp.prove_range(25, 0, 50)
    proofs.append((range_proof, "range"))
    
    # Equality proof
    equality_proof = libzkp.prove_equality(42, 42)
    proofs.append((equality_proof, "equality"))
    
    # Threshold proof
    threshold_proof = libzkp.prove_threshold([10, 20, 30], 50)
    proofs.append((threshold_proof, "threshold"))
    
    # Improvement proof
    improvement_proof = libzkp.prove_improvement(5, 15)
    proofs.append((improvement_proof, "improvement"))
    
    # Verify in parallel
    start_time = time.time()
    results = libzkp.verify_proofs_parallel(proofs)
    end_time = time.time()
    
    print(f"✓ Verified {len(proofs)} proofs in parallel in {(end_time - start_time)*1000:.2f}ms")
    print(f"✓ Results: {results}")
    
    return all(results)

def test_batch_processing():
    """Test the improved batch processing."""
    print("\n=== Testing Batch Processing ===")
    
    # Create a batch
    batch_id = libzkp.create_proof_batch()
    print(f"✓ Created batch with ID: {batch_id}")
    
    # Add various proofs to the batch
    libzkp.batch_add_range_proof(batch_id, 25, 0, 100)
    libzkp.batch_add_equality_proof(batch_id, 50, 50)
    libzkp.batch_add_threshold_proof(batch_id, [10, 20, 30, 40], 80)
    
    # Check batch status
    status = libzkp.get_batch_status(batch_id)
    print(f"✓ Batch status: {status}")
    
    # Process the batch
    start_time = time.time()
    proofs = libzkp.process_batch(batch_id)
    end_time = time.time()
    
    print(f"✓ Processed batch in {(end_time - start_time)*1000:.2f}ms")
    print(f"✓ Generated {len(proofs)} proofs")
    
    return len(proofs) == 3

def test_error_handling():
    """Test improved error handling."""
    print("\n=== Testing Error Handling ===")
    
    # Test range validation
    try:
        libzkp.prove_range(150, 0, 100)
        print("✗ Should have failed for out-of-range value")
        return False
    except ValueError as e:
        print(f"✓ Range validation error: {e}")
    
    # Test integer overflow protection
    try:
        libzkp.prove_threshold([2**63, 2**63], 2**64)
        print("✗ Should have failed for integer overflow")
        return False
    except Exception as e:
        print(f"✓ Integer overflow protection: {e}")
    
    # Test invalid batch ID
    try:
        libzkp.get_batch_status(999999)
        print("✗ Should have failed for invalid batch ID")
        return False
    except ValueError as e:
        print(f"✓ Invalid batch ID error: {e}")
    
    return True

def test_performance_monitoring():
    """Test performance monitoring features."""
    print("\n=== Testing Performance Monitoring ===")
    
    # Enable performance monitoring
    libzkp.enable_performance_monitoring(True)
    
    # Generate some proofs
    for i in range(10):
        libzkp.prove_range(i * 10, 0, 100)
    
    # Get performance metrics
    metrics = libzkp.get_performance_metrics()
    print(f"✓ Performance metrics: {metrics}")
    
    # Benchmark proof generation
    benchmark_results = libzkp.benchmark_proof_generation("range", 100)
    print(f"✓ Benchmark results: {benchmark_results}")
    
    return True

def main():
    """Run all tests."""
    print("Testing libzkp improvements...")
    
    tests = [
        ("STARK Backend", test_stark_backend),
        ("Parallel Verification", test_parallel_verification),
        ("Batch Processing", test_batch_processing),
        ("Error Handling", test_error_handling),
        ("Performance Monitoring", test_performance_monitoring),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
                print(f"\n✓ {test_name} test passed")
            else:
                failed += 1
                print(f"\n✗ {test_name} test failed")
        except Exception as e:
            failed += 1
            print(f"\n✗ {test_name} test failed with exception: {e}")
    
    print(f"\n{'='*50}")
    print(f"Test Results: {passed} passed, {failed} failed")
    print(f"{'='*50}")
    
    return failed == 0

if __name__ == "__main__":
    import sys
    sys.exit(0 if main() else 1)