#!/usr/bin/env python3
"""
Test script for libzkp.benchmark_proof_generation function
"""

import libzkp
import json

def test_benchmark_function():
    """Test the benchmark_proof_generation function with different proof types"""
    
    print("Testing libzkp.benchmark_proof_generation function...")
    print("=" * 60)
    
    # Test all supported proof types
    proof_types = ["range", "equality", "threshold", "membership", "improvement", "consistency"]
    
    for proof_type in proof_types:
        print(f"\nTesting {proof_type} proof benchmarking:")
        print("-" * 40)
        
        try:
            # Run benchmark with 3 iterations
            results = libzkp.benchmark_proof_generation(proof_type, 3)
            
            # Print results in a formatted way
            print(f"✓ Success! Results for {proof_type} proofs:")
            print(f"  Proof Type: {results['proof_type']}")
            print(f"  Iterations: {results['iterations']:.0f}")
            print(f"  Successful: {results['successful_iterations']:.0f}")
            print(f"  Success Rate: {results['success_rate']:.1f}%")
            print(f"  Total Time: {results['total_time_ms']:.2f}ms")
            print(f"  Average Time: {results['avg_time_ms']:.2f}ms")
            print(f"  Min Time: {results['min_time_ms']:.2f}ms")
            print(f"  Max Time: {results['max_time_ms']:.2f}ms")
            print(f"  Std Dev: {results['std_dev_ms']:.2f}ms")
            print(f"  Throughput: {results['proofs_per_second']:.2f} proofs/sec")
            
        except Exception as e:
            print(f"✗ Failed to benchmark {proof_type}: {e}")
    
    # Test with invalid proof type
    print(f"\nTesting invalid proof type:")
    print("-" * 40)
    try:
        results = libzkp.benchmark_proof_generation("invalid_type", 1)
        print("✗ Should have failed with invalid proof type")
    except Exception as e:
        print(f"✓ Correctly rejected invalid proof type: {e}")
    
    # Test with zero iterations
    print(f"\nTesting zero iterations:")
    print("-" * 40)
    try:
        results = libzkp.benchmark_proof_generation("range", 0)
        print("✗ Should have failed with zero iterations")
    except Exception as e:
        print(f"✓ Correctly handled zero iterations: {e}")

if __name__ == "__main__":
    test_benchmark_function()