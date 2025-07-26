#!/usr/bin/env python3
"""
Advanced Features Demo for libzkp

This example demonstrates the enhanced functionality including:
- Proof composition and batching
- Performance optimization with caching
- Parallel verification
- Metadata handling
- Performance benchmarking
"""

import libzkp
import time
import hashlib

def demonstrate_basic_proofs():
    """Demonstrate basic proof functionality with improved error handling"""
    print("=== Basic Proof Functionality ===")
    
    # Range proof
    try:
        proof = libzkp.prove_range(25, 18, 100)
        is_valid = libzkp.verify_range(proof, 18, 100)
        print(f"Range proof (age verification): {'✓' if is_valid else '✗'}")
    except Exception as e:
        print(f"Range proof failed: {e}")
    
    # Equality proof
    try:
        proof = libzkp.prove_equality(42, 42)
        commit = hashlib.sha256((42).to_bytes(8, 'little')).digest()
        is_valid = libzkp.verify_equality(proof, commit)
        print(f"Equality proof: {'✓' if is_valid else '✗'}")
    except Exception as e:
        print(f"Equality proof failed: {e}")
    
    # Threshold proof
    try:
        values = [10, 20, 30, 40]
        threshold = 80
        proof = libzkp.prove_threshold(values, threshold)
        is_valid = libzkp.verify_threshold(proof, threshold)
        print(f"Threshold proof (sum >= {threshold}): {'✓' if is_valid else '✗'}")
    except Exception as e:
        print(f"Threshold proof failed: {e}")

def demonstrate_composite_proofs():
    """Demonstrate composite proof functionality"""
    print("\n=== Composite Proof Functionality ===")
    
    try:
        # Create individual proofs
        range_proof = libzkp.prove_range(25, 18, 65)
        equality_proof = libzkp.prove_equality(100, 100)
        threshold_proof = libzkp.prove_threshold([50, 30, 20], 90)
        
        # Create composite proof
        proof_list = [range_proof, equality_proof, threshold_proof]
        composite_proof = libzkp.create_composite_proof(proof_list)
        
        # Verify composite proof integrity
        is_valid = libzkp.verify_composite_proof(composite_proof)
        print(f"Composite proof integrity: {'✓' if is_valid else '✗'}")
        
        # Add metadata to proof
        metadata = {
            "purpose": b"identity_verification",
            "timestamp": str(int(time.time())).encode(),
            "issuer": b"demo_authority"
        }
        proof_with_metadata = libzkp.create_proof_with_metadata(range_proof, metadata)
        
        # Extract metadata
        extracted_metadata = libzkp.extract_proof_metadata(proof_with_metadata)
        print(f"Metadata extracted: {len(extracted_metadata)} items")
        for key, value in extracted_metadata.items():
            print(f"  {key}: {value.decode() if key != 'timestamp' else value}")
            
    except Exception as e:
        print(f"Composite proof failed: {e}")

def demonstrate_caching():
    """Demonstrate proof caching for performance improvement"""
    print("\n=== Caching and Performance ===")
    
    try:
        # Clear cache first
        libzkp.clear_cache()
        
        # First proof generation (no cache)
        start_time = time.time()
        proof1 = libzkp.prove_range_cached(50, 0, 100)
        first_time = time.time() - start_time
        
        # Second proof generation (should use cache)
        start_time = time.time()
        proof2 = libzkp.prove_range_cached(50, 0, 100)
        second_time = time.time() - start_time
        
        print(f"First proof generation: {first_time:.4f}s")
        print(f"Second proof generation: {second_time:.4f}s")
        print(f"Cache speedup: {first_time/second_time:.2f}x" if second_time > 0 else "Cache speedup: ∞")
        
        # Check cache stats
        cache_stats = libzkp.get_cache_stats()
        print(f"Cache size: {cache_stats.get('size', 0)} entries")
        
    except Exception as e:
        print(f"Caching demo failed: {e}")

def demonstrate_parallel_verification():
    """Demonstrate parallel proof verification"""
    print("\n=== Parallel Verification ===")
    
    try:
        # Create multiple proofs
        proofs = []
        for i in range(5):
            proof = libzkp.prove_range(20 + i, 0, 100)
            proofs.append((proof, "range"))
        
        # Verify in parallel
        start_time = time.time()
        results = libzkp.verify_proofs_parallel(proofs)
        parallel_time = time.time() - start_time
        
        valid_count = sum(results)
        print(f"Parallel verification: {valid_count}/{len(proofs)} proofs valid")
        print(f"Verification time: {parallel_time:.4f}s")
        
    except Exception as e:
        print(f"Parallel verification failed: {e}")

def demonstrate_benchmarking():
    """Demonstrate performance benchmarking"""
    print("\n=== Performance Benchmarking ===")
    
    try:
        # Test all supported proof types
        proof_types = ["range", "equality", "threshold", "membership", "improvement", "consistency"]
        
        for proof_type in proof_types:
            try:
                print(f"\n{proof_type.capitalize()} Proof Benchmarks:")
                metrics = libzkp.benchmark_proof_generation(proof_type, 5)
                
                print(f"  Iterations: {metrics['iterations']:.0f}")
                print(f"  Successful: {metrics['successful_iterations']:.0f} ({metrics['success_rate']:.1f}%)")
                print(f"  Total time: {metrics['total_time_ms']:.2f}ms")
                print(f"  Average time: {metrics['average_time_ms']:.2f}ms")
                print(f"  Min time: {metrics['min_time_ms']:.2f}ms")
                print(f"  Max time: {metrics['max_time_ms']:.2f}ms")
                print(f"  Std dev: {metrics['std_dev_ms']:.2f}ms")
                print(f"  Throughput: {metrics['proofs_per_second']:.2f} proofs/sec")
                
            except Exception as e:
                print(f"  Failed to benchmark {proof_type}: {e}")
        
    except Exception as e:
        print(f"Benchmarking failed: {e}")

def demonstrate_advanced_features():
    """Demonstrate advanced proof features"""
    print("\n=== Advanced Features ===")
    
    try:
        # Advanced equality proof with context
        context = b"authentication_session_12345"
        proof = libzkp.prove_equality_advanced(42, 42, context)
        print(f"Equality proof with context: {len(proof)} bytes")
        
        # Optimized threshold proof
        large_values = [100, 200, 300, 150, 250]
        threshold = 800
        proof = libzkp.prove_threshold_optimized(large_values, threshold)
        print(f"Optimized threshold proof: {len(proof)} bytes")
        
        # Get proof information
        proof_info = libzkp.get_proof_info(proof)
        print("Proof Information:")
        for key, value in proof_info.items():
            print(f"  {key}: {value}")
        
        # Validate proof chain
        proof_chain = [
            libzkp.prove_range(25, 18, 65),
            libzkp.prove_equality(100, 100),
            libzkp.prove_threshold([10, 20, 30], 50)
        ]
        is_valid_chain = libzkp.validate_proof_chain(proof_chain)
        print(f"Proof chain validation: {'✓' if is_valid_chain else '✗'}")
        
    except Exception as e:
        print(f"Advanced features failed: {e}")

def demonstrate_batch_processing():
    """Demonstrate batch proof processing"""
    print("\n=== Batch Processing ===")
    
    try:
        # Create a batch
        batch_id = libzkp.create_proof_batch()
        print(f"Created batch: {batch_id}")
        
        # Add operations to batch
        libzkp.batch_add_range_proof(batch_id, 25, 18, 65)
        print("Added range proof to batch")
        
        # Process batch
        batch_results = libzkp.process_batch(batch_id)
        print(f"Batch processing complete: {len(batch_results)} proofs generated")
        
    except Exception as e:
        print(f"Batch processing failed: {e}")

def real_world_example():
    """Demonstrate a real-world use case: Identity Verification System"""
    print("\n=== Real-World Example: Identity Verification ===")
    
    try:
        # Scenario: Prove you're an adult (18+) without revealing exact age
        actual_age = 25
        age_proof = libzkp.prove_range(actual_age, 18, 150)
        
        # Prove you have sufficient funds without revealing exact amount
        account_balance = 5000
        min_balance = 1000
        balance_proof = libzkp.prove_range(account_balance, min_balance, 1000000)
        
        # Prove you're in an approved country list
        country_code = 1  # USA
        approved_countries = [1, 2, 3, 44, 81]  # USA, Canada, France, UK, Japan
        location_proof = libzkp.prove_membership(country_code, approved_countries)
        
        # Create composite identity proof
        identity_proofs = [age_proof, balance_proof, location_proof]
        identity_proof = libzkp.create_composite_proof(identity_proofs)
        
        # Add identity metadata
        metadata = {
            "verification_type": b"financial_service_kyc",
            "timestamp": str(int(time.time())).encode(),
            "risk_level": b"low",
            "session_id": b"sess_" + str(hash(time.time())).encode()
        }
        
        final_proof = libzkp.create_proof_with_metadata(identity_proof, metadata)
        
        print("✓ Identity verification proof created successfully")
        print(f"  Proof size: {len(final_proof)} bytes")
        
        # Verify the composite proof
        is_valid = libzkp.verify_composite_proof(identity_proof)
        print(f"  Proof verification: {'✓' if is_valid else '✗'}")
        
        # Extract and display metadata
        extracted_metadata = libzkp.extract_proof_metadata(final_proof)
        print("  Verification metadata:")
        for key, value in extracted_metadata.items():
            print(f"    {key}: {value.decode()}")
            
    except Exception as e:
        print(f"Real-world example failed: {e}")

def main():
    """Run all demonstrations"""
    print("libzkp Advanced Features Demonstration")
    print("=" * 50)
    
    # Enable performance monitoring
    try:
        libzkp.enable_performance_monitoring()
        print("Performance monitoring enabled")
    except:
        print("Performance monitoring not available")
    
    # Run all demonstrations
    demonstrate_basic_proofs()
    demonstrate_composite_proofs()
    demonstrate_caching()
    demonstrate_parallel_verification()
    demonstrate_benchmarking()
    demonstrate_advanced_features()
    demonstrate_batch_processing()
    real_world_example()
    
    # Show final performance metrics
    try:
        metrics = libzkp.get_performance_metrics()
        print(f"\n=== Final Performance Metrics ===")
        for key, value in metrics.items():
            print(f"{key}: {value}")
    except:
        pass

if __name__ == "__main__":
    main()