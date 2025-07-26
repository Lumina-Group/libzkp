#!/usr/bin/env python3
"""
Example usage of libzkp.benchmark_proof_generation function
"""

import libzkp
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def run_benchmarks():
    """Run benchmarks for all supported proof types"""
    
    # Supported proof types
    proof_types = ["range", "equality", "threshold", "membership", "improvement", "consistency"]
    
    logger.info("Starting proof generation benchmarks...")
    
    for proof_type in proof_types:
        try:
            logger.info(f"Benchmarking {proof_type} proofs...")
            
            # Run benchmark with 10 iterations
            benchmark_results = libzkp.benchmark_proof_generation(proof_type, 10)
            
            # Log results in the format you specified
            logger.info(f"{proof_type} proof benchmark:")
            logger.info(f"  - Average time: {benchmark_results.get('avg_time_ms', 'N/A')}ms")
            logger.info(f"  - Min time: {benchmark_results.get('min_time_ms', 'N/A')}ms")
            logger.info(f"  - Max time: {benchmark_results.get('max_time_ms', 'N/A')}ms")
            logger.info(f"  - Success rate: {benchmark_results.get('success_rate', 'N/A')}%")
            logger.info(f"  - Throughput: {benchmark_results.get('proofs_per_second', 'N/A')} proofs/sec")
            
        except Exception as e:
            logger.error(f"Failed to benchmark {proof_type} proofs: {e}")
    
    logger.info("All benchmarks completed!")

def benchmark_single_type(proof_type, iterations=100):
    """Benchmark a single proof type with detailed results"""
    
    try:
        logger.info(f"Running {iterations} iterations for {proof_type} proofs...")
        
        results = libzkp.benchmark_proof_generation(proof_type, iterations)
        
        logger.info(f"Benchmark completed: avg time = {results.get('avg_time_ms', 'N/A')}ms")
        logger.info(f"Detailed results for {proof_type}:")
        logger.info(f"  - Total time: {results.get('total_time_ms', 'N/A')}ms")
        logger.info(f"  - Average time: {results.get('avg_time_ms', 'N/A')}ms")
        logger.info(f"  - Min time: {results.get('min_time_ms', 'N/A')}ms")
        logger.info(f"  - Max time: {results.get('max_time_ms', 'N/A')}ms")
        logger.info(f"  - Standard deviation: {results.get('std_dev_ms', 'N/A')}ms")
        logger.info(f"  - Success rate: {results.get('success_rate', 'N/A')}%")
        logger.info(f"  - Throughput: {results.get('proofs_per_second', 'N/A')} proofs/sec")
        
        return results
        
    except Exception as e:
        logger.error(f"Benchmark failed: {e}")
        return None

if __name__ == "__main__":
    # Run all benchmarks
    run_benchmarks()
    
    print("\n" + "="*60 + "\n")
    
    # Run detailed benchmark for range proofs
    benchmark_single_type("range", 50)