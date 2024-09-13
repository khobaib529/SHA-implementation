/*
 * sha_benchmark.cpp
 *
 * This file benchmarks various SHA (Secure Hash Algorithm) functions by measuring
 * their execution time for hashing a fixed input data string. The file includes:
 *
 * - The `BENCHMARK` macro: A utility to measure and display the time taken for
 *   code execution in nanoseconds.
 * - SHA256: Benchmarks the SHA-256 hashing function.
 * - SHA224: Benchmarks the SHA-224 hashing function.
 * - SHA512: Benchmarks the SHA-512 hashing function.
 * - SHA384: Benchmarks the SHA-384 hashing function.
 * - SHA512_224: Benchmarks the SHA-512/224 hashing function.
 * - SHA512_256: Benchmarks the SHA-512/256 hashing function.
 *
 * The `main` function creates instances of each SHA class, computes the hash for
 * a fixed input data string, and prints the hash values along with the time
 * taken for each algorithm.
 *
 * This file relies on the `sha.h` header for the SHA implementations and requires
 * compilation with C++11 or later. The results are output to the console showing
 * the computed hash values and their respective processing times.
 */

#include <iostream>
#include <chrono>
#include <string>

#include "sha.h"  // Include SHA implementation

// Macro to benchmark code execution time
#define BENCHMARK(code) { \
    auto start = std::chrono::high_resolution_clock::now(); \
    code; \
    auto end = std::chrono::high_resolution_clock::now(); \
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start); \
    std::cout << "Elapsed time: " << duration.count() << " ns\n\n" << std::endl; \
}

int main() {
    // Define example input data for hashing
    const char* data = "The quick brown fox jumps over the lazy dog";

    // Instantiate SHA classes for different hash algorithms
    sha::SHA256 sha256;
    sha::SHA224 sha224;
    sha::SHA512 sha512;
    sha::SHA384 sha384;
    sha::SHA512_224 sha512_224;
    sha::SHA512_256 sha512_256;

    // Benchmark SHA-256
    std::cout << "Benchmarking SHA-256..." << std::endl;
    BENCHMARK(
        std::string result = sha256.hash(data);
        std::cout << "SHA-256: " << result << std::endl;
    );

    // Benchmark SHA-224
    std::cout << "Benchmarking SHA-224..." << std::endl;
    BENCHMARK(
        std::string result = sha224.hash(data);
        std::cout << "SHA-224: " << result << std::endl;
    );

    // Benchmark SHA-512
    std::cout << "Benchmarking SHA-512..." << std::endl;
    BENCHMARK(
        std::string result = sha512.hash(data);
        std::cout << "SHA-512: " << result << std::endl;
    );

    // Benchmark SHA-384
    std::cout << "Benchmarking SHA-384..." << std::endl;
    BENCHMARK(
        std::string result = sha384.hash(data);
        std::cout << "SHA-384: " << result << std::endl;
    );

    // Benchmark SHA-512/224
    std::cout << "Benchmarking SHA-512/224..." << std::endl;
    BENCHMARK(
        std::string result = sha512_224.hash(data);
        std::cout << "SHA-512/224: " << result << std::endl;
    );

    // Benchmark SHA-512/256
    std::cout << "Benchmarking SHA-512/256..." << std::endl;
    BENCHMARK(
        std::string result = sha512_256.hash(data);
        std::cout << "SHA-512/256: " << result << std::endl;
    );

    return 0;
}
