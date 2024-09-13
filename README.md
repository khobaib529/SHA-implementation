# SHA C++ Implementation

This repository contains a C++ implementation of various SHA (Secure Hash Algorithm) functions. The header file includes the following algorithms:

- **SHA-256**: Produces a 256-bit hash value.
- **SHA-224**: A truncated version of SHA-256 that produces a 224-bit hash value.
- **SHA-512**: Produces a 512-bit hash value.
- **SHA-384**: A truncated version of SHA-512 that produces a 384-bit hash value.
- **SHA-512/224**: A variant of SHA-512 that produces a 224-bit hash value.
- **SHA-512/256**: A variant of SHA-512 that produces a 256-bit hash value.

## Classes

### `SHABase`

The `SHABase` class provides common methods and utilities used by the SHA algorithms.

**Protected Methods:**
- `to_bit_string(Type number)`: Converts a number to a bit string representation.
- `to_integral(const char* data)`: Converts a character array to an integral type representation.
- `to_integral_vector(const std::string& preprocessed_data)`: Converts a preprocessed string to a vector of integral types.
- `to_hex(const std::string& str)`: Converts a string to its hexadecimal representation.
- `to_string(const Type* hash_digest)`: Converts an array of hash values to a string representation.
- `ch(Type x, Type y, Type z)`: Computes the 'ch' function used in hash computations.
- `maj(Type x, Type y, Type z)`: Computes the 'maj' function used in hash computations.
- `RotR(Type a, short n)`: Performs a right bitwise rotation.
- `ShR(Type a, short n)`: Performs a right arithmetic shift.

### `SHA256`

The `SHA256` class implements the SHA-256 hashing function.

**Public Methods:**
- `std::string hash(const char* data)`: Computes the SHA-256 hash of the input data.

### `SHA224`

The `SHA224` class implements the SHA-224 hashing function.

**Public Methods:**
- `std::string hash(const char* data)`: Computes a SHA-224 hash from the input data.

### `SHA512`

The `SHA512` class implements the SHA-512 hashing function.

**Public Methods:**
- `std::string hash(const char* data)`: Computes the SHA-512 hash of the input data.

**Disclaimer:** While the SHA-512 algorithm theoretically supports hashing up to 2<sup>128</sup> - 1 bits of data, this implementation is limited to handling up to 2<sup>64</sup> -1 bits of data.

### `SHA384`

The `SHA384` class implements the SHA-384 hashing function.

**Public Methods:**
- `std::string hash(const char* data)`: Computes a SHA-384 hash from the input data.

### `SHA512_224`

The `SHA512_224` class implements the SHA-512/224 hashing function.

**Public Methods:**
- `std::string hash(const char* data)`: Computes a SHA-512/224 hash from the input data.

### `SHA512_256`

The `SHA512_256` class implements the SHA-512/256 hashing function.

**Public Methods:**
- `std::string hash(const char* data)`: Computes a SHA-512/256 hash from the input data.

## Usage

To use the SHA hashing functions, include the header file in your C++ project and create instances of the desired SHA class. Call the `hash` method with the input data to obtain the hash value.

```cpp
#include<iostream>
#include "sha.h"

int main() {
    sha::SHA256 sha256;
    std::string hash = sha256.hash("your data here");
    std::cout << "SHA-256 hash: " << hash << std::endl;
    return 0;
}
```

## Benchmarking
To benchmark the performance of the SHA implementations, use the provided benchmarking executable. It measures the time taken to compute hashes for different SHA algorithms.

**1. Build the Benchmarking Executable:**
```shell
make benchmark
```

**2. Run the Benchmark:**
```shell
build/benchmark/sha_benchmark
```

## Testing
To test the SHA implementations, use the provided test executable. It verifies the correctness of the hashing functions using predefined test cases.

**1. Build the Test Executable:**
```shell
make test
```
**2. Run the Tests:**
```shell
build/test/test_sha
```
