/*
 * This file tests the implementations of various SHA hashing algorithms to verify
 * that they produce the expected hash values for given input data. Ensure that the
 * SHA implementation is linked when compiling this test file.
*/

#include <iostream>
#include <cassert>
#include <string>

#include "sha.h"

void test_sha512() {
  const char* data = "Bangladesh is a country of stunning natural beauty, where vibrant landscapes unfold in every direction. The lush, green countryside is adorned with sprawling rice paddies and meandering rivers, with the mighty Ganges, Brahmaputra, and Meghna rivers converging to create a labyrinth of waterways that are vital to the nation's life. The serene Sundarbans mangrove forest, a UNESCO World Heritage Site, is home to the elusive Bengal tiger and a rich array of wildlife, while the rolling hills of the Chittagong Hill Tracts offer breathtaking vistas and serene spots for reflection. The picturesque Cox’s Bazar boasts the world's longest natural sea beach, where golden sands meet the shimmering Bay of Bengal. Throughout the country, the natural beauty is complemented by a warm and welcoming culture, creating a landscape as rich in heart as it is in scenery.";
  SHA512 sha512;
  std::string hash_digest = sha512.hash(data);
  std::string expected_hash_digest = "c5277b97cf1fee58d398f8a112c156fdf5e0fb07f6e2a4222277fdf316412d84da29533998b58b8f1fff4100d37a4055c1a36414e41308ffc1d70dc7602d27e0";
  std::cout << "Hash digest for SHA-512: " << hash_digest << std::endl;
  assert(hash_digest == expected_hash_digest);
}

void test_sha384() {
  const char* data = "Bangladesh is a country of stunning natural beauty, where vibrant landscapes unfold in every direction. The lush, green countryside is adorned with sprawling rice paddies and meandering rivers, with the mighty Ganges, Brahmaputra, and Meghna rivers converging to create a labyrinth of waterways that are vital to the nation's life. The serene Sundarbans mangrove forest, a UNESCO World Heritage Site, is home to the elusive Bengal tiger and a rich array of wildlife, while the rolling hills of the Chittagong Hill Tracts offer breathtaking vistas and serene spots for reflection. The picturesque Cox’s Bazar boasts the world's longest natural sea beach, where golden sands meet the shimmering Bay of Bengal. Throughout the country, the natural beauty is complemented by a warm and welcoming culture, creating a landscape as rich in heart as it is in scenery.";
  SHA384 sha384;
  std::string hash_digest = sha384.hash(data);
  std::string expected_hash_digest = "d49233f7fed6cb61d556934e11ea9c82b86a9e4bfcd4aa48ba2140b9cf85ae0daf414a8d68aa7b4a9b752d8d9be6a041";
  std::cout << "Hash digest for SHA-384: " << hash_digest << std::endl;
  assert(hash_digest == expected_hash_digest);
}

void test_sha256() {
  const char* data = "Bangladesh is a country of stunning natural beauty, where vibrant landscapes unfold in every direction. The lush, green countryside is adorned with sprawling rice paddies and meandering rivers, with the mighty Ganges, Brahmaputra, and Meghna rivers converging to create a labyrinth of waterways that are vital to the nation's life. The serene Sundarbans mangrove forest, a UNESCO World Heritage Site, is home to the elusive Bengal tiger and a rich array of wildlife, while the rolling hills of the Chittagong Hill Tracts offer breathtaking vistas and serene spots for reflection. The picturesque Cox’s Bazar boasts the world's longest natural sea beach, where golden sands meet the shimmering Bay of Bengal. Throughout the country, the natural beauty is complemented by a warm and welcoming culture, creating a landscape as rich in heart as it is in scenery.";
  SHA256 sha256;
  std::string hash_digest = sha256.hash(data);
  std::string expected_hash_digest = "32ce66b1c62d176f259d153156d1cb1e80349ac08f272d6a3e0498623b67c81b";
  std::cout << "Hash digest for SHA-256: " << hash_digest << std::endl;
  assert(hash_digest == expected_hash_digest);
}

void test_sha512_256() {
  const char* data = "Bangladesh is a country of stunning natural beauty, where vibrant landscapes unfold in every direction. The lush, green countryside is adorned with sprawling rice paddies and meandering rivers, with the mighty Ganges, Brahmaputra, and Meghna rivers converging to create a labyrinth of waterways that are vital to the nation's life. The serene Sundarbans mangrove forest, a UNESCO World Heritage Site, is home to the elusive Bengal tiger and a rich array of wildlife, while the rolling hills of the Chittagong Hill Tracts offer breathtaking vistas and serene spots for reflection. The picturesque Cox’s Bazar boasts the world's longest natural sea beach, where golden sands meet the shimmering Bay of Bengal. Throughout the country, the natural beauty is complemented by a warm and welcoming culture, creating a landscape as rich in heart as it is in scenery.";
  SHA512_256 sha512_256;
  std::string hash_digest = sha512_256.hash(data);
  std::string expected_hash_digest = "00d060b30ff3b2971af5afd999ce93d5043cc05918ce70455e1087df641467fc";
  std::cout << "Hash digest for SHA-512/256: " << hash_digest << std::endl;
  assert(hash_digest == expected_hash_digest);
}

void test_sha224() {
  const char* data = "Bangladesh is a country of stunning natural beauty, where vibrant landscapes unfold in every direction. The lush, green countryside is adorned with sprawling rice paddies and meandering rivers, with the mighty Ganges, Brahmaputra, and Meghna rivers converging to create a labyrinth of waterways that are vital to the nation's life. The serene Sundarbans mangrove forest, a UNESCO World Heritage Site, is home to the elusive Bengal tiger and a rich array of wildlife, while the rolling hills of the Chittagong Hill Tracts offer breathtaking vistas and serene spots for reflection. The picturesque Cox’s Bazar boasts the world's longest natural sea beach, where golden sands meet the shimmering Bay of Bengal. Throughout the country, the natural beauty is complemented by a warm and welcoming culture, creating a landscape as rich in heart as it is in scenery.";
  SHA224 sha224;
  std::string hash_digest = sha224.hash(data);
  std::string expected_hash_digest = "562ade37aa31cebfa14b8eb2e5a830c1de2fca5e69513bfe94eeeef6";
  std::cout << "Hash digest for SHA-224: " << hash_digest << std::endl;
  assert(hash_digest == expected_hash_digest);
}

void test_sha512_224() {
  const char* data = "Bangladesh is a country of stunning natural beauty, where vibrant landscapes unfold in every direction. The lush, green countryside is adorned with sprawling rice paddies and meandering rivers, with the mighty Ganges, Brahmaputra, and Meghna rivers converging to create a labyrinth of waterways that are vital to the nation's life. The serene Sundarbans mangrove forest, a UNESCO World Heritage Site, is home to the elusive Bengal tiger and a rich array of wildlife, while the rolling hills of the Chittagong Hill Tracts offer breathtaking vistas and serene spots for reflection. The picturesque Cox’s Bazar boasts the world's longest natural sea beach, where golden sands meet the shimmering Bay of Bengal. Throughout the country, the natural beauty is complemented by a warm and welcoming culture, creating a landscape as rich in heart as it is in scenery.";
  SHA512_224 sha512_224;
  std::string hash_digest = sha512_224.hash(data);
  std::string expected_hash_digest = "c60eb03a1ae4093f39b7d26659a5c41d56a2cf4b5e1071ec13e5cb9f";
  std::cout << "Hash digest for SHA-512/224: " << hash_digest << std::endl;
  assert(hash_digest == expected_hash_digest);
}

int main() {
  test_sha512();
  test_sha384();
  test_sha256();
  test_sha512_256();
  test_sha224();
  test_sha512_224();
  std::cout << "All test passed successfully." << std::endl;
  return 0;
}
