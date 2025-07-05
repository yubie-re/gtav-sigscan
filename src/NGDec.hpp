#ifndef NG_DEC_HPP
#define NG_DEC_HPP

// Custom Arxan Decryption algo
// Uses same as RPF
// Original reimplementation:
// https://github.com/Neodymium146/gta-toolkit/blob/master/RageLib.GTA5/Cryptography/GTA5Encryption.cs

#include <array>
#include <cstdint>
#include <span>

#define ARXAN_BLOCK_SIZE 16

namespace NG {
using ArxanKey = std::array<uint8_t, 272>;
using ArxanRoundKey = std::array<uint32_t, 4>;
using ArxanBlockResult = std::array<uint32_t, 4>;
void DecryptNG(std::span<uint8_t> data, const ArxanKey& key);
} // namespace NG

#endif