#include "NGDec.hpp"
#include "Inc.hpp"
#include <fmt/core.h>

namespace NG {
extern std::array<std::array<std::array<uint32_t, 256>, 16>, 17> g_ArxanTables;
template <typename Iter>
void DecryptNGBlock(std::span<Iter>& data, const ArxanKey& key);
template <typename Iter>
void DecryptNGRoundA(std::span<Iter>& data, const ArxanRoundKey& key,
    const std::array<std::array<uint32_t, 256>, 16>& table);
template <typename Iter>
void DecryptNGRoundB(std::span<Iter>& data, const ArxanRoundKey& key,
    const std::array<std::array<uint32_t, 256>, 16>& table);

template <typename Iter>
void DecryptNGBlock(std::span<Iter>& data, const ArxanKey& key)
{
    for (int i = 0; i < 17; i++) {
        ArxanRoundKey roundKey;
        for (int j = 0; j < 4; j++) {
            int keyIndex = i * 4 + j;
            roundKey[j] = *reinterpret_cast<const uint32_t*>(&key[keyIndex * 4]);
        }

        if (i == 0 || i == 1 || i == 16)
            DecryptNGRoundA(data, roundKey, g_ArxanTables[i]);
        else
            DecryptNGRoundB(data, roundKey, g_ArxanTables[i]);
    }
}

template <typename Iter>
void DecryptNGRoundA(std::span<Iter>& data, const ArxanRoundKey& key,
    const std::array<std::array<uint32_t, 256>, 16>& table)
{
    ArxanBlockResult result;
    result[0] = table[0][data[0]] ^ table[1][data[1]] ^ table[2][data[2]] ^ table[3][data[3]] ^ key[0];
    result[1] = table[4][data[4]] ^ table[5][data[5]] ^ table[6][data[6]] ^ table[7][data[7]] ^ key[1];
    result[2] = table[8][data[8]] ^ table[9][data[9]] ^ table[10][data[10]] ^ table[11][data[11]] ^ key[2];
    result[3] = table[12][data[12]] ^ table[13][data[13]] ^ table[14][data[14]] ^ table[15][data[15]] ^ key[3];
    *reinterpret_cast<uint32_t*>(&data[0]) = result[0];
    *reinterpret_cast<uint32_t*>(&data[4]) = result[1];
    *reinterpret_cast<uint32_t*>(&data[8]) = result[2];
    *reinterpret_cast<uint32_t*>(&data[12]) = result[3];
}

template <typename Iter>
void DecryptNGRoundB(std::span<Iter>& data, const ArxanRoundKey& key,
    const std::array<std::array<uint32_t, 256>, 16>& table)
{
    ArxanBlockResult result;
    result[0] = table[0][data[0]] ^ table[7][data[7]] ^ table[10][data[10]] ^ table[13][data[13]] ^ key[0];
    result[1] = table[1][data[1]] ^ table[4][data[4]] ^ table[11][data[11]] ^ table[14][data[14]] ^ key[1];
    result[2] = table[2][data[2]] ^ table[5][data[5]] ^ table[8][data[8]] ^ table[15][data[15]] ^ key[2];
    result[3] = table[3][data[3]] ^ table[6][data[6]] ^ table[9][data[9]] ^ table[12][data[12]] ^ key[3];
    *reinterpret_cast<uint32_t*>(&data[0]) = result[0];
    *reinterpret_cast<uint32_t*>(&data[4]) = result[1];
    *reinterpret_cast<uint32_t*>(&data[8]) = result[2];
    *reinterpret_cast<uint32_t*>(&data[12]) = result[3];
}

void DecryptNG(std::span<uint8_t> data, const ArxanKey& key)
{
    if (data.size() % ARXAN_BLOCK_SIZE != 0) {
        fmt::print("Failed decrypting NG data: Input length is not a multiple of block size\n");
        return;
    }

    for (size_t i = 0; i < data.size(); i += ARXAN_BLOCK_SIZE) {
        auto block = std::span<uint8_t>(data.begin() + i, ARXAN_BLOCK_SIZE);
        DecryptNGBlock(block, key);
    }
}
} // namespace NG