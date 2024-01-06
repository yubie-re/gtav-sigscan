#include "inc.hpp"
#include <cryptopp/filters.h>
#include "ngdec.hpp"

namespace NG
{
    extern std::array<std::array<std::array<uint32_t, 256>, 16>, 17> g_ArxanTables;

    void DecryptNGRaw(uint8_t* data, size_t size, const ArxanKey& key);
    void DecryptNG(std::vector<uint8_t>& data, const ArxanKey& key);
    void DecryptNGBlock(ArxanBlock& data, const ArxanKey& key);
    void DecryptNGRoundA(ArxanBlock& data, const ArxanRoundKey& key, const std::array<std::array<uint32_t, 256>, 16>& table);
    void DecryptNGRoundB(ArxanBlock& data, const ArxanRoundKey& key, const std::array<std::array<uint32_t, 256>, 16>& table);

    void DecryptNG(std::vector<uint8_t>& data, const ArxanKey& key)
    {
        for(size_t blockIndex = 0; blockIndex < data.size() / 16; blockIndex++)
        {
            ArxanBlock block;
            std::copy(data.begin() + 16 * blockIndex, data.begin() + 16 * (blockIndex + 1), block.begin());
            DecryptNGBlock(block, key);
            std::copy(block.begin(), block.end(), data.begin() + 16 * blockIndex);
        }
    }

    void DecryptNGRaw(uint8_t* data, size_t size, const ArxanKey& key)
    {
        for(size_t blockIndex = 0; blockIndex < size / 16; blockIndex++)
        {
            ArxanBlock block;
            std::copy(data + 16 * blockIndex, data + 16 * (blockIndex + 1), block.begin());
            DecryptNGBlock(block, key);
            std::copy(block.begin(), block.end(), data + 16 * blockIndex);
        }
    }

    void DecryptNGBlock(ArxanBlock& data, const ArxanKey& key)
    {
        for(int i = 0; i < 17; i++)
        {
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

    void DecryptNGRoundA(ArxanBlock& data, const ArxanRoundKey& key, const std::array<std::array<uint32_t, 256>, 16>& table)
    {
        ArxanBlock result;
        *reinterpret_cast<uint32_t*>(&result[0]) = table[0][data[0]] ^ table[1][data[1]] ^ table[2][data[2]] ^ table[3][data[3]] ^ key[0];
        *reinterpret_cast<uint32_t*>(&result[4]) = table[4][data[4]] ^ table[5][data[5]] ^ table[6][data[6]] ^ table[7][data[7]] ^ key[1];
        *reinterpret_cast<uint32_t*>(&result[8]) = table[8][data[8]] ^ table[9][data[9]] ^ table[10][data[10]] ^ table[11][data[11]] ^ key[2];
        *reinterpret_cast<uint32_t*>(&result[12]) = table[12][data[12]] ^ table[13][data[13]] ^ table[14][data[14]] ^ table[15][data[15]] ^ key[3];
        data = result;
    }

    void DecryptNGRoundB(ArxanBlock& data, const ArxanRoundKey& key, const std::array<std::array<uint32_t, 256>, 16>& table)
    {
        ArxanBlock result;
        *reinterpret_cast<uint32_t*>(&result[0]) = table[0][data[0]] ^ table[7][data[7]] ^ table[10][data[10]] ^ table[13][data[13]] ^ key[0];
        *reinterpret_cast<uint32_t*>(&result[4]) = table[1][data[1]] ^ table[4][data[4]] ^ table[11][data[11]] ^ table[14][data[14]] ^ key[1];
        *reinterpret_cast<uint32_t*>(&result[8]) = table[2][data[2]] ^ table[5][data[5]] ^ table[8][data[8]] ^ table[15][data[15]] ^ key[2];
        *reinterpret_cast<uint32_t*>(&result[12]) = table[3][data[3]] ^ table[6][data[6]] ^ table[9][data[9]] ^ table[12][data[12]] ^ key[3];
        data = result;
    }

    void NGDecryptionTransformation::ProcessData(uint8_t* outString, const uint8_t* inString, size_t length)
    {
        if (length % 16 != 0) {
            throw CryptoPP::InvalidCiphertext("Input length is not a multiple of block size");
        }

        for (size_t i = 0; i < length; i += 16)
        {
            ArxanBlock block;
            std::copy(inString + i, inString + i + 16, block.begin());
            DecryptNGBlock(block, m_key);
            std::copy(block.begin(), block.end(), outString + i);
        }
    }
}