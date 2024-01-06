#include "inc.hpp"
#include <cryptopp/filters.h>
#include "ngdec.hpp"

namespace NG
{
    extern std::array<std::array<std::array<uint32_t, 256>, 16>, 17> g_ArxanTables;

    void DecryptNGRaw(uint8_t* data, size_t size, const ArxanKey& key);
    std::vector<uint8_t> DecryptNG(const std::vector<uint8_t>& data, const ArxanKey& key);
    std::vector<uint8_t> DecryptNGBlock(const std::vector<uint8_t>& data, const ArxanKey& key);
    std::vector<uint32_t> DecryptNGRoundA(const std::vector<uint8_t>& data, const std::vector<uint32_t>& key, const std::array<std::array<uint32_t, 256>, 16>& table);
    std::vector<uint32_t> DecryptNGRoundB(const std::vector<uint8_t>& data, const std::vector<uint32_t>& key, const std::array<std::array<uint32_t, 256>, 16>& table);

    std::vector<uint8_t> DecryptNG(const std::vector<uint8_t>& data, const ArxanKey& key)
    {
        std::vector<uint8_t> decryptedData(data.size());

        for(size_t blockIndex = 0; blockIndex < data.size() / 16; blockIndex++)
        {
            std::vector<uint8_t> encryptedBlock(data.begin() + 16 * blockIndex, data.begin() + 16 * (blockIndex + 1));
            std::vector<uint8_t> decryptedBlock = DecryptNGBlock(encryptedBlock, key);
            std::copy(decryptedBlock.begin(), decryptedBlock.end(), decryptedData.begin() + 16 * blockIndex);
        }

        if(data.size() % 16 != 0)
        {
            size_t left = data.size() % 16;
            std::copy(data.end() - left, data.end(), decryptedData.end() - left);
        }

        return decryptedData;
    }

    void DecryptNGRaw(uint8_t* data, size_t size, const ArxanKey& key)
    {
        for(size_t blockIndex = 0; blockIndex < size / 16; blockIndex++)
        {
            std::vector<uint8_t> encryptedBlock(data + 16 * blockIndex, data + 16 * (blockIndex + 1));
            std::vector<uint8_t> decryptedBlock = DecryptNGBlock(encryptedBlock, key);
            std::copy(decryptedBlock.begin(), decryptedBlock.end(), data + 16 * blockIndex);
        }

        if(size % 16 != 0)
        {
            size_t left = size % 16;
            std::copy(data + (size - left), data + size, data + size - left);
        }
    }

    std::vector<uint8_t> DecryptNGBlock(const std::vector<uint8_t>& data, const ArxanKey& key)
    {
        std::vector<uint8_t> buffer(data);

        for(int i = 0; i < 17; i++)
        {
            std::vector<uint32_t> roundKey(4);
            for (int j = 0; j < 4; j++) {
                int keyIndex = i * 4 + j;
                roundKey[j] = *reinterpret_cast<const uint32_t*>(&key[keyIndex * 4]);
            }

            std::vector<uint32_t> roundResult;
            if (i == 0 || i == 1 || i == 16) 
                roundResult = DecryptNGRoundA(buffer, roundKey, g_ArxanTables[i]);
            else
                roundResult = DecryptNGRoundB(buffer, roundKey, g_ArxanTables[i]);
            buffer = std::vector<uint8_t>(reinterpret_cast<uint8_t*>(roundResult.data()), reinterpret_cast<uint8_t*>(roundResult.data()) + roundResult.size() * sizeof(uint32_t));
        }

        return buffer;
    }

    std::vector<uint32_t> DecryptNGRoundA(const std::vector<uint8_t>& data, const std::vector<uint32_t>& key, const std::array<std::array<uint32_t, 256>, 16>& table)
    {
        std::vector<uint32_t> result(4);

        result[0] = table[0][data[0]] ^ table[1][data[1]] ^ table[2][data[2]] ^ table[3][data[3]] ^ key[0];
        result[1] = table[4][data[4]] ^ table[5][data[5]] ^ table[6][data[6]] ^ table[7][data[7]] ^ key[1];
        result[2] = table[8][data[8]] ^ table[9][data[9]] ^ table[10][data[10]] ^ table[11][data[11]] ^ key[2];
        result[3] = table[12][data[12]] ^ table[13][data[13]] ^ table[14][data[14]] ^ table[15][data[15]] ^ key[3];

        return result;
    }

    std::vector<uint32_t> DecryptNGRoundB(const std::vector<uint8_t>& data, const std::vector<uint32_t>& key, const std::array<std::array<uint32_t, 256>, 16>& table)
    {
        std::vector<uint32_t> result(4);

        result[0] = table[0][data[0]] ^ table[7][data[7]] ^ table[10][data[10]] ^ table[13][data[13]] ^ key[0];
        result[1] = table[1][data[1]] ^ table[4][data[4]] ^ table[11][data[11]] ^ table[14][data[14]] ^ key[1];
        result[2] = table[2][data[2]] ^ table[5][data[5]] ^ table[8][data[8]] ^ table[15][data[15]] ^ key[2];
        result[3] = table[3][data[3]] ^ table[6][data[6]] ^ table[9][data[9]] ^ table[12][data[12]] ^ key[3];

        return result;
    }

    void NGDecryptionTransformation::ProcessData(uint8_t* outString, const uint8_t* inString, size_t length)
    {
        if (length % 16 != 0) {
            throw CryptoPP::InvalidCiphertext("Input length is not a multiple of block size");
        }

        for (size_t i = 0; i < length; i += 16)
        {
            std::vector<uint8_t> encryptedBlock(inString + i, inString + i + 16);
            std::vector<uint8_t> decryptedBlock = DecryptNGBlock(encryptedBlock, m_key);
            std::copy(decryptedBlock.begin(), decryptedBlock.end(), outString + i);
        }
    }
}