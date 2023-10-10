#include "inc.hpp"
#include "ngdec.hpp"

namespace NG
{
    extern std::array<std::array<std::array<uint32_t, 256>, 16>, 17> g_ArxanTables;

    void DecryptNGRaw(uint8_t* data, size_t size, const ArxanKey& key);
    std::vector<uint8_t> DecryptNG(const std::vector<uint8_t>& data, const ArxanKey& key);
    std::vector<uint8_t> DecryptNGBlock(const std::vector<uint8_t>& data, const std::vector<uint32_t>& key);
    std::vector<uint8_t> DecryptNGRoundA(const std::vector<uint8_t>& data, const std::vector<uint32_t>& key, const std::array<std::array<uint32_t, 256>, 16>& table);
    std::vector<uint8_t> DecryptNGRoundB(const std::vector<uint8_t>& data, const std::vector<uint32_t>& key, const std::array<std::array<uint32_t, 256>, 16>& table);

    std::vector<uint8_t> DecryptNG(const std::vector<uint8_t>& data, const ArxanKey& key)
    {
        std::vector<uint8_t> decryptedData(data.size());

        std::vector<uint32_t> keyuints(key.size() / 4);
        memcpy(keyuints.data(), key.data(), key.size());

        for(size_t blockIndex = 0; blockIndex < data.size() / 16; blockIndex++)
        {
            std::vector<uint8_t> encryptedBlock(data.begin() + 16 * blockIndex, data.begin() + 16 * (blockIndex + 1));
            std::vector<uint8_t> decryptedBlock = DecryptNGBlock(encryptedBlock, keyuints);
            memcpy(decryptedData.data() + 16 * blockIndex, decryptedBlock.data(), 16);
        }

        if(data.size() % 16 != 0)
        {
            size_t left = data.size() % 16;
            memcpy(decryptedData.data() + (data.size() - left), data.data() + (data.size() - left), left);
        }

        return decryptedData;
    }

    void DecryptNGRaw(uint8_t* data, size_t size, const ArxanKey& key)
    {
        std::vector<uint32_t> keyuints(key.size() / 4);
        memcpy(keyuints.data(), key.data(), key.size());

        for(size_t blockIndex = 0; blockIndex < size / 16; blockIndex++)
        {
            std::vector<uint8_t> encryptedBlock(data + 16 * blockIndex, data + 16 * (blockIndex + 1));
            std::vector<uint8_t> decryptedBlock = DecryptNGBlock(encryptedBlock, keyuints);
            memcpy(data + 16 * blockIndex, decryptedBlock.data(), 16);
        }

        if(size % 16 != 0)
        {
            size_t left = size % 16;
            memcpy(data + (size - left), data + (size - left), left);
        }
    }


    std::vector<uint8_t> DecryptNGBlock(const std::vector<uint8_t>& data, const std::vector<uint32_t>& key)
    {
        std::vector<uint8_t> buffer(data);

        std::vector<std::vector<uint32_t>> subKeys(17, std::vector<uint32_t>(4));
        for(int i = 0; i < 17; i++)
        {
            subKeys[i][0] = key[4 * i + 0];
            subKeys[i][1] = key[4 * i + 1];
            subKeys[i][2] = key[4 * i + 2];
            subKeys[i][3] = key[4 * i + 3];
        }

        buffer = DecryptNGRoundA(buffer, subKeys[0], g_ArxanTables[0]);
        buffer = DecryptNGRoundA(buffer, subKeys[1], g_ArxanTables[1]);
        for(int k = 2; k <= 15; k++)
            buffer = DecryptNGRoundB(buffer, subKeys[k], g_ArxanTables[k]);
        buffer = DecryptNGRoundA(buffer, subKeys[16], g_ArxanTables[16]);

        return buffer;
    }

    std::vector<uint8_t> DecryptNGRoundA(const std::vector<uint8_t>& data, const std::vector<uint32_t>& key, const std::array<std::array<uint32_t, 256>, 16>& table)
    {
        std::vector<uint8_t> result(16);
        uint32_t x1 =
            table[0][data[0]] ^
            table[1][data[1]] ^
            table[2][data[2]] ^
            table[3][data[3]] ^
            key[0];
        uint32_t x2 =
            table[4][data[4]] ^
            table[5][data[5]] ^
            table[6][data[6]] ^
            table[7][data[7]] ^
            key[1];
        uint32_t x3 =
            table[8][data[8]] ^
            table[9][data[9]] ^
            table[10][data[10]] ^
            table[11][data[11]] ^
            key[2];
        uint32_t x4 =
            table[12][data[12]] ^
            table[13][data[13]] ^
            table[14][data[14]] ^
            table[15][data[15]] ^
            key[3];

        memcpy(result.data(), &x1, 4);
        memcpy(result.data() + 4, &x2, 4);
        memcpy(result.data() + 8, &x3, 4);
        memcpy(result.data() + 12, &x4, 4);

        return result;
    }

    std::vector<uint8_t> DecryptNGRoundB(const std::vector<uint8_t>& data, const std::vector<uint32_t>& key, const std::array<std::array<uint32_t, 256>, 16>& table)
    {
        std::vector<uint8_t> result(16);
        uint32_t x1 =
            table[0][data[0]] ^
            table[7][data[7]] ^
            table[10][data[10]] ^
            table[13][data[13]] ^
            key[0];
        uint32_t x2 =
            table[1][data[1]] ^
            table[4][data[4]] ^
            table[11][data[11]] ^
            table[14][data[14]] ^
            key[1];
        uint32_t x3 =
            table[2][data[2]] ^
            table[5][data[5]] ^
            table[8][data[8]] ^
            table[15][data[15]] ^
            key[2];
        uint32_t x4 =
            table[3][data[3]] ^
            table[6][data[6]] ^
            table[9][data[9]] ^
            table[12][data[12]] ^
            key[3];

        result[0] = static_cast<uint8_t>((x1 >> 0) & 0xFF);
        result[1] = static_cast<uint8_t>((x1 >> 8) & 0xFF);
        result[2] = static_cast<uint8_t>((x1 >> 16) & 0xFF);
        result[3] = static_cast<uint8_t>((x1 >> 24) & 0xFF);
        result[4] = static_cast<uint8_t>((x2 >> 0) & 0xFF);
        result[5] = static_cast<uint8_t>((x2 >> 8) & 0xFF);
        result[6] = static_cast<uint8_t>((x2 >> 16) & 0xFF);
        result[7] = static_cast<uint8_t>((x2 >> 24) & 0xFF);
        result[8] = static_cast<uint8_t>((x3 >> 0) & 0xFF);
        result[9] = static_cast<uint8_t>((x3 >> 8) & 0xFF);
        result[10] = static_cast<uint8_t>((x3 >> 16) & 0xFF);
        result[11] = static_cast<uint8_t>((x3 >> 24) & 0xFF);
        result[12] = static_cast<uint8_t>((x4 >> 0) & 0xFF);
        result[13] = static_cast<uint8_t>((x4 >> 8) & 0xFF);
        result[14] = static_cast<uint8_t>((x4 >> 16) & 0xFF);
        result[15] = static_cast<uint8_t>((x4 >> 24) & 0xFF);

        return result;
    }
}