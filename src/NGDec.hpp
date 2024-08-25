#ifndef NG_DEC_HPP
#define NG_DEC_HPP

// Custom Arxan Decryption algo
// Uses same as RPF
// Original reimplementation: https://github.com/Neodymium146/gta-toolkit/blob/master/RageLib.GTA5/Cryptography/GTA5Encryption.cs

#include <cryptopp/aes.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>

namespace NG
{
    using ArxanKey = std::array<uint8_t, 272>;
    using ArxanRoundKey = std::array<uint32_t, 4>;
    using ArxanBlockResult = std::array<uint32_t, 4>;
    template<typename Iter>
    using ArxanBlock = std::ranges::subrange<Iter>;
    std::vector<uint8_t> DecryptNG(const std::vector<uint8_t>& data, const ArxanKey& key);
    void DecryptNGRaw(uint8_t* data, size_t size, const ArxanKey& key);

    class NGDecryptionTransformation : public CryptoPP::StreamTransformation
    {
    public:
        explicit NGDecryptionTransformation(const ArxanKey& key) : m_Key(key) {}
        size_t MinRetrievable() const { return 16; } // Block size
        void ProcessData(uint8_t* outString, const uint8_t* inString, size_t length) override;

        bool IsRandomAccess() const override
        {
            return false;
        }

        bool IsSelfInverting() const override
        {
            return true;
        }

        bool IsForwardTransformation() const override
        {
            return true;
        }

    private:
        ArxanKey m_Key;
    };
}

#endif