#ifndef NG_DEC_HPP
#define NG_DEC_HPP

// Custom Arxan Decryption algo
// Uses same as RPF
// Original reimplementation: https://github.com/Neodymium146/gta-toolkit/blob/master/RageLib.GTA5/Cryptography/GTA5Encryption.cs

namespace NG
{
    using ArxanKey = std::array<uint8_t, 272>;
    std::vector<uint8_t> DecryptNG(const std::vector<uint8_t>& data, const ArxanKey& key);
    void DecryptNGRaw(uint8_t* data, size_t size, const ArxanKey& key);

    class NGDecryptionTransformation : public CryptoPP::StreamTransformation
    {
    public:
        explicit NGDecryptionTransformation(const ArxanKey& key) : m_key(key) {}
        size_t MinRetrievable() const { return 16; } // Block size
        void ProcessData(byte* outString, const byte* inString, size_t length) override;

        bool IsRandomAccess() const
        {
            return false;
        }

        bool IsSelfInverting() const
        {
            return true;
        }

        bool IsForwardTransformation() const
        {
            return true;
        }

    private:
        ArxanKey m_key;
    };
}

#endif