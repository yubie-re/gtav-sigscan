#include "inc.hpp"

#define XOR_KEY 0xB7AC4B1C

int rockstar_hash_func(uint8_t* input, size_t size, unsigned int key) // Some form of CRC?
{
    for(int i = 0; i < size; i++)
        key = ((uint32_t)(1025 * (input[i] + key)) >> 6) ^ (1025 * (input[i] + (uint32_t)key));
    return 0x8001 * (((uint32_t)(9 * key) >> 11) ^ (9 * key));
}

struct sig
{
    uint32_t m_hash;
    uint8_t m_start_byte;
    uint32_t m_start_page;
    uint32_t m_end_page;
    uint32_t m_protect_flag;
    uint32_t m_size;
    uint32_t m_unk;
    uint32_t m_report_id;
    uint32_t m_game_version;

    sig(std::vector<int32_t> data)
    {
        m_hash = data[3];
        auto xor_const = XOR_KEY ^ m_hash;
        m_start_byte = (xor_const ^ data[2]) >> 24 & 0xFF;
        m_start_page = (xor_const ^ data[1]) & 0xffff;
        m_end_page = (xor_const ^ data[1]) >> 16 & 0xffff;
        m_protect_flag =  (xor_const ^ data[3]) >> 8;
        m_size =  (xor_const ^ data[2]) >> 18 & 0x3F;
        m_unk = (xor_const ^ data[2]) & 0x3FFFF;
        m_report_id = (xor_const ^ data[0]);
        m_game_version = (m_hash ^ data[0]) & 0xFFFFFF ^ 0xAC4B1C ^ 0x70000;
    }

    uintptr_t scan(uint8_t* data, size_t size)
    {
        for (auto ptr = data; ptr < data + size - m_size; ptr++)
        {
            if (*ptr != m_start_byte)
                continue;
            if (rockstar_hash_func(ptr, m_size, 79764919) == m_hash)
                return (uintptr_t)ptr;
        }
        return 0;
    }
};

bool is_ascii(const std::string& s)
{
    return !std::any_of(s.begin(), s.end(), [](char c) { 
        return static_cast<unsigned char>(c) > 127; 
    });
}

rapidjson::Document download_tunables()
{
    cpr::Response r = cpr::Get(cpr::Url{"http://prod.cloud.rockstargames.com/titles/gta5/pcros/0x1a098062.json"});
    uint8_t key[] = { 0xf0, 0x6f, 0x12, 0xf4, 0x9b, 0x84, 0x3d, 0xad, 0xe4, 0xa7, 0xbe, 0x05, 0x35, 0x05, 0xb1, 0x9c, 0x9e, 0x41, 0x5c, 0x95, 0xd9, 0x37, 0x53, 0x45, 0x0a, 0x26, 0x91, 0x44, 0xd5, 0x9a, 0x01, 0x15 };
    AES aes(AESKeyLength::AES_256);
    auto crypted_chunk = r.text.size() - (r.text.size() % 16);
    auto out = aes.DecryptECB((uint8_t*)r.text.data(), (uint32_t)crypted_chunk, key);
    std::string j((char*)out, crypted_chunk);
    j += std::string(r.text.data() + crypted_chunk, (r.text.size() % 16));
    delete[] out;
    rapidjson::Document d;
    d.Parse(j);
    return d;
}

int safe_get_int(rapidjson::Value& value)
{
    return value.IsInt() ? value.GetInt() : value.GetUint();
}

void loop_bonus(rapidjson::Document& doc, uint8_t* data, size_t size, std::string filename)
{
    for(auto& bonus : doc["bonus"].GetArray())
    {
        auto values = bonus.GetArray();
        sig s({safe_get_int(values[0]), safe_get_int(values[1]), safe_get_int(values[2]), safe_get_int(values[3]), safe_get_int(values[4])});
        if(auto location = s.scan(data, size))
        {
            auto str = std::string((char*)location, s.m_size);
            if(is_ascii(str))
                printf("(%s) \"%s\" (%u) (v%d)\n", filename.c_str(), str.c_str(), s.m_size, s.m_game_version);
            else
            {
                printf("(%s) { ", filename.c_str());
                for (auto i = 0ull; i < s.m_size; i++)
                    printf("%02hhx ", str[i]);
                printf(" } (%u) (v%d)\n", s.m_size, s.m_game_version);
            }
        }
    }
}

int main()
{
    auto tunables = download_tunables();
    for (const auto& entry : std::filesystem::recursive_directory_iterator("./files/"))
    {
        std::ifstream i(entry.path(), std::ios::binary);
        std::vector<uint8_t> contents((std::istreambuf_iterator<char>(i)), std::istreambuf_iterator<char>());
        loop_bonus(tunables, contents.data(), contents.size(), entry.path().filename().string());
    }
    return 0;
}