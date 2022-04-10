#include "inc.hpp"

#define XOR_KEY 0xb7ac4b1c

// "a modified JOAAT that is initialized with the CRC-32 polynomial."  - pelecanidae
uint32_t sig_joaat(uint8_t *input, uint32_t size)
{
    uint32_t hash = 0x4c11db7;
    for (uint32_t i = 0; i < size; i++)
    {
        hash += input[i];
        hash += hash << 10;
        hash ^= hash >> 6;
    }
    hash += hash << 3;
    hash ^= hash >> 11;
    hash += hash << 15;
    return hash;
}

struct sig
{
    uint32_t m_hash;
    uint8_t m_start_byte;
    uint32_t m_start_page;
    uint32_t m_end_page;
    uint32_t m_protect_flag;
    uint32_t m_size;
    uint32_t m_region_size_estimate;
    uint32_t m_game_version;

    sig(std::vector<uint32_t> data)
    {
        m_hash = data[3]; // joaat hash of scan
        auto xor_const = XOR_KEY ^ m_hash; // used for decryption of values
        m_start_byte = (xor_const ^ data[2]) >> 24 & 0xff; // starting byte of scan
        m_start_page = (xor_const ^ data[1]) & 0xffff; // start page of scan (base_address + 4096 * a1->start_page)
        m_end_page = (xor_const ^ data[1]) >> 16 & 0xffff; // end page of scan (base_address + 4096 * a1->start_page)
        m_protect_flag = (xor_const ^ data[4]) >> 8; // protection flag of scanned region, usually PAGE_READONLY or PAGE_EXECUTE_READWRITE, if different it won't scan
        m_size = (xor_const ^ data[2]) >> 18 & 0x3f; // length of scanned string or bytes
        m_region_size_estimate = ((xor_const ^ data[2]) & 0x3ffff) << 10; // region_size > m_region_size_estimate * 0.9 && region_size < m_region_size_estimate * 1.1, otherwise scan doesn't run.
        m_game_version = (xor_const ^ data[0]) & 0xffff; // game version when scan was added, if game version differs scan will not run
    }

    uint8_t *scan(uint8_t *data, size_t size)
    {
        for (auto ptr = data; ptr < data + size - m_size; ptr++)
        {
            if (*ptr != m_start_byte)
                continue;
            if (sig_joaat(ptr, m_size) == m_hash)
                return ptr;
        }
        return 0;
    }
};

bool is_ascii(uint8_t *start, uint32_t size)
{
    return !std::any_of(start, start + size, [](uint8_t c)
                        { return c > 127; });
}

uint32_t safe_get_uint(rapidjson::Value &value)
{
    return value.IsUint() ? value.GetUint() : value.GetInt();
}

rapidjson::Document download_tunables()
{
    cpr::Response r = cpr::Get(cpr::Url{"http://prod.cloud.rockstargames.com/titles/gta5/pcros/0x1a098062.json"});
    uint8_t key[] = {0xf0, 0x6f, 0x12, 0xf4, 0x9b, 0x84, 0x3d, 0xad, 0xe4, 0xa7, 0xbe, 0x05, 0x35, 0x05, 0xb1, 0x9c, 0x9e, 0x41, 0x5c, 0x95, 0xd9, 0x37, 0x53, 0x45, 0x0a, 0x26, 0x91, 0x44, 0xd5, 0x9a, 0x01, 0x15};
    AES aes(AESKeyLength::AES_256);
    auto crypted_chunk = r.text.size() - (r.text.size() % 16);
    auto out = aes.DecryptECB((uint8_t *)r.text.data(), (uint32_t)crypted_chunk, key);
    std::string j((char *)out, crypted_chunk);
    j += std::string(r.text.data() + crypted_chunk, (r.text.size() % 16));
    delete[] out;
    rapidjson::Document d;
    d.Parse(j);
    return d;
}

void loop_bonus(rapidjson::Document &doc, uint8_t *data, size_t size, std::string filename)
{
    for (auto &bonus : doc["bonus"].GetArray())
    {
        auto values = bonus.GetArray();
        sig s({safe_get_uint(values[0]), safe_get_uint(values[1]), safe_get_uint(values[2]), safe_get_uint(values[3]), safe_get_uint(values[4])});
        if(s.m_game_version != 2545)
             continue;
        if (auto location = s.scan(data, size))
        {
            if (is_ascii(location, s.m_size))
                printf("(%s) \"%.*s\" (%u) (v%d) (%s) (~%.3f kb region)\n", filename.c_str(), s.m_size, location, s.m_size, s.m_game_version, s.m_protect_flag == PAGE_READONLY ? "PAGE_READONLY" : "PAGE_EXECUTE_READWRITE", s.m_region_size_estimate / 1000.0);
            else
            {
                printf("(%s) { ", filename.c_str());
                for (auto i = 0ull; i < s.m_size; i++)
                    printf("%02hhx ", location[i]);
                printf("} (%u) (v%d) (%s) (~%.3f kb region)\n", s.m_size, s.m_game_version, s.m_protect_flag == PAGE_READONLY ? "PAGE_READONLY" : "PAGE_EXECUTE_READWRITE", s.m_region_size_estimate / 1000.0);
            }
        }
    }
}

int main()
{
    auto tunables = download_tunables();
    view_sigs(tunables);
    for (const auto &entry : std::filesystem::recursive_directory_iterator("./files/"))
    {
        std::ifstream i(entry.path(), std::ios::binary);
        std::vector<uint8_t> contents((std::istreambuf_iterator<char>(i)), std::istreambuf_iterator<char>());
        loop_bonus(tunables, contents.data(), contents.size(), entry.path().filename().string());
    }
    return 0;
}