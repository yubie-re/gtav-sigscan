#include "inc.hpp"
#define RAPIDJSON_HAS_STDSTRING 1
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/rapidjson.h>
#include <rapidjson/stringbuffer.h>
#include <fmt/core.h>
#include <fmt/ranges.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/base64.h>
#include <cpr/cpr.h>
#include <mutex>
#include "ngdec.hpp"

using namespace CryptoPP;

NG::ArxanKey g_decKey            = { 0xb1, 0x51, 0x81, 0x7b, 0xcc, 0xa7, 0xed, 0xae, 0x23, 0xa8, 0x6d, 0x03, 0x8b, 0x7e, 0x43, 0x2f, 0x5b, 0xc9, 0xfe, 0xe0, 0xe0, 0x50, 0xaa, 0x69, 0xc0, 0x78, 0x74, 0x72, 0xa2, 0x35, 0xda, 0xf3, 0x6c, 0x5d, 0x08, 0xb5, 0xdf, 0x81, 0x44, 0xfc, 0xbe, 0x36, 0xd5, 0xc7, 0xd5, 0x4e, 0x34, 0x54, 0xf5, 0x67, 0xab, 0x6e, 0xc4, 0x10, 0x4c, 0x1b, 0x40, 0x10, 0x98, 0x4c, 0xeb, 0x22, 0xa3, 0x4c, 0x26, 0x59, 0xa1, 0x11, 0x44, 0x42, 0x78, 0xd5, 0x4b, 0x49, 0x98, 0x22, 0xe6, 0xe8, 0xd1, 0xcd, 0xda, 0xd4, 0x74, 0x43, 0x34, 0x17, 0x07, 0x59, 0x4e, 0x01, 0xee, 0x83, 0x45, 0x71, 0x4b, 0x6e, 0x2c, 0xba, 0xeb, 0x29, 0xfe, 0x21, 0xc1, 0x4d, 0x4e, 0x3a, 0xaf, 0xa7, 0xd6, 0x9a, 0xcc, 0xe5, 0x1b, 0xba, 0x06, 0xc7, 0x5c, 0xdf, 0x69, 0x56, 0x0d, 0x40, 0x54, 0x0c, 0xef, 0x20, 0xb3, 0x7e, 0xa4, 0xd1, 0x83, 0x78, 0x81, 0x8d, 0x40, 0xf9, 0x39, 0x51, 0xf8, 0xe9, 0xc0, 0x47, 0x11, 0x36, 0x2c, 0x20, 0xdb, 0x91, 0xb3, 0x00, 0xc1, 0x13, 0xf2, 0xea, 0x74, 0xca, 0xda, 0x0f, 0x04, 0x51, 0xa7, 0x34, 0xeb, 0x3d, 0x68, 0x70, 0x2c, 0x70, 0x23, 0x19, 0xff, 0xa3, 0x36, 0x1b, 0x57, 0x5c, 0x5a, 0xdf, 0x54, 0x19, 0x7b, 0x75, 0xc3, 0xf5, 0xb0, 0x1e, 0x5d, 0xae, 0x2a, 0xb6, 0xf0, 0x7a, 0x24, 0x9b, 0xcc, 0x57, 0xce, 0xd1, 0x98, 0xce, 0xd4, 0xf0, 0xd7, 0xd8, 0x1d, 0x9e, 0x82, 0xef, 0x70, 0x16, 0xa4, 0xf8, 0x2c, 0x7c, 0x62, 0x99, 0xa3, 0xe9, 0x72, 0x4b, 0xa8, 0xfa, 0x65, 0x17, 0x91, 0x0e, 0x66, 0x5e, 0x76, 0xdb, 0xa2, 0x63, 0xbe, 0xdb, 0xb4, 0x5c, 0x68, 0x10, 0x6c, 0x8d, 0xe0, 0xac, 0x6e, 0x23, 0x8a, 0x2e, 0xe3, 0x19, 0x80, 0x8a, 0xee, 0xbb, 0xc7, 0xeb, 0x2f, 0xf9, 0x45, 0x73, 0x26, 0x12, 0x61, 0xf3, 0xb9, 0x08, 0x14, 0x0e, 0x0b, 0xc9, 0xa3, 0x15, 0x2f, 0x51 };
NG::ArxanKey g_integrityCheckKey = { 0xb1, 0x51, 0x81, 0x7b, 0xcc, 0xa7, 0xed, 0xae, 0x23, 0xa8, 0x6d, 0x03, 0x8b, 0x7e, 0x43, 0x2f, 0x9c, 0xa7, 0x06, 0x1a, 0xf8, 0xe9, 0x4e, 0x9c, 0x12, 0xf4, 0x42, 0xc5, 0x73, 0x5e, 0x3e, 0xb6, 0xaa, 0xba, 0xc8, 0xc3, 0xa9, 0x85, 0xe7, 0x78, 0xb8, 0x20, 0x99, 0x16, 0x39, 0xba, 0xfa, 0x6e, 0xd4, 0x5c, 0xd6, 0x8a, 0xf7, 0xef, 0x66, 0x85, 0x23, 0x20, 0xfe, 0x4b, 0x6f, 0x61, 0xe7, 0xb2, 0xbd, 0xed, 0x1d, 0xcf, 0xf4, 0xa1, 0x1b, 0x27, 0x3b, 0x5b, 0x77, 0x77, 0x0c, 0x0a, 0x53, 0x26, 0x15, 0x47, 0x37, 0x35, 0x26, 0xd3, 0x50, 0x23, 0x1e, 0xce, 0xa2, 0x1a, 0xa2, 0x02, 0x69, 0x97, 0xd4, 0x0f, 0x40, 0x81, 0xd5, 0x76, 0x1e, 0x61, 0x8e, 0xcb, 0x23, 0x00, 0x4c, 0x6a, 0xa1, 0x5b, 0x26, 0x63, 0xf0, 0x34, 0x81, 0x88, 0x7d, 0x5a, 0x4f, 0x4b, 0x4f, 0xef, 0x58, 0x9c, 0xdd, 0x1e, 0x88, 0x66, 0x41, 0x8d, 0x52, 0x6f, 0x34, 0x7d, 0xd2, 0xf7, 0xab, 0x62, 0x9a, 0x46, 0xf0, 0x2f, 0x6f, 0x50, 0x42, 0x98, 0x53, 0x8e, 0x23, 0xec, 0x6d, 0xb6, 0x7b, 0x25, 0x2f, 0xb8, 0x71, 0xd2, 0x7e, 0x8c, 0x34, 0x54, 0x97, 0x25, 0x9a, 0x01, 0x1b, 0x5d, 0xd8, 0xac, 0x87, 0xbc, 0xe5, 0xce, 0x5b, 0xc9, 0x62, 0x60, 0xd8, 0x8b, 0xb8, 0x03, 0xcf, 0xcc, 0xb0, 0xbe, 0x40, 0x5d, 0x8a, 0x16, 0x7a, 0xd7, 0x48, 0x50, 0xe8, 0x3c, 0xf1, 0xd6, 0x13, 0xe1, 0x46, 0xa6, 0x94, 0x7d, 0x17, 0x72, 0x09, 0x24, 0xb8, 0x29, 0x8e, 0x94, 0x2f, 0x16, 0x7f, 0xc5, 0xe4, 0xad, 0xbd, 0xc3, 0xf2, 0x6b, 0x8c, 0x84, 0xd9, 0x1c, 0x0e, 0x7a, 0x4f, 0x7c, 0x5f, 0x27, 0x4c, 0x3a, 0x26, 0xe2, 0x68, 0x6e, 0xe0, 0xac, 0x6e, 0x23, 0x8a, 0x2e, 0xe3, 0x19, 0x80, 0x8a, 0xee, 0xbb, 0xc7, 0xeb, 0x2f, 0xf9, 0x6f, 0x51, 0x8c, 0x9e, 0x9f, 0xa6, 0x63, 0x06, 0x00, 0x18, 0xa1, 0x9b, 0xf6, 0xcf, 0x24, 0x3f };
NG::ArxanKey g_rtmaKey           = { 0xb1, 0x51, 0x81, 0x7b, 0xcc, 0xa7, 0xed, 0xae, 0x23, 0xa8, 0x6d, 0x03, 0x8b, 0x7e, 0x43, 0x2f, 0x1c, 0xd0, 0x36, 0x00, 0xb0, 0x49, 0xfc, 0xd1, 0xa7, 0xc4, 0x01, 0xe0, 0x86, 0x0f, 0x08, 0x64, 0xa2, 0xf1, 0x9b, 0x0f, 0x40, 0xdd, 0xf9, 0xda, 0x27, 0x3d, 0x73, 0x98, 0x7d, 0xdc, 0xc9, 0xa2, 0xb5, 0xe2, 0xec, 0x79, 0x81, 0xec, 0x72, 0x22, 0x7c, 0x10, 0xa6, 0x8c, 0x4e, 0xd3, 0x76, 0x95, 0x40, 0xa9, 0x1f, 0x45, 0x15, 0xb2, 0x56, 0x49, 0x4d, 0x1e, 0x83, 0x5b, 0xd7, 0x71, 0x8a, 0x64, 0x02, 0x61, 0x3d, 0x51, 0x31, 0x6e, 0x7e, 0x77, 0x37, 0xfd, 0xee, 0x7a, 0xdc, 0x80, 0xa0, 0x77, 0xff, 0xb3, 0x74, 0x60, 0xc9, 0x21, 0x51, 0x85, 0x19, 0x9d, 0x9a, 0x42, 0xe1, 0x54, 0x8c, 0x35, 0xd4, 0xa5, 0x2a, 0x68, 0x81, 0x13, 0x59, 0x6a, 0x71, 0xc5, 0x2d, 0xdb, 0x0f, 0x2d, 0x58, 0x9e, 0x27, 0x76, 0x71, 0x28, 0x65, 0x84, 0x4f, 0x78, 0x59, 0xf6, 0x5d, 0xc4, 0xa0, 0x2e, 0x64, 0x03, 0x7d, 0xf5, 0xf4, 0xcc, 0xa1, 0xd3, 0xdd, 0x80, 0x53, 0xa3, 0x3d, 0x21, 0x46, 0x87, 0x96, 0x66, 0xbe, 0x45, 0xd3, 0xb5, 0x0f, 0xde, 0xd1, 0xa1, 0xa7, 0xb7, 0x55, 0x0f, 0x36, 0xd5, 0x87, 0x44, 0xc4, 0x67, 0xaf, 0xa7, 0x38, 0x73, 0xf0, 0x3b, 0x03, 0x84, 0x08, 0xd6, 0x17, 0x77, 0x2b, 0xa6, 0x57, 0x5e, 0x14, 0x55, 0xb0, 0x0e, 0x5d, 0x97, 0x37, 0xf0, 0x80, 0xa5, 0x99, 0xfe, 0xf8, 0x5b, 0xd7, 0x42, 0x88, 0xb0, 0xf1, 0xc2, 0xaa, 0xe9, 0x53, 0x75, 0x14, 0xfd, 0x26, 0xa1, 0xeb, 0xb3, 0xf3, 0x42, 0x0f, 0xe3, 0x7b, 0xc1, 0xbf, 0x38, 0x23, 0x04, 0x26, 0x78, 0x0f, 0x70, 0x41, 0x44, 0xe0, 0xac, 0x6e, 0x23, 0x8a, 0x2e, 0xe3, 0x19, 0x80, 0x8a, 0xee, 0xbb, 0xc7, 0xeb, 0x2f, 0xf9, 0x00, 0x5c, 0xb3, 0x08, 0xdf, 0xd4, 0xdd, 0xfa, 0x34, 0xa6, 0x83, 0xb3, 0x49, 0x9b, 0xd5, 0x6f };

#define THR_COUNT 24

struct ScanJob
{
    uint8_t m_firstByte;
    uint8_t m_len;
    uint32_t m_hash;
};

enum AnticheatID
{
    ANTICHEAT_RTMA = 0x12,
    ANTICHEAT_INTEG = 0x92
};

#pragma pack(push, 1)

class RTMASig
{
public:
	uint8_t m_firstByte; //0x0000
	uint8_t m_len; //0x0001
	uint32_t m_pageLow; //0x0002
	uint32_t m_pageHigh; //0x0006
	uint32_t m_protFlags; //0x000A
	uint32_t m_moduleSize; //0x000E
	uint32_t m_hash; //0x0012
	uint32_t m_unk1; //0x0016
	uint32_t m_unk2; //0x001A
	char pad_001E[2]; //0x001E (Rockstar padding so it fits into 16 byte blocks for dec)
}; //Size: 0x0020

class IntegSig
{
public:
	uint8_t m_firstByte; //0x0000
	uint8_t m_len; //0x0001
	uint32_t m_pageLow; //0x0002
	uint32_t m_pageHigh; //0x0006
	uint32_t m_hash; //0x000A
	uint32_t m_unk1; //0x000E
	uint32_t m_unk2; //0x0012
	char pad_0016[10]; //0x0016 (Rockstar padding so it fits into 16 byte blocks for dec)
}; //Size: 0x0020

#pragma pack(pop)

static_assert(sizeof(IntegSig) == 0x20);
static_assert(sizeof(RTMASig) == 0x20);

std::vector<RTMASig> g_rtmaSigs;
std::array<std::thread, THR_COUNT> g_workers;
std::vector<IntegSig> g_integrityChecks;
std::unordered_map<uint32_t, std::string> g_hashMap;
std::recursive_mutex g_insertionMutex;
std::recursive_mutex g_jobMutex;
std::vector<std::thread> g_openThreads;
std::vector<std::vector<uint8_t>> g_loadedFiles; // contains file contents
std::vector<std::filesystem::path> g_loadedFilePaths; // contains file contents
std::queue<std::pair<size_t, RTMASig>> g_rtmaJobs; // index in g_LoadedFiles, sig
std::queue<std::pair<size_t, IntegSig>> g_integJobs; // index in g_LoadedFiles, sig


std::string DownloadTunables()
{
    cpr::Response r = cpr::Get(cpr::Url{ "http://prod.cloud.rockstargames.com/titles/gta5/pcros/0x1a098062.json" });
    uint8_t key[] = { 0xf0, 0x6f, 0x12, 0xf4, 0x9b, 0x84, 0x3d, 0xad, 0xe4, 0xa7, 0xbe, 0x05, 0x35, 0x05, 0xb1, 0x9c, 0x9e, 0x41, 0x5c, 0x95, 0xd9, 0x37, 0x53, 0x45, 0x0a, 0x26, 0x91, 0x44, 0xd5, 0x9a, 0x01, 0x15 };
    ECB_Mode<AES>::Decryption e;
    e.SetKey(key, 32);
    ArraySource(reinterpret_cast<uint8_t*>(r.text.data()), r.text.size() - (r.text.size() % 16), true,
        new StreamTransformationFilter(e,
        new ArraySink(reinterpret_cast<uint8_t*>(r.text.data()), r.text.size() - (r.text.size() % 16)),
        BlockPaddingSchemeDef::NO_PADDING)
    );
    return r.text;
}

std::vector<uint8_t> DecodeString(const std::string& data)
{
    std::vector<uint8_t> out;
    StringSource(data, true,
        new Base64Decoder(new VectorSink(out))
    );
    return out;
}

std::vector<uint8_t> GetAnticheatData()
{
    std::string data = DownloadTunables();
    rapidjson::Document d;
    d.Parse(data);

    if(!d.HasMember("tunables"))
        return {};
    if(!d["tunables"].HasMember("8B7D3320"))
        return {};
    if(!d["tunables"]["8B7D3320"].IsArray())
        return {};
    if(!d["tunables"]["8B7D3320"][0].HasMember("value"))
        return {};

    return DecodeString(d["tunables"]["8B7D3320"][0]["value"].GetString());
}

uint32_t FNV1a(const uint8_t* input, const uint32_t size)
{
    uint32_t hash = 0x811C9DC5;
    for(uint32_t i = 0; i < size; i++)
    {
        hash = 0x1000193 * (input[i] ^ hash);
    }
    return hash;
}

size_t ScanBuffer(const std::vector<uint8_t>& data, const ScanJob&& sig)
{
    for(size_t off = 0; off < data.size() - sig.m_len; off++)
    {
        if(data[off] != sig.m_firstByte)
            continue;
        if(FNV1a(data.data() + off, sig.m_len) == sig.m_hash)
        {
            return off;
        }
    }
    return 0;
}

template<typename T, typename T2 = uint8_t>
bool IsAscii(std::ranges::subrange<T>&& view)
{
    return !std::ranges::any_of(view, [](T2 c) { return c > 127; });
}

void ProcessRTMA(std::vector<uint8_t>& data, std::filesystem::path filePath, RTMASig& signature)
{
    if(data.size() < signature.m_len)
        return;
    if(size_t location = ScanBuffer(data, ScanJob({signature.m_firstByte, signature.m_len, signature.m_hash})))
    {
        std::lock_guard<std::recursive_mutex> guard(g_insertionMutex);
        if(IsAscii(std::ranges::subrange(data.begin() + location, data.begin() + location + signature.m_len)))
        {
            g_hashMap[signature.m_hash] = std::string(reinterpret_cast<const char*>(data.data()) + location, signature.m_len);
            fmt::print("[RTMA] ({}) (~{:.2f}kb) ({:x}-{:x}) \"{}\" ({:d})\n", filePath.filename().string(), (signature.m_moduleSize * 4096) / 1000.f, signature.m_pageLow * 4096, signature.m_pageHigh * 4096, g_hashMap[signature.m_hash], signature.m_len);
        }
        else
        {
            std::string out = "(Hex) { ";
            fmt::print("[RTMA] ({}) (~{:.2f}kb) ({:x}-{:x}) ", filePath.filename().string(), (signature.m_moduleSize * 4096) / 1000.f, signature.m_pageLow * 4096, signature.m_pageHigh * 4096);
            for(size_t i = location; i < location + signature.m_len; i++)
            {
                out += fmt::format("{:02x} ", data[i]);
            }
            out += fmt::format("}}", signature.m_len);
            g_hashMap[signature.m_hash] = out;
            fmt::print("{} ({:d})\n", out, signature.m_len);
        }
    }
}

void ProcessInteg(std::vector<uint8_t>& data, std::filesystem::path filePath, IntegSig& signature)
{
    if(data.size() < signature.m_len)
            return;
    if(size_t location = ScanBuffer(data, ScanJob({signature.m_firstByte, signature.m_len, signature.m_hash})))
    {
        std::lock_guard<std::recursive_mutex> guard(g_insertionMutex);
        if(IsAscii(std::ranges::subrange(data.begin() + location, data.begin() + location + signature.m_len)))
        {
            g_hashMap[signature.m_hash] = std::string(reinterpret_cast<const char*>(data.data()) + location, signature.m_len);
            fmt::print("[IntegrityCheck] ({}) ({:x}-{:x}) \"{}\" ({:d})\n", filePath.filename().string(), signature.m_pageLow * 4096, signature.m_pageHigh * 4096, g_hashMap[signature.m_hash], signature.m_len);
        }
        else
        {
            std::string out = "(Hex) { ";
            fmt::print("[IntegrityCheck] ({}) ({:x}-{:x}) ", filePath.filename().string(), signature.m_pageLow * 4096, signature.m_pageHigh * 4096);
            for(size_t i = location; i < location + signature.m_len; i++)
            {
                out += fmt::format("{:02x} ", data[i]);
            }
            out += fmt::format("}}", signature.m_len);
            g_hashMap[signature.m_hash] = out;
            fmt::print("{} ({:d})\n", out, signature.m_len);
        }
    }
}


void WorkerThread()
{
    while(true)
    {
        g_jobMutex.lock();
        if(!g_rtmaJobs.empty())
        {
            std::pair<size_t, RTMASig> job = g_rtmaJobs.front();
            g_rtmaJobs.pop();
            g_jobMutex.unlock();
            std::vector<uint8_t>& file = g_loadedFiles[job.first];
            std::filesystem::path path = g_loadedFilePaths[job.first];
            ProcessRTMA(file, path, job.second);
        }
        else
            g_jobMutex.unlock();
        g_jobMutex.lock();
        if(!g_integJobs.empty())
        {
            std::pair<size_t, IntegSig> job = g_integJobs.front();
            g_integJobs.pop();
            g_jobMutex.unlock();
            std::vector<uint8_t>& file = g_loadedFiles[job.first];
            std::filesystem::path path = g_loadedFilePaths[job.first];
            ProcessInteg(file, path, job.second);
        }
        else
            g_jobMutex.unlock();
        g_jobMutex.lock();
        if(g_integJobs.empty() && g_rtmaJobs.empty())
        {
            g_jobMutex.unlock();
            break;
        }
        g_jobMutex.unlock();
        std::this_thread::yield();
    }
}

void LoadFile(std::filesystem::path p)
{
    std::ifstream i(p, std::ios::binary);
    i.seekg(0, std::ios::end);
    std::streamsize size = i.tellg();
    i.seekg(0, std::ios::beg);
    if(size <= 10)
        return;
    std::vector<uint8_t> contents(size);
    i.read(reinterpret_cast<char*>(contents.data()), size);
    g_loadedFiles.push_back(std::move(contents));
    g_loadedFilePaths.push_back(p);
    size_t index = g_loadedFiles.size() - 1;
    for(RTMASig& sig : g_rtmaSigs)
    {
        g_rtmaJobs.push(std::make_pair(index, sig));
    }
    for(IntegSig& sig : g_integrityChecks)
    {
        g_integJobs.push(std::make_pair(index, sig));
    }
}

void LoadAllFiles(std::filesystem::path p)
{
    for(const std::filesystem::directory_entry& entry : std::filesystem::recursive_directory_iterator("./files/"))
        LoadFile(entry);
    fmt::print("Loaded files.\n");
}

void QueueWorkers()
{
    for(int i = 0; i < THR_COUNT; i++)
    {
        g_workers[i] = std::thread(WorkerThread);
    }

    for(auto& thread : g_workers)
    {
        if(thread.joinable())
            thread.join();
    }
}

void ProcessSigs(const std::vector<uint8_t>& acData)
{
    for(int i = 8; i + 0x21 < acData.size(); i += 0x20)
    {
        switch(acData[i++])
        {
            case ANTICHEAT_RTMA:
            {
                RTMASig rtma;
                NG::NGDecryptionTransformation transform(g_rtmaKey);
                ArraySource(acData.data() + i, 0x20, true,
                    new StreamTransformationFilter(transform,
                    new ArraySink(reinterpret_cast<uint8_t*>(&rtma), sizeof(rtma)))
                );
                g_rtmaSigs.push_back(rtma);
                break;
            }
            case ANTICHEAT_INTEG:
            {
                IntegSig integ;
                NG::NGDecryptionTransformation transform(g_integrityCheckKey);
                ArraySource(acData.data() + i, 0x20, true,
                    new StreamTransformationFilter(transform,
                    new ArraySink(reinterpret_cast<uint8_t*>(&integ), sizeof(integ)))
                );
                g_integrityChecks.push_back(integ);
                break;
            }
            default:
            {
                fmt::print("Unknown sig type!\n");
                return;
            }
        }
    }
}

void PrintSigs()
{
    for(const RTMASig& sig : g_rtmaSigs)
    {
        fmt::print("RTMA {:2x} {:2x} {:8x} {:8x} {:8x} {:8x} {:8x} {:8x}\n", sig.m_firstByte, sig.m_len, sig.m_pageLow, sig.m_pageHigh, sig.m_protFlags, sig.m_moduleSize, sig.m_unk1, sig.m_unk2);
    }

    for(const IntegSig& sig : g_integrityChecks) // These will scan in the GTA Dump.
    {
        fmt::print("Integ {:2x} {:2x} {:8x} {:8x} {:8x} {:8x}\n", sig.m_firstByte, sig.m_len, sig.m_pageLow, sig.m_pageHigh, sig.m_unk1, sig.m_unk2);
    }
}

std::string SerializeJSON(int build)
{
    rapidjson::Document doc;
    doc.SetObject();
    auto& alc = doc.GetAllocator();
    rapidjson::Value rtmaArray;
    rapidjson::Value integArray;
    rtmaArray.SetArray();
    integArray.SetArray();

    for(const RTMASig& sig : g_rtmaSigs)
    {
        rapidjson::Value obj;
        obj.SetObject();
        obj.AddMember("m_firstByte", sig.m_firstByte, alc);
        obj.AddMember("m_len", sig.m_len, alc);
        obj.AddMember("m_hash", sig.m_hash, alc);
        obj.AddMember("m_pageLow", sig.m_pageLow, alc);
        obj.AddMember("m_pageHigh", sig.m_pageHigh, alc);
        obj.AddMember("m_protFlags", sig.m_protFlags, alc);
        obj.AddMember("m_moduleSize", sig.m_moduleSize, alc);
        obj.AddMember("m_unk1", sig.m_unk1, alc);
        obj.AddMember("m_unk2", sig.m_unk2, alc);
        obj.AddMember("time", time(0), alc);
        obj.AddMember("build", build, alc);
        if(g_hashMap.contains(sig.m_hash))
            obj.AddMember("translation", g_hashMap[sig.m_hash], alc);
        rtmaArray.PushBack(obj, alc);
    }

    for(const IntegSig& sig : g_integrityChecks) // These will scan in the GTA Dump.
    {
        rapidjson::Value obj;
        obj.SetObject();
        obj.AddMember("m_firstByte", sig.m_firstByte, alc);
        obj.AddMember("m_len", sig.m_len, alc);
        obj.AddMember("m_hash", sig.m_hash, alc);
        obj.AddMember("m_pageLow", sig.m_pageLow, alc);
        obj.AddMember("m_pageHigh", sig.m_pageHigh, alc);
        obj.AddMember("m_unk1", sig.m_unk1, alc);
        obj.AddMember("m_unk2", sig.m_unk2, alc);
        obj.AddMember("time", time(0), alc);
        obj.AddMember("build", build, alc);
        if(g_hashMap.contains(sig.m_hash))
            obj.AddMember("translation", g_hashMap[sig.m_hash], alc);
        integArray.PushBack(obj, alc);
    }

    doc.AddMember("RTMA", rtmaArray, alc);
    doc.AddMember("INTG", integArray, alc);

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    doc.Accept(writer);

    return std::string(buffer.GetString(), buffer.GetSize());
}

void DeserializeJSON(const std::string& json)
{
    g_rtmaSigs.clear();
    g_integrityChecks.clear();
    rapidjson::Document doc;
    doc.Parse(json);
    for(rapidjson::Value& val : doc["RTMA"].GetArray())
    {
        RTMASig sig {};
        sig.m_firstByte = static_cast<uint8_t>(val["m_firstByte"].GetUint());
        sig.m_len = static_cast<uint8_t>(val["m_len"].GetUint());
        sig.m_hash = val["m_hash"].GetUint();
        sig.m_pageLow = val["m_pageLow"].GetUint();
        sig.m_pageHigh = val["m_pageHigh"].GetUint();
        sig.m_protFlags = val["m_protFlags"].GetUint();
        sig.m_moduleSize = val["m_moduleSize"].GetUint();
        sig.m_unk1 = val["m_unk1"].GetUint();
        sig.m_unk2 = val["m_unk2"].GetUint();
        g_rtmaSigs.push_back(sig);
    }
    for(rapidjson::Value& val : doc["INTG"].GetArray())
    {
        IntegSig sig {};
        sig.m_firstByte = static_cast<uint8_t>(val["m_firstByte"].GetInt());
        sig.m_len = static_cast<uint8_t>(val["m_len"].GetInt());
        sig.m_hash = val["m_hash"].GetUint();
        sig.m_pageLow = val["m_pageLow"].GetUint();
        sig.m_pageHigh = val["m_pageHigh"].GetUint();
        sig.m_unk1 = val["m_unk1"].GetUint();
        sig.m_unk2 = val["m_unk2"].GetUint();
        g_integrityChecks.push_back(sig);
    }
}

int main(int argc, const char* args[])
{
    std::filesystem::create_directories("./files/");
    std::vector<uint8_t> data = GetAnticheatData();
    if(data.empty() || data.size() < 8)
    {
        fmt::print("Download failed\n");
        return 0;
    }

    NG::NGDecryptionTransformation decTransformation(g_decKey);
    VectorSource(data, true,
        new StreamTransformationFilter(decTransformation,
        new ArraySink(data.data(), data.size()))
    );

    ProcessSigs(data);
    //PrintSigs();

    fmt::print("Game build: {}\n", *reinterpret_cast<uint32_t*>(data.data()));
    fmt::print("{} sigs loaded\n", g_rtmaSigs.size() + g_integrityChecks.size());

    if(argc == 1)
    {
        LoadAllFiles("./files/");
        QueueWorkers();
    }
    else if (argc >= 2)
    {
        if(!strcmp(args[1], "-savejson"))
        {
            LoadAllFiles("./files/");
            QueueWorkers();
            std::ofstream f("./signatures.json");
            f << SerializeJSON(*reinterpret_cast<uint32_t*>(data.data())) << std::flush;
            return 0;
        }
        else if (argc == 3 && !strcmp(args[1], "-loadjson"))
        {
           std::ifstream f(args[2]);
           std::string j;
           f >> j;
           DeserializeJSON(j);
           LoadAllFiles("./files/");
           QueueWorkers();
        }
        else
        {
            LoadFile(args[1]);
            QueueWorkers();
        }
    }

    return 0;
}