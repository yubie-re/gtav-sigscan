#include "Inc.hpp"
#include "Keys.hpp"
#include "NGDec.hpp"
#include "SigTypes.hpp"
#include <cpr/cpr.h>
#include <fmt/core.h>
#include <fmt/ranges.h>
#include <mutex>
#ifdef max
#undef max
#endif
#define RAPIDJSON_HAS_STDSTRING 1

#include "OldAnticheat.hpp"
#include "SigTypes.hpp"
#include <cstdint>
#include <cxxopts.hpp>
#include <rapidjson/document.h>
#include <rapidjson/rapidjson.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#define XOR_KEY 0xb7ac4b1c

namespace Old {

static int g_GameVersion = 0;

enum CheckType { DllName = 4,
    Rtma = 7,
    Integ = 8 };

enum DetectionAction {
    Metric = (1 << 0),
    P2PMetric = (1 << 1),
    Unk1 = (1 << 2),
    Kick = (1 << 3),
    Unk2 = (1 << 4),
    Bonus = (1 << 5),
    Crash = (1 << 6)
};

struct CheckBase {
    uint32_t m_Type;
    uint32_t m_Hash;
    uint32_t m_Size;
    uint8_t m_StartByte;
    uint32_t m_GameBuild;
    uint32_t m_XorConstant;
    uint32_t m_Flags;
};

struct MemCheckOld : CheckBase {
    uint32_t m_StartPage;
    uint32_t m_EndPage;
    uint32_t m_RegionSize;
};

struct NameCheck : CheckBase { };

uint32_t SafeGetUint(rapidjson::Value& value)
{
    return value.IsUint() ? value.GetUint()
                          : static_cast<uint32_t>(value.GetInt());
}

template <typename T>
void ParseBase(rapidjson::GenericArray<false, rapidjson::Value>& arr, T& data)
{
    data.m_Hash = SafeGetUint(arr[3]);
    data.m_XorConstant = XOR_KEY ^ data.m_Hash;
    data.m_StartByte = (data.m_XorConstant ^ SafeGetUint(arr[2])) >> 24 & 0xff;
    data.m_Flags = (data.m_XorConstant ^ SafeGetUint(arr[4])) >> 8;
    data.m_Size = (data.m_XorConstant ^ SafeGetUint(arr[2])) >> 18 & 0x3f;
    data.m_GameBuild = (data.m_XorConstant ^ SafeGetUint(arr[0])) & 0xffff;
    g_GameVersion = data.m_GameBuild;
}

MemCheckOld ParseMemCheck(rapidjson::GenericArray<false, rapidjson::Value>& arr,
    CheckType type)
{
    MemCheckOld data;
    ParseBase(arr, data);
    data.m_Type = type;
    data.m_StartPage = (data.m_XorConstant ^ SafeGetUint(arr[1])) & 0xffff;
    data.m_EndPage = (data.m_XorConstant ^ SafeGetUint(arr[1])) >> 16 & 0xffff;
    data.m_RegionSize = ((data.m_XorConstant ^ SafeGetUint(arr[2])) & 0x3ffff)
        << 10;
    return data;
}

NameCheck ParseNameCheck(rapidjson::GenericArray<false, rapidjson::Value>& arr)
{
    NameCheck data;
    ParseBase(arr, data);
    data.m_Type = CheckType::DllName;
    fmt::print("found a dll name check, pretty interesting\n");
    return data;
}

uint32_t GetType(rapidjson::GenericArray<false, rapidjson::Value>& arr)
{
    uint32_t hash = SafeGetUint(arr[3]);
    uint32_t xorConstant = XOR_KEY ^ hash;
    uint32_t rawValue = SafeGetUint(arr[0]) ^ xorConstant;
    return rawValue >> 24;
}

IntegSig ConvertIntegToNewFormat(MemCheckOld data)
{
    IntegSig result;
    result.m_FirstByte = data.m_StartByte;
    result.m_Hash = data.m_Hash;
    result.m_PageHigh = data.m_StartPage;
    result.m_PageLow = data.m_EndPage;
    result.m_Len = static_cast<uint8_t>(data.m_Size);
    return result;
}

RTMASig ConvertRtmaToNewFormat(MemCheckOld data)
{
    RTMASig result;
    result.m_FirstByte = data.m_StartByte;
    result.m_Hash = data.m_Hash;
    result.m_PageHigh = data.m_StartPage;
    result.m_PageLow = data.m_EndPage;
    result.m_Len = static_cast<uint8_t>(data.m_Size);
    result.m_ModuleSize = data.m_RegionSize;
    result.m_ProtFlags = data.m_Flags;
    return result;
}

DeserializationResult DeserializeJSON(rapidjson::Document& doc)
{

    if (!doc.HasMember("bonus"))
        return {};

    DeserializationResult result;

    for (auto& i : doc["bonus"].GetArray()) {
        rapidjson::GenericArray<false, rapidjson::Value> valueArray = i.GetArray();
        switch (GetType(valueArray)) {
        case CheckType::DllName:
            ParseNameCheck(valueArray);
            break;
        case CheckType::Integ:
            result.m_Integ.push_back(
                ConvertIntegToNewFormat(ParseMemCheck(valueArray, CheckType::Integ)));
            break;
        case CheckType::Rtma:
            result.m_Rtma.push_back(
                ConvertRtmaToNewFormat(ParseMemCheck(valueArray, CheckType::Rtma)));
            break;
        }
    }
    return result;
}

bool IsOld(rapidjson::Document& doc)
{
    return doc.HasMember("bonus");
}

uint32_t GetGameVersion() { return g_GameVersion; }
} // namespace Old