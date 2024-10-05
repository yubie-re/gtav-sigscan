#ifndef OLD_AC
#define OLD_AC

#include "SigTypes.hpp"
#include <vector>

namespace Old {
struct DeserializationResult {
  std::vector<RTMASig> m_Rtma;
  std::vector<IntegSig> m_Integ;
};

DeserializationResult DeserializeJSON(rapidjson::Document& doc);
bool IsOld(rapidjson::Document& doc);
uint32_t GetGameVersion();
} // namespace Old

#endif