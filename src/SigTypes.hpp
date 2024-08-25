#ifndef SIG_TYPES_HPP
#define SIG_TYPES_HPP

#pragma pack(push, 1)

enum AnticheatID { ANTICHEAT_RTMA = 0x12, ANTICHEAT_INTEG = 0x92 };

class RTMASig {
public:
  uint8_t m_FirstByte;   // 0x0000
  uint8_t m_Len;         // 0x0001
  uint32_t m_PageLow;    // 0x0002
  uint32_t m_PageHigh;   // 0x0006
  uint32_t m_ProtFlags;  // 0x000A
  uint32_t m_ModuleSize; // 0x000E
  uint32_t m_Hash;       // 0x0012
  uint32_t m_Unk1;       // 0x0016
  uint32_t m_Unk2;       // 0x001A
private:
  char p_0016[2]; // 0x001E (Rockstar padding so it fits into 16 byte blocks
                    // for dec)
}; // Size: 0x0020

class IntegSig {
public:
  uint8_t m_FirstByte; // 0x0000
  uint8_t m_Len;       // 0x0001
  uint32_t m_PageLow;  // 0x0002
  uint32_t m_PageHigh; // 0x0006
  uint32_t m_Hash;     // 0x000A
  uint32_t m_Unk1;     // 0x000E
  uint32_t m_Unk2;     // 0x0012
private:
  char p_0016[10]; // 0x0016 (Rockstar padding so it fits into 16 byte blocks
                     // for dec)
}; // Size: 0x0020

#pragma pack(pop)

static_assert(sizeof(IntegSig) == 0x20);
static_assert(sizeof(RTMASig) == 0x20);

#endif