#ifndef SIG_TYPES_HPP
#define SIG_TYPES_HPP

#pragma pack(push, 1)

enum AnticheatID { ANTICHEAT_RTMA = 0x12, ANTICHEAT_INTEG = 0x92 };

class RTMASig {
public:
  uint8_t m_firstByte;   // 0x0000
  uint8_t m_len;         // 0x0001
  uint32_t m_pageLow;    // 0x0002
  uint32_t m_pageHigh;   // 0x0006
  uint32_t m_protFlags;  // 0x000A
  uint32_t m_moduleSize; // 0x000E
  uint32_t m_hash;       // 0x0012
  uint32_t m_unk1;       // 0x0016
  uint32_t m_unk2;       // 0x001A
  char pad_001E[2]; // 0x001E (Rockstar padding so it fits into 16 byte blocks
                    // for dec)
}; // Size: 0x0020

class IntegSig {
public:
  uint8_t m_firstByte; // 0x0000
  uint8_t m_len;       // 0x0001
  uint32_t m_pageLow;  // 0x0002
  uint32_t m_pageHigh; // 0x0006
  uint32_t m_hash;     // 0x000A
  uint32_t m_unk1;     // 0x000E
  uint32_t m_unk2;     // 0x0012
  char pad_0016[10]; // 0x0016 (Rockstar padding so it fits into 16 byte blocks
                     // for dec)
}; // Size: 0x0020

#pragma pack(pop)

static_assert(sizeof(IntegSig) == 0x20);
static_assert(sizeof(RTMASig) == 0x20);

#endif