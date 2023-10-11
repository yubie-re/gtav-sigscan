#ifndef INC_HPP
#define INC_HPP

#include <iostream>
#include <filesystem>
#include <unordered_set>
#include <cstdint> 
#include <unordered_map>
#include <cstring>
#include <vector>
#include <fstream>
#include <iostream>
#include <array>
#include <cpr/cpr.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/base64.h>
#include <fmt/core.h>
#include <fmt/ranges.h>
#undef max
#define RAPIDJSON_HAS_STDSTRING 1
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>

#ifndef PAGE_NOACCESS  // Credits to @melvyn2, this is for cross platform compilation
#define PAGE_NOACCESS 0x01
#define PAGE_READONLY 0x02
#define PAGE_READWRITE 0x04
#define PAGE_WRITECOPY 0x08
#define PAGE_EXECUTE 0x10
#define PAGE_EXECUTE_READ 0x20
#define PAGE_EXECUTE_READWRITE 0x40
#define PAGE_EXECUTE_WRITECOPY 0x80
#define PAGE_GUARD 0x100
#define PAGE_NOCACHE 0x200
#define PAGE_WRITECOMBINE 0x400
#define PAGE_GRAPHICS_NOACCESS 0x0800
#define PAGE_GRAPHICS_READONLY 0x1000
#define PAGE_GRAPHICS_READWRITE 0x2000
#define PAGE_GRAPHICS_EXECUTE 0x4000
#define PAGE_GRAPHICS_EXECUTE_READ 0x8000
#define PAGE_GRAPHICS_EXECUTE_READWRITE 0x10000
#define PAGE_GRAPHICS_COHERENT 0x20000
#define PAGE_ENCLAVE_THREAD_CONTROL 0x80000000
#define PAGE_REVERT_TO_FILE_MAP 0x80000000
#define PAGE_TARGETS_NO_UPDATE 0x40000000
#define PAGE_TARGETS_INVALID 0x40000000
#define PAGE_ENCLAVE_UNVALIDATED 0x20000000
#define PAGE_ENCLAVE_DECOMMIT 0x10000000
#endif

#endif