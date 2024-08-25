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
#include <cxxopts.hpp>
#include <rapidjson/document.h>
#include <rapidjson/rapidjson.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

using namespace CryptoPP;

#define THR_COUNT 24

struct ScanJob {
  uint8_t m_firstByte;
  uint8_t m_len;
  uint32_t m_hash;
};

// Disables output of signatures to console
bool g_Silent;
// vector of all memory signatures in tunable file
std::vector<RTMASig> g_RTMASigs;
// vector of all integrity checks in tunable file
std::vector<IntegSig> g_IntegrityChecks;
// array of threads used for finding sigs
std::array<std::thread, THR_COUNT> g_Workers;
// contains found hash translations
std::unordered_map<uint32_t, std::string> g_HashTranslationMap;
std::recursive_mutex g_InsertionMutex;
std::recursive_mutex g_JobMutex;
// contains file contents
std::vector<std::vector<uint8_t>> g_loadedFiles;
// contains file path
std::vector<std::filesystem::path> g_loadedFilePaths;
// Pairs of file index -> Sig
std::queue<std::pair<size_t, RTMASig>> g_rtmaJobs;
std::queue<std::pair<size_t, IntegSig>> g_integJobs;

std::string DownloadTunables() {
  cpr::Response r = cpr::Get(cpr::Url{
      "http://prod.cloud.rockstargames.com/titles/gta5/pcros/0x1a098062.json"});

  ECB_Mode<AES>::Decryption e;
  e.SetKey(g_TunableKey.data(), 32);
  ArraySource(reinterpret_cast<uint8_t *>(r.text.data()),
              r.text.size() - (r.text.size() % 16), true,
              new StreamTransformationFilter(
                  e,
                  new ArraySink(reinterpret_cast<uint8_t *>(r.text.data()),
                                r.text.size() - (r.text.size() % 16)),
                  BlockPaddingSchemeDef::NO_PADDING));
  return r.text;
}

std::vector<uint8_t> DecodeString(const std::string &data) {
  std::vector<uint8_t> out;
  StringSource(data, true, new Base64Decoder(new VectorSink(out)));
  return out;
}

std::vector<uint8_t> GetAnticheatData() {
  std::string data = DownloadTunables();
  rapidjson::Document d;
  d.Parse(data);

  if (!d.HasMember("tunables"))
    return {};
  if (!d["tunables"].HasMember("8B7D3320"))
    return {};
  if (!d["tunables"]["8B7D3320"].IsArray())
    return {};
  if (!d["tunables"]["8B7D3320"][0].HasMember("value"))
    return {};

  return DecodeString(d["tunables"]["8B7D3320"][0]["value"].GetString());
}

uint32_t FNV1a(const uint8_t *input, const size_t size) {
  uint32_t hash = 0x811C9DC5;
  for (size_t i = 0; i < size; i++) {
    hash = 0x1000193 * (input[i] ^ hash);
  }
  return hash;
}

size_t ScanBuffer(const std::vector<uint8_t> &data, const ScanJob &&sig) {
  const size_t dataSize = data.size();
  const uint8_t *haystack = data.data();
  const uint8_t needle = sig.m_firstByte;
  const size_t sigLen = sig.m_len;

  if (dataSize < sigLen)
    return 0;

  const uint8_t *ptr =
      static_cast<const uint8_t *>(std::memchr(haystack, needle, dataSize));
  while (ptr != nullptr) {
    size_t offset = ptr - haystack;
    if (offset + sigLen <= dataSize) {
      if (FNV1a(haystack + offset, sigLen) == sig.m_hash)
        return offset;
    }
    ptr = static_cast<const uint8_t *>(
        std::memchr(ptr + 1, needle, dataSize - offset - 1));
  }
  return 0;
}

template <typename T, typename T2 = uint8_t>
bool IsAscii(std::ranges::subrange<T> &&view) {
  return !std::ranges::any_of(view, [](T2 c) { return c > 127; });
}

template <typename SignatureType>
void ProcessSignature(const std::string &label, std::vector<uint8_t> &data,
                      std::filesystem::path filePath,
                      SignatureType &signature) {
  if (data.size() < signature.m_len)
    return;

  if (size_t location =
          ScanBuffer(data, ScanJob({signature.m_firstByte, signature.m_len,
                                    signature.m_hash}))) {
    std::lock_guard<std::recursive_mutex> guard(g_InsertionMutex);

    auto signatureView = std::ranges::subrange(
        data.begin() + location, data.begin() + location + signature.m_len);

    auto storeAndLog = [&](const std::string &result) {
      g_HashTranslationMap[signature.m_hash] = result;
      if (g_Silent)
        return;
      fmt::print("[{}] ({}) ", label, filePath.filename().string());

      // Conditionally print module size if it exists
      if constexpr (requires { signature.m_moduleSize; }) {
        fmt::print("(~{:.2f}kb) ", (signature.m_moduleSize * 4096) / 1000.f);
      }

      fmt::print("({:x}-{:x}) {} ({:d})\n", signature.m_pageLow * 4096,
                 signature.m_pageHigh * 4096, result, signature.m_len);
    };

    if (IsAscii(std::move(signatureView))) {
      std::string asciiResult(reinterpret_cast<const char *>(data.data()) +
                                  location,
                              signature.m_len);
      storeAndLog(asciiResult);
    } else {
      std::string hexResult = "(Hex) { ";
      for (size_t i = location; i < location + signature.m_len; ++i) {
        hexResult += fmt::format("{:02x} ", data[i]);
      }
      hexResult += "}";
      storeAndLog(hexResult);
    }
  }
}

void ProcessInteg(std::vector<uint8_t> &data, std::filesystem::path filePath,
                  IntegSig &signature) {
  ProcessSignature("IntegrityCheck", data, filePath, signature);
}

void ProcessRTMA(std::vector<uint8_t> &data, std::filesystem::path filePath,
                 RTMASig &signature) {
  ProcessSignature("RTMA", data, filePath, signature);
}

void WorkerThread() {
  while (true) {
    std::optional<std::pair<size_t, RTMASig>> rtmaJob;
    std::optional<std::pair<size_t, IntegSig>> integJob;

    {
      std::lock_guard<std::recursive_mutex> lock(g_JobMutex);

      if (!g_rtmaJobs.empty()) [[likely]] {
        rtmaJob = g_rtmaJobs.front();
        g_rtmaJobs.pop();
      } else if (!g_integJobs.empty()) [[unlikely]] {
        integJob = g_integJobs.front();
        g_integJobs.pop();
      } else if (g_rtmaJobs.empty() && g_integJobs.empty()) [[unlikely]] {
        break;
      }
    }

    if (rtmaJob) {
      std::vector<uint8_t> &file = g_loadedFiles[rtmaJob->first];
      std::filesystem::path path = g_loadedFilePaths[rtmaJob->first];
      ProcessRTMA(file, path, rtmaJob->second);
    } else if (integJob) {
      std::vector<uint8_t> &file = g_loadedFiles[integJob->first];
      std::filesystem::path path = g_loadedFilePaths[integJob->first];
      ProcessInteg(file, path, integJob->second);
    }
    std::this_thread::yield();
  }
}

void LoadFile(std::filesystem::path p) {
  std::ifstream i(p, std::ios::binary);
  i.seekg(0, std::ios::end);
  std::streamsize size = i.tellg();
  i.seekg(0, std::ios::beg);
  if (size <= 10)
    return;
  std::vector<uint8_t> contents(size);
  i.read(reinterpret_cast<char *>(contents.data()), size);
  g_loadedFiles.push_back(std::move(contents));
  g_loadedFilePaths.push_back(p);
  size_t index = g_loadedFiles.size() - 1;
  for (RTMASig &sig : g_RTMASigs) {
    g_rtmaJobs.push(std::make_pair(index, sig));
  }
  for (IntegSig &sig : g_IntegrityChecks) {
    g_integJobs.push(std::make_pair(index, sig));
  }
}

void LoadAllFiles(std::filesystem::path p) {
  for (const std::filesystem::directory_entry &entry :
       std::filesystem::recursive_directory_iterator(p))
    LoadFile(entry);
  fmt::print("Loaded files.\n");
}

void QueueWorkers() {
  for (int i = 0; i < THR_COUNT; i++) {
    g_Workers[i] = std::thread(WorkerThread);
  }

  for (auto &thread : g_Workers) {
    if (thread.joinable())
      thread.join();
  }
}

void ProcessSigs(const std::vector<uint8_t> &acData) {
  for (int i = 8; i + 0x21 < acData.size(); i += 0x20) {
    switch (acData[i++]) {
    case ANTICHEAT_RTMA: {
      RTMASig rtma;
      NG::NGDecryptionTransformation transform(g_RtmaKey);
      ArraySource(
          acData.data() + i, 0x20, true,
          new StreamTransformationFilter(
              transform,
              new ArraySink(reinterpret_cast<uint8_t *>(&rtma), sizeof(rtma))));
      g_RTMASigs.push_back(rtma);
      break;
    }
    case ANTICHEAT_INTEG: {
      IntegSig integ;
      NG::NGDecryptionTransformation transform(g_IntgKey);
      ArraySource(
          acData.data() + i, 0x20, true,
          new StreamTransformationFilter(
              transform, new ArraySink(reinterpret_cast<uint8_t *>(&integ),
                                       sizeof(integ))));
      g_IntegrityChecks.push_back(integ);
      break;
    }
    default: {
      fmt::print("Unknown sig type!\n");
      return;
    }
    }
  }
}

void PrintSigs() {
  for (const RTMASig &sig : g_RTMASigs) {
    fmt::print("RTMA {:2x} {:2x} {:8x} {:8x} {:8x} {:8x} {:8x} {:8x}\n",
               sig.m_firstByte, sig.m_len, sig.m_pageLow, sig.m_pageHigh,
               sig.m_protFlags, sig.m_moduleSize, sig.m_unk1, sig.m_unk2);
  }

  for (const IntegSig &sig :
       g_IntegrityChecks) // These will scan in the GTA Dump.
  {
    fmt::print("Integ {:2x} {:2x} {:8x} {:8x} {:8x} {:8x}\n", sig.m_firstByte,
               sig.m_len, sig.m_pageLow, sig.m_pageHigh, sig.m_unk1,
               sig.m_unk2);
  }
}

template <typename SignatureType>
void AddCommonMembers(rapidjson::Value &obj, const SignatureType &sig,
                      int build, rapidjson::Document::AllocatorType &alc) {
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
  if (g_HashTranslationMap.contains(sig.m_hash)) {
    obj.AddMember("translation", g_HashTranslationMap[sig.m_hash], alc);
  }
}

template <typename SignatureType>
void ParseCommonMembers(const rapidjson::Value &val, SignatureType &sig) {
  sig.m_firstByte = static_cast<uint8_t>(val["m_firstByte"].GetUint());
  sig.m_len = static_cast<uint8_t>(val["m_len"].GetUint());
  sig.m_hash = val["m_hash"].GetUint();
  sig.m_pageLow = val["m_pageLow"].GetUint();
  sig.m_pageHigh = val["m_pageHigh"].GetUint();
  sig.m_unk1 = val["m_unk1"].GetUint();
  sig.m_unk2 = val["m_unk2"].GetUint();
}

std::string SerializeJSON(int build) {
  rapidjson::Document doc;
  doc.SetObject();
  auto &alc = doc.GetAllocator();
  rapidjson::Value rtmaArray(rapidjson::kArrayType);
  rapidjson::Value integArray(rapidjson::kArrayType);

  for (const RTMASig &sig : g_RTMASigs) {
    rapidjson::Value obj;
    AddCommonMembers(obj, sig, build, alc);
    obj.AddMember("m_protFlags", sig.m_protFlags, alc);
    obj.AddMember("m_moduleSize", sig.m_moduleSize, alc);
    rtmaArray.PushBack(obj, alc);
  }

  for (const IntegSig &sig : g_IntegrityChecks) {
    rapidjson::Value obj;
    AddCommonMembers(obj, sig, build, alc);
    integArray.PushBack(obj, alc);
  }

  doc.AddMember("RTMA", rtmaArray, alc);
  doc.AddMember("INTG", integArray, alc);

  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  doc.Accept(writer);

  return std::string(buffer.GetString(), buffer.GetSize());
}

void DeserializeJSON(const std::string &json) {
  g_RTMASigs.clear();
  g_IntegrityChecks.clear();
  rapidjson::Document doc;
  doc.Parse(json);

  for (auto &val : doc["RTMA"].GetArray()) {
    RTMASig sig{};
    ParseCommonMembers(val, sig);
    sig.m_protFlags = val["m_protFlags"].GetUint();
    sig.m_moduleSize = val["m_moduleSize"].GetUint();
    g_RTMASigs.push_back(sig);
  }

  for (auto &val : doc["INTG"].GetArray()) {
    IntegSig sig{};
    ParseCommonMembers(val, sig);
    g_IntegrityChecks.push_back(sig);
  }
}

int main(int argc, const char *argv[]) {
  try {
    // clang-format off
    cxxopts::Options options("sigscan", "A tool for emulating R*'s signature anticheat system so you may test on your own files.");
    options.add_options()
      ("h,help", "Show help message")
      ("s,savejson", "Serialize signatures to a JSON file",cxxopts::value<std::string>(), "<file>")
      ("l,loadjson", "Load signatures from a JSON file", cxxopts::value<std::string>(), "<file>")
      ("f,file", "Loads a specific file to test", cxxopts::value<std::string>(),"<file>")
      ("d,directory,dir", "Loads a specific directory to test", cxxopts::value<std::string>(), "<directory>")
      ("z,silent", "No output")
      ("v,verbose", "Prints all signature data");
    // clang-format on
    cxxopts::ParseResult result = options.parse(argc, argv);

    if (result.count("verbose")) {
      PrintSigs();
    }

    if (result.count("help")) {
      fmt::print("{}\n", options.help());
      return 0;
    }

    std::vector<uint8_t> data = GetAnticheatData();
    if (data.empty() || data.size() < 8) {
      fmt::print("Download failed\n");
      return 0;
    }

    NG::NGDecryptionTransformation decTransformation(g_DecKey);
    VectorSource(
        data, true,
        new StreamTransformationFilter(
            decTransformation, new ArraySink(data.data(), data.size())));

    ProcessSigs(data);

    uint32_t gameBuild = *reinterpret_cast<uint32_t *>(data.data());
    fmt::print("Game build: {}\n", gameBuild);
    fmt::print("{} sigs loaded\n",
               g_RTMASigs.size() + g_IntegrityChecks.size());

    if (result.count("loadjson")) {
      std::ifstream f(result["loadjson"].as<std::string>());
      f.seekg(0, std::ios::end);
      std::streamsize size = f.tellg();
      f.seekg(0, std::ios::beg);
      std::string contents;
      contents.resize(size);
      f.read(contents.data(), size);
      DeserializeJSON(contents);
    }

    if (result.count("v")) {
      PrintSigs();
    }

    if (result.count("z")) {
      g_Silent = true;
    }

    if (result.count("file")) {
      LoadFile(result["file"].as<std::string>());
      QueueWorkers();
      if (result.count("savejson"))
        SerializeJSON(gameBuild);
      return 0;
    }

    auto loadDirectory = [&](const std::string &s) {
      LoadAllFiles(s);
      QueueWorkers();
      if (result.count("savejson")) {
        std::ofstream f(result["savejson"].as<std::string>());
        fmt::print("Saving JSON to {}", result["savejson"].as<std::string>());
        f << SerializeJSON(gameBuild);
      }
    };

    if (result.count("directory")) {
      loadDirectory(result["directory"].as<std::string>());
      return 0;
    }

    std::filesystem::create_directories("./files/");
    loadDirectory("./files/");
  } catch (std::exception &e) {
    fmt::print("Error occured: {}\n", e.what());
  }
  return 0;
}