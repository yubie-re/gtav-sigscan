project(sigscan)
cmake_minimum_required(VERSION 3.15)
include_directories(${PROJECT_SOURCE_DIR}/src ${rapidjson_SOURCE_DIR}/include)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../cmake)

find_package(
    Botan 3.4.0
    REQUIRED
)

set(CMAKE_CXX_STANDARD 23)
botan_generate(
    botan
        aes
        base64
)

add_executable(sigscan Main.cpp NGDec.cpp NGTables.cpp OldAnticheat.cpp)
target_link_libraries(sigscan botan cpr fmt cxxopts)