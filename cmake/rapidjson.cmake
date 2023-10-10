include(FetchContent)
set(RAPIDJSON_BUILD_DOC OFF)
set(RAPIDJSON_BUILD_EXAMPLES OFF)
set(RAPIDJSON_BUILD_TESTS OFF)
set(RAPIDJSON_BUILD_CXX11 OFF)
set(RAPIDJSON_BUILD_CXX17 ON)
set(RAPIDJSON_HAS_STDSTRING ON)
FetchContent_Declare(
    RapidJSON
    GIT_REPOSITORY https://github.com/Tencent/rapidjson.git
    GIT_TAG        a98e99992bd633a2736cc41f96ec85ef0c50e44d
    GIT_PROGRESS TRUE
)
message("RapidJSON")
FetchContent_MakeAvailable(RapidJSON)