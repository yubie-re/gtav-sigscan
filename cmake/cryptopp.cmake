include(FetchContent)
set(CRYPTOPP_BUILD_TESTING OFF)
FetchContent_Declare(
    cryptopp_cmake
    GIT_REPOSITORY https://github.com/abdes/cryptopp-cmake.git
    GIT_TAG        f857b775bcb4ff24e4993d85cce811587f8b0616
)
message("Crypto++")
FetchContent_MakeAvailable(cryptopp_cmake)