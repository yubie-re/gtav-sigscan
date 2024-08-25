include(FetchContent)
FetchContent_Declare(
    cxxopts
    GIT_REPOSITORY https://github.com/jarro2783/cxxopts.git
    GIT_TAG        2ad116a9d3297e87e7f6afcb77fbf3dd5d13ff06
)
message("cxxopts")
FetchContent_MakeAvailable(cxxopts)