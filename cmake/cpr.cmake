include(FetchContent)
set(BUILD_SHARED_LIBS OFF)
FetchContent_Declare(
    cpr
    GIT_REPOSITORY https://github.com/libcpr/cpr.git
    GIT_TAG        da40186618909b1a7363d4e4495aa899c6e0eb75
    GIT_PROGRESS TRUE
    DOWLOAD_EXTRACT_TIMESTAMP TRUE
)
message("CPR")
FetchContent_MakeAvailable(cpr)