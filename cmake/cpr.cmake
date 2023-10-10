include(FetchContent)
set(BUILD_SHARED_LIBS OFF)
FetchContent_Declare(
    cpr
    GIT_REPOSITORY https://github.com/libcpr/cpr.git
    GIT_TAG        2553fc41450301cd09a9271c8d2c3e0cf3546b73
    GIT_PROGRESS TRUE
)
message("CPR")
FetchContent_MakeAvailable(cpr)