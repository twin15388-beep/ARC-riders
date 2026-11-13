cmake_minimum_required(VERSION 3.24)
project(arc_tool VERSION 0.1.0 LANGUAGES CXX)

option(ARC_BUILD_TESTS "Build isolated core checks" ON)

add_library(arc_core
    src/Chain.cpp
    src/Config.cpp
    src/Names.cpp
    src/Pattern.cpp
    src/Usmap.cpp
    src/ArcDecrypt.cpp
)
target_include_directories(arc_core PUBLIC src)
target_compile_features(arc_core PUBLIC cxx_std_20)

# Embedded provenance so a stale executable is visible in every report ("arc_tool version").
set(ARC_BUILD_STAMP "untagged" CACHE STRING "Provenance stamp embedded in the tool")
target_compile_definitions(arc_core PUBLIC ARC_BUILD_STAMP="${ARC_BUILD_STAMP}")

if(MSVC)
    target_compile_options(arc_core PRIVATE /W4 /WX /permissive- /EHsc)
else()
    target_compile_options(arc_core PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

if(WIN32)
    add_executable(arc_tool
        src/Main.cpp
        src/DumpFile.cpp
        src/PeFile.cpp
        src/Process.cpp
        src/Scanner.cpp
    )
    target_link_libraries(arc_tool PRIVATE arc_core advapi32)
    target_compile_features(arc_tool PRIVATE cxx_std_20)
    add_executable(arc_inject src/Injector.cpp)
    target_compile_features(arc_inject PRIVATE cxx_std_20)
    if(MSVC)
        target_compile_options(arc_tool PRIVATE /W4 /WX /permissive- /EHsc)
        target_compile_options(arc_inject PRIVATE /W4 /WX /permissive- /EHsc)
    endif()
else()
    message(STATUS "arc_tool requires Windows; only arc_core and its checks will be built")
endif()

if(ARC_BUILD_TESTS)
    enable_testing()
    add_executable(arc_core_tests tests/CoreTests.cpp)
    target_link_libraries(arc_core_tests PRIVATE arc_core)
    if(MSVC)
        target_compile_options(arc_core_tests PRIVATE /W4 /WX /permissive- /EHsc)
    else()
        target_compile_options(arc_core_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
    add_test(NAME arc_core_tests COMMAND arc_core_tests)
endif()
