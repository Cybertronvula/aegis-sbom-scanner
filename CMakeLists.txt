cmake_minimum_required(VERSION 3.20)
project(AegisPrimeSBOM VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Optimised release build — fast, small binary, no debug symbols
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -march=native")

# ── Dependencies ─────────────────────────────────────────────────────────────
find_package(OpenSSL REQUIRED)
find_package(CURL    REQUIRED)

# nlohmann/json — header-only, just needs to be findable
find_package(nlohmann_json QUIET)
if(NOT nlohmann_json_FOUND)
  # Fallback: download single-header version during configure
  include(FetchContent)
  FetchContent_Declare(json
    URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.hpp
    DOWNLOAD_NO_EXTRACT TRUE
    DOWNLOAD_DIR ${CMAKE_CURRENT_BINARY_DIR}/include/nlohmann
  )
  FetchContent_MakeAvailable(json)
  add_library(nlohmann_json INTERFACE)
  target_include_directories(nlohmann_json INTERFACE ${CMAKE_CURRENT_BINARY_DIR}/include)
  add_library(nlohmann_json::nlohmann_json ALIAS nlohmann_json)
endif()

# ── Core library ─────────────────────────────────────────────────────────────
add_library(aegis_core STATIC
  core/sbom_generator.cpp
)
target_include_directories(aegis_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(aegis_core
  PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
    CURL::libcurl
)

# ── CLI executable ────────────────────────────────────────────────────────────
add_executable(aegis cli/aegis.cpp)
target_link_libraries(aegis PRIVATE aegis_core)

# Strip the binary in release mode (reduces size, harder to reverse)
if(CMAKE_BUILD_TYPE STREQUAL "Release" AND UNIX)
  add_custom_command(TARGET aegis POST_BUILD
    COMMAND strip $<TARGET_FILE:aegis>
    COMMENT "Stripping binary for release"
  )
endif()

# ── Install targets ───────────────────────────────────────────────────────────
install(TARGETS aegis DESTINATION bin)

# ── Tests ─────────────────────────────────────────────────────────────────────
enable_testing()
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/tests/sbom_tests.cpp)
  add_executable(aegis_tests tests/sbom_tests.cpp)
  target_link_libraries(aegis_tests PRIVATE aegis_core)
  add_test(NAME SbomTests COMMAND aegis_tests)
endif()

message(STATUS "═══════════════════════════════════════")
message(STATUS " Aegis Prime SBOM Engine v${PROJECT_VERSION}")
message(STATUS " Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS " OpenSSL:    ${OPENSSL_VERSION}")
message(STATUS "═══════════════════════════════════════")
