# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

cmake_minimum_required(VERSION 3.24)
project(lumtail VERSION 0.1.0 LANGUAGES CXX)

# Set install paths before dependencies choose their defaults.
include(GNUInstallDirs)

if(NOT UNIX)
  message(FATAL_ERROR "lumtail targets Linux, macOS, NetBSD, OpenBSD and FreeBSD with the required POSIX APIs.")
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
include(CTest)
option(LUMTAIL_NATIVE "Optimize for this CPU (not for redistribution)" OFF)
option(LUMTAIL_LTO "Enable Release link-time optimization when supported" ON)
option(LUMTAIL_BUILD_BENCHMARKS "Build core benchmarks and allocation measurement tools" OFF)

include(CheckCXXSourceCompiles)
check_cxx_source_compiles("
  #include <expected>
  int main() {
    std::expected<int, int> value{1};
    std::expected<void, int> status{};
    return value && status ? 0 : 1;
  }
" LUMTAIL_HAS_EXPECTED)
if(NOT LUMTAIL_HAS_EXPECTED)
  message(FATAL_ERROR "lumtail requires a C++23 compiler and standard library with <expected>.")
endif()

check_cxx_source_compiles("
  #include <string>
  int main() {
    std::string text = \"ok\";
    text.resize_and_overwrite(3, [](char* data, std::size_t size) noexcept {
      data[2] = '!';
      return size;
    });
    return text == \"ok!\" ? 0 : 1;
  }
" LUMTAIL_HAS_STRING_RESIZE_AND_OVERWRITE)

include(cmake/Quality.cmake)

set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)

include(CMakePushCheckState)
include(CheckCXXSymbolExists)
cmake_push_check_state(RESET)
set(CMAKE_REQUIRED_LIBRARIES Threads::Threads)
check_cxx_source_compiles("
  #include <condition_variable>
  #include <mutex>
  #include <stop_token>
  #include <thread>
  #include <pthread.h>
  int main() {
    pthread_t worker{};
    if (::pthread_create(&worker, nullptr, [](void*) -> void* { return nullptr; }, nullptr)) return 1;
    if (::pthread_join(worker, nullptr)) return 1;
    std::stop_source stop;
    stop.request_stop();
    std::mutex mutex;
    std::unique_lock lock(mutex);
    std::condition_variable_any changed;
    return changed.wait(lock, stop.get_token(), [] { return true; }) ? 0 : 1;
  }
" LUMTAIL_HAS_NATIVE_STOPPABLE_THREADS)
cmake_pop_check_state()
if(NOT LUMTAIL_HAS_NATIVE_STOPPABLE_THREADS)
  message(FATAL_ERROR "lumtail requires POSIX threads, stop tokens and cancellable condition-variable waits.")
endif()

cmake_push_check_state(RESET)
# Keep large-file offsets usable on 32-bit Unix.
set(CMAKE_REQUIRED_DEFINITIONS -D_FILE_OFFSET_BITS=64)
check_cxx_source_compiles("
  #include <csignal>
  #include <fcntl.h>
  #include <poll.h>
  #include <sys/select.h>
  #include <sys/stat.h>
  #include <unistd.h>
  static_assert(sizeof(off_t) >= 8, \"64-bit file offsets are required\");
  int main() {
    struct stat info{};
    char buffer[1]{};
    const int fd = ::open(\"\", O_RDONLY | O_NONBLOCK);
    pollfd input{fd, POLLIN, 0};
    (void)::poll(&input, 1, 0);
    fd_set readable;
    FD_ZERO(&readable);
    FD_SET(0, &readable);
    timeval timeout{0, 0};
    (void)::select(1, &readable, nullptr, nullptr, &timeout);
    (void)::fcntl(fd, F_SETFD, FD_CLOEXEC);
    (void)::fcntl(fd, F_GETFD);
    const int duplicate = ::fcntl(fd, F_DUPFD, 0);
    if (duplicate >= 0 && ::close(duplicate) != 0) return 1;
    (void)::read(fd, buffer, sizeof(buffer));
    (void)::write(fd, buffer, sizeof(buffer));
    (void)::fstat(fd, &info);
    (void)::stat(\"\", &info);
    (void)S_ISREG(info.st_mode);
    (void)S_ISFIFO(info.st_mode);
    (void)::lseek(fd, 0, SEEK_SET);
    (void)::isatty(STDOUT_FILENO);
    (void)STDIN_FILENO;
    std::signal(SIGPIPE, SIG_IGN);
    return ::close(fd);
  }
" LUMTAIL_HAS_POSIX_IO)
check_cxx_symbol_exists(O_CLOEXEC "fcntl.h" LUMTAIL_HAS_O_CLOEXEC)
check_cxx_source_compiles("
  #include <arpa/inet.h>
  #include <netinet/in.h>
  #include <sys/socket.h>
  int main() {
    in_addr ipv4{};
    in6_addr ipv6{};
    return ::inet_pton(AF_INET, \"127.0.0.1\", &ipv4) +
           ::inet_pton(AF_INET6, \"::1\", &ipv6);
  }
" LUMTAIL_HAS_INET_PTON)
cmake_pop_check_state()
if(NOT LUMTAIL_HAS_POSIX_IO)
  message(FATAL_ERROR "lumtail requires POSIX file I/O, SIGPIPE and 64-bit off_t.")
endif()
if(NOT LUMTAIL_HAS_INET_PTON)
  message(FATAL_ERROR "lumtail requires POSIX inet_pton for IPv4 and IPv6 addresses.")
endif()

# Compile dispatch once so coverage has a single source map.
add_library(lumtail_file_access STATIC src/file_access.cpp)
target_include_directories(lumtail_file_access PUBLIC include)
target_link_libraries(lumtail_file_access PUBLIC lumtail_options)
target_compile_definitions(lumtail_file_access PUBLIC _FILE_OFFSET_BITS=64)
set_property(TARGET lumtail_file_access PROPERTY POSITION_INDEPENDENT_CODE ON)

include(cmake/Confinement.cmake)

include(cmake/Dependencies.cmake)

find_package(nlohmann_json 3.12 QUIET)
if(NOT nlohmann_json_FOUND)
  include(FetchContent)
  FetchContent_Declare(json
    URL https://codeload.github.com/nlohmann/json/tar.gz/refs/tags/v3.12.0
    URL_HASH SHA256=4b92eb0c06d10683f7447ce9406cb97cd4b453be18d7279320f7b2f025c10187
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
  lumtail_require_dependency_source(json)
  FetchContent_MakeAvailable(json)
endif()

if(NOT (LUMTAIL_SANITIZERS OR LUMTAIL_FUZZING OR LUMTAIL_THREAD_SANITIZER OR LUMTAIL_COVERAGE))
  find_package(simdjson 5.1 CONFIG QUIET)
endif()
# Build dependency code with the selected sanitizer.
if(NOT TARGET simdjson::simdjson)
  include(FetchContent)
  set(SIMDJSON_DEVELOPER_MODE OFF CACHE BOOL "" FORCE)
  FetchContent_Declare(simdjson
    URL https://codeload.github.com/simdjson/simdjson/tar.gz/refs/tags/v5.1.1
    URL_HASH SHA256=d669fa399613c20bbf7705f057a72984331b223cd5e8d20666ef063dbf97f3e6
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
  lumtail_require_dependency_source(simdjson)
  FetchContent_MakeAvailable(simdjson)
  target_link_libraries(simdjson PRIVATE lumtail_instrumentation)
  # Keep upstream headers on their own warning policy.
  get_target_property(lumtail_simdjson_includes simdjson INTERFACE_INCLUDE_DIRECTORIES)
  set_property(TARGET simdjson APPEND PROPERTY INTERFACE_SYSTEM_INCLUDE_DIRECTORIES
    "${lumtail_simdjson_includes}")
endif()

include(cmake/Simd.cmake)

add_library(lumtail_core
  src/scan.cpp
  src/agent.cpp
  src/filter.cpp
  src/event.cpp
  src/pattern.cpp
  src/parser.cpp
  src/builtin_rules.cpp
  src/json.cpp
  src/json_bound.cpp
  src/eve.cpp
  src/zeek.cpp
  src/kubernetes.cpp
  src/access.cpp
  src/auditd.cpp
  src/web_error.cpp
  src/cef.cpp
  src/leef.cpp
  src/syslog.cpp
  src/structured_data.cpp
  src/security.cpp
  src/rules.cpp
  src/renderer.cpp
  src/record.cpp
  src/processor.cpp
  src/stream.cpp)
target_include_directories(lumtail_core PUBLIC include)
target_include_directories(lumtail_core PRIVATE src)
set_property(SOURCE src/scan.cpp APPEND PROPERTY COMPILE_DEFINITIONS
  LUMTAIL_SIMD_ENABLED=$<BOOL:${LUMTAIL_SIMD}>)
if(LUMTAIL_SIMD)
  target_link_libraries(lumtail_core PRIVATE hwy::hwy)
  get_target_property(lumtail_hwy_includes hwy::hwy INTERFACE_INCLUDE_DIRECTORIES)
  # Keep ISA-specific flags inside the byte-kernel implementation.
  set_property(SOURCE src/scan.cpp APPEND PROPERTY COMPILE_DEFINITIONS
    HWY_COMPILE_ALL_ATTAINABLE=1)
endif()
target_include_directories(lumtail_core SYSTEM PUBLIC
  $<TARGET_PROPERTY:nlohmann_json::nlohmann_json,INTERFACE_INCLUDE_DIRECTORIES>)

target_include_directories(lumtail_core SYSTEM PRIVATE
  $<TARGET_PROPERTY:simdjson::simdjson,INTERFACE_INCLUDE_DIRECTORIES>)
if(LUMTAIL_SIMD)
  target_include_directories(lumtail_core SYSTEM PRIVATE ${lumtail_hwy_includes})
endif()
# Keep shared package prefixes from shadowing selected headers.
foreach(dependency_target IN ITEMS nlohmann_json::nlohmann_json simdjson::simdjson hwy::hwy)
  if(TARGET ${dependency_target})
    get_target_property(dependency_imported ${dependency_target} IMPORTED)
    if(NOT dependency_imported)
      target_include_directories(lumtail_core SYSTEM BEFORE PRIVATE
        $<TARGET_PROPERTY:${dependency_target},INTERFACE_INCLUDE_DIRECTORIES>)
    endif()
  endif()
endforeach()
# Reclassify Apple's implicit prefix so selected headers win.
if(CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang" AND
    "/usr/local/include" IN_LIST CMAKE_CXX_IMPLICIT_INCLUDE_DIRECTORIES)
  target_compile_options(lumtail_core PRIVATE "SHELL:-isystem /usr/local/include")
endif()
target_link_libraries(lumtail_core PRIVATE simdjson::simdjson)
target_link_libraries(lumtail_core PUBLIC nlohmann_json::nlohmann_json lumtail_options lumtail_file_access
  PRIVATE Threads::Threads)
target_compile_definitions(lumtail_core PUBLIC _FILE_OFFSET_BITS=64 PRIVATE
  LUMTAIL_HAS_STRING_RESIZE_AND_OVERWRITE=$<BOOL:${LUMTAIL_HAS_STRING_RESIZE_AND_OVERWRITE}>
  LUMTAIL_HAS_O_CLOEXEC=$<BOOL:${LUMTAIL_HAS_O_CLOEXEC}>)


add_library(lumtail_cli STATIC src/cli.cpp)
target_link_libraries(lumtail_cli PUBLIC lumtail_core)
add_executable(lumtail src/main.cpp)
target_link_libraries(lumtail PRIVATE lumtail_cli lumtail_sandbox)
set(lumtail_cli_contract "${CMAKE_CURRENT_SOURCE_DIR}/contracts/cli/v1/contract.json")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${lumtail_cli_contract}")
file(READ "${lumtail_cli_contract}" LUMTAIL_CLI_CONTRACT)
set(lumtail_record_schema "${CMAKE_CURRENT_SOURCE_DIR}/contracts/cli/v1-json-records/record-schema.json")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${lumtail_record_schema}")
file(READ "${lumtail_record_schema}" LUMTAIL_RECORD_SCHEMA)
configure_file(cmake/cli_contract.hpp.in generated/cli_contract.hpp @ONLY)
target_include_directories(lumtail PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")

if(LUMTAIL_NATIVE AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(lumtail_core PRIVATE -march=native)
  target_compile_options(lumtail_cli PRIVATE -march=native)
  target_compile_options(lumtail PRIVATE -march=native)
endif()
if(LUMTAIL_LTO)
  include(CheckIPOSupported)
  check_ipo_supported(RESULT lumtail_ipo_supported OUTPUT lumtail_ipo_error LANGUAGES CXX)
  if(lumtail_ipo_supported)
    set_property(TARGET lumtail_core lumtail_cli lumtail PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
    # Non-IPO consumers need the plugin to read an LTO archive.
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
      target_link_options(lumtail_core INTERFACE "$<$<CONFIG:Release>:-flto=thin>")
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
      target_link_options(lumtail_core INTERFACE "$<$<CONFIG:Release>:-flto>")
    endif()
  else()
    message(STATUS "LTO unavailable: ${lumtail_ipo_error}")
  endif()
endif()

if(BUILD_TESTING)
  find_package(Python3 COMPONENTS Interpreter REQUIRED)
  add_test(NAME cli_compatibility_v1
    COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/contracts/cli/v1/check.py
      $<TARGET_FILE:lumtail>)
  add_test(NAME cli_auditd_contract
    COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/contracts/cli/v1-auditd-raw/check.py
      $<TARGET_FILE:lumtail>)
  add_test(NAME cli_pipeline_contract
    COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/contracts/cli/v1-pipeline-assertions/check.py
      $<TARGET_FILE:lumtail>)
  add_test(NAME cli_security_json_contract
    COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/contracts/cli/v1-security-json/check.py
      $<TARGET_FILE:lumtail>)
  add_test(NAME cli_json_records
    COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/contracts/cli/v1-json-records/check.py
      $<TARGET_FILE:lumtail>)
  set(_lumtail_cli_consumer_timeout 300)
  if(LUMTAIL_THREAD_SANITIZER)
    # Published consumers start hundreds of instrumented processes.
    set(_lumtail_cli_consumer_timeout 900)
  endif()
  set_tests_properties(cli_compatibility_v1 cli_auditd_contract cli_pipeline_contract
    cli_security_json_contract cli_json_records PROPERTIES TIMEOUT ${_lumtail_cli_consumer_timeout})
  add_executable(lumtail_cli_defaults tests/cli_defaults.cpp)
  target_include_directories(lumtail_cli_defaults PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
  target_link_libraries(lumtail_cli_defaults PRIVATE lumtail_cli)
  add_test(NAME cli_declared_defaults COMMAND lumtail_cli_defaults)
  set_tests_properties(cli_declared_defaults PROPERTIES TIMEOUT 30)
  add_executable(lumtail_auditd tests/auditd.cpp)
  target_link_libraries(lumtail_auditd PRIVATE lumtail_core)
  add_test(NAME auditd_core COMMAND lumtail_auditd)
  set_tests_properties(auditd_core PROPERTIES TIMEOUT 60)
  add_test(NAME build_configuration
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/build_configuration.py)
  set_tests_properties(build_configuration PROPERTIES TIMEOUT 60)
  add_test(NAME ci_tools
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/ci_tools.py)
  set_tests_properties(ci_tools PROPERTIES TIMEOUT 30)
  add_executable(lumtail_scan tests/scan.cpp)
  target_link_libraries(lumtail_scan PRIVATE lumtail_core)
  add_test(NAME simd_contracts COMMAND lumtail_scan)
  add_test(NAME simd_scalar_dispatch COMMAND lumtail_scan scalar)
  add_test(NAME simd_lazy_dispatch COMMAND lumtail_scan lazy)
  set_tests_properties(simd_contracts simd_scalar_dispatch simd_lazy_dispatch PROPERTIES TIMEOUT 120)
  if(LUMTAIL_THREAD_SANITIZER)
    # Allow for instrumented reads in exhaustive backend checks.
    set_tests_properties(simd_contracts simd_scalar_dispatch PROPERTIES TIMEOUT 300)
  endif()
  add_executable(lumtail_json_render tests/json_render.cpp)
  target_link_libraries(lumtail_json_render PRIVATE lumtail_core)
  add_test(NAME json_render_compatibility COMMAND lumtail_json_render)
  set_tests_properties(json_render_compatibility PROPERTIES TIMEOUT 120)
  add_executable(lumtail_runtime_failure tests/runtime_failure.cpp)
  target_include_directories(lumtail_runtime_failure PRIVATE include)
  target_link_libraries(lumtail_runtime_failure PRIVATE lumtail_options)
  add_test(NAME allocation_failure_policy
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/runtime_failure.py
      $<TARGET_FILE:lumtail_runtime_failure>)
  set_tests_properties(allocation_failure_policy PROPERTIES TIMEOUT 30)
  if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_test(NAME api_contracts
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/api_contracts.py
        --compiler ${CMAKE_CXX_COMPILER}
        --compiler-id ${CMAKE_CXX_COMPILER_ID}
        --source ${CMAKE_CURRENT_SOURCE_DIR}
        --work-dir ${CMAKE_CURRENT_BINARY_DIR}/api-contracts
        --capsicum-fileargs $<BOOL:${LUMTAIL_HAS_CAPSICUM_FILEARGS}>)
    set_tests_properties(api_contracts PROPERTIES TIMEOUT 150)
  endif()
  add_executable(lumtail_sandbox_tests tests/sandbox.cpp)
  target_include_directories(lumtail_sandbox_tests PRIVATE src)
  target_link_libraries(lumtail_sandbox_tests PRIVATE lumtail_sandbox Threads::Threads)
  add_test(NAME runtime_confinement COMMAND lumtail_sandbox_tests)
  set_tests_properties(runtime_confinement PROPERTIES TIMEOUT 30)
  add_executable(lumtail_unicode tests/unicode.cpp)
  target_include_directories(lumtail_unicode PRIVATE src)
  target_link_libraries(lumtail_unicode PRIVATE lumtail_core)
  add_test(NAME unicode_core COMMAND lumtail_unicode)
  set_tests_properties(unicode_core PROPERTIES TIMEOUT 30)
  add_executable(lumtail_agent tests/agent.cpp)
  target_link_libraries(lumtail_agent PRIVATE lumtail_core)
  add_test(NAME agent_core COMMAND lumtail_agent)
  set_tests_properties(agent_core PROPERTIES TIMEOUT 60)
  add_test(NAME agent_cli
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/agent.py $<TARGET_FILE:lumtail>)
  set_tests_properties(agent_cli PROPERTIES TIMEOUT 60)
  add_test(NAME integration
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration.py $<TARGET_FILE:lumtail>)
  add_test(NAME concurrency_cli
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/concurrency.py $<TARGET_FILE:lumtail>)
  set_tests_properties(concurrency_cli PROPERTIES TIMEOUT 120)
  add_test(NAME features
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/features.py $<TARGET_FILE:lumtail>)
  add_test(NAME benchmarks
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/benchmarks.py $<TARGET_FILE:lumtail>)
  set_tests_properties(benchmarks PROPERTIES TIMEOUT 120)
  add_executable(lumtail_records tests/records.cpp)
  target_link_libraries(lumtail_records PRIVATE lumtail_core)
  add_test(NAME records COMMAND lumtail_records)
  set_tests_properties(features records PROPERTIES TIMEOUT 60)
  add_executable(lumtail_platform tests/platform.cpp)
  target_include_directories(lumtail_platform PRIVATE src)
  target_link_libraries(lumtail_platform PRIVATE lumtail_core)
  add_test(NAME platform_contracts COMMAND lumtail_platform)
  set_tests_properties(platform_contracts PROPERTIES TIMEOUT 30)
  add_executable(lumtail_concurrency tests/concurrency.cpp)
  target_link_libraries(lumtail_concurrency PRIVATE lumtail_core Threads::Threads)
  add_test(NAME concurrency_core COMMAND lumtail_concurrency)
  set_tests_properties(concurrency_core PROPERTIES TIMEOUT 30)
  add_executable(lumtail_unit tests/unit.cpp)
  target_link_libraries(lumtail_unit PRIVATE lumtail_core)
  add_test(NAME unit COMMAND lumtail_unit)
  add_executable(lumtail_cef tests/cef.cpp)
  target_link_libraries(lumtail_cef PRIVATE lumtail_core)
  add_test(NAME cef_core COMMAND lumtail_cef)
  set_tests_properties(cef_core PROPERTIES TIMEOUT 60)
  add_executable(lumtail_leef tests/leef.cpp)
  target_link_libraries(lumtail_leef PRIVATE lumtail_core)
  add_test(NAME leef_core COMMAND lumtail_leef)
  set_tests_properties(leef_core PROPERTIES TIMEOUT 60)
  add_executable(lumtail_zeek tests/zeek.cpp)
  target_link_libraries(lumtail_zeek PRIVATE lumtail_core)
  add_test(NAME zeek_core COMMAND lumtail_zeek)
  set_tests_properties(zeek_core PROPERTIES TIMEOUT 60)
  add_executable(lumtail_kubernetes tests/kubernetes.cpp)
  target_link_libraries(lumtail_kubernetes PRIVATE lumtail_core)
  add_test(NAME kubernetes_core COMMAND lumtail_kubernetes)
  set_tests_properties(kubernetes_core PROPERTIES TIMEOUT 60)
  add_executable(lumtail_syslog tests/syslog.cpp)
  target_link_libraries(lumtail_syslog PRIVATE lumtail_core)
  add_test(NAME syslog_core COMMAND lumtail_syslog)
  set_tests_properties(syslog_core PROPERTIES TIMEOUT 60)
  add_executable(lumtail_web_error tests/web_error.cpp)
  target_link_libraries(lumtail_web_error PRIVATE lumtail_core)
  add_test(NAME web_error_core COMMAND lumtail_web_error)
  set_tests_properties(web_error_core PROPERTIES TIMEOUT 60)
  add_executable(lumtail_properties tests/properties.cpp)
  target_link_libraries(lumtail_properties PRIVATE lumtail_core)
  add_test(NAME properties COMMAND lumtail_properties)
  set_tests_properties(integration unit properties PROPERTIES TIMEOUT 60)
  if(LUMTAIL_THREAD_SANITIZER)
    set_tests_properties(agent_core agent_cli integration concurrency_cli features benchmarks unit properties PROPERTIES
      ENVIRONMENT "LUMTAIL_TEST_TIMEOUT_SCALE=10" TIMEOUT 600)
  elseif(LUMTAIL_SANITIZERS OR LUMTAIL_FUZZING)
    set_tests_properties(agent_core agent_cli integration concurrency_cli features benchmarks unit properties PROPERTIES
      ENVIRONMENT "LUMTAIL_TEST_TIMEOUT_SCALE=3" TIMEOUT 180)
  endif()
endif()

if(LUMTAIL_BUILD_BENCHMARKS)
  add_executable(lumtail_simd_benchmarks benchmarks/simd.cpp)
  target_link_libraries(lumtail_simd_benchmarks PRIVATE lumtail_core)
  # Keep the optimizer from folding measured calls across units.
  set_property(TARGET lumtail_simd_benchmarks PROPERTY INTERPROCEDURAL_OPTIMIZATION FALSE)
  if(BUILD_TESTING)
    add_test(NAME simd_benchmark_contracts
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/simd_benchmarks.py
        $<TARGET_FILE:lumtail_simd_benchmarks>)
    set_tests_properties(simd_benchmark_contracts PROPERTIES TIMEOUT 120)
  endif()
  add_executable(lumtail_benchmarks benchmarks/core.cpp)
  target_link_libraries(lumtail_benchmarks PRIVATE lumtail_core)
  add_executable(lumtail_allocations benchmarks/allocations.cpp benchmarks/allocation_contracts.cpp)
  # Keep allocation calls separate so optimization preserves them.
  set_property(TARGET lumtail_allocations PROPERTY INTERPROCEDURAL_OPTIMIZATION FALSE)
  target_link_libraries(lumtail_allocations PRIVATE lumtail_core)
  if(LUMTAIL_LTO AND lumtail_ipo_supported)
    set_property(TARGET lumtail_benchmarks
      PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
  endif()
  if(BUILD_TESTING)
    add_test(NAME benchmarks_core
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/benchmarks.py
        $<TARGET_FILE:lumtail> $<TARGET_FILE:lumtail_benchmarks> $<TARGET_FILE:lumtail_allocations>)
    set_tests_properties(benchmarks_core PROPERTIES TIMEOUT 120)
    if(LUMTAIL_THREAD_SANITIZER)
      set_tests_properties(benchmarks_core PROPERTIES
        ENVIRONMENT "LUMTAIL_TEST_TIMEOUT_SCALE=10" TIMEOUT 600)
    elseif(LUMTAIL_SANITIZERS OR LUMTAIL_FUZZING)
      set_tests_properties(benchmarks_core PROPERTIES
        ENVIRONMENT "LUMTAIL_TEST_TIMEOUT_SCALE=3" TIMEOUT 180)
    endif()
    add_test(NAME allocation_contracts COMMAND lumtail_allocations 100)
    set_tests_properties(allocation_contracts PROPERTIES TIMEOUT 60)
  endif()
endif()

if(LUMTAIL_FUZZING)
  add_subdirectory(fuzz)
endif()

install(TARGETS lumtail RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY contracts/cli/v1 DESTINATION ${CMAKE_INSTALL_DATADIR}/lumtail/contracts/cli)
install(DIRECTORY contracts/cli/v1-auditd-raw DESTINATION ${CMAKE_INSTALL_DATADIR}/lumtail/contracts/cli)
install(DIRECTORY contracts/cli/v1-pipeline-assertions DESTINATION ${CMAKE_INSTALL_DATADIR}/lumtail/contracts/cli)
install(DIRECTORY contracts/cli/v1-security-json DESTINATION ${CMAKE_INSTALL_DATADIR}/lumtail/contracts/cli)
install(DIRECTORY contracts/cli/v1-json-records DESTINATION ${CMAKE_INSTALL_DATADIR}/lumtail/contracts/cli)
install(FILES README.md CONTRIBUTING.md LICENSE LICENSING.md contributors.md
  THIRD_PARTY_NOTICES.md
  DESTINATION ${CMAKE_INSTALL_DOCDIR})
install(DIRECTORY assets docs examples DESTINATION ${CMAKE_INSTALL_DOCDIR})
install(DIRECTORY LICENSES DESTINATION ${CMAKE_INSTALL_DOCDIR})

if(BUILD_TESTING)
  add_test(NAME license_metadata_contracts
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/license_metadata.py)
  set_tests_properties(license_metadata_contracts PROPERTIES TIMEOUT 30)
  add_test(NAME license_distribution
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/licenses.py
      --cmake ${CMAKE_COMMAND} --build-dir ${CMAKE_BINARY_DIR}
      --doc-dir ${CMAKE_INSTALL_DOCDIR}
      --contract-dir "${CMAKE_INSTALL_DATADIR}/lumtail/contracts/cli" --config $<CONFIG>)
  set_tests_properties(license_distribution PROPERTIES TIMEOUT 60)
endif()
