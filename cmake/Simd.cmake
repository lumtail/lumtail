# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

include_guard(GLOBAL)

option(LUMTAIL_SIMD "Enable portable SIMD kernels with runtime CPU dispatch" ON)
option(LUMTAIL_SYSTEM_HIGHWAY "Use a compatible installed Highway instead of the pinned static dependency" OFF)
if(LUMTAIL_SIMD)
  if(LUMTAIL_SYSTEM_HIGHWAY AND NOT (LUMTAIL_SANITIZERS OR LUMTAIL_FUZZING OR LUMTAIL_THREAD_SANITIZER OR LUMTAIL_COVERAGE))
    find_package(hwy 1.4 CONFIG QUIET)
  endif()
  if(NOT TARGET hwy::hwy)
    include(FetchContent)
    set(HWY_ENABLE_CONTRIB OFF CACHE BOOL "" FORCE)
    set(HWY_ENABLE_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(HWY_ENABLE_TESTS OFF CACHE BOOL "" FORCE)
    set(HWY_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
    set(HWY_FORCE_STATIC_LIBS ON CACHE BOOL "" FORCE)
    # Keep optional vector flags out of the CPU baseline.
    set(HWY_CMAKE_RVV OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(hwy
      URL https://codeload.github.com/google/highway/tar.gz/refs/tags/1.4.0
      URL_HASH SHA256=e72241ac9524bb653ae52ced768b508045d4438726a303f10181a38f764a453c
      DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
    lumtail_require_dependency_source(hwy)
    FetchContent_MakeAvailable(hwy)
    # Link sanitizer runtimes on upstream diagnostic targets too.
    foreach(dependency_target IN ITEMS hwy hwy_test hwy_list_targets)
      if(TARGET ${dependency_target})
        target_link_libraries(${dependency_target} PRIVATE lumtail_instrumentation)
      endif()
    endforeach()
    if(NOT TARGET hwy::hwy)
      add_library(hwy::hwy ALIAS hwy)
    endif()
  endif()

  include(CMakePushCheckState)
  function(lumtail_probe_portable_simd)
    # Compile an archive because Debug headers reference abort().
    set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
    cmake_push_check_state(RESET)
    get_target_property(lumtail_hwy_imported hwy::hwy IMPORTED)
    if(lumtail_hwy_imported)
      set(CMAKE_REQUIRED_LIBRARIES hwy::hwy)
    else()
      # Probe headers because the dependency target is not built yet.
      set(CMAKE_REQUIRED_INCLUDES "${hwy_SOURCE_DIR}")
      get_target_property(lumtail_hwy_definitions hwy::hwy INTERFACE_COMPILE_DEFINITIONS)
      foreach(definition IN LISTS lumtail_hwy_definitions)
        list(APPEND CMAKE_REQUIRED_DEFINITIONS "-D${definition}")
      endforeach()
    endif()
    set(CMAKE_REQUIRED_FLAGS "-fno-exceptions")
    check_cxx_source_compiles("
      #include <hwy/highway.h>
      #include <cstdint>
      int main() {
        namespace hn = hwy::HWY_NAMESPACE;
        const hn::ScalableTag<std::uint8_t> d;
        const auto bytes = hn::Set(d, std::uint8_t{32});
        return hn::FindFirstTrue(d, hn::Eq(bytes, bytes)) < 0;
      }
    " LUMTAIL_HAS_PORTABLE_SIMD)
    cmake_pop_check_state()
  endfunction()
  lumtail_probe_portable_simd()
  if(NOT LUMTAIL_HAS_PORTABLE_SIMD)
    message(FATAL_ERROR "The selected Highway/toolchain cannot compile the required byte kernels; use LUMTAIL_SIMD=OFF for the scalar build.")
  endif()
endif()
