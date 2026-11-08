# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

# An external runner can supply an archive or compiler link arguments, including
# OSS-Fuzz's LIB_FUZZING_ENGINE. Keep the compiler-provided runtime as the default.
set(LUMTAIL_FUZZING_ENGINE "" CACHE STRING "External libFuzzer archive or link arguments")
if(LUMTAIL_FUZZING_ENGINE)
  separate_arguments(lumtail_fuzzing_engine NATIVE_COMMAND "${LUMTAIL_FUZZING_ENGINE}")
else()
  set(lumtail_fuzzing_engine -fsanitize=fuzzer)
endif()

# Probe the selected runtime instead of assuming every Clang ships libFuzzer.
include(CMakePushCheckState)
cmake_push_check_state(RESET)
if(NOT LUMTAIL_EXTERNAL_FUZZING)
  set(CMAKE_REQUIRED_FLAGS "-fsanitize=fuzzer-no-link,${LUMTAIL_SANITIZER_SET}")
endif()
set(CMAKE_REQUIRED_LIBRARIES ${lumtail_fuzzing_engine})
# A reconfigure may select a different engine or instrumentation flags.
unset(LUMTAIL_HAS_LIBFUZZER CACHE)
check_cxx_source_compiles("
  #include <cstddef>
  #include <cstdint>
  extern \"C\" int LLVMFuzzerTestOneInput(const std::uint8_t*, std::size_t) { return 0; }
" LUMTAIL_HAS_LIBFUZZER)
cmake_pop_check_state()
if(NOT LUMTAIL_HAS_LIBFUZZER)
  message(FATAL_ERROR "The selected libFuzzer runtime cannot link. Install compiler-rt or set LUMTAIL_FUZZING_ENGINE to compatible link arguments.")
endif()

foreach(name IN ITEMS parser pattern rules stream agent filter scan renderer)
  add_executable(fuzz_${name} ${name}.cpp)
  target_link_libraries(fuzz_${name} PRIVATE lumtail_core ${lumtail_fuzzing_engine})
  if(BUILD_TESTING)
    add_test(NAME fuzz_${name}_seeds COMMAND fuzz_${name}
      -runs=0 "${CMAKE_CURRENT_SOURCE_DIR}/corpus/${name}")
    set_tests_properties(fuzz_${name}_seeds PROPERTIES TIMEOUT 60)
  endif()
endforeach()
