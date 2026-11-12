# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

include_guard(GLOBAL)
include(FetchContent)

function(lumtail_require_dependency_source name)
  if(NOT FETCHCONTENT_FULLY_DISCONNECTED)
    return()
  endif()
  string(TOUPPER "${name}" upper_name)
  set(override "FETCHCONTENT_SOURCE_DIR_${upper_name}")
  if(DEFINED ${override} AND NOT "${${override}}" STREQUAL "")
    set(source "${${override}}")
  else()
    set(source "${FETCHCONTENT_BASE_DIR}/${name}-src")
  endif()
  # Reject missing offline sources before targets become incomplete.
  if(NOT EXISTS "${source}/CMakeLists.txt")
    message(FATAL_ERROR
      "Offline dependency '${name}' is missing at '${source}'. Install a compatible package or provide -D${override}=/absolute/source/path. FETCHCONTENT_FULLY_DISCONNECTED=ON forbids downloading missing sources.")
  endif()
endfunction()
