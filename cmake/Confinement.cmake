# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

include(CheckCXXSourceCompiles)
include(CheckCXXSymbolExists)
include(CMakePushCheckState)

cmake_push_check_state(RESET)
check_cxx_symbol_exists(pledge "unistd.h" LUMTAIL_HAS_PLEDGE)
check_cxx_symbol_exists(unveil "unistd.h" LUMTAIL_HAS_UNVEIL)
check_cxx_symbol_exists(closefrom "unistd.h" LUMTAIL_HAS_CLOSEFROM)
check_cxx_symbol_exists(issetugid "unistd.h" LUMTAIL_HAS_ISSETUGID)
check_cxx_source_compiles("
  #include <sys/resource.h>
  int main() { rlimit limit{}; return getrlimit(RLIMIT_CORE, &limit) + setrlimit(RLIMIT_CORE, &limit); }
" LUMTAIL_HAS_CORE_LIMIT)
check_cxx_source_compiles("
  #include <dirent.h>
  int main() { DIR *d = opendir(\"/dev/fd\"); if (!d) return 0;
    (void)readdir(d); (void)dirfd(d); return closedir(d); }
" LUMTAIL_HAS_FD_DIRECTORY)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  check_cxx_source_compiles("
    #include <linux/audit.h>
    #include <linux/filter.h>
    #include <linux/seccomp.h>
    #include <sys/prctl.h>
    #include <sys/syscall.h>
    #include <unistd.h>
    int main() { sock_fprog p{};
      return static_cast<int>(syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &p)) +
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); }
  " LUMTAIL_HAS_SECCOMP)
  check_cxx_source_compiles("
    #include <fcntl.h>
    #include <linux/landlock.h>
    #include <sys/syscall.h>
    #include <unistd.h>
    int main() { landlock_ruleset_attr r{}; landlock_path_beneath_attr p{};
      (void)LANDLOCK_ACCESS_FS_READ_FILE; (void)LANDLOCK_RULE_PATH_BENEATH; (void)O_PATH;
      return static_cast<int>(syscall(SYS_landlock_create_ruleset, &r, sizeof(r), 0) +
        syscall(SYS_landlock_add_rule, -1, LANDLOCK_RULE_PATH_BENEATH, &p, 0) +
        syscall(SYS_landlock_restrict_self, -1, 0)); }
  " LUMTAIL_HAS_LANDLOCK)
  check_cxx_symbol_exists(getauxval "sys/auxv.h" LUMTAIL_HAS_GETAUXVAL)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
  find_library(LUMTAIL_CASPER_LIBRARY casper)
  find_library(LUMTAIL_FILEARGS_LIBRARY cap_fileargs)
  if(LUMTAIL_CASPER_LIBRARY AND LUMTAIL_FILEARGS_LIBRARY)
    set(CMAKE_REQUIRED_LIBRARIES ${LUMTAIL_FILEARGS_LIBRARY} ${LUMTAIL_CASPER_LIBRARY})
    set(CMAKE_REQUIRED_DEFINITIONS -DWITH_CASPER)
    check_cxx_source_compiles("
      #include <cstdio>
      #include <sys/types.h>
      #include <sys/capsicum.h>
      #include <sys/nv.h>
      #include <sys/stat.h>
      #include <libcasper.h>
      #include <casper/cap_fileargs.h>
      #include <fcntl.h>
      #include <sys/ioctl.h>
      #include <termios.h>
      int main() { cap_rights_t rights;
        cap_rights_init(&rights, CAP_READ, CAP_FSTAT, CAP_SEEK, CAP_EVENT, CAP_FCNTL);
        fileargs_t *f = fileargs_init(0, nullptr, O_RDONLY | O_CLOEXEC, 0, &rights, FA_OPEN | FA_LSTAT);
        struct stat info{}; (void)fileargs_lstat(f, \"\", &info);
        const unsigned long requests[] = {TIOCGETA, FIONREAD};
        (void)cap_ioctls_limit(0, requests, 2);
        (void)cap_fcntls_limit(0, CAP_FCNTL_GETFL);
        unsigned mode = 0; (void)cap_getmode(&mode);
        fileargs_free(f); return cap_enter(); }
    " LUMTAIL_HAS_CAPSICUM_FILEARGS)
  endif()
endif()

if(APPLE)
  find_library(LUMTAIL_SECURITY_FRAMEWORK Security REQUIRED)
  find_library(LUMTAIL_COREFOUNDATION_FRAMEWORK CoreFoundation REQUIRED)
  set(CMAKE_REQUIRED_LIBRARIES ${LUMTAIL_SECURITY_FRAMEWORK} ${LUMTAIL_COREFOUNDATION_FRAMEWORK})
  set(CMAKE_REQUIRED_DEFINITIONS "")
  check_cxx_source_compiles("
    #include <Security/SecTask.h>
    int main() { auto task = SecTaskCreateFromSelf(kCFAllocatorDefault);
      if (task) { auto value = SecTaskCopyValueForEntitlement(task, CFSTR(\"com.apple.security.app-sandbox\"), nullptr);
        if (value) CFRelease(value); CFRelease(task); } return 0; }
  " LUMTAIL_HAS_APP_SANDBOX_STATUS)
  if(LUMTAIL_HAS_APP_SANDBOX_STATUS)
    set(CMAKE_REQUIRED_LIBRARIES ${CMAKE_DL_LIBS})
    check_cxx_source_compiles("
      #include <dlfcn.h>
      #include <Security/SecTask.h>
      int main() {
        auto library = dlopen(\"/System/Library/Frameworks/Security.framework/Security\", RTLD_LAZY | RTLD_LOCAL);
        if (!library) return 1;
        auto create = reinterpret_cast<decltype(&SecTaskCreateFromSelf)>(dlsym(library, \"SecTaskCreateFromSelf\"));
        const bool available = create != nullptr;
        return dlclose(library) == 0 && available ? 0 : 1;
      }
    " LUMTAIL_HAS_DYNAMIC_APP_SANDBOX_STATUS)
  endif()
endif()
cmake_pop_check_state()

set(lumtail_confinement_instrumented OFF)
if(LUMTAIL_SANITIZERS OR LUMTAIL_THREAD_SANITIZER OR LUMTAIL_FUZZING OR LUMTAIL_COVERAGE)
  set(lumtail_confinement_instrumented ON)
endif()
add_library(lumtail_sandbox STATIC src/sandbox.cpp src/sandbox_linux.cpp src/sandbox_apple.cpp)
target_include_directories(lumtail_sandbox PUBLIC include PRIVATE src)
target_link_libraries(lumtail_sandbox PUBLIC lumtail_options lumtail_file_access)
target_compile_definitions(lumtail_sandbox PUBLIC _FILE_OFFSET_BITS=64
  LUMTAIL_HAS_CAPSICUM_FILEARGS=$<BOOL:${LUMTAIL_HAS_CAPSICUM_FILEARGS}>)
target_compile_definitions(lumtail_sandbox PRIVATE
  LUMTAIL_HAS_PLEDGE=$<BOOL:${LUMTAIL_HAS_PLEDGE}>
  LUMTAIL_HAS_UNVEIL=$<BOOL:${LUMTAIL_HAS_UNVEIL}>
  LUMTAIL_HAS_CLOSEFROM=$<BOOL:${LUMTAIL_HAS_CLOSEFROM}>
  LUMTAIL_HAS_ISSETUGID=$<BOOL:${LUMTAIL_HAS_ISSETUGID}>
  LUMTAIL_HAS_CORE_LIMIT=$<BOOL:${LUMTAIL_HAS_CORE_LIMIT}>
  LUMTAIL_HAS_FD_DIRECTORY=$<BOOL:${LUMTAIL_HAS_FD_DIRECTORY}>
  LUMTAIL_HAS_SECCOMP=$<BOOL:${LUMTAIL_HAS_SECCOMP}>
  LUMTAIL_HAS_LANDLOCK=$<BOOL:${LUMTAIL_HAS_LANDLOCK}>
  LUMTAIL_HAS_GETAUXVAL=$<BOOL:${LUMTAIL_HAS_GETAUXVAL}>
  LUMTAIL_HAS_APP_SANDBOX_STATUS=$<BOOL:${LUMTAIL_HAS_APP_SANDBOX_STATUS}>
  LUMTAIL_HAS_DYNAMIC_APP_SANDBOX_STATUS=$<BOOL:${LUMTAIL_HAS_DYNAMIC_APP_SANDBOX_STATUS}>
  LUMTAIL_HAS_O_CLOEXEC=$<BOOL:${LUMTAIL_HAS_O_CLOEXEC}>
  LUMTAIL_CONFINEMENT_INSTRUMENTED=$<BOOL:${lumtail_confinement_instrumented}>
  LUMTAIL_CONFINEMENT_COVERAGE=$<BOOL:${LUMTAIL_COVERAGE}>
  LUMTAIL_CONFINEMENT_BUILD_DIR="${CMAKE_BINARY_DIR}")
if(LUMTAIL_HAS_CAPSICUM_FILEARGS)
  target_compile_definitions(lumtail_sandbox PRIVATE WITH_CASPER)
  target_link_libraries(lumtail_sandbox PRIVATE ${LUMTAIL_FILEARGS_LIBRARY} ${LUMTAIL_CASPER_LIBRARY})
endif()
if(LUMTAIL_HAS_APP_SANDBOX_STATUS)
  if(LUMTAIL_HAS_DYNAMIC_APP_SANDBOX_STATUS)
    target_link_libraries(lumtail_sandbox PRIVATE ${CMAKE_DL_LIBS})
  else()
    target_link_libraries(lumtail_sandbox PRIVATE ${LUMTAIL_SECURITY_FRAMEWORK} ${LUMTAIL_COREFOUNDATION_FRAMEWORK})
  endif()
endif()
