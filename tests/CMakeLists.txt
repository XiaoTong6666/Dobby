
find_package(PkgConfig REQUIRED)
pkg_check_modules(CAPSTONE REQUIRED capstone)
message(STATUS "Capstone libraries: " ${CAPSTONE_LIBRARY_DIRS})
message(STATUS "Capstone includes: " ${CAPSTONE_INCLUDE_DIRS})

pkg_check_modules(UNICORN REQUIRED unicorn)
message(STATUS "unicorn libraries: " ${UNICORN_LIBRARY_DIRS})
message(STATUS "unicorn includes: " ${UNICORN_INCLUDE_DIRS})

get_property(DOBBY_SOURCE_FILE_LIST
  TARGET dobby
  PROPERTY SOURCES)

set(DOBBY_SOURCES)
foreach (path ${DOBBY_SOURCE_FILE_LIST})
  if (NOT path MATCHES "^/")
    list(APPEND DOBBY_SOURCES ${DOBBY_DIR}/${path})
  else ()
    list(APPEND DOBBY_SOURCES ${path})
  endif ()
endforeach ()


add_executable(test_insn_relo_arm64
  test_insn_relo_arm64.cpp
  UniconEmulator.cpp
  ${DOBBY_SOURCES}
  )

target_compile_definitions(test_insn_relo_arm64 PUBLIC
  LOGGING_DEBUG=1
  DISABLE_ARCH_DETECT=1
  TARGET_ARCH_ARM64=1
  TEST_WITH_UNICORN=1
  )

target_include_directories(test_insn_relo_arm64 PUBLIC
  ${CAPSTONE_INCLUDE_DIRS}
  ${UNICORN_INCLUDE_DIRS}
  )

target_link_directories(test_insn_relo_arm64 PUBLIC
  ${CAPSTONE_LIBRARY_DIRS}
  ${UNICORN_LIBRARY_DIRS}
  )

target_link_libraries(test_insn_relo_arm64 PUBLIC
  ${CAPSTONE_LIBRARIES}
  ${UNICORN_LIBRARIES}
  )

# ---

add_executable(test_insn_relo_arm
  test_insn_relo_arm.cpp
  UniconEmulator.cpp
  ${DOBBY_SOURCES}
  )

target_compile_definitions(test_insn_relo_arm PUBLIC
  LOGGING_DEBUG=1
  DISABLE_ARCH_DETECT=1
  TARGET_ARCH_ARM=1
  TEST_WITH_UNICORN=1
  )

target_include_directories(test_insn_relo_arm PUBLIC
  ${CAPSTONE_INCLUDE_DIRS}
  ${UNICORN_INCLUDE_DIRS}
  )

target_link_directories(test_insn_relo_arm PUBLIC
  ${CAPSTONE_LIBRARY_DIRS}
  ${UNICORN_LIBRARY_DIRS}
  )

target_link_libraries(test_insn_relo_arm PUBLIC
  ${CAPSTONE_LIBRARIES}
  ${UNICORN_LIBRARIES}
  )

# ---

add_executable(test_insn_relo_x64
  test_insn_relo_x64.cpp
  UniconEmulator.cpp
  ${DOBBY_SOURCES}
  )

target_compile_definitions(test_insn_relo_x64 PUBLIC
  LOGGING_DEBUG=1
  DISABLE_ARCH_DETECT=1
  TARGET_ARCH_X64=1
  TEST_WITH_UNICORN=1
  # TARGET_ARCH_IA32=1
  )

target_include_directories(test_insn_relo_x64 PUBLIC
  ${CAPSTONE_INCLUDE_DIRS}
  ${UNICORN_INCLUDE_DIRS}
  )

target_link_directories(test_insn_relo_x64 PUBLIC
  ${CAPSTONE_LIBRARY_DIRS}
  ${UNICORN_LIBRARY_DIRS}
  )

target_link_libraries(test_insn_relo_x64 PUBLIC
  ${CAPSTONE_LIBRARIES}
  ${UNICORN_LIBRARIES}
  )

# The existing emulator callbacks use Clang Blocks, not C++ lambdas.
foreach (relo_test test_insn_relo_arm64 test_insn_relo_arm test_insn_relo_x64)
  target_compile_options(${relo_test} PRIVATE -fblocks)
endforeach ()

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
  find_library(BLOCKS_RUNTIME_LIBRARY NAMES BlocksRuntime)
  if (BLOCKS_RUNTIME_LIBRARY)
    foreach (relo_test test_insn_relo_arm64 test_insn_relo_arm test_insn_relo_x64)
      target_link_libraries(${relo_test} PUBLIC ${BLOCKS_RUNTIME_LIBRARY})
    endforeach ()
  endif ()
endif ()

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
  add_test(NAME unicorn_arm64 COMMAND test_insn_relo_arm64)
  add_test(NAME unicorn_arm64_x17 COMMAND test_insn_relo_arm64 --x17-branch)
  add_test(NAME unicorn_arm64_x17_matrix COMMAND test_insn_relo_arm64 --x17-matrix)
  add_test(NAME unicorn_arm64_intra_prologue COMMAND test_insn_relo_arm64 --intra-prologue)
  add_test(NAME unicorn_arm64_out_of_range COMMAND test_insn_relo_arm64 --out-of-range)
  add_test(NAME unicorn_arm64_adr_backward_rejected COMMAND test_insn_relo_arm64 --adr-backward-rejected)
  add_test(NAME unicorn_arm64_inline_literal COMMAND test_insn_relo_arm64 --inline-literal)
  add_test(NAME unicorn_arm32_thumb COMMAND test_insn_relo_arm)
  add_test(NAME unicorn_x64_rip COMMAND test_insn_relo_x64)
  add_test(NAME unicorn_x64_unreachable_rip COMMAND test_insn_relo_x64 --unreachable-rip)
endif ()

# ---

if (Plugin.SymbolResolver)
  add_executable(test_native
    test_native.cpp)
  target_link_libraries(test_native dobby)
endif ()
