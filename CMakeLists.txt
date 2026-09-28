cmake_minimum_required(VERSION 3.10)
project(Dobby)
enable_language(ASM)

if(POLICY CMP0069)
  cmake_policy(SET CMP0069 NEW)
endif()

if(DEFINED API)
  set(DOBBY_ANDROID_API "${API}")
endif()

if(DEFINED CORE_ROOT)
  set(DOBBY_CORE_ROOT "${CORE_ROOT}")
endif()

include(cmake/Util.cmake)
include(cmake/Macros.cmake)
include(cmake/build_environment_check.cmake)
include(cmake/auto_source_group.cmake)
include(cmake/xcode_generator_helper.cmake)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

auto_source_group("." "auto-source-group" "\\.(cc|cpp|c|h)$")

# ===== handle option =====

option(DOBBY_GENERATE_SHARED "Build shared library" ON)

option(DOBBY_DEBUG "Enable debug logging" OFF)

option(NearBranch "Enable near branch trampoline" ON)

option(FullFloatingPointRegisterPack "Save and pack all floating-point registers" OFF)

option(Plugin.SymbolResolver "Enable symbol resolver" ON)

option(Plugin.ImportTableReplace "Enable import table replace " OFF)

option(Plugin.Android.BionicLinkerUtil "Enable android bionic linker util" OFF)

option(BUILD_EXAMPLE "Build example" OFF)

option(BUILD_TEST "Build test" OFF)

# private
option(Obfuscation "Enable llvm obfuscation" OFF)

# private
option(BUILD_KERNEL_MODE "Build xnu kernel mode" OFF)

# Enable debug will log more information
if ((NOT DEFINED CMAKE_BUILD_TYPE) OR (CMAKE_BUILD_TYPE STREQUAL "Debug"))
  set(DOBBY_DEBUG ON)
endif ()

if (DOBBY_DEBUG)
  add_definitions(-DDOBBY_DEBUG)
  add_definitions(-DLOGGING_DEBUG)
  message(STATUS "[Dobby] Enable debug logging")
endif ()

# Enable full floating point register pack
# for arm64, allow access q8 - q31
if (FullFloatingPointRegisterPack)
  add_definitions(-DFULL_FLOATING_POINT_REGISTER_PACK)
  message(STATUS "[Dobby] Save and pack all floating-point registers")
endif ()

if (BUILD_KERNEL_MODE)
  set(BUILDING_KERNEL ON)
  add_definitions(-DBUILDING_KERNEL)
  message(STATUS "[Dobby] Build xnu kernel mode")
endif ()

if (CMAKE_GENERATOR STREQUAL Xcode)
endif ()

include(cmake/compiler_and_linker.cmake)

# ---

include_directories(
  .
  ./include
  ./source
  ./source/include

  ./external
  ./external/logging

  ./builtin-plugin
)

if (SYSTEM.Darwin AND BUILDING_KERNEL)
  include_directories(
    source/Backend/KernelMode
  )
else ()
  include_directories(
    source/Backend/UserMode
  )
endif ()

# ---

set(DOBBY_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(dobby.SOURCE_FILE_LIST ${dobby.SOURCE_FILE_LIST}
  # cpu
  source/core/arch/CpuFeature.cc
  source/core/arch/CpuRegister.cc

  # assembler
  source/core/assembler/assembler.cc
  source/core/assembler/assembler-arm.cc
  source/core/assembler/assembler-arm64.cc
  source/core/assembler/assembler-ia32.cc
  source/core/assembler/assembler-x64.cc

  # codegen
  source/core/codegen/codegen-arm.cc
  source/core/codegen/codegen-arm64.cc
  source/core/codegen/codegen-ia32.cc
  source/core/codegen/codegen-x64.cc

  # memory kit
  source/MemoryAllocator/CodeBuffer/CodeBufferBase.cc
  source/MemoryAllocator/AssemblyCodeBuilder.cc
  source/MemoryAllocator/MemoryAllocator.cc

  # instruction relocation
  source/InstructionRelocation/arm/InstructionRelocationARM.cc
  source/InstructionRelocation/arm64/InstructionRelocationARM64.cc
  source/InstructionRelocation/x86/InstructionRelocationX86.cc
  source/InstructionRelocation/x86/InstructionRelocationX86Shared.cc
  source/InstructionRelocation/x64/InstructionRelocationX64.cc
  source/InstructionRelocation/x86/x86_insn_decode/x86_insn_decode.c

  # intercept routing
  source/InterceptRouting/InterceptRouting.cpp

  # intercept routing trampoline
  source/TrampolineBridge/Trampoline/arm/trampoline_arm.cc
  source/TrampolineBridge/Trampoline/arm64/trampoline_arm64.cc
  source/TrampolineBridge/Trampoline/x86/trampoline_x86.cc
  source/TrampolineBridge/Trampoline/x64/trampoline_x64.cc

  # closure trampoline bridge - arm
  source/TrampolineBridge/ClosureTrampolineBridge/common_bridge_handler.cc
  source/TrampolineBridge/ClosureTrampolineBridge/arm/helper_arm.cc
  source/TrampolineBridge/ClosureTrampolineBridge/arm/closure_bridge_arm.cc
  source/TrampolineBridge/ClosureTrampolineBridge/arm/ClosureTrampolineARM.cc
  # closure trampoline bridge - arm64
  source/TrampolineBridge/ClosureTrampolineBridge/arm64/helper_arm64.cc
  source/TrampolineBridge/ClosureTrampolineBridge/arm64/closure_bridge_arm64.cc
  source/TrampolineBridge/ClosureTrampolineBridge/arm64/ClosureTrampolineARM64.cc
  # closure trampoline bridge - x86
  source/TrampolineBridge/ClosureTrampolineBridge/x86/helper_x86.cc
  source/TrampolineBridge/ClosureTrampolineBridge/x86/closure_bridge_x86.cc
  source/TrampolineBridge/ClosureTrampolineBridge/x86/ClosureTrampolineX86.cc
  # closure trampoline bridge - x64
  source/TrampolineBridge/ClosureTrampolineBridge/x64/helper_x64.cc
  source/TrampolineBridge/ClosureTrampolineBridge/x64/closure_bridge_x64.cc
  source/TrampolineBridge/ClosureTrampolineBridge/x64/ClosureTrampolineX64.cc

  source/InterceptRouting/Routing/InstructionInstrument/InstructionInstrument.cc
  source/InterceptRouting/Routing/InstructionInstrument/RoutingImpl.cc
  source/InterceptRouting/Routing/InstructionInstrument/instrument_routing_handler.cc

  source/InterceptRouting/Routing/FunctionInlineHook/FunctionInlineHook.cc
  source/InterceptRouting/Routing/FunctionInlineHook/RoutingImpl.cc

  # plugin register
  source/InterceptRouting/RoutingPlugin/RoutingPlugin.cc

  # main
  source/dobby.cpp
  source/Interceptor.cpp
  source/InterceptEntry.cpp
  )

if (SYSTEM.Darwin AND BUILDING_KERNEL)
  set(dobby.SOURCE_FILE_LIST ${dobby.SOURCE_FILE_LIST}
    # platform util
    source/Backend/KernelMode/PlatformUtil/Darwin/ProcessRuntimeUtility.cc

    # kernel mode - platform interface
    source/Backend/KernelMode/UnifiedInterface/platform-darwin.cc
    source/Backend/KernelMode/UnifiedInterface/exec_mem_placeholder.asm

    # kernel mode - executable memory
    source/Backend/KernelMode/ExecMemory/code-patch-tool-darwin.cc
    source/Backend/KernelMode/ExecMemory/clear-cache-tool-all.c
    )
elseif (SYSTEM.Darwin)
  set(dobby.SOURCE_FILE_LIST ${dobby.SOURCE_FILE_LIST}
    # platform util
    source/Backend/UserMode/PlatformUtil/Darwin/ProcessRuntimeUtility.cc

    # user mode - platform interface
    source/Backend/UserMode/UnifiedInterface/platform-posix.cc

    # user mode - executable memory
    source/Backend/UserMode/ExecMemory/code-patch-tool-darwin.cc
    source/Backend/UserMode/ExecMemory/clear-cache-tool-all.c
    )

elseif (SYSTEM.Linux OR SYSTEM.Android)
  set(dobby.SOURCE_FILE_LIST ${dobby.SOURCE_FILE_LIST}
    # platform util
    source/Backend/UserMode/PlatformUtil/Linux/ProcessRuntimeUtility.cc

    # user mode - platform interface
    source/Backend/UserMode/UnifiedInterface/platform-posix.cc

    # user mode - executable memory
    source/Backend/UserMode/ExecMemory/code-patch-tool-posix.cc
    source/Backend/UserMode/ExecMemory/clear-cache-tool-all.c
    )
elseif (SYSTEM.Windows)
  set(dobby.SOURCE_FILE_LIST ${dobby.SOURCE_FILE_LIST}
    # platform util
    source/Backend/UserMode/PlatformUtil/Windows/ProcessRuntimeUtility.cc

    # user mode - platform interface
    source/Backend/UserMode/UnifiedInterface/platform-windows.cc

    # user mode - executable memory
    source/Backend/UserMode/ExecMemory/code-patch-tool-windows.cc
    source/Backend/UserMode/ExecMemory/clear-cache-tool-all.c
    )
endif ()

if (PROCESSOR.X86_64 OR PROCESSOR.X86)
  set(NearBranch ON)
endif ()

# ---

if (0 AND SYSTEM.iOS AND (NOT BUILDING_KERNEL))
  include_directories(
    source/Backend/UserMode/ExecMemory/substrated
  )
  add_definitions(-DCODE_PATCH_WITH_SUBSTRATED)
  set(dobby.SOURCE_FILE_LIST ${dobby.SOURCE_FILE_LIST}
    source/Backend/UserMode/ExecMemory/substrated/mach_interface_support
    )
endif ()

# ----- instrument -----

if (FunctionWrapper)
  set(dobby.SOURCE_FILE_LIST ${dobby.SOURCE_FILE_LIST}
    # user mode - multi thread support
    # source/UserMode/MultiThreadSupport/ThreadSupport.cpp
    # source/UserMode/Thread/PlatformThread.cc
    # source/UserMode/Thread/platform-thread-${platform1}.cc
    )
  message(FATAL_ERROR "[!] FunctionWrapper plugin is not supported")
endif ()

# ---

if (PROCESSOR.AARCH64 OR NearBranch)
  # ARM64 instruction relocation uses near executable memory for the
  # register-transparent branch back to the original function. Keep the
  # allocator available even when the optional near-branch routing plugin is
  # disabled.
  set(dobby.SOURCE_FILE_LIST ${dobby.SOURCE_FILE_LIST}
    source/MemoryAllocator/NearMemoryAllocator.cc)
endif ()

if (NearBranch)
  message(STATUS "[Dobby] Enable near branch trampoline")
  set(dobby.SOURCE_FILE_LIST ${dobby.SOURCE_FILE_LIST}
    source/InterceptRouting/RoutingPlugin/NearBranchTrampoline/near_trampoline_arm64.cc
    source/InterceptRouting/RoutingPlugin/NearBranchTrampoline/NearBranchTrampoline.cc)
endif ()

# ---

# add logging library
add_subdirectory(external/logging)
get_target_property(logging.SOURCE_FILE_LIST logging SOURCES)

# ---

if (Plugin.SymbolResolver)
  message(STATUS "[Dobby] Enable symbol resolver")
  include_directories(builtin-plugin/SymbolResolver)
  add_subdirectory(builtin-plugin/SymbolResolver)
  get_target_property(symbol_resolver.SOURCE_FILE_LIST symbol_resolver SOURCES)
  set(dobby.plugin.SOURCE_FILE_LIST ${dobby.plugin.SOURCE_FILE_LIST}
    ${symbol_resolver.SOURCE_FILE_LIST}
    )
endif ()

# ---

set(dobby.HEADER_FILE_LIST
  include/dobby.h
  )

# ---

# add build version
if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/.git")
  execute_process(
    COMMAND git rev-parse --short --verify HEAD
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    OUTPUT_VARIABLE VERSION_COMMIT_HASH
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
  if (VERSION_COMMIT_HASH)
    set(VERSION_REVISION "${VERSION_COMMIT_HASH}")
  endif ()
endif ()
set(DOBBY_BUILD_VERSION "Dobby${VERSION_REVISION}")
add_definitions(-D__DOBBY_BUILD_VERSION__="${DOBBY_BUILD_VERSION}")
message(STATUS "[Dobby] ${DOBBY_BUILD_VERSION}")

# ---

if (DOBBY_GENERATE_SHARED)
  message(STATUS "[Dobby] Generate shared library")
  set(DOBBY_LIBRARY_TYPE SHARED)
else ()
  message(STATUS "[Dobby] Generate static library")
  set(DOBBY_LIBRARY_TYPE STATIC)
endif ()
add_library(dobby ${DOBBY_LIBRARY_TYPE} ${dobby.HEADER_FILE_LIST} ${dobby.SOURCE_FILE_LIST} ${logging.SOURCE_FILE_LIST} ${misc_helper.SOURCE_FILE_LIST} ${dobby.plugin.SOURCE_FILE_LIST})

# ---

target_include_directories(dobby PUBLIC include)

# ---

if (Obfuscation)
  set(linker_flags "${linker_flags} -Wl,-mllvm -Wl,-obfuscator-conf=all")
endif ()

set_target_properties(dobby
  PROPERTIES
  LINK_FLAGS "${linker_flags}"
  COMPILE_FLAGS "${compiler_flags}"
  )

# ---

if (SYSTEM.Android)
  target_link_libraries(dobby log)
  if (PROCESSOR.ARM)
    set_target_properties(dobby
      PROPERTIES
      ANDROID_ARM_MODE arm
      )
  endif ()
endif ()

if (SYSTEM.Linux)
  target_link_libraries(dobby dl)
endif ()

# ---

if (BUILD_EXAMPLE AND (NOT BUILDING_KERNEL))
  add_subdirectory(examples)
endif ()

if (BUILD_TEST AND (NOT BUILDING_KERNEL))
  enable_testing()
  add_subdirectory(tests)
endif ()

# Small host regressions do not require the optional Unicorn/Capstone packages.
option(DOBBY_REGRESSION_TESTS "Build standalone correctness regressions" OFF)
if (DOBBY_REGRESSION_TESTS AND SYSTEM.Linux AND NOT BUILDING_KERNEL)
  enable_testing()
  add_executable(dobby_regression_memory tests/regression_memory.cpp)
  target_link_libraries(dobby_regression_memory PRIVATE dobby)
  add_test(NAME regression_tinystl COMMAND dobby_regression_memory tinystl)
  add_test(NAME regression_data_arena COMMAND dobby_regression_memory data)
  add_test(NAME regression_exec_alignment COMMAND dobby_regression_memory exec-align)
  add_test(NAME regression_near_data COMMAND dobby_regression_memory near)
  add_test(NAME regression_near_failure COMMAND dobby_regression_memory near-fail)
  add_test(NAME regression_near_no_overwrite COMMAND dobby_regression_memory fixed-map)
  add_test(NAME regression_near_data_reuse COMMAND dobby_regression_memory near-data-reuse)
  add_executable(dobby_regression_patch tests/regression_patch.cpp)
  target_link_libraries(dobby_regression_patch PRIVATE dobby)
  target_link_options(dobby_regression_patch PRIVATE "-Wl,--wrap=mprotect")
  add_test(NAME regression_patch_two_pages COMMAND dobby_regression_patch two)
  add_test(NAME regression_patch_three_pages COMMAND dobby_regression_patch three)
  add_test(NAME regression_patch_restore_failure COMMAND dobby_regression_patch restore)
  add_test(NAME regression_patch_preserve_rw COMMAND dobby_regression_patch rw)
  add_test(NAME regression_patch_mixed_permissions COMMAND dobby_regression_patch mixed)
  add_executable(dobby_regression_maps tests/regression_maps.cpp)
  target_link_libraries(dobby_regression_maps PRIVATE dobby)
  target_link_options(dobby_regression_maps PRIVATE "-Wl,--wrap=fopen" "-Wl,--wrap=qsort")
  add_test(NAME regression_maps_empty COMMAND dobby_regression_maps empty)
  add_executable(dobby_review_edges tests/review_edge_cases.cpp)
  target_link_libraries(dobby_review_edges PRIVATE dobby)
  foreach(edge patch3 permissions near-data)
    add_test(NAME review_${edge} COMMAND dobby_review_edges ${edge})
  endforeach()
  if (PROCESSOR.X86_64)
    foreach(edge loopnz-prefix loopnz-redzone loopnz-intra)
      add_test(NAME review_${edge} COMMAND dobby_review_edges ${edge})
    endforeach()
  endif()
  add_test(NAME regression_maps_permissions COMMAND dobby_regression_maps permissions)
  add_executable(dobby_regression_lifecycle tests/regression_lifecycle.cpp)
  target_link_libraries(dobby_regression_lifecycle PRIVATE dobby)
  add_test(NAME regression_failed_hook_output COMMAND dobby_regression_lifecycle hook)
  add_test(NAME regression_failed_destroy COMMAND dobby_regression_lifecycle destroy)
  add_test(NAME regression_hook_roundtrip COMMAND dobby_regression_lifecycle roundtrip)
  add_test(NAME regression_hook_duplicate COMMAND dobby_regression_lifecycle duplicate)
  add_test(NAME regression_hook_reinstall COMMAND dobby_regression_lifecycle reinstall)
  add_test(NAME regression_hook_transaction_race COMMAND dobby_regression_lifecycle race)
  if (PROCESSOR.X86_64)
    add_executable(dobby_regression_x64 tests/regression_x64.cpp)
    target_link_libraries(dobby_regression_x64 PRIVATE dobby)
    add_test(NAME regression_x64 COMMAND dobby_regression_x64)
    add_test(NAME regression_sse COMMAND dobby_regression_x64 sse)
    add_test(NAME regression_x64_loopnz COMMAND dobby_regression_x64 loopnz)
    add_test(NAME regression_x64_jecxz COMMAND dobby_regression_x64 jcxz)
  endif ()
endif ()

# Explicit opt-in: executable integration fixture for native ARM64 devices.
option(DOBBY_ANDROID_ARM64_REVIEW_TEST "Build ARM64 inline hook/original roundtrip fixture" OFF)
if (DOBBY_ANDROID_ARM64_REVIEW_TEST)
  if (NOT ANDROID OR NOT CMAKE_ANDROID_ARCH_ABI STREQUAL "arm64-v8a")
    message(FATAL_ERROR "DOBBY_ANDROID_ARM64_REVIEW_TEST requires Android arm64-v8a")
  endif ()
  add_executable(dobby_android_arm64_review tests/review_android_arm64.cpp)
  target_link_libraries(dobby_android_arm64_review PRIVATE dobby log dl)
endif ()

# ---

if (SYSTEM.Darwin AND (NOT BUILDING_KERNEL))
  include(cmake/platform/platform-darwin.cmake)
endif ()
