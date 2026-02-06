cmake_minimum_required(VERSION 3.20)
project(BinaryLens VERSION 1.0 LANGUAGES CXX)

# Set architecture for Apple Silicon
if(APPLE)
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")
    set(CMAKE_OSX_ARCHITECTURES "arm64" CACHE STRING "Target architecture" FORCE)
    set(CMAKE_SYSTEM_PROCESSOR "arm64")
    message(STATUS "Configuring for Apple Silicon (ARM64)")
  elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
    set(CMAKE_OSX_ARCHITECTURES "x86_64" CACHE STRING "Target architecture" FORCE)
    message(STATUS "Configuring for Intel macOS (x86_64)")
  endif()
endif()

option(BINARYLENS_EXPERIMENTAL_MACOS "Allow configuring on macOS (still requires porting Win32 APIs)." OFF)

if(CMAKE_SIZEOF_VOID_P LESS 8)
  message(FATAL_ERROR "BinaryLens must be built for 64-bit IDA (set your generator to x64).")
endif()

if(APPLE AND NOT BINARYLENS_EXPERIMENTAL_MACOS)
  message(FATAL_ERROR "BinaryLens currently uses Win32 APIs (registry, windows.h). Enable BINARYLENS_EXPERIMENTAL_MACOS=ON only if you plan to port the code for macOS.")
endif()

if(NOT (WIN32 OR APPLE OR UNIX))
  message(FATAL_ERROR "Unsupported platform. Build on Windows or set BINARYLENS_EXPERIMENTAL_MACOS=ON for macOS porting work.")
endif()

#set(IDA_SDK_ROOT "" CACHE PATH "Path to the IDA SDK root containing include/ and platform-specific lib directory")
set(OPENSSL_ROOT_DIR "" CACHE PATH "Root of your OpenSSL install (forwarded to find_package(OpenSSL))")
set(IDA_SDK_ROOT "./ida-sdk/" CACHE PATH "Path to the IDA SDK root containing include/ and src/lib")
if(NOT IDA_SDK_ROOT)
  message(FATAL_ERROR "Set IDA_SDK_ROOT to your IDA SDK path (e.g. C:/idasdk91/idasdk91 or /Applications/IDA/sdk).")
endif()

find_path(IDA_SDK_INCLUDE_DIR ida.hpp
  PATHS
    "${IDA_SDK_ROOT}/include"
    "${IDA_SDK_ROOT}/src/include"
  NO_DEFAULT_PATH
)
if(NOT IDA_SDK_INCLUDE_DIR)
  message(FATAL_ERROR "Could not find ida.hpp under ${IDA_SDK_ROOT}/include")
endif()

if(WIN32)
  # Windows IDA SDK layout
  find_library(IDA_SDK_LIBRARY
    NAMES ida
    PATHS
      "${IDA_SDK_ROOT}/lib/x64_win_vc_64"
      "${IDA_SDK_ROOT}/src/lib/x64_win_vc_64"
    NO_DEFAULT_PATH
  )
elseif(APPLE)
  # macOS IDA SDK - detect architecture and use appropriate library path
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64" OR CMAKE_OSX_ARCHITECTURES MATCHES "arm64")
    # Apple Silicon (M1/M2/M3)
    find_library(IDA_SDK_LIBRARY
      NAMES ida ida64 libida64
      PATHS
        "${IDA_SDK_ROOT}/src/lib/arm64_mac_clang_64"
        "${IDA_SDK_ROOT}/lib/arm64_mac_clang_64"
        "${IDA_SDK_ROOT}/lib"
      NO_DEFAULT_PATH
    )
    message(STATUS "Using ARM64 macOS IDA SDK library path")
  else()
    # Intel macOS
    find_library(IDA_SDK_LIBRARY
      NAMES ida ida64 libida64
      PATHS
        "${IDA_SDK_ROOT}/src/lib/x64_mac_clang_64"
        "${IDA_SDK_ROOT}/lib/x64_mac_clang_64"
        "${IDA_SDK_ROOT}/lib"
      NO_DEFAULT_PATH
    )
    message(STATUS "Using x64 macOS IDA SDK library path")
  endif()
elseif(UNIX)
  # Linux IDA SDK layout
  find_library(IDA_SDK_LIBRARY
    NAMES ida ida64 libida64 libida
    PATHS
      "${IDA_SDK_ROOT}/src/lib/x64_linux_gcc_64"
      "${IDA_SDK_ROOT}/lib/x64_linux_gcc_64"
      "${IDA_SDK_ROOT}/src/lib"
      "${IDA_SDK_ROOT}/lib"
    NO_DEFAULT_PATH
  )
  message(STATUS "Using Linux IDA SDK library path")
endif()

if(NOT IDA_SDK_LIBRARY)
  message(FATAL_ERROR "Could not find the IDA SDK library (adjust IDA_SDK_ROOT and platform lib path).")
endif()

# Prefer dynamic OpenSSL (matches the original project). Pass OPENSSL_ROOT_DIR if needed.
set(OPENSSL_USE_STATIC_LIBS OFF)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

set(SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_library(BinaryLens SHARED
  ${SRC_DIR}/main.cpp
  ${SRC_DIR}/helper/helper.cpp
  ${SRC_DIR}/helper/helper.h
  ${SRC_DIR}/helper/httplib.h
  ${SRC_DIR}/helper/json.hpp
  ${SRC_DIR}/plugin/action_handler.cpp
  ${SRC_DIR}/plugin/action_handler.h
  ${SRC_DIR}/plugin/plugin.cpp
  ${SRC_DIR}/plugin/plugin.h
)

target_include_directories(BinaryLens
  PRIVATE
    ${SRC_DIR}
    ${SRC_DIR}/helper
    ${SRC_DIR}/plugin
    ${IDA_SDK_INCLUDE_DIR}
)

target_compile_features(BinaryLens PRIVATE cxx_std_17)

if(MSVC)
  # Keep parity with the MSVC project: static CRT and required plugin flags.
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# Suppress IDA SDK warnings that we cannot control
if(APPLE)
  target_compile_options(BinaryLens PRIVATE
    -Wno-nullability-completeness      # IDA SDK pointer nullability warnings
    -Wno-nontrivial-memcall           # IDA SDK memcpy/memmove warnings
    -Wno-varargs                      # IDA SDK va_start warnings
    -Wno-unused-parameter             # Suppress unused parameter warnings
    -Wno-deprecated-declarations      # Suppress deprecated API warnings
  )
endif()

target_compile_definitions(BinaryLens PRIVATE
  _CRT_SECURE_NO_WARNINGS
  _SILENCE_CXX20_IS_POD_DEPRECATION_WARNING
  __EA64__
  CPPHTTPLIB_OPENSSL_SUPPORT
  $<$<PLATFORM_ID:Windows>:WIN32_LEAN_AND_MEAN>
)

if(WIN32)
  target_link_libraries(BinaryLens
    PRIVATE
      ${IDA_SDK_LIBRARY}
      OpenSSL::SSL
      OpenSSL::Crypto
      shlwapi
      advapi32
      ws2_32
      crypt32
  )
elseif(APPLE)
  # Still requires code changes to replace Win32 APIs; link minimal deps for when porting is done.
  target_link_libraries(BinaryLens
    PRIVATE
      ${IDA_SDK_LIBRARY}
      OpenSSL::SSL
      OpenSSL::Crypto
  )

  # Ensure proper ARM64 compilation flags for Apple Silicon
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")
    # Set deployment target to match system and library requirements
    set(CMAKE_OSX_DEPLOYMENT_TARGET "26.0" CACHE STRING "Minimum macOS deployment version" FORCE)

    target_compile_options(BinaryLens PRIVATE
      -arch arm64
      -stdlib=libc++
    )
    target_link_options(BinaryLens PRIVATE
      -arch arm64
      -stdlib=libc++
      -L/opt/homebrew/opt/llvm/lib/c++
      -rpath /opt/homebrew/opt/llvm/lib/c++
    )
  endif()
elseif(UNIX)
  target_link_libraries(BinaryLens
    PRIVATE
      ${IDA_SDK_LIBRARY}
      OpenSSL::SSL
      OpenSSL::Crypto
      Threads::Threads
      dl
  )
endif()

set_target_properties(BinaryLens PROPERTIES
  OUTPUT_NAME "BinaryLens"
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
