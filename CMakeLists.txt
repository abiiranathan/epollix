cmake_minimum_required(VERSION 3.30.0)
project(epollix VERSION 0.1.0 LANGUAGES C)

# -----------------------------------------------------------------------------
# Global Project Settings
# -----------------------------------------------------------------------------
set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_VERBOSE_MAKEFILE ON)

# Add these to supress warnings about exec stack
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--no-warn-execstack")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--no-warn-execstack")
set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} -Wl,--no-warn-execstack")

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# Add additional module search path
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# -----------------------------------------------------------------------------
# External Dependencies
# -----------------------------------------------------------------------------
include(GNUInstallDirs)
include(CTest)
include(FetchContent)
include(ExternalProject)

enable_testing()

# Option to build tests (default ON)
option(BUILD_TESTS "Build the tests" ON)

# -----------------------------------------------------------------------------
# Find or Download Solidc
# -----------------------------------------------------------------------------
# Try to find an existing installation of solidc
find_package(solidc QUIET)

if(NOT solidc_FOUND)
  message(STATUS "solidc not found. Downloading solidc from GitHub...")

  FetchContent_Declare(
    solidc
    GIT_REPOSITORY https://github.com/abiiranathan/solidc.git
    GIT_TAG main
  )
  FetchContent_MakeAvailable(solidc)
endif()


# -----------------------------------------------------------------------------
# Find Cipherkit using pkg-config
# -----------------------------------------------------------------------------
find_package(PkgConfig REQUIRED)
pkg_check_modules(CIPHERKIT cipherkit)

if(CIPHERKIT_FOUND)
  message(STATUS "Cipherkit found, middleware and example will be built")
endif()

# -----------------------------------------------------------------------------
# Add External Libraries (deps)
# -----------------------------------------------------------------------------
add_subdirectory(deps/libbcrypt)

# -----------------------------------------------------------------------------
# Define Source and Header Files
# -----------------------------------------------------------------------------
set(SOURCES
  src/header.c
  src/method.c
  src/middleware.c
  src/mime.c
  src/multipart.c
  src/net.c
  src/params.c
  src/request.c
  src/response.c
  src/route.c
  src/server.c
  src/static.c
  src/status.c
  src/taskpool.c
  src/url.c
  src/fast_str.c
)

if(CIPHERKIT_FOUND)
  list(APPEND SOURCES
    src/middleware/basicauth.c
    src/middleware/logger.c
    src/middleware/tokenauth.c
  )
endif()

set(HEADERS
  include/constants.h
  include/defer.h
  include/net.h
  include/logging.h
  include/method.h
  include/header.h
  include/mime.h
  include/multipart.h
  include/params.h
  include/status.h
  include/header.h
  include/middleware.h
  include/request.h
  include/route.h
  include/static.h
  include/response.h
  include/server.h
  include/epollix.h
  include/taskpool.h
  include/url.h
  include/fast_str.h
)

# Conditionally add automem.h for GCC/Clang (when not in C++ mode)
if(CMAKE_C_COMPILER_ID STREQUAL "GNU" OR CMAKE_C_COMPILER_ID STREQUAL "Clang")
  if(NOT CMAKE_CXX_COMPILER_ID)
    list(APPEND HEADERS include/automem.h)
  endif()
endif()

if(CIPHERKIT_FOUND)
  list(APPEND HEADERS
    include/middleware/basicauth.h
    include/middleware/logger.h
    include/middleware/tokenauth.h
  )
endif()

# -----------------------------------------------------------------------------
# Create Library Target
# -----------------------------------------------------------------------------
add_library(epollix ${SOURCES})

# Link public libraries and dependencies
target_link_libraries(epollix PUBLIC
  m
  z
  pthread
  bcrypt
  atomic
  solidc
)



if(CIPHERKIT_FOUND)
  target_link_libraries(epollix PUBLIC ${CIPHERKIT_LIBRARIES} cipherkit)

  # variable for the .pc file
  set(CIPHERKIT_LIBRARIES_PC "-lcipherkit -lssl -lcrypto -lsodium -lcjson")
endif()

# -----------------------------------------------------------------------------
# Compiler Options & Platform Specific Settings
# -----------------------------------------------------------------------------
target_compile_options(epollix PUBLIC -Wall -Wextra -Werror -mavx2 -mfma -mtune=native -march=native)

if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
  target_compile_options(epollix PUBLIC -Wno-gnu-zero-variadic-macro-arguments -fblocks)
  target_link_libraries(epollix PUBLIC BlocksRuntime)
elseif(CMAKE_C_COMPILER_ID STREQUAL "GNU")
  if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(epollix PUBLIC -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -fPIC)
  endif()
endif()

# Define public include directories for the target
target_include_directories(epollix PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/epollix>
)

# -----------------------------------------------------------------------------
# Installation Rules
# -----------------------------------------------------------------------------
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/epollix)

install(TARGETS epollix
  EXPORT epollix_export
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(EXPORT epollix_export
  FILE epollixTargets.cmake
  NAMESPACE epollix::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/epollix
)

# -----------------------------------------------------------------------------
# Package Configuration
# -----------------------------------------------------------------------------
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/epollixConfigVersion.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY AnyNewerVersion
)

configure_package_config_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/epollixConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/epollixConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/epollix
)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/epollixConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/epollix
)

# -----------------------------------------------------------------------------
# pkg-config File Generation
# -----------------------------------------------------------------------------
configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/epollix.pc.in
  ${CMAKE_CURRENT_BINARY_DIR}/epollix.pc
  @ONLY
)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/epollix.pc
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)

# -----------------------------------------------------------------------------
# Optional Subdirectories: Tests and Example
# -----------------------------------------------------------------------------
if(BUILD_TESTS AND CIPHERKIT_FOUND)
  add_subdirectory(tests)
endif()

if(CIPHERKIT_FOUND)
  add_subdirectory(example)
endif()
