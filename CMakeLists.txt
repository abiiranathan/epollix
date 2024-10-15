cmake_minimum_required(VERSION 3.5.0)
project(epollix VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include(GNUInstallDirs)
include(CTest)
enable_testing()

option(BUILD_TESTS "Build the tests" ON)

find_package(solidc REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(CIPHERKIT cipherkit)

if(CIPHERKIT_FOUND)
    message(STATUS "Cipherkit found, middleware and example will be built")
else()
    message(STATUS "Cipherkit not found, middleware and example will not be built")
endif()


# Add libbcrypt
add_subdirectory(deps/libbcrypt)

set(SOURCES
    src/epollix.c
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
)

# Add the middleware sources
if(CIPHERKIT_FOUND)
    list(APPEND SOURCES
        src/middleware/basicauth.c
        src/middleware/logger.c
        src/middleware/tokenauth.c
    )
endif()

# Headers
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
)

# Include "include/automem.h" if using GCC or Clang and not in C++ mode
if(CMAKE_C_COMPILER_ID STREQUAL "GNU" OR CMAKE_C_COMPILER_ID STREQUAL "Clang")
    if(NOT CMAKE_CXX_COMPILER_ID)
        list(APPEND HEADERS include/automem.h)
    endif()
endif()


# Add the middleware headers
if(CIPHERKIT_FOUND)
    list(APPEND HEADERS
        include/middleware/basicauth.h
        include/middleware/logger.h
        include/middleware/tokenauth.h
    )
endif()

# Build the epollix static library
# Can pass -DBUILD_SHARED_LIB to build a shared library
add_library(epollix ${SOURCES})

target_link_libraries(epollix PUBLIC m z pthread bcrypt atomic solidc::solidc)
if(CIPHERKIT_FOUND)
    target_link_libraries(epollix PUBLIC ${CIPHERKIT_LIBRARIES} cipherkit)
    set(CIPHERKIT_LIBRARIES_PC "-lcipherkit -lssl -lcrypto -lsodium -lcjson")
endif()

target_compile_options(epollix PUBLIC -Wall -Wextra -Werror)

# If using clang, add support for -fblocks
# sudo pacman -S libdispatch # provides libBlocksRuntime
# Or sudo apt-get install libblocksruntime-dev
if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
    message(STATUS "Using Clang, adding -fblocks support")
    target_compile_options(epollix PUBLIC -Wno-gnu-zero-variadic-macro-arguments -fblocks)
    target_link_libraries(epollix PUBLIC BlocksRuntime)
elseif(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    # If in release mode, add some security flags
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        message(STATUS "Using GCC, adding security flags")
        target_compile_options(epollix PUBLIC -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -fPIC)
    endif()
endif()

# Include the include directory
target_include_directories(epollix PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include/epollix>
)

# Set the public macros for auto memory management
target_compile_definitions(epollix PUBLIC AUTOMEM_IMPL)

# Install targets
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/epollix)

install(TARGETS epollix 
    EXPORT epollix_export
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} 
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# Add the tests and build middleware
if(BUILD_TESTS AND CIPHERKIT_FOUND)
    add_subdirectory(tests)
endif()

if (CIPHERKIT_FOUND)
    add_subdirectory(example)
endif()

# Install export targets
install(EXPORT epollix_export
    FILE epollixTargets.cmake
    NAMESPACE epollix::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/epollix)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/epollixConfig.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/epollix)

# Generate the configuration file for the library
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
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/epollix)

# Generate the .pc file for pkg-config
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/epollix.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/epollix.pc
    @ONLY)

# Install the .pc file
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/epollix.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
