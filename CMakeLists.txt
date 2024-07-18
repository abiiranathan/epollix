cmake_minimum_required(VERSION 3.5.0)
project(epollix VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# Set compiler
# set(CMAKE_C_COMPILER "clang")

option(BUILD_TESTS "Build the tests" ON)

# Find the solidc library
find_package(solidc REQUIRED)

include(GNUInstallDirs)
include(CTest)
enable_testing()

# Source files as all .c files in the src directory
file(GLOB SOURCES "src/*.c")

# Header files as all .h files in the include directory
file(GLOB HEADERS "include/*.h")

# Include our main epollix library.
# Can pass -DBUILD_SHARED_LIB to build a shared library
add_library(epollix ${SOURCES})

# Link the math library, pthreads, and the solidc library
target_link_libraries(epollix PUBLIC m pthread solidc::solidc)

# Include the include directory
target_include_directories(epollix PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include/epollix>
)

# Configure the target to use the C11 standard
target_compile_options(epollix PRIVATE -Wall -Wextra -pedantic -Werror)

# Install targets
install(FILES ${HEADERS} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/epollix)

install(TARGETS epollix 
    EXPORT epollix_export
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} 
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# Add the tests
if(BUILD_TESTS)
    add_subdirectory(tests)
endif()

add_subdirectory(example)

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
