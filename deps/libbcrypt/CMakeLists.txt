add_library(bcrypt STATIC
    bcrypt.c
    crypt_blowfish/crypt_blowfish.c
    crypt_blowfish/crypt_gensalt.c
    crypt_blowfish/wrapper.c
    crypt_blowfish/x86.S
)

target_compile_options(bcrypt PRIVATE 
    -W -Wall -Wbad-function-cast -Wcast-align 
    -Wcast-qual -Wmissing-prototypes -Wstrict-prototypes 
    -Wshadow -Wundef -Wpointer-arith -O2 
    -fomit-frame-pointer -funroll-loops)

install(FILES bcrypt.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/bcrypt)

install(TARGETS bcrypt 
    EXPORT bcrypt_export
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} 
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/bcryptConfig.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/bcrypt)

# Install export targets for bcrypt
install(EXPORT bcrypt_export
    FILE bcryptTargets.cmake
    NAMESPACE bcrypt::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/bcrypt)

# Generate the configuration file for the library
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/bcryptConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/bcryptConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/bcryptConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/bcrypt
)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/bcryptConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/bcrypt)

# Generate the .pc file for pkg-config
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/bcrypt.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/bcrypt.pc
    @ONLY)

# Install the .pc file
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/bcrypt.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
