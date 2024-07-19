# Tests module CMakeLists.txt

# Add mime test
# Add the executable
add_executable(mime_test mime_test.c)

# Link the library
target_link_libraries(mime_test PRIVATE epollix)

# Register test with ctest
add_test(NAME mime_test COMMAND mime_test)


# Add epollix test
# Add the executable
add_executable(epollix_test epollix_test.c)

# Link the library
target_link_libraries(epollix_test PRIVATE epollix)

# Register test with ctest
add_test(NAME epollix_test COMMAND epollix_test)