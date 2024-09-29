add_executable(mime_test mime_test.c)
target_link_libraries(mime_test PRIVATE epollix)
add_test(NAME mime_test COMMAND mime_test)

add_executable(epollix_test epollix_test.c)
target_link_libraries(epollix_test PRIVATE epollix)
add_test(NAME epollix_test COMMAND epollix_test)

