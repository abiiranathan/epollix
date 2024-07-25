add_executable(mime_test mime_test.c)
target_link_libraries(mime_test PRIVATE epollix)
add_test(NAME mime_test COMMAND mime_test)


add_executable(epollix_test epollix_test.c)
target_link_libraries(epollix_test PRIVATE epollix)
add_test(NAME epollix_test COMMAND epollix_test)


add_executable(crypto_test crypto_test.c)
target_link_libraries(crypto_test PRIVATE epollix)
add_test(NAME crypto_test COMMAND crypto_test)

add_executable(gzip_test gzip_test.c)
target_link_libraries(gzip_test PRIVATE epollix)
add_test(NAME gzip_test COMMAND gzip_test)
