add_executable(example main.c routes.c)
target_link_libraries(example PRIVATE epollix atomic)