file(GLOB gostTest_src
    "*.cpp"
)

add_executable(gostTest ${gostTest_src})
target_include_directories(gostTest PRIVATE "../include/")
target_link_libraries(gostTest gost)