file(GLOB gost_src
    "*.cpp"
)

add_library(gost STATIC ${gost_src})
target_include_directories(gost PRIVATE "../include/")