cmake_minimum_required(VERSION 3.10)
project(localtunnel C)

################################################################################
## dependencies

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

find_package(CURL REQUIRED)
find_package(CJSON REQUIRED libcjson)
find_package(libev REQUIRED)

################################################################################
## project

add_executable(
    localtunnel
    localtunnel.c
)

target_include_directories(
    localtunnel PRIVATE 
    ${CURL_INCLUDE_DIRS} 
    ${LIBEV_INCLUDE_DIRS} 
    ${CJSON_INCLUDE_DIRS}
)

target_link_libraries(
    localtunnel 
    ${CURL_LIBRARIES} 
    ${LIBEV_LIBRARIES} 
    ${CJSON_LIBRARIES}
)
