cmake_minimum_required (VERSION 2.8.12)
project("DoryDB")

option(DEBUG "Debug Build" OFF)
message(STATUS "Option: DEBUG = ${DEBUG}")

set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/build)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(CMAKE_PREFIX_PATH 
    "${CMAKE_CURRENT_SOURCE_DIR}/fss-core/libOTe/build/lib/cmake;
    ${CMAKE_CURRENT_SOURCE_DIR}/fss-core/libPSI/build/lib/cmake")

find_package(Boost COMPONENTS thread system REQUIRED)
find_package(OpenMP REQUIRED)
find_package(libOTe  REQUIRED)
find_package(libPSI REQUIRED)

# can set directory specific flags if needed by changing position of this line
set(CMAKE_C_FLAGS "-march=native -Wall -maes -msse2 -msse4.1 -mavx -mavx2 -mpclmul -Wfatal-errors -pthread -fPIC -Wno-ignored-attributes -Wno-parentheses")
set(CMAKE_CXX_FLAGS  "${CMAKE_C_FLAGS}  -std=c++14 -O3")

if(DEBUG)
    set(CMAKE_C_FLAGS "-march=native -Wall -maes -msse2 -msse4.1 -mavx -mavx2 -mpclmul -Wfatal-errors -pthread -fPIC -Wno-ignored-attributes -Wno-parentheses -g")
    set(CMAKE_CXX_FLAGS  "${CMAKE_C_FLAGS}  -std=c++14 -g")
endif()

add_subdirectory(fss-core)
add_subdirectory(network-emp)
add_subdirectory(network)
add_subdirectory(secure-indices)
add_subdirectory(client)
add_subdirectory(server)
