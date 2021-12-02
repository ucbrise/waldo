include_directories(${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/fss-core/libOTe
    ${CMAKE_SOURCE_DIR}/fss-core/libOTe/cryptoTools
    ${Boost_INCLUDE_DIRS})

add_library(EMPNetIO INTERFACE)

target_link_libraries(EMPNetIO INTERFACE
    libOTe 
    cryptoTools)
