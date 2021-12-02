include_directories(${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/fss-core/common
    ${CMAKE_SOURCE_DIR}/fss-core/libPSI 
    ${CMAKE_SOURCE_DIR}/fss-core/libOTe 
    ${CMAKE_SOURCE_DIR}/fss-core/libOTe/cryptoTools
    ${Boost_INCLUDE_DIRS})

add_library(DPFClient DPFClient.cpp)
add_library(DPFServer DPFServer.cpp)

target_link_libraries(DPFClient PRIVATE FSSCoreCommon libPSI_Tests libOTe cryptoTools)
target_link_libraries(DPFServer PRIVATE FSSCoreCommon libPSI_Tests libOTe cryptoTools)

