include_directories(${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/fss-core/libPSI 
    ${CMAKE_SOURCE_DIR}/fss-core/libOTe 
    ${CMAKE_SOURCE_DIR}/fss-core/libOTe/cryptoTools
    ${Boost_INCLUDE_DIRS})

add_library(FSSCoreCommon common.cpp)

target_link_libraries(FSSCoreCommon PRIVATE libPSI_Tests libOTe cryptoTools)

