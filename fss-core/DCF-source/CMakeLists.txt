include_directories(${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/fss-core/libPSI 
    ${CMAKE_SOURCE_DIR}/fss-core/libOTe 
    ${CMAKE_SOURCE_DIR}/fss-core/libOTe/cryptoTools
    ${Boost_INCLUDE_DIRS})

add_library(DCFClient DCFClient.cpp)
add_library(DCFServer DCFServer.cpp)

target_link_libraries(DCFClient PRIVATE FSSCoreCommon libPSI_Tests libOTe cryptoTools OpenMP::OpenMP_CXX Boost::system Boost::thread)
target_link_libraries(DCFServer PRIVATE FSSCoreCommon libPSI_Tests libOTe cryptoTools OpenMP::OpenMP_CXX Boost::system Boost::thread)

