include_directories(
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/fss-core/libPSI
    ${CMAKE_SOURCE_DIR}/fss-core/libOTe 
    ${CMAKE_SOURCE_DIR}/fss-core/libOTe/cryptoTools
    ${Boost_INCLUDE_DIRS})

add_library(AggTree AggTree.cpp Tree.cpp players.cpp keys.cpp)
add_library(DPFTable DPFTable.cpp players.cpp keys.cpp common.cpp)
add_library(DCFTable DCFTable.cpp players.cpp keys.cpp common.cpp)
add_library(Common common.cpp)

target_link_libraries(AggTree PRIVATE DCFClient DCFServer libPSI_Tests libOTe cryptoTools)
target_link_libraries(DPFTable PRIVATE DPFClient DPFServer libPSI_Tests libOTe cryptoTools)
target_link_libraries(DCFTable PRIVATE DCFClient DCFServer libPSI_Tests libOTe cryptoTools)
target_link_libraries(Common PRIVATE libPSI_Tests libOTe cryptoTools)
