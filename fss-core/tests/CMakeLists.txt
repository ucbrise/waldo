include_directories(${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/fss-core/libPSI 
    ${CMAKE_SOURCE_DIR}/fss-core/libOTe 
    ${CMAKE_SOURCE_DIR}/fss-core/libOTe/cryptoTools
    ${Boost_INCLUDE_DIRS})

add_library(BgiPirTests BgiPirTests.cpp)

foreach(_target
    DPF_unit_test DCF_unit_test)
  add_executable(${_target} "${_target}.cpp")  
  target_link_libraries(${_target}
    DCFClient
    DCFServer
    DPFClient
    DPFServer
    BgiPirTests
    libOTe
    libPSI_Tests)
endforeach()

