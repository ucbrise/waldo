include_directories(${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/fss-core/libPSI 
    ${CMAKE_SOURCE_DIR}/fss-core/libOTe 
    ${CMAKE_SOURCE_DIR}/fss-core/libOTe/cryptoTools
    ${Boost_INCLUDE_DIRS})

foreach(_target
        AggTreeUnitTest DPFTableUnitTest DCFTableUnitTest DCFTableICUnitTest DCFTableParallelICUnitTest DPFTableParallelUnitTest RollUpUnitTest)
  add_executable(${_target} "${_target}.cpp")
  target_link_libraries(${_target}
    AggTree
    DPFTable
    DCFTable
    Common
    BgiPirTests
    libOTe
    libPSI_Tests
    )
endforeach()
