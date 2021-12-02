include_directories(${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/network-emp/core
    ${CMAKE_SOURCE_DIR}/fss-core/libOTe
    ${CMAKE_SOURCE_DIR}/fss-core/libOTe/cryptoTools
    ${Boost_INCLUDE_DIRS})

foreach(_target
        EMPNetIOUnitTest)
  add_executable(${_target} "${_target}.cpp")
  target_link_libraries(${_target}
    libOTe
    cryptoTools
    EMPNetIO)
endforeach()

