# Generated by CMake

if("${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION}" LESS 2.5)
   message(FATAL_ERROR "CMake >= 2.6.0 required")
endif()
cmake_policy(PUSH)
cmake_policy(VERSION 2.6)
#----------------------------------------------------------------
# Generated CMake target import file.
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Protect against multiple inclusion, which would fail when already imported targets are added once more.
set(_targetsDefined)
set(_targetsNotDefined)
set(_expectedTargets)
foreach(_expectedTarget libPSI_Tests libPSI)
  list(APPEND _expectedTargets ${_expectedTarget})
  if(NOT TARGET ${_expectedTarget})
    list(APPEND _targetsNotDefined ${_expectedTarget})
  endif()
  if(TARGET ${_expectedTarget})
    list(APPEND _targetsDefined ${_expectedTarget})
  endif()
endforeach()
if("${_targetsDefined}" STREQUAL "${_expectedTargets}")
  unset(_targetsDefined)
  unset(_targetsNotDefined)
  unset(_expectedTargets)
  set(CMAKE_IMPORT_FILE_VERSION)
  cmake_policy(POP)
  return()
endif()
if(NOT "${_targetsDefined}" STREQUAL "")
  message(FATAL_ERROR "Some (but not all) targets in this export set were already defined.\nTargets Defined: ${_targetsDefined}\nTargets not yet defined: ${_targetsNotDefined}\n")
endif()
unset(_targetsDefined)
unset(_targetsNotDefined)
unset(_expectedTargets)


# Create imported target libPSI_Tests
add_library(libPSI_Tests STATIC IMPORTED)

# Create imported target libPSI
add_library(libPSI STATIC IMPORTED)

set_target_properties(libPSI PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES "/home/ec2-user/dorydb/fss-core/libOTe/cmake/..;/home/ec2-user/dorydb/fss-core/libOTe/cmake/../cryptoTools;/home/ec2-user/dorydb/fss-core/libOTe/cmake/../;/home/ec2-user/dorydb/fss-core/libOTe/cmake/..//cryptoTools;/home/ec2-user/boost-target/include;/usr/local/include;/home/ec2-user/dorydb/fss-core/libPSI/..;/home/ec2-user/dorydb/fss-core/libPSI/libPSI/..;/home/ec2-user/dorydb/fss-core/libPSI/thirdparty/linux/sparsehash/src/"
)

# Import target "libPSI_Tests" for configuration "Release"
set_property(TARGET libPSI_Tests APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(libPSI_Tests PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LINK_INTERFACE_LIBRARIES_RELEASE "libPSI"
  IMPORTED_LOCATION_RELEASE "/home/ec2-user/dorydb/fss-core/libPSI/libPSI_Tests/liblibPSI_Tests.a"
  )

# Import target "libPSI" for configuration "Release"
set_property(TARGET libPSI APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(libPSI PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LINK_INTERFACE_LIBRARIES_RELEASE "/home/ec2-user/dorydb/fss-core/libOTe/libOTe/liblibOTe.a;/home/ec2-user/dorydb/fss-core/libOTe/libOTe/liblibOTe.a;/home/ec2-user/dorydb/fss-core/libOTe/cryptoTools/cryptoTools/libcryptoTools.a;Boost::system;Boost::thread;/usr/local/lib/librelic.so"
  IMPORTED_LOCATION_RELEASE "/home/ec2-user/dorydb/fss-core/libPSI/libPSI/liblibPSI.a"
  )

# This file does not depend on other imported targets which have
# been exported from the same project but in a separate export set.

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
cmake_policy(POP)