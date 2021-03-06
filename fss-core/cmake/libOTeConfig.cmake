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
foreach(_expectedTarget libOTe_Tests libOTe cryptoTools)
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


# Create imported target libOTe_Tests
add_library(libOTe_Tests STATIC IMPORTED)

set_target_properties(libOTe_Tests PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES "/home/ec2-user/dorydb/fss-core/libOTe"
)

# Create imported target libOTe
add_library(libOTe STATIC IMPORTED)

set_target_properties(libOTe PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES "/home/ec2-user/dorydb/fss-core/libOTe/libOTe/..;/home/ec2-user/dorydb/fss-core/libOTe/libOTe/.."
)

# Create imported target cryptoTools
add_library(cryptoTools STATIC IMPORTED)

set_target_properties(cryptoTools PROPERTIES
  INTERFACE_COMPILE_OPTIONS "\$<\$<COMPILE_LANGUAGE:CXX>:-std=c++14>;-pthread;-maes;-msse2;-msse3;-msse4.1;-mpclmul"
  INTERFACE_INCLUDE_DIRECTORIES "/home/ec2-user/dorydb/fss-core/libOTe/cryptoTools/cryptoTools/..;/home/ec2-user/dorydb/fss-core/libOTe/cryptoTools/cryptoTools/..;/usr/local/include;/home/ec2-user/boost-target/include"
  INTERFACE_LINK_OPTIONS "-pthread"
)

# Import target "libOTe_Tests" for configuration "Release"
set_property(TARGET libOTe_Tests APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(libOTe_Tests PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LINK_INTERFACE_LIBRARIES_RELEASE "libOTe"
  IMPORTED_LOCATION_RELEASE "/home/ec2-user/dorydb/fss-core/libOTe/libOTe_Tests/liblibOTe_Tests.a"
  )

# Import target "libOTe" for configuration "Release"
set_property(TARGET libOTe APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(libOTe PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LINK_INTERFACE_LIBRARIES_RELEASE "OpenMP::OpenMP_CXX;cryptoTools"
  IMPORTED_LOCATION_RELEASE "/home/ec2-user/dorydb/fss-core/libOTe/libOTe/liblibOTe.a"
  )

# Import target "cryptoTools" for configuration "Release"
set_property(TARGET cryptoTools APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(cryptoTools PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "C;CXX"
  IMPORTED_LINK_INTERFACE_LIBRARIES_RELEASE "/usr/local/lib/librelic.so;Boost::system;Boost::thread"
  IMPORTED_LOCATION_RELEASE "/home/ec2-user/dorydb/fss-core/libOTe/cryptoTools/cryptoTools/libcryptoTools.a"
  )

# This file does not depend on other imported targets which have
# been exported from the same project but in a separate export set.

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
cmake_policy(POP)
