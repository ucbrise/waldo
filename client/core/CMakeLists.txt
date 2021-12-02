include_directories(
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/fss-core/libPSI
    ${CMAKE_SOURCE_DIR}/fss-core/libOTe 
    ${CMAKE_SOURCE_DIR}/fss-core/libOTe/cryptoTools
    ${PROTOBUF_INCLUDE_DIRS}
    ${PROTO_GRPC_DIR}
    ${Boost_INCLUDE_DIRS})

#target_link_libraries(client PRIVATE DCFClient DCFServer libPSI_Tests libOTe cryptoTools)

message(STATUS "Finding Protobuf before gRPC")
include(FindProtobuf)
find_package(Protobuf REQUIRED)
# Find gRPC installation
# Looks for gRPCConfig.cmake file installed by gRPC's cmake installation.
find_package(gRPC CONFIG REQUIRED)
message(STATUS "Using gRPC ${gRPC_VERSION}")
  
set(protobuf_MODULE_COMPATIBLE TRUE)
message(STATUS "Using protobuf ${Protobuf_VERSION}")

set(_PROTOBUF_LIBPROTOBUF protobuf::libprotobuf)
set(_REFLECTION gRPC::grpc++_reflection)
if(CMAKE_CROSSCOMPILING)
    find_program(_PROTOBUF_PROTOC protoc)
else()
    set(_PROTOBUF_PROTOC $<TARGET_FILE:protobuf::protoc>)
endif()

set(_GRPC_GRPCPP gRPC::grpc++)

set(hw_proto_hdrs "${CMAKE_CURRENT_BINARY_DIR}/../../network/core/query.pb.h")
set(hw_proto_srcs "${CMAKE_CURRENT_BINARY_DIR}/../../network/core/query.pb.cc")
set(hw_grpc_hdrs "${CMAKE_CURRENT_BINARY_DIR}/../../network/core/query.grpc.pb.h")
set(hw_grpc_srcs "${CMAKE_CURRENT_BINARY_DIR}/../../network/core/query.grpc.pb.cc")

add_executable(query_client main.cpp client.cpp ../../secure-indices/core/DPFTable.cpp ../../secure-indices/core/DCFTable.cpp ../../secure-indices/core/common.cpp ${hw_proto_srcs} ${hw_grpc_srcs})

target_link_libraries(query_client
    ${_REFLECTION}
    ${_GRPC_GRPCPP}
    ${_PROTOBUF_LIBPROTOBUF}
    DCFTable
    DPFTable
    AggTree
    Common
    BgiPirTests
    libOTe
    libPSI_Tests)
