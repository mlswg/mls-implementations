cmake_minimum_required(VERSION 3.12.1)

project(MLSClient CXX)

###
### Global Config
###

set(APP_NAME "mock_client")
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "GNU")
  add_compile_options(-Wall -pedantic -Wextra -Werror -Wmissing-declarations)
elseif(MSVC)
  add_compile_options(/W4 /WX)
endif()

###
### Dependencies
###

find_package(Protobuf REQUIRED)
find_package(gRPC CONFIG REQUIRED)

###
### Protobuf generation
###

# Proto file
set(PROTO "mls_client")
get_filename_component(PROTO_FILE "../proto/${PROTO}.proto" ABSOLUTE)
get_filename_component(PROTO_PATH "${PROTO_FILE}" PATH)

# Generated sources
set(PB_SRC "${CMAKE_CURRENT_BINARY_DIR}/${PROTO}.pb.cc")
set(PB_HDR "${CMAKE_CURRENT_BINARY_DIR}/${PROTO}.pb.h")
set(GRPC_SRC "${CMAKE_CURRENT_BINARY_DIR}/${PROTO}.grpc.pb.cc")
set(GRPC_HDR "${CMAKE_CURRENT_BINARY_DIR}/${PROTO}.grpc.pb.h")
find_program(PROTOBUF_PROTOC protoc)
find_program(GRPC_CPP_PLUGIN_EXECUTABLE grpc_cpp_plugin)

# Generate sources from proto file
add_custom_command(
      OUTPUT "${PB_SRC}" "${PB_HDR}" "${GRPC_SRC}" "${GRPC_HDR}"
      COMMAND ${PROTOBUF_PROTOC}
      ARGS --grpc_out "${CMAKE_CURRENT_BINARY_DIR}"
        --cpp_out "${CMAKE_CURRENT_BINARY_DIR}"
        -I "${PROTO_PATH}"
        --plugin=protoc-gen-grpc="${GRPC_CPP_PLUGIN_EXECUTABLE}"
        "${PROTO_FILE}"
      DEPENDS "${PROTO_FILE}")

add_executable(${APP_NAME} mock_client.cpp ${PB_SRC} ${GRPC_SRC})
target_include_directories(${APP_NAME} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(mock_client gRPC::grpc++ protobuf::libprotobuf)
