# C++ Mock Client

This directory shows how to make a C++ gRPC server that wraps an MLS client.
The methods are all mocked in; that's where the calls to the actual MLS client
go.

## Prerequisites

```
# MacOS
> brew install cmake protobuf grpc

# Linux (seems right? untested)
> sudo apt install -y cmake protobuf-compiler libgrpc++-dev 
```

## Building and Running

```
> cmake -Bbuild .
> cmake --build build
> ./build/mock_client
```
