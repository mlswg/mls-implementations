# MLS Interop Testing Framework

This directory provides a gRPC-based framework for interop testing among MLS
clients.  In this framework, each MLS client is a gRPC server, and the test
runner acts as a gRPC client to coordinate tests.  In addition to the test
runner logic, we include stub / mock client implementations (again, gRPC
servers) in C++, Go, and Rust.

## Quickstart

```
# Start up a client
> make run-go   # ... in Go
> make run-cpp  # ... in C++

# Invoke the test runner against that client
> make run-test
```
