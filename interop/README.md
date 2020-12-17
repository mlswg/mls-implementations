# MLS Interop Testing Framework

This directory provides a gRPC-based framework for interop testing among MLS
clients.  In this framework, each MLS client is a gRPC server, and the test
runner acts as a gRPC client to coordinate tests.  In addition to the test
runner logic, we include stub / mock client implementations (again, gRPC
servers) in C++, Go, and Rust.

## Quickstart

```bash
# Start up a client
make run-go   # ... in Go
make run-cpp  # ... in C++
make run-rs   # ... in Rust

# Invoke the test runner against that client
make run-test

# You should get an output of the following form, depending on 
# which client you started:
2020/12/16 17:44:07 Client name: Mock-Go
2020/12/16 17:44:07 Client name: Mock-C++
2020/12/16 17:44:07 Client name: Mock-Rust
```
