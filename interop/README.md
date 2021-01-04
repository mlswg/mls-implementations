# MLS Interop Testing Framework

This directory provides a gRPC-based framework for interop testing among MLS
clients.  In this framework, each MLS client is a gRPC server, and the test
runner acts as a gRPC client to coordinate tests.  In addition to the test
runner logic, we include stub / mock client implementations (again, gRPC
servers) in C++, Go, and Rust.

## Quickstart

```bash
# Start the clients in different windows
make run-go   # ... in Go
make run-cpp  # ... in C++
make run-rs   # ... in Rust

# Invoke the test runner against that client
make run-test

# You should get an output of the following form
2021/01/01 17:26:09 Connected to: name=[Mock-Go] suites=[[41120 41377]]
2021/01/01 17:26:09 Connected to: name=[Mock-C++] suites=[[41120 41377]]
2021/01/01 17:26:09 Connected to: name=[Mock-Rust] suites=[[41120 41377]]
```
