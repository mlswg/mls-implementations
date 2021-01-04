# This is a convenience Makefile to avoid the need to remember a lot of command
# line options to protoc etc.
#
# This file also handles the building of the Go protobuf/gRPC code, which is is
# shared between the test runner and the Go example.

PROTO_DIR=proto
PROTO_NAME=mls_client
PROTO_FILE=${PROTO_NAME}.proto
PROTO_GO=${PROTO_DIR}/${PROTO_NAME}.pb.go ${PROTO_DIR}/${PROTO_NAME}_grpc.pb.go
GO_CLIENT_BINARY=go-mock-client/go-mock-client
TEST_RUNNER_BINARY=test-runner/test-runner

.PHONY: go-tools run-go run-test clean

# Install tools for generating Go library
go-tools:
	go get google.golang.org/protobuf/cmd/protoc-gen-go \
         google.golang.org/grpc/cmd/protoc-gen-go-grpc

${PROTO_GO}: ${PROTO_DIR}/${PROTO_FILE}
	protoc --go_out=${PROTO_DIR} \
				 --go_opt=paths=source_relative \
    		 --go-grpc_out=${PROTO_DIR} \
				 --go-grpc_opt=paths=source_relative \
				 -I ${PROTO_DIR} \
		     ${PROTO_FILE}

# Run mock clients (gRPC servers) in various languages
${GO_CLIENT_BINARY}: ${PROTO_GO} go-mock-client/*.go
	cd go-mock-client && go build

run-go: ${GO_CLIENT_BINARY}
	${GO_CLIENT_BINARY} -port 50001

run-cpp: ${PROTO_DIR}/${PROTO_FILE}
	make -C cpp-mock-client run

run-rs:
	cd rust-mock-client && cargo run -- -p 50003

# Run the test runner
${TEST_RUNNER_BINARY}: ${PROTO_GO} test-runner/*.go
	cd test-runner && go build

run-test: ${TEST_RUNNER_BINARY}
	${TEST_RUNNER_BINARY}

clean:
	rm -f ${PROTO_GO}
	rm -f ${GO_CLIENT_BINARY}
	rm -f ${TEST_RUNNER_BINARY}
	make -C cpp-mock-client cclean
	cd rust-mock-client && cargo clean
