# This is a convenience Makefile to avoid the need to remember a lot of command
# line options to protoc etc.
#
# This file also handles the building of the Go protobuf/gRPC code, which is is
# shared between the test runner and the Go example.

PROTO_DIR=proto
PROTO_NAME=mls_client
PROTO_FILE=${PROTO_NAME}.proto
PROTO_GO=${PROTO_DIR}/${PROTO_NAME}.pb.go ${PROTO_DIR}/${PROTO_NAME}_grpc.pb.go

PHONY: go-tools run-go run-test clean

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
	
run-go: ${PROTO_GO}
	go run go-mock-client/main.go

run-cpp: ${PROTO_DIR}/${PROTO_FILE}
	make -C cpp-mock-client run

run-test: ${PROTO_GO}
	go run test-runner/main.go

clean:
	rm -f ${PROTO_GO}
	make -C cpp-mock-client cclean
