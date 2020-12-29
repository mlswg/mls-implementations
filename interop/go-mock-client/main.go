package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"net"

	"google.golang.org/grpc"

	pb "github.com/mlswg/mls-implementations/interop/proto"
)

var (
	implementationName    = "Mock-Go"
	supportedCiphersuites = []uint32{0xA0A0, 0xA1A1}
	testVectorType        = pb.TestVectorType_TREE_MATH
	testVector            = []byte{0, 1, 2, 3}
)

///
/// Mock client implementation
///
type MockClient struct {
	pb.MLSClientServer
}

func (mc *MockClient) Name(ctx context.Context, req *pb.NameRequest) (*pb.NameResponse, error) {
	log.Printf("Received Name request")
	return &pb.NameResponse{Name: implementationName}, nil
}

func (mc *MockClient) SupportedCiphersuites(ctx context.Context, req *pb.SupportedCiphersuitesRequest) (*pb.SupportedCiphersuitesResponse, error) {
	log.Printf("Received SupportedCiphersuites request")
	return &pb.SupportedCiphersuitesResponse{Ciphersuites: []uint32{}}, nil
}

func (mc *MockClient) GenerateTestVector(ctx context.Context, req *pb.GenerateTestVectorRequest) (*pb.GenerateTestVectorResponse, error) {
	log.Printf("Received GenerateTestVector request")

	if req.Type != testVectorType {
		response := &pb.GenerateTestVectorResponse{
			Result: &pb.GenerateTestVectorResponse_Error{"Invalid test vector type"},
		}
		return response, nil
	}

	response := &pb.GenerateTestVectorResponse{
		Result: &pb.GenerateTestVectorResponse_TestVector{testVector},
	}

	return response, nil
}

func (mc *MockClient) VerifyTestVector(ctx context.Context, req *pb.VerifyTestVectorRequest) (*pb.VerifyTestVectorResponse, error) {
	log.Printf("Received VerifyTestVector request")

	if req.Type != testVectorType {
		response := &pb.VerifyTestVectorResponse{
			Result: &pb.VerifyTestVectorResponse_Error{"Invalid test vector type"},
		}
		return response, nil
	}

	if !bytes.Equal(req.TestVector, testVector) {
		response := &pb.VerifyTestVectorResponse{
			Result: &pb.VerifyTestVectorResponse_Error{"Invalid test vector"},
		}
		return response, nil
	}

	response := &pb.VerifyTestVectorResponse{
		Result: &pb.VerifyTestVectorResponse_Success{true},
	}

	return response, nil
}

///
/// Run the server
///

var (
	portOpt int
)

func init() {
	flag.IntVar(&portOpt, "port", 50051, "port to listen on")
}

func main() {
	port := fmt.Sprintf(":%d", portOpt)
	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()
	pb.RegisterMLSClientServer(s, &MockClient{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
