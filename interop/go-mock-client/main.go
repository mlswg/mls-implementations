package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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
	return &pb.SupportedCiphersuitesResponse{Ciphersuites: supportedCiphersuites}, nil
}

func (mc *MockClient) GenerateTestVector(ctx context.Context, req *pb.GenerateTestVectorRequest) (*pb.GenerateTestVectorResponse, error) {
	log.Printf("Received GenerateTestVector request")

	if req.TestVectorType != testVectorType {
		return nil, status.Error(codes.InvalidArgument, "Invalid test vector type")
	}

	return &pb.GenerateTestVectorResponse{TestVector: testVector}, nil
}

func (mc *MockClient) VerifyTestVector(ctx context.Context, req *pb.VerifyTestVectorRequest) (*pb.VerifyTestVectorResponse, error) {
	log.Printf("Received VerifyTestVector request")

	if req.TestVectorType != testVectorType {
		return nil, status.Error(codes.InvalidArgument, "Invalid test vector type")
	}

	if !bytes.Equal(req.TestVector, testVector) {
		return nil, status.Error(codes.InvalidArgument, "Invalid test vector")
	}

	return &pb.VerifyTestVectorResponse{}, nil
}

///
/// Run the server
///

var (
	portOpt int
)

func init() {
	flag.IntVar(&portOpt, "port", 50051, "port to listen on")
	flag.Parse()
}

func main() {
	port := fmt.Sprintf(":%d", portOpt)
	log.Printf("Listening on %s", port)

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
