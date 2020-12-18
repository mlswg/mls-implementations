package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"

	"google.golang.org/grpc"

	pb "github.com/mlswg/mls-implementations/interop/proto"
)

const (
	implementationName = "Mock-Go"
)

///
/// Mock client implementation
///
type MockClient struct {
	pb.MLSClientServer
}

func (mc *MockClient) Name(ctx context.Context, req *pb.NameRequest) (*pb.NameResponse, error) {
	log.Printf("Received name request")
	return &pb.NameResponse{Name: implementationName}, nil
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
