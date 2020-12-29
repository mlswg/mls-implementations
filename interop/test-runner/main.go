package main

import (
	"context"
	"flag"
	"log"
	"time"

	"google.golang.org/grpc"

	pb "github.com/mlswg/mls-implementations/interop/proto"
)

var (
	serverOpt string
)

func init() {
	flag.StringVar(&serverOpt, "server", "localhost:50051", "gRPC server address")
}

func main() {
	// Set up a connection to the server.
	conn, err := grpc.Dial(serverOpt, grpc.WithInsecure(), grpc.WithBlock())
	chk("Failure to connect", err)

	defer conn.Close()
	c := pb.NewMLSClientClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// Get client name
	nr, err := c.Name(ctx, &pb.NameRequest{})
	chk("name", err)
	log.Printf("Client name: %s", nr.GetName())

	// Get client's supported ciphersuites
	scr, err := c.SupportedCiphersuites(ctx, &pb.SupportedCiphersuitesRequest{})
	chk("supported ciphersuites", err)
	log.Printf("Supported ciphersuites: %+v", scr.Ciphersuites)

	// Generate a test vector
	gtvr, err := c.GenerateTestVector(ctx, &pb.GenerateTestVectorRequest{
		TestVectorType: pb.TestVectorType_TREE_MATH,
	})
	chk("generate test vector", err)
	log.Printf("Generated test vector: %x", gtvr.TestVector)

	// Verify a test vector
	_, err = c.VerifyTestVector(ctx, &pb.VerifyTestVectorRequest{
		TestVectorType: pb.TestVectorType_TREE_MATH,
		TestVector:     gtvr.TestVector,
	})
	chk("verify test vector", err)
	log.Printf("Verified test vector")
}

func chk(message string, err error) {
	if err != nil {
		log.Fatalf("Error: %s - %v", message, err)
	}
}
