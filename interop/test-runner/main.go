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
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewMLSClientClient(conn)

	// Contact the server and print out its response.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	r, err := c.Name(ctx, &pb.NameRequest{})
	if err != nil {
		log.Fatalf("could not get client name: %v", err)
	}
	log.Printf("Client name: %s", r.GetName())
}
