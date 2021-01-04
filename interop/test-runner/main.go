package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"google.golang.org/grpc"

	pb "github.com/mlswg/mls-implementations/interop/proto"
)

type RunConfig struct {
	Clients []string `json:"clients"`
}

type Client struct {
	conn         *grpc.ClientConn
	rpc          pb.MLSClientClient
	name         string
	cipherSuites []uint32
}

func NewClient(addr string) (*Client, error) {
	c := &Client{}
	var err error

	defer func() {
		if err != nil && c.conn != nil {
			c.conn.Close()
		}
	}()

	c.conn, err = grpc.Dial(addr, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		return nil, err
	}

	c.rpc = pb.NewMLSClientClient(c.conn)

	// Get the client's name and supported ciphersuites
	ctx, _ := context.WithTimeout(context.Background(), 200*time.Millisecond)
	nr, err := c.rpc.Name(ctx, &pb.NameRequest{})
	if err != nil {
		return nil, err
	}

	scr, err := c.rpc.SupportedCiphersuites(ctx, &pb.SupportedCiphersuitesRequest{})
	if err != nil {
		return nil, err
	}

	c.name = nr.GetName()
	c.cipherSuites = scr.GetCiphersuites()
	return c, nil
}

var (
	configOpt string
)

func init() {
	flag.StringVar(&configOpt, "config", "config.json", "config file name")
}

func main() {
	// Load and parse the config
	jsonFile, err := os.Open(configOpt)
	chk("Failure to open config file", err)

	jsonData, err := ioutil.ReadAll(jsonFile)
	chk("Failure to read config file", err)

	config := new(RunConfig)
	err = json.Unmarshal(jsonData, config)
	chk("Failure to parse config file", err)

	// Connect to clients
	clients := make([]*Client, len(config.Clients))
	for i, addr := range config.Clients {
		clients[i], err = NewClient(addr)
		chk(fmt.Sprintf("Failure to connect to client [%s]", addr), err)
		defer clients[i].conn.Close()
	}

	// Announce the connected clients
	for _, client := range clients {
		log.Printf("Connected to: name=[%s] suites=[%v]", client.name, client.cipherSuites)
	}

	/*
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
	*/
}

func chk(message string, err error) {
	if err != nil {
		log.Fatalf("Error: %s - %v", message, err)
	}
}
