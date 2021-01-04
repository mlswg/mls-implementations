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
	Clients     []string `json:"clients"`
	TestVectors []string `json:"test_vectors,omitempty"`
}

type TestVectorResult struct {
	Generator   string `json:"generator"`
	Verifier    string `json:"verifier"`
	CipherSuite uint32 `json:"cipher_suite,omitempty"`
	Error       string `json:"error,omitempty"`
}

type TestResults struct {
	TestVectors map[string][]TestVectorResult `json:"test_vectors"`
}

type Client struct {
	conn      *grpc.ClientConn
	rpc       pb.MLSClientClient
	name      string
	supported map[uint32]bool
	compat    map[uint32]bool
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
	c.supported = map[uint32]bool{}
	for _, suite := range scr.GetCiphersuites() {
		c.supported[suite] = true
	}
	c.compat = map[uint32]bool{}

	return c, nil
}

func (c *Client) AddCompat(other *Client) {
	for suite := range other.supported {
		if !c.supported[suite] {
			continue
		}

		c.compat[suite] = true
	}
}

var (
	configOpt string
)

func init() {
	flag.StringVar(&configOpt, "config", "config.json", "config file name")
	flag.Parse()
}

var (
	testVectorType = map[string]pb.TestVectorType{
		"tree_math":    pb.TestVectorType_TREE_MATH,
		"encryption":   pb.TestVectorType_ENCRYPTION,
		"key_schedule": pb.TestVectorType_KEY_SCHEDULE,
		"treekem":      pb.TestVectorType_TREEKEM,
		"messages":     pb.TestVectorType_MESSAGES,
	}

	cipherSuiteDependent = map[pb.TestVectorType]bool{
		pb.TestVectorType_TREE_MATH:    false,
		pb.TestVectorType_ENCRYPTION:   true,
		pb.TestVectorType_KEY_SCHEDULE: true,
		pb.TestVectorType_TREEKEM:      true,
		pb.TestVectorType_MESSAGES:     false,
	}

	testVectorParams = struct {
		NLeaves      uint32
		NGenerations uint32
		NEpochs      uint32
	}{
		NLeaves:      10,
		NGenerations: 10,
		NEpochs:      10,
	}
)

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

		log.Printf("Connected to [%s] @ [%s]", clients[i].name, addr)
	}

	// Build a ciphersuite compatibility matrix.  Entry `i` is the set of suites
	// that client `i` has in common with any other client.  This tells us what
	// cases that client needs to generate in order to test all cases with other
	// clients.
	for _, client := range clients {
		for _, other := range clients {
			client.AddCompat(other)
		}
	}

	// Run each requested test vector across each pair of clients
	// NB(RLB): You could reorder these operations a bunch of different ways.  Do
	// all the generations before the verifications, do everything in parallel,
	// etc.
	results := TestResults{}
	results.TestVectors = map[string][]TestVectorResult{}
	ctx, _ := context.WithTimeout(context.Background(), 1*time.Second)
	for _, typeString := range config.TestVectors {
		typeVal, ok := testVectorType[typeString]
		if !ok {
			log.Fatalf("Invalid test vector type [%s]", typeString)
		}

		tvResults := []TestVectorResult{}
		for _, generator := range clients {
			// Generate test vectors for all ciphersuites (if required)
			generatedVectors := map[uint32][]byte{0: []byte{}}
			if cipherSuiteDependent[typeVal] {
				delete(generatedVectors, 0)
				for suite := range generator.compat {
					generatedVectors[suite] = []byte{}
				}
			}

			for suite := range generatedVectors {
				genReq := &pb.GenerateTestVectorRequest{
					TestVectorType: typeVal,
					CipherSuite:    suite,
					NLeaves:        testVectorParams.NLeaves,
					NGenerations:   testVectorParams.NGenerations,
					NEpochs:        testVectorParams.NEpochs,
				}
				genResp, err := generator.rpc.GenerateTestVector(ctx, genReq)
				if err != nil {
					log.Printf("Error generating test vector [%s] [%s] [%v]", typeString, generator.name, err)
					continue
				}

				generatedVectors[suite] = genResp.TestVector
			}

			// Verify test vectors for each supported ciphersuite with other clients
			for _, verifier := range clients {
				for suite, testVector := range generatedVectors {
					if suite != 0 && !verifier.supported[suite] {
						continue
					}

					if len(testVector) == 0 {
						// This indicates that there was an error generating the vector
						continue
					}

					verReq := &pb.VerifyTestVectorRequest{TestVectorType: typeVal, TestVector: testVector}
					_, err := verifier.rpc.VerifyTestVector(ctx, verReq)

					errStr := ""
					if err != nil {
						errStr = err.Error()
					}

					tvResults = append(tvResults, TestVectorResult{
						Generator:   generator.name,
						CipherSuite: suite,
						Verifier:    verifier.name,
						Error:       errStr,
					})
				}
			}
		}

		results.TestVectors[typeString] = tvResults
	}

	resultsJSON, err := json.MarshalIndent(results, "", "  ")
	chk("Error marshaling results", err)
	fmt.Println(string(resultsJSON))

}

func chk(message string, err error) {
	if err != nil {
		log.Fatalf("Error: %s - %v", message, err)
	}
}
