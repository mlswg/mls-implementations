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

///
/// Configuration
///
type ScriptAction string

const (
	ActionCreateGroup      ScriptAction = "create_group"
	ActionCreateKeyPackage ScriptAction = "create_key_package"
	ActionAddProposal      ScriptAction = "add_proposal"
	ActionCommit           ScriptAction = "commit"
	ActionHandleCommit     ScriptAction = "handle_commit"
	ActionVerifyStateAuth  ScriptAction = "verify_state_auth"

	AllActors = "*"
)

type ScriptStep struct {
	Actor  string                 `json:"actor"`
	Action ScriptAction           `json:"action"`
	Params map[string]interface{} `json:"params"`
}

func (step *ScriptStep) UnmarshalJSON(data []byte) error {
	err := json.Unmarshal(data, &step.Params)
	if err != nil {
		return err
	}

	actor, okActor := step.Params["actor"]
	action, okAction := step.Params["action"]
	if !okActor || !okAction {
		return fmt.Errorf("Incomplete step %v %v", okActor, okAction)
	}

	step.Actor = actor.(string)
	step.Action = action.(ScriptAction)
	delete(step.Params, "actor")
	delete(step.Params, "action")
	return nil
}

type TestVectorConfig []string
type Script []ScriptStep

type RunConfig struct {
	Clients     []string          `json:"clients"`
	TestVectors TestVectorConfig  `json:"test_vectors,omitempty"`
	Scripts     map[string]Script `json:"scripts",omitempty`
}

///
/// Results
///
type TestVectorResult struct {
	Generator   string `json:"generator"`
	Verifier    string `json:"verifier"`
	CipherSuite uint32 `json:"cipher_suite,omitempty"`
	Error       string `json:"error,omitempty"`
}

type TestVectorResults map[string][]TestVectorResult

type TestResults struct {
	TestVectors map[string][]TestVectorResult `json:"test_vectors"`
}

///
/// Clients
///
type Client struct {
	conn      *grpc.ClientConn
	rpc       pb.MLSClientClient
	name      string
	supported map[uint32]bool
}

func ctx() context.Context {
	c, _ := context.WithTimeout(context.Background(), time.Second)
	return c
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
	nr, err := c.rpc.Name(ctx(), &pb.NameRequest{})
	if err != nil {
		return nil, err
	}

	scr, err := c.rpc.SupportedCiphersuites(ctx(), &pb.SupportedCiphersuitesRequest{})
	if err != nil {
		return nil, err
	}

	c.name = nr.GetName()
	c.supported = map[uint32]bool{}
	for _, suite := range scr.GetCiphersuites() {
		c.supported[suite] = true
	}

	return c, nil
}

type ClientPool struct {
	clients []*Client
}

func NewClientPool(configs []string) (*ClientPool, error) {
	p := &ClientPool{clients: make([]*Client, len(configs))}

	var err error
	for i, addr := range configs {
		p.clients[i], err = NewClient(addr)
		if err != nil {
			return nil, err
		}
	}

	return p, nil
}

func (p *ClientPool) Close() {
	for _, c := range p.clients {
		c.conn.Close()
	}
}

func (p *ClientPool) RunTestVectors(config TestVectorConfig) TestVectorResults {
	results := TestVectorResults{}
	for _, typeString := range config {
		typeVal, ok := testVectorType[typeString]
		if !ok {
			log.Fatalf("Invalid test vector type [%s]", typeString)
		}

		tvResults := []TestVectorResult{}
		for _, generator := range p.clients {
			// Generate test vectors for all ciphersuites (if required)
			generatedVectors := map[uint32][]byte{0: []byte{}}
			if cipherSuiteDependent[typeVal] {
				delete(generatedVectors, 0)
				for suite := range generator.supported {
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
				genResp, err := generator.rpc.GenerateTestVector(ctx(), genReq)
				if err != nil {
					log.Printf("Error generating test vector [%s] [%s] [%v]", typeString, generator.name, err)
					continue
				}

				generatedVectors[suite] = genResp.TestVector
			}

			// Verify test vectors for each supported ciphersuite with other clients
			for _, verifier := range p.clients {
				for suite, testVector := range generatedVectors {
					if suite != 0 && !verifier.supported[suite] {
						continue
					}

					if len(testVector) == 0 {
						// This indicates that there was an error generating the vector
						continue
					}

					verReq := &pb.VerifyTestVectorRequest{TestVectorType: typeVal, TestVector: testVector}
					_, err := verifier.rpc.VerifyTestVector(ctx(), verReq)

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

		results[typeString] = tvResults
	}

	return results
}

///
/// Main logic
///
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
		"transcript":   pb.TestVectorType_TRANSCRIPT,
		"treekem":      pb.TestVectorType_TREEKEM,
		"messages":     pb.TestVectorType_MESSAGES,
	}

	cipherSuiteDependent = map[pb.TestVectorType]bool{
		pb.TestVectorType_TREE_MATH:    false,
		pb.TestVectorType_ENCRYPTION:   true,
		pb.TestVectorType_KEY_SCHEDULE: true,
		pb.TestVectorType_TRANSCRIPT:   true,
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
	clientPool, err := NewClientPool(config.Clients)
	chk("Failure to conenct to clients", err)
	defer clientPool.Close()

	// Run test vectors
	results := TestResults{}
	results.TestVectors = clientPool.RunTestVectors(config.TestVectors)

	resultsJSON, err := json.MarshalIndent(results, "", "  ")
	chk("Error marshaling results", err)
	fmt.Println(string(resultsJSON))

}

func chk(message string, err error) {
	if err != nil {
		log.Fatalf("Error: %s - %v", message, err)
	}
}
