package main

import (
	"context"
	"encoding/hex"
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
	ActionCreateGroup      ScriptAction = "createGroup"
	ActionCreateKeyPackage ScriptAction = "createKeyPackage"
	ActionJoinGroup        ScriptAction = "joinGroup"
	ActionExternalJoin     ScriptAction = "externalJoin"
	ActionPublicGroupState ScriptAction = "publicGroupState"
	ActionAddProposal      ScriptAction = "addProposal"
	ActionCommit           ScriptAction = "commit"
	ActionHandleCommit     ScriptAction = "handleCommit"
	ActionVerifyStateAuth  ScriptAction = "verifyStateAuth"
)

type ScriptStep struct {
	Actor  string       `json:"actor"`
	Action ScriptAction `json:"action"`
	Raw    []byte       `json:"raw"`
}

type JoinGroupStepParams struct {
	Welcome int `json:"welcome"`
}

type ExternalJoinStepParams struct {
	PublicGroupState int `json:"publicGroupState"`
}

type AddProposalStepParams struct {
	KeyPackage int `json:"keyPackage"`
}

type CommitStepParams struct {
	ByReference []int `json:"byReference"`
	ByValue     []int `json:"byValue"`
}

type HandleCommitStepParams struct {
	Commit      int   `json:"commit"`
	ByReference []int `json:"byReference"`
}

func (step *ScriptStep) UnmarshalJSON(data []byte) error {
	var parsed map[string]interface{}
	err := json.Unmarshal(data, &parsed)
	if err != nil {
		return err
	}

	if action, ok := parsed["action"]; ok {
		step.Action = ScriptAction(action.(string))
	} else {
		return fmt.Errorf("Incomplete step: Missing action")
	}

	if actor, ok := parsed["actor"]; ok {
		step.Actor = actor.(string)
	}

	step.Raw = make([]byte, len(data))
	copy(step.Raw, data)

	return nil
}

type TestVectorConfig []string

type Script []ScriptStep

func (s Script) Actors() []string {
	actorMap := map[string]bool{}
	for _, step := range s {
		if len(step.Actor) == 0 {
			continue
		}

		actorMap[step.Actor] = true
	}

	actors := make([]string, 0, len(actorMap))
	for actor := range actorMap {
		actors = append(actors, actor)
	}

	return actors
}

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

type ScriptResult struct {
	CipherSuite      uint32            `json:"cipher_suite"`
	Actors           map[string]string `json:"actors"`
	EncryptHandshake bool              `json:"encrypt_flag"`

	Transcript []map[string]string `json:"transcript,omitempty"`
	Error      interface{}         `json:"error,omitempty"`
	FailedStep *int                `json:"failed_step,omitempty"`
}

type ScriptResults []ScriptResult

type TestResults struct {
	TestVectors TestVectorResults        `json:"test_vectors"`
	Scripts     map[string]ScriptResults `json:"scripts"`
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
	clients      []*Client
	suiteSupport map[uint32][]int
}

func NewClientPool(configs []string) (*ClientPool, error) {
	p := &ClientPool{
		clients:      make([]*Client, len(configs)),
		suiteSupport: map[uint32][]int{},
	}

	var err error
	for i, addr := range configs {
		p.clients[i], err = NewClient(addr)
		if err != nil {
			return nil, err
		}

		for suite := range p.clients[i].supported {
			p.suiteSupport[suite] = append(p.suiteSupport[suite], i)
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
			// Generate test vectors for all supported ciphersuites
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

func combinations(vals, slots int) [][]int {
	return combinationsInner(vals, slots, [][]int{{}})
}

func combinationsInner(vals int, slots int, base [][]int) [][]int {
	if slots == 0 {
		return base
	}

	ix := make([]bool, vals)
	out := make([][]int, 0, vals*len(base))
	for _, tuple := range base {
		for v := range ix {
			out = append(out, append(tuple, v))
		}
	}

	return combinationsInner(vals, slots-1, out)
}

// Each script is run for each combination of:
// * Ciphersuite
// * Assignment of clients to roles
// * Encrypted or plaintext handshake
type ScriptActorConfig struct {
	CipherSuite      uint32
	EncryptHandshake bool
	ActorClients     map[string]*Client

	stateID       map[string]uint32
	transactionID map[string]uint32
	transcript    []map[string]string
}

func (config *ScriptActorConfig) StoreMessage(index int, key string, message []byte) {
	config.transcript[index][key] = hex.EncodeToString(message)
}

func (config *ScriptActorConfig) GetMessage(index int, key string) ([]byte, error) {
	messageHex, ok := config.transcript[index][key]
	if !ok {
		return nil, fmt.Errorf("No message for key %s at step %d", key, index)
	}

	message, err := hex.DecodeString(messageHex)
	if err != nil {
		return nil, err
	}

	return message, nil
}

func (config *ScriptActorConfig) RunStep(index int, step ScriptStep) error {
	switch step.Action {
	case ActionCreateGroup:
		client := config.ActorClients[step.Actor]
		req := &pb.CreateGroupRequest{
			GroupId:          []byte("group"),
			CipherSuite:      config.CipherSuite,
			EncryptHandshake: config.EncryptHandshake,
		}
		resp, err := client.rpc.CreateGroup(ctx(), req)
		if err != nil {
			return err
		}

		config.stateID[step.Actor] = resp.StateId

	case ActionCreateKeyPackage:
		client := config.ActorClients[step.Actor]
		req := &pb.CreateKeyPackageRequest{
			CipherSuite: config.CipherSuite,
		}
		resp, err := client.rpc.CreateKeyPackage(ctx(), req)
		if err != nil {
			return err
		}

		config.transactionID[step.Actor] = resp.TransactionId
		config.StoreMessage(index, "keyPackage", resp.KeyPackage)

	case ActionJoinGroup:
		client := config.ActorClients[step.Actor]
		var params JoinGroupStepParams
		err := json.Unmarshal(step.Raw, &params)
		if err != nil {
			return err
		}

		welcome, err := config.GetMessage(params.Welcome, "welcome")
		if err != nil {
			return err
		}

		txID, ok := config.transactionID[step.Actor]
		if !ok {
			return fmt.Errorf("Malformed step: No transaction for %d", step.Actor)
		}

		req := &pb.JoinGroupRequest{
			TransactionId:    txID,
			Welcome:          welcome,
			EncryptHandshake: config.EncryptHandshake,
		}
		resp, err := client.rpc.JoinGroup(ctx(), req)
		if err != nil {
			return err
		}

		config.stateID[step.Actor] = resp.StateId

	case ActionExternalJoin:
		client := config.ActorClients[step.Actor]
		var params ExternalJoinStepParams
		err := json.Unmarshal(step.Raw, &params)
		if err != nil {
			return err
		}

		pgs, err := config.GetMessage(params.PublicGroupState, "publicGroupState")
		if err != nil {
			return err
		}

		req := &pb.ExternalJoinRequest{
			PublicGroupState: pgs,
			EncryptHandshake: config.EncryptHandshake,
		}
		resp, err := client.rpc.ExternalJoin(ctx(), req)
		if err != nil {
			return err
		}

		config.stateID[step.Actor] = resp.StateId
		config.StoreMessage(index, "commit", resp.Commit)

	case ActionPublicGroupState:
		client := config.ActorClients[step.Actor]

		req := &pb.PublicGroupStateRequest{
			StateId: config.stateID[step.Actor],
		}
		resp, err := client.rpc.PublicGroupState(ctx(), req)
		if err != nil {
			return err
		}

		config.StoreMessage(index, "publicGroupState", resp.PublicGroupState)

	case ActionAddProposal:
		client := config.ActorClients[step.Actor]
		var params AddProposalStepParams
		err := json.Unmarshal(step.Raw, &params)
		if err != nil {
			return err
		}

		keyPackage, err := config.GetMessage(params.KeyPackage, "keyPackage")
		if err != nil {
			return err
		}

		req := &pb.AddProposalRequest{
			StateId:    config.stateID[step.Actor],
			KeyPackage: keyPackage,
		}
		resp, err := client.rpc.AddProposal(ctx(), req)
		if err != nil {
			return err
		}

		config.StoreMessage(index, "proposal", resp.Proposal)

	case ActionCommit:
		client := config.ActorClients[step.Actor]
		var params CommitStepParams
		err := json.Unmarshal(step.Raw, &params)
		if err != nil {
			return err
		}

		byRef := make([][]byte, len(params.ByReference))
		for i, ix64 := range params.ByReference {
			byRef[i], err = config.GetMessage(int(ix64), "proposal")
			if err != nil {
				return err
			}
		}

		byVal := make([][]byte, len(params.ByValue))
		for i, ix64 := range params.ByValue {
			byVal[i], err = config.GetMessage(int(ix64), "proposal")
			if err != nil {
				return err
			}
		}

		req := &pb.CommitRequest{
			StateId:     config.stateID[step.Actor],
			ByReference: byRef,
			ByValue:     byVal,
		}
		resp, err := client.rpc.Commit(ctx(), req)
		if err != nil {
			return err
		}

		config.StoreMessage(index, "commit", resp.Commit)
		config.StoreMessage(index, "welcome", resp.Welcome)

	case ActionHandleCommit:
		client := config.ActorClients[step.Actor]
		var params HandleCommitStepParams
		err := json.Unmarshal(step.Raw, &params)
		if err != nil {
			return err
		}

		commit, err := config.GetMessage(params.Commit, "commit")
		if err != nil {
			return err
		}

		byRef := make([][]byte, len(params.ByReference))
		for i, ix64 := range params.ByReference {
			byRef[i], err = config.GetMessage(int(ix64), "proposal")
			if err != nil {
				return err
			}
		}

		req := &pb.HandleCommitRequest{
			StateId:  config.stateID[step.Actor],
			Proposal: byRef,
			Commit:   commit,
		}
		resp, err := client.rpc.HandleCommit(ctx(), req)
		if err != nil {
			return err
		}

		config.stateID[step.Actor] = resp.StateId

	case ActionVerifyStateAuth:
		authSet := map[string]bool{}
		for actor, client := range config.ActorClients {
			req := &pb.StateAuthRequest{StateId: config.stateID[actor]}
			resp, err := client.rpc.StateAuth(ctx(), req)
			if err != nil {
				return err
			}

			auth := resp.StateAuthSecret
			authSet[string(auth)] = true
			config.StoreMessage(index, actor, auth)
		}

		if len(authSet) > 1 {
			return fmt.Errorf("Members do not agree on state auth secret")
		}

	default:
		return fmt.Errorf("Unknown action: %s", step.Action)
	}

	return nil
}

func (config *ScriptActorConfig) Run(script Script) ScriptResult {
	config.stateID = map[string]uint32{}
	config.transactionID = map[string]uint32{}
	config.transcript = make([]map[string]string, len(script))

	for i := range config.transcript {
		config.transcript[i] = map[string]string{}
	}

	// Prepare a partial result to return if we need to abort
	result := ScriptResult{
		CipherSuite:      config.CipherSuite,
		Actors:           map[string]string{},
		EncryptHandshake: config.EncryptHandshake,

		// Since this copies the map by reference, it will be updates as
		// config.transcript is updated below
		Transcript: config.transcript,
	}

	actors := script.Actors()
	for i := range actors {
		result.Actors[actors[i]] = config.ActorClients[actors[i]].name
	}

	// Run the steps to completion or error
	for i, step := range script {
		err := config.RunStep(i, step)
		if err != nil {
			result.Error = err.Error()
			result.FailedStep = new(int)
			*result.FailedStep = i
			return result
		}
	}

	return result
}

func (p *ClientPool) ScriptMatrix(actors []string) []ScriptActorConfig {
	configSize := 2 * len(p.suiteSupport) * len(p.clients)

	configs := make([]ScriptActorConfig, 0, configSize)
	for suite, clients := range p.suiteSupport {
		for _, combo := range combinations(len(clients), len(actors)) {
			for _, encrypt := range []bool{true, false} {
				config := ScriptActorConfig{
					CipherSuite:      suite,
					EncryptHandshake: encrypt,
					ActorClients:     map[string]*Client{},
				}

				for i := range actors {
					config.ActorClients[actors[i]] = p.clients[combo[i]]
				}

				configs = append(configs, config)
			}
		}
	}

	return configs
}

func (p *ClientPool) RunScript(script Script) ScriptResults {
	actors := script.Actors()
	configs := p.ScriptMatrix(actors)
	results := make(ScriptResults, 0, len(configs))

	for _, config := range configs {
		result := config.Run(script)
		results = append(results, result)
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
	results.Scripts = map[string]ScriptResults{}
	for name, script := range config.Scripts {
		results.Scripts[name] = clientPool.RunScript(script)
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
