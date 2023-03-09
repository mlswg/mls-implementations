package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"strconv"
	"time"

	"google.golang.org/grpc"

	pb "github.com/mlswg/mls-implementations/interop/proto"
)

// /
// / Configuration
// /
type ClientMode string
type HandshakeMode string
type ScriptAction string

const (
	ClientModeAll    ClientMode = "allCombinations"
	ClientModeRandom ClientMode = "random"

	HandshakeModeAll     HandshakeMode = "all"
	HandshakeModePrivate HandshakeMode = "private"
	HandshakeModePublic  HandshakeMode = "public"

	ActionCreateGroup          ScriptAction = "createGroup"
	ActionCreateKeyPackage     ScriptAction = "createKeyPackage"
	ActionJoinGroup            ScriptAction = "joinGroup"
	ActionExternalJoin         ScriptAction = "externalJoin"
	ActionInstallExternalPSK   ScriptAction = "installExternalPSK"
	ActionPublicGroupState     ScriptAction = "publicGroupState"
	ActionAddProposal          ScriptAction = "addProposal"
	ActionUpdateProposal       ScriptAction = "updateProposal"
	ActionRemoveProposal       ScriptAction = "removeProposal"
	ActionPreSharedKeyProposal ScriptAction = "preSharedKeyProposal"
	ActionFullCommit           ScriptAction = "fullCommit"
	ActionCommit               ScriptAction = "commit"
	ActionHandleCommit         ScriptAction = "handleCommit"
	ActionHandlePendingCommit  ScriptAction = "handlePendingCommit"
	ActionProtect              ScriptAction = "protect"
	ActionUnprotect            ScriptAction = "unprotect"

	TimeoutSeconds = 120
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

type InstallExternalPSKStepParams struct {
	Clients []string `json:"clients"`
}

type AddProposalStepParams struct {
	KeyPackage int `json:"keyPackage"`
}

type RemoveProposalStepParams struct {
	Removed string `json:"removed"`
}

type PreSharedKeyProposalStepParams struct {
	PSK int `json:"psk"`
}

type FullCommitStepParams struct {
	ByReference  []int    `json:"byReference"`
	ByValue      []int    `json:"byValue"`
	Members      []string `json:"members"`
	Joiners      []string `json:"joiners"`
	ForcePath    bool     `json:"force_path"`
	ExternalTree bool     `json:"external_tree"`
}

type CommitStepParams struct {
	ByReference  []int `json:"byReference"`
	ByValue      []int `json:"byValue"`
	ForcePath    bool  `json:"force_path"`
	ExternalTree bool  `json:"external_tree"`
}

type HandleCommitStepParams struct {
	Commit      int   `json:"commit"`
	ByReference []int `json:"byReference"`
}

type ProtectStepParams struct {
	ApplicationData []byte `json:"applicationData"`
}

type UnprotectStepParams struct {
	Ciphertext int `json:"ciphertext"`
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
	Mode    ClientMode        `json:"mode",omitempty`
	Scripts map[string]Script `json:"scripts",omitempty`
}

// /
// / Results
// /
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
	Scripts map[string]ScriptResults `json:"scripts"`
}

// /
// / Clients
// /
type Client struct {
	conn      *grpc.ClientConn
	rpc       pb.MLSClientClient
	name      string
	supported map[uint32]bool
}

func ctx() context.Context {
	c, _ := context.WithTimeout(context.Background(), time.Second*TimeoutSeconds)
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

func randomCombination(vals, slots int) []int {
	combo := make([]int, slots)
	for i := range combo {
		combo[i] = rand.Intn(vals)
	}
	return combo
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

func (config *ScriptActorConfig) StoreInteger(index int, key string, integer uint32) {
	config.transcript[index][key] = strconv.FormatUint(uint64(integer), 10)
}

func (config *ScriptActorConfig) RunStep(index int, step ScriptStep) error {
	switch step.Action {
	case ActionCreateGroup:
		client := config.ActorClients[step.Actor]
		req := &pb.CreateGroupRequest{
			GroupId:          []byte("group"),
			CipherSuite:      config.CipherSuite,
			EncryptHandshake: config.EncryptHandshake,
			Identity:         []byte(step.Actor),
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
			Identity:    []byte(step.Actor),
		}
		resp, err := client.rpc.CreateKeyPackage(ctx(), req)
		if err != nil {
			return err
		}

		config.transactionID[step.Actor] = resp.TransactionId
		config.StoreMessage(index, "key_package", resp.KeyPackage)
		config.StoreMessage(index, "init_priv", resp.InitPriv)
		config.StoreMessage(index, "encryption_priv", resp.EncryptionPriv)
		config.StoreMessage(index, "signature_priv", resp.SignaturePriv)

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
			return fmt.Errorf("Malformed step: No transaction for %s", step.Actor)
		}

		req := &pb.JoinGroupRequest{
			TransactionId:    txID,
			Welcome:          welcome,
			EncryptHandshake: config.EncryptHandshake,
			Identity:         []byte(step.Actor),
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
			Identity:         []byte(step.Actor),
		}
		resp, err := client.rpc.ExternalJoin(ctx(), req)
		if err != nil {
			return err
		}

		config.stateID[step.Actor] = resp.StateId
		config.StoreMessage(index, "commit", resp.Commit)

	case ActionInstallExternalPSK:
		var params InstallExternalPSKStepParams
		err := json.Unmarshal(step.Raw, &params)
		if err != nil {
			return err
		}

		pskID := make([]byte, 32)
		rand.Read(pskID)
		config.StoreMessage(index, "psk_id", pskID)

		pskSecret := make([]byte, 32)
		rand.Read(pskSecret)
		config.StoreMessage(index, "psk_secret", pskSecret)

		for _, clientName := range params.Clients {
			client := config.ActorClients[clientName]

			id := uint32(0)
			if stateID, ok := config.stateID[clientName]; ok {
				id = stateID
			} else if txID, ok := config.transactionID[clientName]; ok {
				id = txID
			}

			req := &pb.StorePSKRequest{
				StateOrTransactionId: id,
				PskId:                pskID,
				PskSecret:            pskSecret,
			}
			_, err := client.rpc.StorePSK(ctx(), req)
			if err != nil {
				return err
			}
		}

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

		keyPackage, err := config.GetMessage(params.KeyPackage, "key_package")
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

	case ActionRemoveProposal:
		client := config.ActorClients[step.Actor]
		var params RemoveProposalStepParams
		err := json.Unmarshal(step.Raw, &params)

		if err != nil {
			return err
		}

		req := &pb.RemoveProposalRequest{
			StateId:   config.stateID[step.Actor],
			RemovedId: []byte(params.Removed),
		}

		resp, err := client.rpc.RemoveProposal(ctx(), req)

		if err != nil {
			return err
		}

		config.StoreMessage(index, "proposal", resp.Proposal)

	case ActionUpdateProposal:
		client := config.ActorClients[step.Actor]

		req := &pb.UpdateProposalRequest{
			StateId: config.stateID[step.Actor],
		}

		resp, err := client.rpc.UpdateProposal(ctx(), req)

		if err != nil {
			return err
		}

		config.StoreMessage(index, "proposal", resp.Proposal)

	case ActionPreSharedKeyProposal:
		client := config.ActorClients[step.Actor]
		var params PreSharedKeyProposalStepParams
		err := json.Unmarshal(step.Raw, &params)
		if err != nil {
			return err
		}

		pskID, err := config.GetMessage(params.PSK, "psk_id")
		if err != nil {
			return err
		}

		req := &pb.PSKProposalRequest{
			StateId: config.stateID[step.Actor],
			PskId:   pskID,
		}
		resp, err := client.rpc.PSKProposal(ctx(), req)
		if err != nil {
			return err
		}

		config.StoreMessage(index, "proposal", resp.Proposal)

	case ActionFullCommit:
		client := config.ActorClients[step.Actor]
		var params FullCommitStepParams
		err := json.Unmarshal(step.Raw, &params)
		if err != nil {
			return err
		}

		// Create the Commit [ActionCommit]
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

		commitReq := &pb.CommitRequest{
			StateId:      config.stateID[step.Actor],
			ByReference:  byRef,
			ByValue:      byVal,
			ForcePath:    params.ForcePath,
			ExternalTree: params.ExternalTree,
		}
		commitResp, err := client.rpc.Commit(ctx(), commitReq)
		if err != nil {
			return err
		}

		config.StoreMessage(index, "welcome", commitResp.Welcome)
		config.StoreMessage(index, "commit", commitResp.Commit)
		if !params.ExternalTree {
			config.StoreMessage(index, "ratchet_tree", commitResp.RatchetTree)
		}

		// Apply it at the committer [ActionHandlePendingCommit]
		epochAuthenticator := []byte{}
		{
			req := &pb.HandlePendingCommitRequest{
				StateId: config.stateID[step.Actor],
			}

			resp, err := client.rpc.HandlePendingCommit(ctx(), req)
			if err != nil {
				return err
			}

			config.stateID[step.Actor] = resp.StateId
			epochAuthenticator = resp.EpochAuthenticator
		}

		config.StoreMessage(index, "epoch_authenticator", epochAuthenticator)

		// Apply it at the other members [ActionHandleCommit]
		for _, member := range params.Members {
			client := config.ActorClients[member]
			req := &pb.HandleCommitRequest{
				StateId:  config.stateID[member],
				Proposal: byRef,
				Commit:   commitResp.Commit,
			}
			resp, err := client.rpc.HandleCommit(ctx(), req)
			if err != nil {
				return err
			}

			if !bytes.Equal(resp.EpochAuthenticator, epochAuthenticator) {
				return fmt.Errorf("Member [%s] failed to agree on epoch authenticator", member)
			}

			config.stateID[member] = resp.StateId
		}

		// Initialize the joiners [ActionJoinGroup]
		for _, joiner := range params.Joiners {
			txID, ok := config.transactionID[joiner]
			if !ok {
				return fmt.Errorf("Malformed step: No transaction for %s", joiner)
			}

			client := config.ActorClients[joiner]

			req := &pb.JoinGroupRequest{
				TransactionId:    txID,
				Welcome:          commitResp.Welcome,
				EncryptHandshake: config.EncryptHandshake,
				Identity:         []byte(joiner),
			}

			if params.ExternalTree {
				req.RatchetTree = commitResp.RatchetTree
			}

			resp, err := client.rpc.JoinGroup(ctx(), req)
			if err != nil {
				return err
			}

			if !bytes.Equal(resp.EpochAuthenticator, epochAuthenticator) {
				return fmt.Errorf("Joiner [%s] failed to agree on epoch authenticator", joiner)
			}

			config.stateID[joiner] = resp.StateId
		}

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
			StateId:      config.stateID[step.Actor],
			ByReference:  byRef,
			ByValue:      byVal,
			ForcePath:    params.ForcePath,
			ExternalTree: params.ExternalTree,
		}
		resp, err := client.rpc.Commit(ctx(), req)
		if err != nil {
			return err
		}

		config.StoreMessage(index, "commit", resp.Commit)
		config.StoreMessage(index, "welcome", resp.Welcome)
		if !params.ExternalTree {
			config.StoreMessage(index, "ratchet_tree", resp.RatchetTree)
		}

	case ActionProtect:
		client := config.ActorClients[step.Actor]
		var params ProtectStepParams
		err := json.Unmarshal(step.Raw, &params)
		if err != nil {
			return err
		}

		req := &pb.ProtectRequest{
			StateId:         config.stateID[step.Actor],
			ApplicationData: params.ApplicationData,
		}
		resp, err := client.rpc.Protect(ctx(), req)
		if err != nil {
			return err
		}

		config.StoreMessage(index, "ciphertext", resp.Ciphertext)

	case ActionUnprotect:
		client := config.ActorClients[step.Actor]
		var params UnprotectStepParams
		err := json.Unmarshal(step.Raw, &params)
		if err != nil {
			return err
		}

		ciphertext, err := config.GetMessage(params.Ciphertext, "ciphertext")
		if err != nil {
			return err
		}

		req := &pb.UnprotectRequest{
			StateId:    config.stateID[step.Actor],
			Ciphertext: ciphertext,
		}
		resp, err := client.rpc.Unprotect(ctx(), req)
		if err != nil {
			return err
		}

		config.StoreMessage(index, "applicationData", resp.ApplicationData)

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

	case ActionHandlePendingCommit:
		client := config.ActorClients[step.Actor]

		req := &pb.HandlePendingCommitRequest{
			StateId: config.stateID[step.Actor],
		}

		resp, err := client.rpc.HandlePendingCommit(ctx(), req)

		if err != nil {
			return err
		}

		config.stateID[step.Actor] = resp.StateId

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

func (p *ClientPool) ScriptMatrix(actors []string, clientMode ClientMode, suite int, hsMode HandshakeMode) []ScriptActorConfig {
	suite32 := uint32(suite)
	suites := []uint32{}
	if suite == 0 {
		suites = []uint32{}
		for suite := range p.suiteSupport {
			suites = append(suites, suite)
		}
	} else if _, ok := p.suiteSupport[suite32]; ok {
		suites = []uint32{suite32}
	} else {
		panic(fmt.Sprintf("Unsupported ciphersuite: %d", suite))
	}

	encryptOptions := []bool{true, false}
	switch hsMode {
	case HandshakeModeAll:
		// Default

	case HandshakeModePrivate:
		encryptOptions = []bool{true}

	case HandshakeModePublic:
		encryptOptions = []bool{false}
	}

	configs := []ScriptActorConfig{}
	for _, suite := range suites {
		clients := p.suiteSupport[suite]

		for _, encrypt := range encryptOptions {
			combos := [][]int{}
			switch clientMode {
			case ClientModeAll:
				combos = combinations(len(clients), len(actors))

			case ClientModeRandom:
				combos = [][]int{randomCombination(len(clients), len(actors))}
			}

			for _, combo := range combos {
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

func (p *ClientPool) RunScript(name string, clientMode ClientMode, suite int, hsMode HandshakeMode, script Script) ScriptResults {
	actors := script.Actors()
	configs := p.ScriptMatrix(actors, clientMode, suite, hsMode)

	results := make(ScriptResults, 0, len(configs))
	for _, config := range configs {
		result := config.Run(script)
		results = append(results, result)
	}

	return results
}

// /
// / Main logic
// /

type stringListFlag []string

func (i *stringListFlag) String() string {
	return "repeated options"
}

func (i *stringListFlag) Set(value string) error {
	*i = append(*i, value)
	return nil
}

var (
	clientsOpt stringListFlag
	configOpt  string
	randomOpt  bool
	suiteOpt   int
	privateOpt bool
	publicOpt  bool
)

func init() {
	flag.Var(&clientsOpt, "client", "host:port for a client")
	flag.StringVar(&configOpt, "config", "config.json", "config file name")
	flag.BoolVar(&randomOpt, "random", false, "run a random assignment of clients to roles")
	flag.IntVar(&suiteOpt, "suite", 0, "only run tests for a single ciphersuite")
	flag.BoolVar(&privateOpt, "private", false, "only run tests with handshake messages as PrivateMessage")
	flag.BoolVar(&publicOpt, "public", false, "only run tests with handshake messages as PublicMessage")
	flag.Parse()
}

var (
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
	// Determine the operating modes
	clientMode := ClientModeAll
	if randomOpt {
		clientMode = ClientModeRandom
	}

	hsMode := HandshakeModeAll
	if privateOpt && !publicOpt {
		hsMode = HandshakeModePrivate
	} else if !privateOpt && publicOpt {
		hsMode = HandshakeModePublic
	}

	// Load and parse the config
	jsonFile, err := os.Open(configOpt)
	chk("Failure to open config file", err)

	jsonData, err := ioutil.ReadAll(jsonFile)
	chk("Failure to read config file", err)

	config := new(RunConfig)
	err = json.Unmarshal(jsonData, config)
	chk("Failure to parse config file", err)

	// Connect to clients
	clientPool, err := NewClientPool(clientsOpt)
	chk("Failure to conenct to clients", err)
	defer clientPool.Close()

	// Run scripts
	results := TestResults{
		Scripts: map[string]ScriptResults{},
	}
	for name, script := range config.Scripts {
		results.Scripts[name] = clientPool.RunScript(name, clientMode, suiteOpt, hsMode, script)
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
