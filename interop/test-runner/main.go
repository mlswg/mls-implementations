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
	"strconv"
	"time"

	"google.golang.org/grpc"

	pb "github.com/mlswg/mls-implementations/interop/proto"
)

// /
// / Configuration
// /
type ScriptAction string

const (
	ActionCreateGroup          ScriptAction = "createGroup"
	ActionCreateKeyPackage     ScriptAction = "createKeyPackage"
	ActionJoinGroup            ScriptAction = "joinGroup"
	ActionExternalJoin         ScriptAction = "externalJoin"
	ActionPublicGroupState     ScriptAction = "publicGroupState"
	ActionAddProposal          ScriptAction = "addProposal"
	ActionUpdateProposal       ScriptAction = "updateProposal"
	ActionRemoveProposal       ScriptAction = "removeProposal"
	ActionCommit               ScriptAction = "commit"
	ActionHandleCommit         ScriptAction = "handleCommit"
	ActionHandlePendingCommit  ScriptAction = "handlePendingCommit"
	ActionHandleExternalCommit ScriptAction = "handleExternalCommit"
	ActionVerifyStateAuth      ScriptAction = "verifyStateAuth"
	ActionStateProperties      ScriptAction = "stateProperties"
	ActionProtect              ScriptAction = "protect"
	ActionUnprotect            ScriptAction = "unprotect"

	ScriptStateProperties = "stateProperties"
	ActorLeader           = "leader"

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

type AddProposalStepParams struct {
	KeyPackage int `json:"keyPackage"`
}

type RemoveProposalStepParams struct {
	Removed string `json:"removed"`
}

type CommitStepParams struct {
	ByReference []int `json:"byReference"`
	ByValue     []int `json:"byValue"`
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
	Clients []string          `json:"clients"`
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

		for i, leafIndex := range resp.Added {
			config.StoreInteger(index, fmt.Sprintf("added %d", i), leafIndex)
		}

		for i, leafIndex := range resp.Updated {
			config.StoreInteger(index, fmt.Sprintf("updated %d", i), leafIndex)
		}

		if len(resp.RemovedIndices) != len(resp.RemovedLeaves) {
			return fmt.Errorf("Lengths of removed leaves (%d) and indices(%d) do not match.", len(resp.RemovedLeaves), len(resp.RemovedIndices))
		}

		for i := 0; i < len(resp.RemovedIndices); i++ {
			config.StoreInteger(index, fmt.Sprintf("removedIndex %d", i), resp.RemovedIndices[i])
			config.StoreMessage(index, fmt.Sprintf("removedLeaf %d", i), resp.RemovedLeaves[i])
		}

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

		for i, leafIndex := range resp.Added {
			config.StoreInteger(index, fmt.Sprintf("added %d", i), leafIndex)
		}

		for i, leafIndex := range resp.Updated {
			config.StoreInteger(index, fmt.Sprintf("updated %d", i), leafIndex)
		}

		if len(resp.RemovedIndices) != len(resp.RemovedLeaves) {
			return fmt.Errorf("Lengths of removed leaves (%d) and indices(%d) do not match.", len(resp.RemovedLeaves), len(resp.RemovedIndices))
		}

		for i := 0; i < len(resp.RemovedIndices); i++ {
			config.StoreInteger(index, fmt.Sprintf("removedIndex %d", i), resp.RemovedIndices[i])
			config.StoreMessage(index, fmt.Sprintf("removedLeaf %d", i), resp.RemovedLeaves[i])
		}

	case ActionHandleExternalCommit:
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

		req := &pb.HandleExternalCommitRequest{
			StateId: config.stateID[step.Actor],
			Commit:  commit,
		}
		resp, err := client.rpc.HandleExternalCommit(ctx(), req)
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

	case ActionStateProperties:
		// Have the leader create the group
		leader := config.ActorClients[ActorLeader]
		cgReq := &pb.CreateGroupRequest{
			GroupId:          []byte("group"),
			CipherSuite:      config.CipherSuite,
			EncryptHandshake: config.EncryptHandshake,
			Identity:         []byte(ActorLeader),
		}
		cgResp, err := leader.rpc.CreateGroup(ctx(), cgReq)
		if err != nil {
			return fmt.Errorf("CreateGroup: %s %v", leader.name, err)
		}

		config.stateID[ActorLeader] = cgResp.StateId

		// Get KeyPackages from each client, generate Add Proposals
		adds := make([][]byte, 0, len(config.ActorClients)-1)
		for actor, client := range config.ActorClients {
			// Get a KeyPackage
			kpReq := &pb.CreateKeyPackageRequest{
				CipherSuite: config.CipherSuite,
				Identity:    []byte(actor),
			}
			kpResp, err := client.rpc.CreateKeyPackage(ctx(), kpReq)
			if err != nil {
				return fmt.Errorf("CreateKeyPackage: %s %v", client.name, err)
			}

			config.transactionID[actor] = kpResp.TransactionId

			// Have the leader generate an Add Proposal
			addReq := &pb.AddProposalRequest{
				StateId:    config.stateID[ActorLeader],
				KeyPackage: kpResp.KeyPackage,
			}
			addResp, err := leader.rpc.AddProposal(ctx(), addReq)
			if err != nil {
				return fmt.Errorf("AddProposal: %s %v", client.name, err)
			}

			adds = append(adds, addResp.Proposal)
		}

		// Have the leader generate and handle a Commit
		commitReq := &pb.CommitRequest{
			StateId: config.stateID[ActorLeader],
			ByValue: adds,
		}
		commitResp, err := leader.rpc.Commit(ctx(), commitReq)
		if err != nil {
			return fmt.Errorf("Commit: %s %v", leader.name, err)
		}

		handleReq := &pb.HandleCommitRequest{
			StateId: config.stateID[ActorLeader],
			Commit:  commitResp.Commit,
		}
		handleResp, err := leader.rpc.HandleCommit(ctx(), handleReq)
		if err != nil {
			return fmt.Errorf("HandleCommit: %s %v", leader.name, err)
		}

		config.stateID[step.Actor] = handleResp.StateId

		// Have the other participants handle the Welcome
		for actor, client := range config.ActorClients {
			// Get a KeyPackage
			joinReq := &pb.JoinGroupRequest{
				TransactionId:    config.transactionID[actor],
				Welcome:          commitResp.Welcome,
				EncryptHandshake: config.EncryptHandshake,
				Identity:         []byte(actor),
			}
			joinResp, err := client.rpc.JoinGroup(ctx(), joinReq)
			if err != nil {
				return fmt.Errorf("JoinGroup: %s %v", client.name, err)
			}

			config.stateID[actor] = joinResp.StateId
		}

		// Verify that everyone produces the same derived values as the leader

		// XXX(RLB): We cannot compare PublicGroupState for equality, because there
		// are randomized signature algorithms.

		authReq := &pb.StateAuthRequest{StateId: config.stateID[ActorLeader]}
		authResp, err := leader.rpc.StateAuth(ctx(), authReq)
		if err != nil {
			return fmt.Errorf("StateAuth: %s %v", leader.name, err)
		}

		expReq := &pb.ExportRequest{
			StateId:   config.stateID[ActorLeader],
			Label:     "interop test",
			Context:   []byte{1, 2, 3, 4},
			KeyLength: 32,
		}
		expResp, err := leader.rpc.Export(ctx(), expReq)
		if err != nil {
			return fmt.Errorf("Export: %s %v", leader.name, err)
		}

		leaderStateAuth := string(authResp.StateAuthSecret)
		leaderExport := string(expResp.ExportedSecret)
		for actor, client := range config.ActorClients {
			authReq.StateId = config.stateID[actor]
			authResp, err := client.rpc.StateAuth(ctx(), authReq)
			if err != nil {
				return fmt.Errorf("StateAuth: %s %v", client.name, err)
			}

			expReq.StateId = config.stateID[actor]
			expResp, err := client.rpc.Export(ctx(), expReq)
			if err != nil {
				return fmt.Errorf("StateAuth: %s %v", client.name, err)
			}

			if string(authResp.StateAuthSecret) != leaderStateAuth {
				return fmt.Errorf("StateAuthSecret value: %s", client.name)
			}

			if string(expResp.ExportedSecret) != leaderExport {
				return fmt.Errorf("ExportedSecret value: %s", client.name)
			}
		}

		// TODO Verify that everyone can encrypt and be decrypted by the others
		for actor, client := range config.ActorClients {
			message := []byte(fmt.Sprintf("hello from %s!", actor))

			encReq := &pb.ProtectRequest{
				StateId:         config.stateID[actor],
				ApplicationData: message,
			}
			encResp, err := client.rpc.Protect(ctx(), encReq)
			if err != nil {
				return fmt.Errorf("Protect: %s %v", client.name, err)
			}

			for otherActor, otherClient := range config.ActorClients {
				if actor == otherActor {
					// Don't test loopback
					continue
				}

				decReq := &pb.UnprotectRequest{
					StateId:    config.stateID[otherActor],
					Ciphertext: encResp.Ciphertext,
				}
				decResp, err := otherClient.rpc.Unprotect(ctx(), decReq)
				if err != nil {
					return fmt.Errorf("Unprotect: %s %v", client.name, err)
				}

				if string(decResp.ApplicationData) != string(message) {
					return fmt.Errorf("Unprotect value: %s", otherClient.name)
				}
			}
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

func (p *ClientPool) AllClientsForEachSuite() []ScriptActorConfig {
	configSize := 2 * len(p.suiteSupport)

	configs := make([]ScriptActorConfig, 0, configSize)
	for suite, clients := range p.suiteSupport {
		for _, encrypt := range []bool{true, false} {
			config := ScriptActorConfig{
				CipherSuite:      suite,
				EncryptHandshake: encrypt,
				ActorClients:     map[string]*Client{},
			}

			first := true
			for i := range clients {
				client := p.clients[clients[i]]
				config.ActorClients[client.name] = client

				// Assign the first client as the leader as well as being a member
				if first {
					config.ActorClients[ActorLeader] = client
					first = false
				}
			}

			configs = append(configs, config)
		}
	}

	return configs
}

func (p *ClientPool) RunScript(name string, script Script) ScriptResults {
	actors := script.Actors()

	configs := p.ScriptMatrix(actors)
	if name == ScriptStateProperties {
		configs = p.AllClientsForEachSuite()
	}

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
var (
	configOpt string
)

func init() {
	flag.StringVar(&configOpt, "config", "config.json", "config file name")
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

	// Run scripts
	results := TestResults{
		Scripts: map[string]ScriptResults{},
	}
	for name, script := range config.Scripts {
		results.Scripts[name] = clientPool.RunScript(name, script)
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
