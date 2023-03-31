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

	"github.com/google/uuid"
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

	ActionCreateGroup                    ScriptAction = "createGroup"
	ActionCreateKeyPackage               ScriptAction = "createKeyPackage"
	ActionJoinGroup                      ScriptAction = "joinGroup"
	ActionExternalJoin                   ScriptAction = "externalJoin"
	ActionInstallExternalPSK             ScriptAction = "installExternalPSK"
	ActionGroupInfo                      ScriptAction = "groupInfo"
	ActionAddProposal                    ScriptAction = "addProposal"
	ActionUpdateProposal                 ScriptAction = "updateProposal"
	ActionRemoveProposal                 ScriptAction = "removeProposal"
	ActionExternalPSKProposal            ScriptAction = "externalPSKProposal"
	ActionResumptionPSKProposal          ScriptAction = "resumptionPSKProposal"
	ActionGroupContextExtensionsProposal ScriptAction = "groupContextExtensionsProposal"
	ActionFullCommit                     ScriptAction = "fullCommit"
	ActionCommit                         ScriptAction = "commit"
	ActionHandleCommit                   ScriptAction = "handleCommit"
	ActionHandlePendingCommit            ScriptAction = "handlePendingCommit"
	ActionProtect                        ScriptAction = "protect"
	ActionUnprotect                      ScriptAction = "unprotect"
	ActionReInit                         ScriptAction = "reinit"
	ActionBranch                         ScriptAction = "branch"
	ActionNewMemberAddProposal           ScriptAction = "newMemberAddProposal"
	ActionAddExternalSigner              ScriptAction = "addExternalSigner"
	ActionExternalSignerProposal         ScriptAction = "externalSignerProposal"

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
	Joiner       string   `json:"joiner"`
	Members      []string `json:"members"`
	ExternalTree bool     `json:"externalTree"`
	RemovePrior  bool     `json:"removePrior"`
	PSKs         []int    `json:"psks"`
}

type GroupInfoStepParams struct {
	ExternalTree bool `json:"externalTree"`
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

type ExternalPSKProposalStepParams struct {
	PskId int `json:"pskID"`
}

type ResumptionPSKProposalStepParams struct {
	EpochId int `json:"epochID"`
}

type GroupContextExtensionsProposalStepParams struct {
	Extensions []*pb.Extension `json:"extensions"`
}

type ProposalDescription struct {
	ProposalType      string          `json:"proposalType"`
	KeyPackage        int             `json:"keyPackage"`
	Removed           string          `json:"removed"`
	PskId             int             `json:"pskID"`
	EpochId           int             `json:"epochID"`
	Extensions        []*pb.Extension `json:"extensions"`
	ChangeGroupId     bool            `json:"changeGroupID"`
	ChangeCipherSuite bool            `json:"changeCipherSuite"`
}

func (proposalDescription *ProposalDescription) ProposalDescriptionToProto(config *ScriptActorConfig) (*pb.ProposalDescription, error) {
	proposalDescProto := &pb.ProposalDescription{ProposalType: []byte(proposalDescription.ProposalType)}
	var err error

	switch proposalDescription.ProposalType {
	case "add":
		proposalDescProto.KeyPackage, err = config.GetMessage(proposalDescription.KeyPackage, "key_package")
	case "remove":
		proposalDescProto.RemovedId = []byte(proposalDescription.Removed)
	case "externalPSK":
		proposalDescProto.PskId, err = config.GetMessage(proposalDescription.PskId, "psk_id")
	case "resumptionPSK":
		proposalDescProto.EpochId = uint64(proposalDescription.EpochId)
	case "groupContextExtensions":
		proposalDescProto.Extensions = proposalDescription.Extensions
	case "reinit":
		proposalDescProto.Extensions = proposalDescription.Extensions
		if proposalDescription.ChangeCipherSuite {
			err = config.ChangeCipherSuite()
			if err != nil {
				return nil, err
			}
		}
		proposalDescProto.CipherSuite = config.CipherSuite
		proposalDescProto.GroupId, err = config.NewGroupID(proposalDescription.ChangeGroupId)

	default:
		err = fmt.Errorf("unknown proposal type [%s]", proposalDescription.ProposalType)
	}

	if err != nil {
		return nil, err
	}

	return proposalDescProto, nil
}

type FullCommitStepParams struct {
	ByReference  []int                 `json:"byReference"`
	ByValue      []ProposalDescription `json:"byValue"`
	Members      []string              `json:"members"`
	Joiners      []string              `json:"joiners"`
	ForcePath    bool                  `json:"force_path"`
	ExternalTree bool                  `json:"external_tree"`
}

type CommitStepParams struct {
	ByReference  []int                 `json:"byReference"`
	ByValue      []ProposalDescription `json:"byValue"`
	ForcePath    bool                  `json:"force_path"`
	ExternalTree bool                  `json:"external_tree"`
}

type HandleCommitStepParams struct {
	Commit      int   `json:"commit"`
	ByReference []int `json:"byReference"`
}

type ProtectStepParams struct {
	AuthenticatedData string `json:"authenticatedData"`
	Plaintext         string `json:"plaintext"`
}

type UnprotectStepParams struct {
	Ciphertext int `json:"ciphertext"`
}

type ReInitStepParams struct {
	Proposer               string          `json:"proposer"`
	Committer              string          `json:"committer"`
	Welcomer               string          `json:"welcomer"`
	Members                []string        `json:"members"`
	ChangeCipherSuite      bool            `json:"changeCipherSuite"`
	ChangeGroupID          bool            `json:"changeGroupID"`
	Extensions             []*pb.Extension `json:"extensions"`
	ForcePath              bool            `json:"forcePath"`
	ExternalTree           bool            `json:"externalTree"`
	ExternalReinitProposal int             `json:"externalReinitProposal"`
}

type BranchStepParams struct {
	Members      []string        `json:"members"`
	ForcePath    bool            `json:"force_path"`
	ExternalTree bool            `json:"external_tree"`
	Extensions   []*pb.Extension `json:"extensions"`
}

type NewMemberAddProposalStepParams struct {
	Joiner string `json:"joiner"`
}

type AddExternalSignerStepParams struct {
	Signer string `json:"signer"`
}

type ExternalSignerProposalStepParams struct {
	Member      string              `json:"member"`
	Description ProposalDescription `json:"description"`
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

		if step.Action == ActionExternalJoin {
			var params ExternalJoinStepParams
			err := json.Unmarshal(step.Raw, &params)
			if err != nil {
				continue
			}

			actorMap[params.Joiner] = true
		}

		if step.Action == ActionNewMemberAddProposal {
			var params NewMemberAddProposalStepParams
			err := json.Unmarshal(step.Raw, &params)
			if err != nil {
				continue
			}

			actorMap[params.Joiner] = true
		}

		if step.Action == ActionAddExternalSigner {
			var params AddExternalSignerStepParams
			err := json.Unmarshal(step.Raw, &params)
			if err != nil {
				continue
			}

			actorMap[params.Signer] = true
		}
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

type RPCTranscriptEntry struct {
	Actor    string      `json:"actor"`
	RPC      string      `json:"rpc"`
	Request  interface{} `json:"request"`
	Response interface{} `json:"response"`
}

type ScriptResult struct {
	CipherSuite      uint32            `json:"cipher_suite"`
	Actors           map[string]string `json:"actors"`
	EncryptHandshake bool              `json:"encrypt_flag"`

	Transcript     []RPCTranscriptEntry `json:"transcript,omitempty"`
	Error          interface{}          `json:"error,omitempty"`
	FailedStep     *int                 `json:"failed_step,omitempty"`
	FailedStepJSON string               `json:"failed_step_json,omitempty"`
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
	signerID      map[string]uint32
	messageCache  []map[string]string
	transcript    []RPCTranscriptEntry
}

func (config *ScriptActorConfig) Log(actor string, rpc string, request, response interface{}) {
	config.transcript = append(config.transcript, RPCTranscriptEntry{actor, rpc, request, response})
}

func (config *ScriptActorConfig) StoreMessage(index int, key string, message []byte) {
	config.messageCache[index][key] = hex.EncodeToString(message)
}

func (config *ScriptActorConfig) GetMessage(index int, key string) ([]byte, error) {
	messageHex, ok := config.messageCache[index][key]
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
	config.messageCache[index][key] = strconv.FormatUint(uint64(integer), 10)
}

func (config *ScriptActorConfig) NewGroupID(changeId bool) ([]byte, error) {
	newGroupID, err := config.GetMessage(0, "group_id")
	if err != nil {
		return nil, err
	}
	if changeId {
		newGroupID = append(newGroupID, []byte("++")...)
	}
	return newGroupID, nil
}

func (config *ScriptActorConfig) ChangeCipherSuite() error {
	// Compute the set of ciphersuites supported by all clients
	var supportedSuites map[uint32]bool
	for _, client := range config.ActorClients {
		// Initialize with the first client
		if supportedSuites == nil {
			supportedSuites = map[uint32]bool{}
			for suite := range client.supported {
				supportedSuites[suite] = true
			}
			continue
		}

		// Then remove suites not supported by other clients
		for suite := range supportedSuites {
			if !client.supported[suite] {
				delete(supportedSuites, suite)
			}
		}
	}

	// Remove the current ciphersuite
	delete(supportedSuites, config.CipherSuite)

	// Select one of the remaining ones
	if len(supportedSuites) == 0 {
		return fmt.Errorf("no remaining supported ciphersuite")
	}

	for suite := range supportedSuites {
		config.CipherSuite = suite
		break
	}

	return nil
}

func (config *ScriptActorConfig) RunStep(index int, step ScriptStep) error {
	switch step.Action {
	case ActionCreateGroup:
		client := config.ActorClients[step.Actor]
		groupID := []byte(uuid.New().String())
		req := &pb.CreateGroupRequest{
			GroupId:          groupID,
			CipherSuite:      config.CipherSuite,
			EncryptHandshake: config.EncryptHandshake,
			Identity:         []byte(step.Actor),
		}
		resp, err := client.rpc.CreateGroup(ctx(), req)
		if err != nil {
			return err
		}
		config.Log(step.Actor, "CreateGroup", req, resp)

		config.stateID[step.Actor] = resp.StateId
		config.StoreMessage(index, "group_id", groupID)

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
		config.Log(step.Actor, "CreateKeyPackage", req, resp)

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
		config.Log(step.Actor, "JoinGroup", req, resp)

		config.stateID[step.Actor] = resp.StateId

	case ActionExternalJoin:
		var params ExternalJoinStepParams
		err := json.Unmarshal(step.Raw, &params)
		if err != nil {
			return err
		}

		// Get a GroupInfo and maybe a ratchet tree from the adder
		groupInfo := []byte{}
		ratchetTree := []byte{}
		{
			client := config.ActorClients[step.Actor]
			req := &pb.GroupInfoRequest{
				StateId:      config.stateID[step.Actor],
				ExternalTree: params.ExternalTree,
			}
			resp, err := client.rpc.GroupInfo(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(step.Actor, "GroupInfo", req, resp)

			groupInfo = resp.GroupInfo
			ratchetTree = resp.RatchetTree
		}

		config.StoreMessage(index, "group_info", groupInfo)
		config.StoreMessage(index, "ratchet_tree", ratchetTree)

		// Create an external Commit
		commit := []byte{}
		epochAuthenticator := []byte{}
		{
			psks := make([]*pb.PreSharedKey, len(params.PSKs))
			for i, pskIx := range params.PSKs {
				pskID, err := config.GetMessage(pskIx, "psk_id")
				if err != nil {
					return err
				}

				pskSecret, err := config.GetMessage(pskIx, "psk_secret")
				if err != nil {
					return err
				}

				psks[i] = &pb.PreSharedKey{PskId: pskID, PskSecret: pskSecret}
			}

			client := config.ActorClients[params.Joiner]
			req := &pb.ExternalJoinRequest{
				GroupInfo:        groupInfo,
				RatchetTree:      ratchetTree,
				EncryptHandshake: config.EncryptHandshake,
				Identity:         []byte(params.Joiner),
				RemovePrior:      params.RemovePrior,
				Psks:             psks,
			}
			resp, err := client.rpc.ExternalJoin(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(params.Joiner, "ExternalJoin", req, resp)

			config.stateID[params.Joiner] = resp.StateId

			commit = resp.Commit
			epochAuthenticator = resp.EpochAuthenticator
		}

		config.StoreMessage(index, "commit", commit)
		config.StoreMessage(index, "epoch_authenticator", epochAuthenticator)

		// Process the Commit at the adder and other members
		params.Members = append(params.Members, step.Actor)
		for _, member := range params.Members {
			client := config.ActorClients[member]
			req := &pb.HandleCommitRequest{
				StateId: config.stateID[member],
				Commit:  commit,
			}
			resp, err := client.rpc.HandleCommit(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(member, "HandleCommit", req, resp)

			if !bytes.Equal(resp.EpochAuthenticator, epochAuthenticator) {
				return fmt.Errorf("Member [%s] failed to agree on epoch authenticator", member)
			}

			config.stateID[member] = resp.StateId
		}

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
			resp, err := client.rpc.StorePSK(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(clientName, "StorePSK", req, resp)
		}

	case ActionGroupInfo:
		client := config.ActorClients[step.Actor]
		var params GroupInfoStepParams
		err := json.Unmarshal(step.Raw, &params)
		if err != nil {
			return err
		}

		req := &pb.GroupInfoRequest{
			StateId:      config.stateID[step.Actor],
			ExternalTree: params.ExternalTree,
		}
		resp, err := client.rpc.GroupInfo(ctx(), req)
		if err != nil {
			return err
		}
		config.Log(step.Actor, "GroupInfo", req, resp)

		config.StoreMessage(index, "group_info", resp.GroupInfo)
		config.StoreMessage(index, "ratchet_tree", resp.RatchetTree)

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
		config.Log(step.Actor, "AddProposal", req, resp)

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
		config.Log(step.Actor, "RemoveProposal", req, resp)

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
		config.Log(step.Actor, "UpdateProposal", req, resp)

		config.StoreMessage(index, "proposal", resp.Proposal)

	case ActionExternalPSKProposal:
		client := config.ActorClients[step.Actor]
		var params ExternalPSKProposalStepParams
		err := json.Unmarshal(step.Raw, &params)
		if err != nil {
			return err
		}

		pskID, err := config.GetMessage(params.PskId, "psk_id")
		if err != nil {
			return err
		}

		req := &pb.ExternalPSKProposalRequest{
			StateId: config.stateID[step.Actor],
			PskId:   pskID,
		}
		resp, err := client.rpc.ExternalPSKProposal(ctx(), req)
		if err != nil {
			return err
		}
		config.Log(step.Actor, "ExternalPSKProposal", req, resp)

		config.StoreMessage(index, "proposal", resp.Proposal)

	case ActionResumptionPSKProposal:
		client := config.ActorClients[step.Actor]
		var params ResumptionPSKProposalStepParams
		err := json.Unmarshal(step.Raw, &params)
		if err != nil {
			return err
		}

		req := &pb.ResumptionPSKProposalRequest{
			StateId: config.stateID[step.Actor],
			EpochId: uint64(params.EpochId),
		}
		resp, err := client.rpc.ResumptionPSKProposal(ctx(), req)
		if err != nil {
			return err
		}
		config.Log(step.Actor, "ResumptionPSKProposal", req, resp)

		config.StoreMessage(index, "proposal", resp.Proposal)

	case ActionGroupContextExtensionsProposal:
		client := config.ActorClients[step.Actor]
		var params GroupContextExtensionsProposalStepParams
		err := json.Unmarshal(step.Raw, &params)

		if err != nil {
			return err
		}

		req := &pb.GroupContextExtensionsProposalRequest{
			StateId:    config.stateID[step.Actor],
			Extensions: params.Extensions,
		}
		resp, err := client.rpc.GroupContextExtensionsProposal(ctx(), req)
		if err != nil {
			return err
		}
		config.Log(step.Actor, "GroupContextExtensionsProposal", req, resp)

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

		byVal := make([]*pb.ProposalDescription, len(params.ByValue))
		for i, proposalDescription := range params.ByValue {
			byVal[i], err = proposalDescription.ProposalDescriptionToProto(config)
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
		config.Log(step.Actor, "Commit", commitReq, commitResp)

		config.StoreMessage(index, "welcome", commitResp.Welcome)
		config.StoreMessage(index, "commit", commitResp.Commit)
		if params.ExternalTree {
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
			config.Log(step.Actor, "HandlePendingCommit", req, resp)

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
			config.Log(member, "HandleCommit", req, resp)

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
			config.Log(joiner, "JoinGroup", req, resp)

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

		byVal := make([]*pb.ProposalDescription, len(params.ByValue))
		for i, proposalDescription := range params.ByValue {
			byVal[i], err = proposalDescription.ProposalDescriptionToProto(config)
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
		config.Log(step.Actor, "Commit", req, resp)

		config.StoreMessage(index, "commit", resp.Commit)
		config.StoreMessage(index, "welcome", resp.Welcome)
		if params.ExternalTree {
			config.StoreMessage(index, "ratchet_tree", resp.RatchetTree)
		}

	case ActionProtect:
		client := config.ActorClients[step.Actor]
		var params ProtectStepParams
		err := json.Unmarshal(step.Raw, &params)
		if err != nil {
			return err
		}

		authenticatedData := []byte(params.AuthenticatedData)
		plaintext := []byte(params.Plaintext)
		req := &pb.ProtectRequest{
			StateId:           config.stateID[step.Actor],
			AuthenticatedData: authenticatedData,
			Plaintext:         plaintext,
		}
		resp, err := client.rpc.Protect(ctx(), req)
		if err != nil {
			return err
		}
		config.Log(step.Actor, "Protect", req, resp)

		config.StoreMessage(index, "authenticatedData", authenticatedData)
		config.StoreMessage(index, "plaintext", plaintext)
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
		config.Log(step.Actor, "Unprotect", req, resp)

		authenticatedData, err := config.GetMessage(params.Ciphertext, "authenticatedData")
		if err != nil {
			return err
		}

		plaintext, err := config.GetMessage(params.Ciphertext, "plaintext")
		if err != nil {
			return err
		}

		if !bytes.Equal(authenticatedData, resp.AuthenticatedData) {
			return fmt.Errorf("Incorrect authenticated data")
		}

		if !bytes.Equal(plaintext, resp.Plaintext) {
			return fmt.Errorf("Incorrect plaintext")
		}

		config.StoreMessage(index, "authenticatedData", resp.AuthenticatedData)
		config.StoreMessage(index, "plaintext", resp.Plaintext)

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
		config.Log(step.Actor, "HandleCommit", req, resp)

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
		config.Log(step.Actor, "HandlePendingCommit", req, resp)

		config.stateID[step.Actor] = resp.StateId

	// XXX(RLB): This step does not store anything in the transcript.  With the
	// KeyPackages and whatnot, it would be too complicated.  When we refactor to
	// make the transcript tracking more elegant, we can add the tracking here.
	case ActionReInit:
		var params ReInitStepParams
		err := json.Unmarshal(step.Raw, &params)
		if err != nil {
			return err
		}

		// Compute sets of members less the committer and the welcomer
		notCommitter := map[string]bool{params.Welcomer: true}
		notWelcomer := map[string]bool{params.Committer: true}
		for _, member := range params.Members {
			notCommitter[member] = true
			notWelcomer[member] = true
		}
		if params.Proposer != "" {
			notCommitter[params.Proposer] = true
			notWelcomer[params.Proposer] = true
		}

		delete(notCommitter, params.Committer)
		delete(notWelcomer, params.Welcomer)

		// Decide on the parameters to send
		newGroupID, err := config.NewGroupID(params.ChangeGroupID)
		if err != nil {
			return err
		}

		if params.ChangeCipherSuite {
			err = config.ChangeCipherSuite()
			if err != nil {
				return err
			}
		}

		// Have the proposer create the Proposal or get the external proposal created
		// earlier
		var proposal []byte
		if params.Proposer != "" {
			client := config.ActorClients[params.Proposer]
			req := &pb.ReInitProposalRequest{
				StateId:     config.stateID[params.Proposer],
				CipherSuite: config.CipherSuite,
				GroupId:     newGroupID,
				Extensions:  params.Extensions,
			}
			resp, err := client.rpc.ReInitProposal(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(params.Proposer, "ReInitProposal", req, resp)

			proposal = resp.Proposal
		} else {
			proposal, err = config.GetMessage(params.ExternalReinitProposal, "proposal")
			if err != nil {
				return err
			}
		}

		// Have the committer commit the Proposal and advance their state
		// XXX(RLB): This only supports committing ReInit by reference.  We might
		// want to refactor so that it can be done by value as well.
		commit := []byte{}
		epochAuthenticator := []byte{}
		reinitIDs := map[string]uint32{}
		keyPackages := map[string][]byte{}
		{
			client := config.ActorClients[params.Committer]
			commitReq := &pb.CommitRequest{
				StateId:     config.stateID[params.Committer],
				ByReference: [][]byte{proposal},
			}
			commitResp, err := client.rpc.ReInitCommit(ctx(), commitReq)
			if err != nil {
				return err
			}
			config.Log(params.Committer, "ReInitCommit", commitReq, commitResp)

			commit = commitResp.Commit

			req := &pb.HandlePendingCommitRequest{
				StateId: config.stateID[params.Committer],
			}
			resp, err := client.rpc.HandlePendingReInitCommit(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(params.Committer, "HandlePendingReInitCommit", req, resp)

			reinitIDs[params.Committer] = resp.ReinitId
			keyPackages[params.Committer] = resp.KeyPackage
			epochAuthenticator = resp.EpochAuthenticator
		}

		// Have everyone except the committer handle the Commit
		for member := range notCommitter {
			client := config.ActorClients[member]
			req := &pb.HandleCommitRequest{
				StateId:  config.stateID[member],
				Proposal: [][]byte{proposal},
				Commit:   commit,
			}
			resp, err := client.rpc.HandleReInitCommit(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(member, "HandleReInitCommit", req, resp)

			if !bytes.Equal(resp.EpochAuthenticator, epochAuthenticator) {
				return fmt.Errorf("Member [%s] failed to agree on epoch authenticator", member)
			}

			reinitIDs[member] = resp.ReinitId
			keyPackages[member] = resp.KeyPackage
		}

		// Have the welcomer create the Welcome
		// XXX(RLB) Note that this assumes that the welcomer will advance its state
		// as a side effect of `ReInitWelcome()`
		var welcome []byte
		var ratchetTree []byte
		reinitEpochAuthenticator := []byte{}
		{
			keyPackageList := [][]byte{}
			for member := range notWelcomer {
				keyPackageList = append(keyPackageList, keyPackages[member])
			}

			client := config.ActorClients[params.Welcomer]
			req := &pb.ReInitWelcomeRequest{
				ReinitId:     reinitIDs[params.Welcomer],
				KeyPackage:   keyPackageList,
				ForcePath:    params.ForcePath,
				ExternalTree: params.ExternalTree,
			}
			resp, err := client.rpc.ReInitWelcome(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(params.Welcomer, "ReInitWelcome", req, resp)

			config.stateID[params.Welcomer] = resp.StateId
			welcome = resp.Welcome
			reinitEpochAuthenticator = resp.EpochAuthenticator
			if params.ExternalTree {
				ratchetTree = resp.RatchetTree
			}
		}

		// Have everyone except the welcomer process the Welcome
		for member := range notWelcomer {
			client := config.ActorClients[member]
			req := &pb.HandleReInitWelcomeRequest{
				ReinitId:    reinitIDs[member],
				Welcome:     welcome,
				RatchetTree: ratchetTree,
			}
			resp, err := client.rpc.HandleReInitWelcome(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(member, "HandleReInitWelcome", req, resp)

			if !bytes.Equal(resp.EpochAuthenticator, reinitEpochAuthenticator) {
				return fmt.Errorf("Member [%s] failed to agree on reinit epoch authenticator", member)
			}

			config.stateID[member] = resp.StateId
		}

	case ActionBranch:
		// XXX(RLB): Note that after this step, the state IDs remembered by the test
		// runner will be for the members' states in the *new* group.  It would be
		// nice to test that both the old and new groups now work.  But it's not
		// clear how to do that in the scripting language.
		// XXX(RLB): Also, this step does not write any output to the transcript
		// right now, for similar reasons to ActionReInit and previous XXX note.
		var params BranchStepParams
		err := json.Unmarshal(step.Raw, &params)
		if err != nil {
			return err
		}

		// Get KeyPackages from the members
		transactionIDs := map[string]uint32{}
		keyPackages := [][]byte{}
		for _, member := range params.Members {
			client := config.ActorClients[member]
			req := &pb.CreateKeyPackageRequest{
				CipherSuite: config.CipherSuite,
				Identity:    []byte(member),
			}
			resp, err := client.rpc.CreateKeyPackage(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(member, "CreateKeyPackage", req, resp)

			transactionIDs[member] = resp.TransactionId
			keyPackages = append(keyPackages, resp.KeyPackage)
		}

		// Have the committer create a branch Welcome
		var welcome []byte
		var ratchetTree []byte
		var epochAuthenticator []byte
		{
			client := config.ActorClients[step.Actor]
			req := &pb.CreateBranchRequest{
				StateId:      config.stateID[step.Actor],
				GroupId:      []byte(uuid.New().String()),
				Extensions:   params.Extensions,
				KeyPackages:  keyPackages,
				ForcePath:    params.ForcePath,
				ExternalTree: params.ExternalTree,
			}
			resp, err := client.rpc.CreateBranch(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(step.Actor, "CreateBranch", req, resp)

			welcome = resp.Welcome
			epochAuthenticator = resp.EpochAuthenticator
			if params.ExternalTree {
				ratchetTree = resp.RatchetTree
			}

			config.stateID[step.Actor] = resp.StateId
		}

		// Apply the Welcome at each other member
		for _, member := range params.Members {
			client := config.ActorClients[member]
			req := &pb.HandleBranchRequest{
				StateId:       config.stateID[member],
				TransactionId: transactionIDs[member],
				Welcome:       welcome,
				RatchetTree:   ratchetTree,
			}
			resp, err := client.rpc.HandleBranch(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(member, "HandleBranch", req, resp)

			if !bytes.Equal(resp.EpochAuthenticator, epochAuthenticator) {
				return fmt.Errorf("Member [%s] failed to agree on epoch authenticator", member)
			}

			config.stateID[member] = resp.StateId
		}

	case ActionNewMemberAddProposal:
		var params NewMemberAddProposalStepParams
		err := json.Unmarshal(step.Raw, &params)
		if err != nil {
			return err
		}

		// Get a GroupInfo from the `actor`
		var groupInfo []byte
		{
			client := config.ActorClients[step.Actor]
			req := &pb.GroupInfoRequest{
				StateId: config.stateID[step.Actor],
			}
			resp, err := client.rpc.GroupInfo(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(step.Actor, "GroupInfo", req, resp)

			groupInfo = resp.GroupInfo
		}

		// Get a self-signed Add proposal from the joiner
		{
			client := config.ActorClients[params.Joiner]
			req := &pb.NewMemberAddProposalRequest{
				GroupInfo: groupInfo,
				Identity:  []byte(params.Joiner),
			}
			resp, err := client.rpc.NewMemberAddProposal(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(params.Joiner, "NewMemberAddProposal", req, resp)

			config.transactionID[params.Joiner] = resp.TransactionId
			config.StoreMessage(index, "proposal", resp.Proposal)
			config.StoreMessage(index, "init_priv", resp.InitPriv)
			config.StoreMessage(index, "encryption_priv", resp.EncryptionPriv)
			config.StoreMessage(index, "signature_priv", resp.SignaturePriv)
		}

	case ActionAddExternalSigner:
		var params AddExternalSignerStepParams
		err := json.Unmarshal(step.Raw, &params)
		if err != nil {
			return err
		}

		// Create the external signer
		var externalSender []byte
		{
			client := config.ActorClients[params.Signer]
			req := &pb.CreateExternalSignerRequest{
				CipherSuite: config.CipherSuite,
				Identity:    []byte(params.Signer),
			}
			resp, err := client.rpc.CreateExternalSigner(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(params.Signer, "CreateExternalSigner", req, resp)

			config.signerID[params.Signer] = resp.SignerId
			externalSender = resp.ExternalSender
		}

		// Create a GroupContextExtensions proposal adding the signer
		{
			client := config.ActorClients[step.Actor]
			req := &pb.AddExternalSignerRequest{
				StateId:        config.stateID[step.Actor],
				ExternalSender: externalSender,
			}
			resp, err := client.rpc.AddExternalSigner(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(step.Actor, "AddExternalSigner", req, resp)

			config.StoreMessage(index, "proposal", resp.Proposal)
		}

	case ActionExternalSignerProposal:
		var params ExternalSignerProposalStepParams
		err := json.Unmarshal(step.Raw, &params)
		if err != nil {
			return err
		}

		// Get GroupInfo and ratchet tree from the `member`
		var groupInfo []byte
		var ratchetTree []byte
		{
			client := config.ActorClients[params.Member]
			req := &pb.GroupInfoRequest{
				StateId:      config.stateID[params.Member],
				ExternalTree: true,
			}
			resp, err := client.rpc.GroupInfo(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(params.Member, "GroupInfo", req, resp)

			groupInfo = resp.GroupInfo
			ratchetTree = resp.RatchetTree
		}

		// Get a proposal from the `actor`
		{
			client := config.ActorClients[step.Actor]
			description, err := params.Description.ProposalDescriptionToProto(config)
			if err != nil {
				return err
			}

			req := &pb.ExternalSignerProposalRequest{
				SignerId:    config.signerID[step.Actor],
				GroupInfo:   groupInfo,
				RatchetTree: ratchetTree,
				Description: description,
			}
			resp, err := client.rpc.ExternalSignerProposal(ctx(), req)
			if err != nil {
				return err
			}
			config.Log(step.Actor, "ExternalSignerProposal", req, resp)

			config.StoreMessage(index, "proposal", resp.Proposal)
		}

	default:
		return fmt.Errorf("Unknown action: %s", step.Action)
	}

	return nil
}

func (config *ScriptActorConfig) Run(script Script) ScriptResult {
	config.stateID = map[string]uint32{}
	config.transactionID = map[string]uint32{}
	config.signerID = map[string]uint32{}
	config.messageCache = make([]map[string]string, len(script))

	for i := range config.messageCache {
		config.messageCache[i] = map[string]string{}
	}

	// Prepare a partial result to return if we need to abort
	result := ScriptResult{
		CipherSuite:      config.CipherSuite,
		Actors:           map[string]string{},
		EncryptHandshake: config.EncryptHandshake,
	}

	actors := script.Actors()
	for i := range actors {
		result.Actors[actors[i]] = config.ActorClients[actors[i]].name
	}

	// Run the steps to completion or error
	for i, step := range script {
		err := config.RunStep(i, step)

		// Store the transcript before error checking / possible abort
		result.Transcript = config.transcript

		if err != nil {
			result.Error = err.Error()
			result.FailedStep = new(int)
			*result.FailedStep = i
			result.FailedStepJSON = string(step.Raw)
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

func (p *ClientPool) RunScript(name string, clientMode ClientMode, suite int, hsMode HandshakeMode, script Script, failFast bool) ScriptResults {
	actors := script.Actors()
	configs := p.ScriptMatrix(actors, clientMode, suite, hsMode)

	results := make(ScriptResults, 0, len(configs))
	for _, config := range configs {
		result := config.Run(script)
		results = append(results, result)
		if failFast && result.FailedStep != nil {
			break
		}
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
	failFast   bool
)

func init() {
	flag.Var(&clientsOpt, "client", "host:port for a client")
	flag.StringVar(&configOpt, "config", "config.json", "config file name")
	flag.BoolVar(&randomOpt, "random", false, "run a random assignment of clients to roles")
	flag.IntVar(&suiteOpt, "suite", 0, "only run tests for a single ciphersuite")
	flag.BoolVar(&privateOpt, "private", false, "only run tests with handshake messages as PrivateMessage")
	flag.BoolVar(&publicOpt, "public", false, "only run tests with handshake messages as PublicMessage")
	flag.BoolVar(&failFast, "fail-fast", false, "abort after the first failure")
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
	chk("Failure to connect to clients", err)
	defer clientPool.Close()

	// Run scripts
	results := TestResults{
		Scripts: map[string]ScriptResults{},
	}
	for name, script := range config.Scripts {
		results.Scripts[name] = clientPool.RunScript(name, clientMode, suiteOpt, hsMode, script, failFast)
	}

	resultsJSON, err := json.MarshalIndent(results, "", "  ")
	chk("Error marshaling results", err)
	fmt.Println(string(resultsJSON))

	for _, results := range results.Scripts {
		for _, result := range results {
			if result.FailedStep != nil {
				log.Fatal("Test failed")
			}
		}
	}
}

func chk(message string, err error) {
	if err != nil {
		log.Fatalf("Error: %s - %v", message, err)
	}
}
