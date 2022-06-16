package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/mlswg/mls-implementations/interop/proto"
)

var (
	implementationName    = "Mock-Go"
	supportedCiphersuites = []uint32{0xA0A0, 0xA1A1}
	testVector            = []byte{0, 1, 2, 3}
)

func newID(universe map[uint32]bool) uint32 {
	id := rand.Uint32()
	universe[id] = true
	return id
}

///
/// Mock client implementation
///
type MockClient struct {
	pb.MLSClientServer
	transactions map[uint32]bool
	states       map[uint32]bool
}

func NewMockClient() *MockClient {
	return &MockClient{
		transactions: map[uint32]bool{},
		states:       map[uint32]bool{},
	}
}

func (mc *MockClient) Name(ctx context.Context, req *pb.NameRequest) (*pb.NameResponse, error) {
	log.Printf("Received Name request")
	return &pb.NameResponse{Name: implementationName}, nil
}

func (mc *MockClient) SupportedCiphersuites(ctx context.Context, req *pb.SupportedCiphersuitesRequest) (*pb.SupportedCiphersuitesResponse, error) {
	log.Printf("Received SupportedCiphersuites request")
	return &pb.SupportedCiphersuitesResponse{Ciphersuites: supportedCiphersuites}, nil
}

func (mc *MockClient) GenerateTestVector(ctx context.Context, req *pb.GenerateTestVectorRequest) (*pb.GenerateTestVectorResponse, error) {
	log.Printf("Received GenerateTestVector request")

	switch req.TestVectorType {
	case pb.TestVectorType_TREE_MATH:
		log.Printf("Tree math test vector request")

	case pb.TestVectorType_ENCRYPTION:
		log.Printf("Encryption test vector request")

	case pb.TestVectorType_KEY_SCHEDULE:
		log.Printf("Key schedule test vector request")

	case pb.TestVectorType_TRANSCRIPT:
		log.Printf("Transcript test vector request")

	case pb.TestVectorType_TREEKEM:
		log.Printf("TreeKEM test vector request")

	case pb.TestVectorType_MESSAGES:
		log.Printf("Messages test vector request")

	default:
		return nil, status.Error(codes.InvalidArgument, "Invalid test vector type")
	}

	return &pb.GenerateTestVectorResponse{TestVector: testVector}, nil
}

func (mc *MockClient) VerifyTestVector(ctx context.Context, req *pb.VerifyTestVectorRequest) (*pb.VerifyTestVectorResponse, error) {
	log.Printf("Received VerifyTestVector request")

	switch req.TestVectorType {
	case pb.TestVectorType_TREE_MATH:
		log.Printf("Tree math test vector request")

	case pb.TestVectorType_ENCRYPTION:
		log.Printf("Encryption test vector request")

	case pb.TestVectorType_KEY_SCHEDULE:
		log.Printf("Key schedule test vector request")

	case pb.TestVectorType_TRANSCRIPT:
		log.Printf("Transcript test vector request")

	case pb.TestVectorType_TREEKEM:
		log.Printf("TreeKEM test vector request")

	case pb.TestVectorType_MESSAGES:
		log.Printf("Messages test vector request")

	default:
		return nil, status.Error(codes.InvalidArgument, "Invalid test vector type")
	}

	if !bytes.Equal(req.TestVector, testVector) {
		return nil, status.Error(codes.InvalidArgument, "Invalid test vector")
	}

	return &pb.VerifyTestVectorResponse{}, nil
}

// Ways to become a member of a group
func (mc *MockClient) CreateGroup(ctx context.Context, in *pb.CreateGroupRequest) (*pb.CreateGroupResponse, error) {
	resp := &pb.CreateGroupResponse{
		StateId: newID(mc.states),
	}

	return resp, nil
}

func (mc *MockClient) CreateKeyPackage(ctx context.Context, in *pb.CreateKeyPackageRequest) (*pb.CreateKeyPackageResponse, error) {
	resp := &pb.CreateKeyPackageResponse{
		TransactionId: newID(mc.transactions),
		KeyPackage:    []byte("keyPackage"),
	}

	return resp, nil
}

func (mc *MockClient) JoinGroup(ctx context.Context, in *pb.JoinGroupRequest) (*pb.JoinGroupResponse, error) {
	if !mc.transactions[in.TransactionId] {
		return nil, status.Error(codes.InvalidArgument, "Invalid transaction")
	}

	if string(in.Welcome) != "welcome" {
		return nil, status.Error(codes.InvalidArgument, "Invalid welcome")
	}

	resp := &pb.JoinGroupResponse{
		StateId: newID(mc.states),
	}

	return resp, nil
}

func (mc *MockClient) ExternalJoin(ctx context.Context, in *pb.ExternalJoinRequest) (*pb.ExternalJoinResponse, error) {
	if string(in.PublicGroupState) != "publicGroupState" {
		return nil, status.Error(codes.InvalidArgument, "Invalid PublicGroupState")
	}

	resp := &pb.ExternalJoinResponse{
		StateId: newID(mc.states),
		Commit:  []byte("commit"),
	}
	return resp, nil
}

// Operations using a group state
func (mc *MockClient) PublicGroupState(ctx context.Context, in *pb.PublicGroupStateRequest) (*pb.PublicGroupStateResponse, error) {
	resp := &pb.PublicGroupStateResponse{
		PublicGroupState: []byte("publicGroupState"),
	}
	return resp, nil
}

func (mc *MockClient) StateAuth(ctx context.Context, in *pb.StateAuthRequest) (*pb.StateAuthResponse, error) {
	if !mc.states[in.StateId] {
		fmt.Printf("Invalid state (auth): %d\n", in.StateId)
		return nil, status.Error(codes.InvalidArgument, "Invalid state")
	}

	resp := &pb.StateAuthResponse{
		StateAuthSecret: []byte("stateAuthSecret"),
	}

	return resp, nil
}

func (mc *MockClient) Export(ctx context.Context, in *pb.ExportRequest) (*pb.ExportResponse, error) {
	if !mc.states[in.StateId] {
		fmt.Printf("Invalid state (auth): %d\n", in.StateId)
		return nil, status.Error(codes.InvalidArgument, "Invalid state")
	}

	resp := &pb.ExportResponse{
		ExportedSecret: []byte("exportedSecret"),
	}

	return resp, nil
}

func (mc *MockClient) Protect(ctx context.Context, in *pb.ProtectRequest) (*pb.ProtectResponse, error) {
	if !mc.states[in.StateId] {
		fmt.Printf("Invalid state (auth): %d\n", in.StateId)
		return nil, status.Error(codes.InvalidArgument, "Invalid state")
	}

	resp := &pb.ProtectResponse{
		Ciphertext: in.ApplicationData,
	}

	return resp, nil
}

func (mc *MockClient) Unprotect(ctx context.Context, in *pb.UnprotectRequest) (*pb.UnprotectResponse, error) {
	if !mc.states[in.StateId] {
		fmt.Printf("Invalid state (auth): %d\n", in.StateId)
		return nil, status.Error(codes.InvalidArgument, "Invalid state")
	}

	resp := &pb.UnprotectResponse{
		ApplicationData: in.Ciphertext,
	}

	return resp, nil
}

func (mc *MockClient) StorePSK(ctx context.Context, in *pb.StorePSKRequest) (*pb.StorePSKResponse, error) {
	resp := &pb.StorePSKResponse{}
	return resp, nil // TODO
}

func (mc *MockClient) AddProposal(ctx context.Context, in *pb.AddProposalRequest) (*pb.ProposalResponse, error) {
	if !mc.states[in.StateId] {
		fmt.Printf("Invalid state (add): %d\n", in.StateId)
		return nil, status.Error(codes.InvalidArgument, "Invalid state")
	}

	if string(in.KeyPackage) != "keyPackage" {
		return nil, status.Error(codes.InvalidArgument, "Invalid key package")
	}

	resp := &pb.ProposalResponse{
		Proposal: []byte("addProposal"),
	}

	return resp, nil
}

func (mc *MockClient) UpdateProposal(ctx context.Context, in *pb.UpdateProposalRequest) (*pb.ProposalResponse, error) {
	resp := &pb.ProposalResponse{}
	return resp, nil // TODO
}

func (mc *MockClient) RemoveProposal(ctx context.Context, in *pb.RemoveProposalRequest) (*pb.ProposalResponse, error) {
	resp := &pb.ProposalResponse{}
	return resp, nil // TODO
}

func (mc *MockClient) PSKProposal(ctx context.Context, in *pb.PSKProposalRequest) (*pb.ProposalResponse, error) {
	resp := &pb.ProposalResponse{}
	return resp, nil // TODO
}

func (mc *MockClient) ReInitProposal(ctx context.Context, in *pb.ReInitProposalRequest) (*pb.ProposalResponse, error) {
	resp := &pb.ProposalResponse{}
	return resp, nil // TODO
}

func (mc *MockClient) GroupContextExtensionsProposal(ctx context.Context, in *pb.GroupContextExtensionsProposalRequest) (*pb.ProposalResponse, error) {
	resp := &pb.ProposalResponse{}
	return resp, nil // TODO
}

func (mc *MockClient) Commit(ctx context.Context, in *pb.CommitRequest) (*pb.CommitResponse, error) {
	if !mc.states[in.StateId] {
		fmt.Printf("Invalid state (commit): %d\n", in.StateId)
		return nil, status.Error(codes.InvalidArgument, "Invalid state")
	}

	resp := &pb.CommitResponse{
		Commit:  []byte("commit"),
		Welcome: []byte("welcome"),
	}

	return resp, nil
}

func (mc *MockClient) HandleCommit(ctx context.Context, in *pb.HandleCommitRequest) (*pb.HandleCommitResponse, error) {
	if !mc.states[in.StateId] {
		fmt.Printf("Invalid state (handle): %d\n", in.StateId)
		return nil, status.Error(codes.InvalidArgument, "Invalid state")
	}

	if string(in.Commit) != "commit" {
		return nil, status.Error(codes.InvalidArgument, "Invalid commit")
	}

	resp := &pb.HandleCommitResponse{
		StateId: newID(mc.states),
	}

	mc.states[resp.StateId] = true
	return resp, nil
}

func (mc *MockClient) HandleExternalCommit(ctx context.Context, in *pb.HandleExternalCommitRequest) (*pb.HandleExternalCommitResponse, error) {
	if !mc.states[in.StateId] {
		fmt.Printf("Invalid state (handle): %d\n", in.StateId)
		return nil, status.Error(codes.InvalidArgument, "Invalid state")
	}

	if string(in.Commit) != "commit" {
		return nil, status.Error(codes.InvalidArgument, "Invalid commit")
	}

	resp := &pb.HandleExternalCommitResponse{
		StateId: newID(mc.states),
	}

	mc.states[resp.StateId] = true
	return resp, nil
}

///
/// Run the server
///

var (
	portOpt int
)

func init() {
	flag.IntVar(&portOpt, "port", 50051, "port to listen on")
	flag.Parse()
}

func main() {
	port := fmt.Sprintf(":%d", portOpt)
	log.Printf("Listening on %s", port)

	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()
	pb.RegisterMLSClientServer(s, NewMockClient())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
