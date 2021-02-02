package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
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

///
/// Mock client implementation
///
type MockClient struct {
	pb.MLSClientServer
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
	return nil, nil // TODO
}

func (mc *MockClient) CreateKeyPackage(ctx context.Context, in *pb.CreateKeyPackageRequest) (*pb.CreateKeyPackageResponse, error) {
	return nil, nil // TODO
}

func (mc *MockClient) JoinGroup(ctx context.Context, in *pb.JoinGroupRequest) (*pb.JoinGroupResponse, error) {
	return nil, nil // TODO
}

func (mc *MockClient) ExternalJoin(ctx context.Context, in *pb.ExternalJoinRequest) (*pb.ExternalJoinResponse, error) {
	return nil, nil // TODO
}

// Operations using a group state
func (mc *MockClient) PublicGroupState(ctx context.Context, in *pb.PublicGroupStateRequest) (*pb.PublicGroupStateResponse, error) {
	return nil, nil // TODO
}

func (mc *MockClient) StateAuth(ctx context.Context, in *pb.StateAuthRequest) (*pb.StateAuthResponse, error) {
	return nil, nil // TODO
}

func (mc *MockClient) Export(ctx context.Context, in *pb.ExportRequest) (*pb.ExportResponse, error) {
	return nil, nil // TODO
}

func (mc *MockClient) Protect(ctx context.Context, in *pb.ProtectRequest) (*pb.ProtectResponse, error) {
	return nil, nil // TODO
}

func (mc *MockClient) Unprotect(ctx context.Context, in *pb.UnprotectRequest) (*pb.UnprotectResponse, error) {
	return nil, nil // TODO
}

func (mc *MockClient) StorePSK(ctx context.Context, in *pb.StorePSKRequest) (*pb.StorePSKResponse, error) {
	return nil, nil // TODO
}

func (mc *MockClient) AddProposal(ctx context.Context, in *pb.AddProposalRequest) (*pb.ProposalResponse, error) {
	return nil, nil // TODO
}

func (mc *MockClient) UpdateProposal(ctx context.Context, in *pb.UpdateProposalRequest) (*pb.ProposalResponse, error) {
	return nil, nil // TODO
}

func (mc *MockClient) RemoveProposal(ctx context.Context, in *pb.RemoveProposalRequest) (*pb.ProposalResponse, error) {
	return nil, nil // TODO
}

func (mc *MockClient) PSKProposal(ctx context.Context, in *pb.PSKProposalRequest) (*pb.ProposalResponse, error) {
	return nil, nil // TODO
}

func (mc *MockClient) ReInitProposal(ctx context.Context, in *pb.ReInitProposalRequest) (*pb.ProposalResponse, error) {
	return nil, nil // TODO
}

func (mc *MockClient) AppAckProposal(ctx context.Context, in *pb.AppAckProposalRequest) (*pb.ProposalResponse, error) {
	return nil, nil // TODO
}

func (mc *MockClient) Commit(ctx context.Context, in *pb.CommitRequest) (*pb.CommitResponse, error) {
	return nil, nil // TODO
}

func (mc *MockClient) HandleCommit(ctx context.Context, in *pb.HandleCommitRequest) (*pb.HandleCommitResponse, error) {
	return nil, nil // TODO
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
	pb.RegisterMLSClientServer(s, &MockClient{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
