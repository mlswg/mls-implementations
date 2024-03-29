#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <cstdlib>

#include <gflags/gflags.h>
#include <grpcpp/grpcpp.h>

#include "mls_client.grpc.pb.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using grpc::StatusCode;
using namespace mls_client;

static constexpr char implementation_name[] = "Mock-C++";
static constexpr std::array<uint32_t, 2> supported_ciphersuites = { 0xA0A0,
                                                                    0xA1A1 };
static constexpr std::array<char, 4> test_vector = { 0, 1, 2, 3 };

class MLSClientImpl final : public MLSClient::Service
{
  static const std::string fixed_test_vector;

  std::set<uint32_t> transactions;
  std::set<uint32_t> states;

  uint32_t newID(std::set<uint32_t>& universe) {
    auto id = static_cast<uint32_t>(rand());
    universe.insert(id);
    return id;
  }

  Status Name(ServerContext* /* context */,
              const NameRequest* /* request */,
              NameResponse* reply) override
  {
    std::cout << "Got Name request" << std::endl;
    reply->set_name(implementation_name);
    return Status::OK;
  }

  Status SupportedCiphersuites(
    ServerContext* /* context */,
    const SupportedCiphersuitesRequest* /* request */,
    SupportedCiphersuitesResponse* reply) override
  {
    std::cout << "Got SupportedCiphersuites request" << std::endl;
    reply->clear_ciphersuites();
    for (const auto suite : supported_ciphersuites) {
      reply->add_ciphersuites(suite);
    }
    return Status::OK;
  }

  // Ways to become a member of a group
  Status CreateGroup(ServerContext* /* context */,
                     const CreateGroupRequest* /* request */,
                     CreateGroupResponse* response) override
  {
    response->set_state_id(newID(states));
    return Status::OK;
  }

  Status CreateKeyPackage(ServerContext* /* context */,
                          const CreateKeyPackageRequest* /* request */,
                          CreateKeyPackageResponse* response) override
  {
    response->set_transaction_id(newID(transactions));
    response->set_key_package("keyPackage");
    return Status::OK;
  }

  Status JoinGroup(ServerContext* /* context */,
                   const JoinGroupRequest* request,
                   JoinGroupResponse* response) override
  {
    if (transactions.count(request->transaction_id()) == 0) {
      return Status(StatusCode::INVALID_ARGUMENT, "Invalid transaction");
    }

    if (request->welcome() != "welcome") {
      return Status(StatusCode::INVALID_ARGUMENT, "Invalid welcome");
    }

    response->set_state_id(newID(states));
    return Status::OK;
  }

  Status ExternalJoin(ServerContext* /* context */,
                      const ExternalJoinRequest* request,
                      ExternalJoinResponse* response) override
  {
    if (request->public_group_state() != "publicGroupState") {
      return Status(StatusCode::INVALID_ARGUMENT, "Invalid PublicGroupState");
    }

    response->set_state_id(newID(states));
    response->set_commit("commit");
    return Status::OK;
  }

  // Operations using a group state
  Status PublicGroupState(ServerContext* /* context */,
                          const PublicGroupStateRequest* /* request */,
                          PublicGroupStateResponse* response) override
  {
    response->set_public_group_state("publicGroupState");
    return Status::OK;
  }

  Status StateAuth(ServerContext* /* context */,
                   const StateAuthRequest* request,
                   StateAuthResponse* response) override
  {
    if (states.count(request->state_id()) == 0) {
      return Status(StatusCode::INVALID_ARGUMENT, "Invalid state");
    }

    response->set_state_auth_secret("stateAuthSecret");
    return Status::OK;
  }

  Status Export(ServerContext* /* context */,
                   const ExportRequest* request,
                   ExportResponse* response) override
  {
    if (states.count(request->state_id()) == 0) {
      return Status(StatusCode::INVALID_ARGUMENT, "Invalid state");
    }

    response->set_exported_secret("exportedSecret");
    return Status::OK;
  }

  Status Protect(ServerContext* /* context */,
                   const ProtectRequest* request,
                   ProtectResponse* response) override
  {
    if (states.count(request->state_id()) == 0) {
      return Status(StatusCode::INVALID_ARGUMENT, "Invalid state");
    }

    response->set_ciphertext(request->application_data());
    return Status::OK;
  }

  Status Unprotect(ServerContext* /* context */,
                   const UnprotectRequest* request,
                   UnprotectResponse* response) override
  {
    if (states.count(request->state_id()) == 0) {
      return Status(StatusCode::INVALID_ARGUMENT, "Invalid state");
    }

    response->set_application_data(request->ciphertext());
    return Status::OK;
  }

  Status StorePSK(ServerContext* /* context */,
                  const StorePSKRequest* /* request */,
                  StorePSKResponse* /* response */) override
  {
    return Status::OK; // TODO
  }

  Status AddProposal(ServerContext* /* context */,
                     const AddProposalRequest* request,
                     ProposalResponse* response) override
  {
    if (states.count(request->state_id()) == 0) {
      return Status(StatusCode::INVALID_ARGUMENT, "Invalid state");
    }

    if (request->key_package() != "keyPackage") {
      return Status(StatusCode::INVALID_ARGUMENT, "Invalid commit");
    }

    response->set_proposal("addProposal");
    return Status::OK;
  }

  Status UpdateProposal(ServerContext* /* context */,
                        const UpdateProposalRequest* /* request */,
                        ProposalResponse* /* response */) override
  {
    return Status::OK; // TODO
  }

  Status RemoveProposal(ServerContext* /* context */,
                        const RemoveProposalRequest* /* request */,
                        ProposalResponse* /* response */) override
  {
    return Status::OK; // TODO
  }

  Status PSKProposal(ServerContext* /* context */,
                     const PSKProposalRequest* /* request */,
                     ProposalResponse* /* response */) override
  {
    return Status::OK; // TODO
  }

  Status ReInitProposal(ServerContext* /* context */,
                        const ReInitProposalRequest* /* request */,
                        ProposalResponse* /* response */) override
  {
    return Status::OK; // TODO
  }

  Status Commit(ServerContext* /* context */,
                const CommitRequest* request,
                CommitResponse* response) override
  {
    if (states.count(request->state_id()) == 0) {
      return Status(StatusCode::INVALID_ARGUMENT, "Invalid state");
    }

    response->set_commit("commit");
    response->set_welcome("welcome");
    response->set_epoch_authenticator("epoch_authenticator");
    return Status::OK;
  }

  Status HandleCommit(ServerContext* /* context */,
                      const HandleCommitRequest* request,
                      HandleCommitResponse* response) override
  {
    if (states.count(request->state_id()) == 0) {
      return Status(StatusCode::INVALID_ARGUMENT, "Invalid state");
    }

    if (request->commit() != "commit") {
      return Status(StatusCode::INVALID_ARGUMENT, "Invalid commit");
    }

    response->set_state_id(newID(states));
    response->set_epoch_authenticator("epoch_authenticator");
    return Status::OK;
  }

  Status HandlePendingCommit(ServerContext* /* context */,
                      const HandlePendingCommitRequest* request,
                      HandleCommitResponse* response) override
  {
    if (states.count(request->state_id()) == 0) {
      return Status(StatusCode::INVALID_ARGUMENT, "Invalid state");
    }

    response->set_state_id(newID(states));
    response->set_epoch_authenticator("epoch_authenticator");
    return Status::OK;
  }
};

const std::string MLSClientImpl::fixed_test_vector = { test_vector.begin(),
                                                       test_vector.end() };

DEFINE_uint64(port, 50051, "Port to listen on");

int
main(int argc, char* argv[])
{
  gflags::ParseCommandLineFlags(&argc, &argv, true);

  auto service = MLSClientImpl{};
  auto server_address = (std::stringstream{} << "0.0.0.0:" << FLAGS_port).str();

  grpc::EnableDefaultHealthCheckService(true);
  ServerBuilder builder;
  builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
  builder.RegisterService(&service);

  std::cout << "Listening on " << server_address << std::endl;
  std::unique_ptr<Server> server(builder.BuildAndStart());
  server->Wait();

  return 0;
}
