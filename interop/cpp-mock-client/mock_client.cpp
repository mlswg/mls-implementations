#include <iostream>
#include <memory>
#include <sstream>
#include <string>

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

  Status GenerateTestVector(ServerContext* /* context */,
                            const GenerateTestVectorRequest* request,
                            GenerateTestVectorResponse* reply) override
  {
    std::cout << "Got GenerateTestVector request" << std::endl;
    switch (request->test_vector_type()) {
      case TestVectorType::TREE_MATH: {
        std::cout << "Tree math test vector request" << std::endl;
        break;
      }

      case TestVectorType::ENCRYPTION: {
        std::cout << "Encryption test vector request" << std::endl;
        break;
      }

      case TestVectorType::KEY_SCHEDULE: {
        std::cout << "Key schedule test vector request" << std::endl;
        break;
      }

      case TestVectorType::TREEKEM: {
        std::cout << "TreeKEM test vector request" << std::endl;
        break;
      }

      case TestVectorType::MESSAGES: {
        std::cout << "Messages test vector request" << std::endl;
        break;
      }

      default:
        return Status(StatusCode::INVALID_ARGUMENT, "Invalid test vector type");
    }

    std::cout << "  ... ok" << std::endl;
    reply->set_test_vector(fixed_test_vector);
    return Status::OK;
  }

  Status VerifyTestVector(ServerContext* /* context */,
                          const VerifyTestVectorRequest* request,
                          VerifyTestVectorResponse* /* reply */) override
  {
    std::cout << "Got VerifyTestVector request" << std::endl;
    switch (request->test_vector_type()) {
      case TestVectorType::TREE_MATH: {
        std::cout << "Tree math test vector request" << std::endl;
        break;
      }

      case TestVectorType::ENCRYPTION: {
        std::cout << "Encryption test vector request" << std::endl;
        break;
      }

      case TestVectorType::KEY_SCHEDULE: {
        std::cout << "Key schedule test vector request" << std::endl;
        break;
      }

      case TestVectorType::TREEKEM: {
        std::cout << "TreeKEM test vector request" << std::endl;
        break;
      }

      case TestVectorType::MESSAGES: {
        std::cout << "Messages test vector request" << std::endl;
        break;
      }

      default:
        return Status(StatusCode::INVALID_ARGUMENT, "Invalid test vector type");
    }

    if (request->test_vector() != fixed_test_vector) {
      return Status(StatusCode::INVALID_ARGUMENT, "Invalid test vector");
    }

    return Status::OK;
  }

  // Ways to become a member of a group
  Status CreateGroup(ServerContext* /* context */,
                     const CreateGroupRequest* /* request */,
                     CreateGroupResponse* /* response */) override
  {
    return Status::OK; // TODO
  }

  Status CreateKeyPackage(ServerContext* /* context */,
                          const CreateKeyPackageRequest* /* request */,
                          CreateKeyPackageResponse* /* response */) override
  {
    return Status::OK; // TODO
  }

  Status JoinGroup(ServerContext* /* context */,
                   const JoinGroupRequest* /* request */,
                   JoinGroupResponse* /* response */) override
  {
    return Status::OK; // TODO
  }

  Status ExternalJoin(ServerContext* /* context */,
                      const ExternalJoinRequest* /* request */,
                      ExternalJoinResponse* /* response */) override
  {
    return Status::OK; // TODO
  }

  // Operations using a group state
  Status PublicGroupState(ServerContext* /* context */,
                          const PublicGroupStateRequest* /* request */,
                          PublicGroupStateResponse* /* response */) override
  {
    return Status::OK; // TODO
  }

  Status StateAuth(ServerContext* /* context */,
                   const StateAuthRequest* /* request */,
                   StateAuthResponse* /* response */) override
  {
    return Status::OK; // TODO
  }

  Status Export(ServerContext* /* context */,
                const ExportRequest* /* request */,
                ExportResponse* /* response */) override
  {
    return Status::OK; // TODO
  }

  Status Protect(ServerContext* /* context */,
                 const ProtectRequest* /* request */,
                 ProtectResponse* /* response */) override
  {
    return Status::OK; // TODO
  }

  Status Unprotect(ServerContext* /* context */,
                   const UnprotectRequest* /* request */,
                   UnprotectResponse* /* response */) override
  {
    return Status::OK; // TODO
  }

  Status StorePSK(ServerContext* /* context */,
                  const StorePSKRequest* /* request */,
                  StorePSKResponse* /* response */) override
  {
    return Status::OK; // TODO
  }

  Status AddProposal(ServerContext* /* context */,
                     const AddProposalRequest* /* request */,
                     ProposalResponse* /* response */) override
  {
    return Status::OK; // TODO
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

  Status AppAckProposal(ServerContext* /* context */,
                        const AppAckProposalRequest* /* request */,
                        ProposalResponse* /* response */) override
  {
    return Status::OK; // TODO
  }

  Status Commit(ServerContext* /* context */,
                const CommitRequest* /* request */,
                CommitResponse* /* response */) override
  {
    return Status::OK; // TODO
  }

  Status HandleCommit(ServerContext* /* context */,
                      const HandleCommitRequest* /* request */,
                      HandleCommitResponse* /* response */) override
  {
    return Status::OK; // TODO
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
