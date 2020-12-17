#include <memory>
#include <string>

#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>

#include "mls_client.grpc.pb.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using mls_client::MLSClient;
using mls_client::NameRequest;
using mls_client::NameResponse;

static constexpr char implementationName[] = "Mock-C++";

class MLSClientImpl final : public MLSClient::Service
{
  Status Name(ServerContext* /* context */,
              const NameRequest* /* request */,
              NameResponse* reply) override
  {
    reply->set_name(implementationName);
    return Status::OK;
  }
};

int
main()
{
  std::string server_address("0.0.0.0:50051");
  MLSClientImpl service;

  grpc::EnableDefaultHealthCheckService(true);
  ServerBuilder builder;
  builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
  builder.RegisterService(&service);

  std::unique_ptr<Server> server(builder.BuildAndStart());
  server->Wait();

  return 0;
}
