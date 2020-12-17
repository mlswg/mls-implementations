use tonic::{transport::Server, Request, Response, Status};

use mls_client::mls_client_server::{MlsClient, MlsClientServer};
use mls_client::{NameRequest, NameResponse};

pub mod mls_client {
    tonic::include_proto!("mls_client");
}

const IMPLEMENTATION_NAME: &str = "Mock-Rust";

#[derive(Default)]
pub struct MlsClientImpl {}

#[tonic::async_trait]
impl MlsClient for MlsClientImpl {
    async fn name(
        &self,
        request: Request<NameRequest>,
    ) -> Result<Response<NameResponse>, Status> {
        println!("Got a request from {:?}", request.remote_addr());

        let reply = NameResponse {
            name: IMPLEMENTATION_NAME.to_string(),
        };
        Ok(Response::new(reply))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse().unwrap();
    let mls_client_impl = MlsClientImpl::default();

    println!("Listening on {}", addr);

    Server::builder()
        .add_service(MlsClientServer::new(mls_client_impl))
        .serve(addr)
        .await?;

    Ok(())
}
