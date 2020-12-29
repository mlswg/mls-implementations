use tonic::{transport::Server, Request, Response, Status};

use mls_client::mls_client_server::{MlsClient, MlsClientServer};
use mls_client::TestVectorType;
use mls_client::{GenerateTestVectorRequest, GenerateTestVectorResponse};
use mls_client::{NameRequest, NameResponse};
use mls_client::{SupportedCiphersuitesRequest, SupportedCiphersuitesResponse};
use mls_client::{VerifyTestVectorRequest, VerifyTestVectorResponse};

pub mod mls_client {
    tonic::include_proto!("mls_client");
}

const IMPLEMENTATION_NAME: &str = "Mock-Rust";
const SUPPORTED_CIPHERSUITES: [u32; 2] = [0xA0A0, 0xA1A1];
const TEST_VECTOR_TYPE: TestVectorType = TestVectorType::TreeMath;
const TEST_VECTOR: [u8; 4] = [0, 1, 2, 3];

#[derive(Default)]
pub struct MlsClientImpl {}

#[tonic::async_trait]
impl MlsClient for MlsClientImpl {
    async fn name(&self, _request: Request<NameRequest>) -> Result<Response<NameResponse>, Status> {
        println!("Got Name request");

        let response = NameResponse {
            name: IMPLEMENTATION_NAME.to_string(),
        };
        Ok(Response::new(response))
    }

    async fn supported_ciphersuites(
        &self,
        _request: tonic::Request<SupportedCiphersuitesRequest>,
    ) -> Result<tonic::Response<SupportedCiphersuitesResponse>, tonic::Status> {
        println!("Got SupportedCiphersuites request");

        let response = SupportedCiphersuitesResponse {
            ciphersuites: SUPPORTED_CIPHERSUITES.to_vec(),
        };

        Ok(Response::new(response))
    }

    async fn generate_test_vector(
        &self,
        request: tonic::Request<GenerateTestVectorRequest>,
    ) -> Result<tonic::Response<GenerateTestVectorResponse>, tonic::Status> {
        println!("Got GenerateTestVector request");

        let obj = request.get_ref();
        if (obj.test_vector_type != TEST_VECTOR_TYPE as i32) {
            return Err(tonic::Status::new(tonic::Code::InvalidArgument, "Invalid test vector type"))
        }

        let response = GenerateTestVectorResponse {
            test_vector: TEST_VECTOR.to_vec(),
        };

        Ok(Response::new(response))
    }

    async fn verify_test_vector(
        &self,
        request: tonic::Request<VerifyTestVectorRequest>,
    ) -> Result<tonic::Response<VerifyTestVectorResponse>, tonic::Status> {
        println!("Got VerifyTestVector request");

        let obj = request.get_ref();
        if (obj.test_vector_type != TEST_VECTOR_TYPE as i32) {
            return Err(tonic::Status::new(tonic::Code::InvalidArgument, "Invalid test vector type"))
        }

        if (obj.test_vector != TEST_VECTOR) {
            return Err(tonic::Status::new(tonic::Code::InvalidArgument, "Invalid test vector"))
        }

        Ok(Response::new(VerifyTestVectorResponse::default()))
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
