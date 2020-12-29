use tonic::{transport::Server, Request, Response, Status};

use mls_client::mls_client_server::{MlsClient, MlsClientServer};
use mls_client::TestVectorType;
use mls_client::{GenerateTestVectorRequest, GenerateTestVectorResponse};
use mls_client::{NameRequest, NameResponse};
use mls_client::{SupportedCiphersuitesRequest, SupportedCiphersuitesResponse};
use mls_client::{VerifyTestVectorRequest, VerifyTestVectorResponse};

use mls_client::generate_test_vector_response;
use mls_client::verify_test_vector_response;

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
        if (obj.r#type != TEST_VECTOR_TYPE as i32) {
            let msg = "Invalid test vector type";
            let result = generate_test_vector_response::Result::Error(msg.to_string());
            let response = GenerateTestVectorResponse {
                result: Some(result),
            };
            return Ok(Response::new(response));
        }

        let result = generate_test_vector_response::Result::TestVector(TEST_VECTOR.to_vec());
        let response = GenerateTestVectorResponse {
            result: Some(result),
        };

        Ok(Response::new(response))
    }

    async fn verify_test_vector(
        &self,
        request: tonic::Request<VerifyTestVectorRequest>,
    ) -> Result<tonic::Response<VerifyTestVectorResponse>, tonic::Status> {
        println!("Got VerifyTestVector request");

        let obj = request.get_ref();
        if (obj.r#type != TEST_VECTOR_TYPE as i32) {
            let msg = "Invalid test vector type";
            let result = verify_test_vector_response::Result::Error(msg.to_string());
            let response = VerifyTestVectorResponse {
                result: Some(result),
            };
            return Ok(Response::new(response));
        }

        if (obj.test_vector != TEST_VECTOR) {
            let msg = "Invalid test vector";
            let result = verify_test_vector_response::Result::Error(msg.to_string());
            let response = VerifyTestVectorResponse {
                result: Some(result),
            };
            return Ok(Response::new(response));
        }

        let result = verify_test_vector_response::Result::Success(true);
        let response = VerifyTestVectorResponse {
            result: Some(result),
        };

        Ok(Response::new(response))
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
