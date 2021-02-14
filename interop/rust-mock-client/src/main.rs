use clap::Clap;
use std::convert::TryFrom;
use tonic::{transport::Server, Request, Response, Status};

use mls_client::mls_client_server::{MlsClient, MlsClientServer};
// TODO(RLB) Convert this back to more specific `use` directives
use mls_client::*;

pub mod mls_client {
    tonic::include_proto!("mls_client");
}

const IMPLEMENTATION_NAME: &str = "Mock-Rust";
const SUPPORTED_CIPHERSUITES: [u32; 2] = [0xA0A0, 0xA1A1];
const TEST_VECTOR: [u8; 4] = [0, 1, 2, 3];

impl TryFrom<i32> for TestVectorType {
    type Error = ();

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(TestVectorType::TreeMath),
            1 => Ok(TestVectorType::Encryption),
            2 => Ok(TestVectorType::KeySchedule),
            3 => Ok(TestVectorType::Transcript),
            4 => Ok(TestVectorType::Treekem),
            5 => Ok(TestVectorType::Messages),
            _ => Err(()),
        }
    }
}

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
        let type_msg = match TestVectorType::try_from(obj.test_vector_type) {
            Ok(TestVectorType::TreeMath) => "Tree math",
            Ok(TestVectorType::Encryption) => "Encryption",
            Ok(TestVectorType::KeySchedule) => "Key Schedule",
            Ok(TestVectorType::Transcript) => "Transcript",
            Ok(TestVectorType::Treekem) => "TreeKEM",
            Ok(TestVectorType::Messages) => "Messages",
            Err(_) => {
                return Err(tonic::Status::new(
                    tonic::Code::InvalidArgument,
                    "Invalid test vector type",
                ));
            }
        };
        println!("{} test vector request", type_msg);

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
        let type_msg = match TestVectorType::try_from(obj.test_vector_type) {
            Ok(TestVectorType::TreeMath) => "Tree math",
            Ok(TestVectorType::Encryption) => "Encryption",
            Ok(TestVectorType::KeySchedule) => "Key Schedule",
            Ok(TestVectorType::Transcript) => "Transcript",
            Ok(TestVectorType::Treekem) => "TreeKEM",
            Ok(TestVectorType::Messages) => "Messages",
            Err(_) => {
                return Err(tonic::Status::new(
                    tonic::Code::InvalidArgument,
                    "Invalid test vector type",
                ));
            }
        };
        println!("{} test vector request", type_msg);

        if (obj.test_vector != TEST_VECTOR) {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "Invalid test vector",
            ));
        }

        Ok(Response::new(VerifyTestVectorResponse::default()))
    }

    async fn create_group(
        &self,
        _request: tonic::Request<CreateGroupRequest>,
    ) -> Result<tonic::Response<CreateGroupResponse>, tonic::Status> {
        Ok(Response::new(CreateGroupResponse::default())) // TODO
    }

    async fn create_key_package(
        &self,
        _request: tonic::Request<CreateKeyPackageRequest>,
    ) -> Result<tonic::Response<CreateKeyPackageResponse>, tonic::Status> {
        let resp = CreateKeyPackageResponse{ 
            transaction_id: 0,
            key_package: String::from("keyPackage").into_bytes(),
        };

        Ok(Response::new(resp)) // TODO
    }

    async fn join_group(
        &self,
        request: tonic::Request<JoinGroupRequest>,
    ) -> Result<tonic::Response<JoinGroupResponse>, tonic::Status> {
        let obj = request.get_ref();
        let welcome = String::from("welcome");
        let welcome_in = String::from_utf8(obj.welcome.clone()).unwrap();
        if (welcome != welcome_in) {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "Invalid welcome",
            ));
        }

        Ok(Response::new(JoinGroupResponse::default())) // TODO
    }

    async fn external_join(
        &self,
        _request: tonic::Request<ExternalJoinRequest>,
    ) -> Result<tonic::Response<ExternalJoinResponse>, tonic::Status> {
        Ok(Response::new(ExternalJoinResponse::default())) // TODO
    }

    async fn public_group_state(
        &self,
        _request: tonic::Request<PublicGroupStateRequest>,
    ) -> Result<tonic::Response<PublicGroupStateResponse>, tonic::Status> {
        Ok(Response::new(PublicGroupStateResponse::default())) // TODO
    }

    async fn state_auth(
        &self,
        _request: tonic::Request<StateAuthRequest>,
    ) -> Result<tonic::Response<StateAuthResponse>, tonic::Status> {
        let resp = StateAuthResponse{ 
            state_auth_secret: String::from("stateAuthSecret").into_bytes(),
        };

        Ok(Response::new(resp)) // TODO
    }

    async fn export(
        &self,
        _request: tonic::Request<ExportRequest>,
    ) -> Result<tonic::Response<ExportResponse>, tonic::Status> {
        Ok(Response::new(ExportResponse::default())) // TODO
    }

    async fn protect(
        &self,
        _request: tonic::Request<ProtectRequest>,
    ) -> Result<tonic::Response<ProtectResponse>, tonic::Status> {
        Ok(Response::new(ProtectResponse::default())) // TODO
    }

    async fn unprotect(
        &self,
        _request: tonic::Request<UnprotectRequest>,
    ) -> Result<tonic::Response<UnprotectResponse>, tonic::Status> {
        Ok(Response::new(UnprotectResponse::default())) // TODO
    }

    async fn store_psk(
        &self,
        _request: tonic::Request<StorePskRequest>,
    ) -> Result<tonic::Response<StorePskResponse>, tonic::Status> {
        Ok(Response::new(StorePskResponse::default())) // TODO
    }

    async fn add_proposal(
        &self,
        request: tonic::Request<AddProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        let obj = request.get_ref();
        let key_package = String::from("keyPackage");
        let key_package_in = String::from_utf8(obj.key_package.clone()).unwrap();
        if (key_package != key_package_in) {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "Invalid key package",
            ));
        }

        let resp = ProposalResponse{ 
            proposal: String::from("addProposal").into_bytes(),
        };

        Ok(Response::new(resp)) // TODO
    }

    async fn update_proposal(
        &self,
        _request: tonic::Request<UpdateProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        Ok(Response::new(ProposalResponse::default())) // TODO
    }

    async fn remove_proposal(
        &self,
        _request: tonic::Request<RemoveProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        Ok(Response::new(ProposalResponse::default())) // TODO
    }

    async fn psk_proposal(
        &self,
        _request: tonic::Request<PskProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        Ok(Response::new(ProposalResponse::default())) // TODO
    }

    async fn re_init_proposal(
        &self,
        _request: tonic::Request<ReInitProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        Ok(Response::new(ProposalResponse::default())) // TODO
    }

    async fn app_ack_proposal(
        &self,
        _request: tonic::Request<AppAckProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        Ok(Response::new(ProposalResponse::default())) // TODO
    }

    async fn commit(
        &self,
        _request: tonic::Request<CommitRequest>,
    ) -> Result<tonic::Response<CommitResponse>, tonic::Status> {
        let resp = CommitResponse{ 
            commit: String::from("commit").into_bytes(),
            welcome: String::from("welcome").into_bytes(),
        };

        Ok(Response::new(resp)) // TODO
    }

    async fn handle_commit(
        &self,
        request: tonic::Request<HandleCommitRequest>,
    ) -> Result<tonic::Response<HandleCommitResponse>, tonic::Status> {
        let obj = request.get_ref();
        let commit = String::from("commit");
        let commit_in = String::from_utf8(obj.commit.clone()).unwrap();
        if (commit != commit_in) {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "Invalid commit",
            ));
        }

        Ok(Response::new(HandleCommitResponse::default())) // TODO
    }
}

#[derive(Clap)]
struct Opts {
    #[clap(short, long, default_value = "[::1]")]
    host: String,

    #[clap(short, long, default_value = "50051")]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts = Opts::parse();

    // XXX(RLB): There's probably a more direct way to do this than building a string and then
    // parsing it.
    let addr = format!("{}:{}", opts.host, opts.port).parse().unwrap();
    let mls_client_impl = MlsClientImpl::default();

    println!("Listening on {}", addr);

    Server::builder()
        .add_service(MlsClientServer::new(mls_client_impl))
        .serve(addr)
        .await?;

    Ok(())
}
