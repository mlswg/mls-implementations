use clap::Parser;
use std::net::IpAddr;
use tonic::{transport::Server, Request, Response, Status};

use mls_client::mls_client_server::{MlsClient, MlsClientServer};
// TODO(RLB) Convert this back to more specific `use` directives
use mls_client::*;

pub mod mls_client {
    tonic::include_proto!("mls_client");
}

const IMPLEMENTATION_NAME: &str = "Mock-Rust";
const SUPPORTED_CIPHERSUITES: [u32; 2] = [0xA0A0, 0xA1A1];

#[derive(Default)]
pub struct MlsClientImpl {}

impl MlsClientImpl {
    const FIXED_TRANSACTION_ID: u32 = 42;
    const FIXED_STATE_ID: u32 = 43;

    // TODO(RLB): Figure out how to make these work with non-fixed values
    fn new_transaction_id(&self) -> u32 {
        MlsClientImpl::FIXED_TRANSACTION_ID
    }
    fn new_state_id(&self) -> u32 {
        MlsClientImpl::FIXED_STATE_ID
    }

    fn known_transaction_id(&self, id: u32) -> bool {
        id == MlsClientImpl::FIXED_TRANSACTION_ID
    }
    fn known_state_id(&self, id: u32) -> bool {
        id == MlsClientImpl::FIXED_STATE_ID
    }
}

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

    async fn create_group(
        &self,
        _request: tonic::Request<CreateGroupRequest>,
    ) -> Result<tonic::Response<CreateGroupResponse>, tonic::Status> {
        let resp = CreateGroupResponse {
            state_id: self.new_state_id(),
        };

        Ok(Response::new(resp)) // TODO
    }

    async fn create_key_package(
        &self,
        _request: tonic::Request<CreateKeyPackageRequest>,
    ) -> Result<tonic::Response<CreateKeyPackageResponse>, tonic::Status> {
        let resp = CreateKeyPackageResponse {
            transaction_id: self.new_transaction_id(),
            key_package: String::from("keyPackage").into_bytes(),
        };

        Ok(Response::new(resp)) // TODO
    }

    async fn join_group(
        &self,
        request: tonic::Request<JoinGroupRequest>,
    ) -> Result<tonic::Response<JoinGroupResponse>, tonic::Status> {
        let obj = request.get_ref();
        if !self.known_transaction_id(obj.transaction_id) {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "Invalid transasction ID",
            ));
        }

        let welcome = String::from("welcome");
        let welcome_in = String::from_utf8(obj.welcome.clone()).unwrap();
        if welcome != welcome_in {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "Invalid welcome",
            ));
        }

        let resp = JoinGroupResponse {
            state_id: self.new_state_id(),
        };

        Ok(Response::new(resp)) // TODO
    }

    async fn external_join(
        &self,
        request: tonic::Request<ExternalJoinRequest>,
    ) -> Result<tonic::Response<ExternalJoinResponse>, tonic::Status> {
        let obj = request.get_ref();
        let public_group_state = String::from("publicGroupState");
        let public_group_state_in = String::from_utf8(obj.public_group_state.clone()).unwrap();
        if public_group_state != public_group_state_in {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "Invalid public_group_state",
            ));
        }

        let resp = ExternalJoinResponse {
            state_id: self.new_state_id(),
            commit: String::from("commit").into_bytes(),
        };

        Ok(Response::new(resp)) // TODO
    }

    async fn public_group_state(
        &self,
        request: tonic::Request<PublicGroupStateRequest>,
    ) -> Result<tonic::Response<PublicGroupStateResponse>, tonic::Status> {
        let obj = request.get_ref();
        if !self.known_state_id(obj.state_id) {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "Invalid state ID",
            ));
        }

        let resp = PublicGroupStateResponse {
            public_group_state: String::from("publicGroupState").into_bytes(),
        };

        Ok(Response::new(resp)) // TODO
    }

    async fn state_auth(
        &self,
        request: tonic::Request<StateAuthRequest>,
    ) -> Result<tonic::Response<StateAuthResponse>, tonic::Status> {
        let obj = request.get_ref();
        if !self.known_state_id(obj.state_id) {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                format!("Invalid state ID: {}", obj.state_id),
            ));
        }

        let resp = StateAuthResponse {
            state_auth_secret: String::from("stateAuthSecret").into_bytes(),
        };

        Ok(Response::new(resp)) // TODO
    }

    async fn export(
        &self,
        request: tonic::Request<ExportRequest>,
    ) -> Result<tonic::Response<ExportResponse>, tonic::Status> {
        let obj = request.get_ref();
        if !self.known_state_id(obj.state_id) {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                format!("Invalid state ID: {}", obj.state_id),
            ));
        }

        let resp = ExportResponse {
            exported_secret: String::from("exportedSecret").into_bytes(),
        };

        Ok(Response::new(resp))
    }

    async fn protect(
        &self,
        request: tonic::Request<ProtectRequest>,
    ) -> Result<tonic::Response<ProtectResponse>, tonic::Status> {
        let obj = request.get_ref();
        if !self.known_state_id(obj.state_id) {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                format!("Invalid state ID: {}", obj.state_id),
            ));
        }

        let resp = ProtectResponse {
            ciphertext: obj.application_data.clone(),
        };

        Ok(Response::new(resp))
    }

    async fn unprotect(
        &self,
        request: tonic::Request<UnprotectRequest>,
    ) -> Result<tonic::Response<UnprotectResponse>, tonic::Status> {
        let obj = request.get_ref();
        if !self.known_state_id(obj.state_id) {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                format!("Invalid state ID: {}", obj.state_id),
            ));
        }

        let resp = UnprotectResponse {
            application_data: obj.ciphertext.clone(),
        };

        Ok(Response::new(resp))
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
        if !self.known_state_id(obj.state_id) {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "Invalid state ID",
            ));
        }

        let key_package = String::from("keyPackage");
        let key_package_in = String::from_utf8(obj.key_package.clone()).unwrap();
        if key_package != key_package_in {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "Invalid key package",
            ));
        }

        let resp = ProposalResponse {
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

    async fn commit(
        &self,
        request: tonic::Request<CommitRequest>,
    ) -> Result<tonic::Response<CommitResponse>, tonic::Status> {
        let obj = request.get_ref();
        if !self.known_state_id(obj.state_id) {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "Invalid state ID",
            ));
        }

        let resp = CommitResponse {
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
        if !self.known_state_id(obj.state_id) {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "Invalid state ID",
            ));
        }

        let obj = request.get_ref();
        let commit = String::from("commit");
        let commit_in = String::from_utf8(obj.commit.clone()).unwrap();
        if commit != commit_in {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "Invalid commit",
            ));
        }

        let resp = HandleCommitResponse {
            state_id: self.new_state_id(),
            added: vec![0, 1, 2],
            removed_indices: vec![0, 1],
            removed_leaves: vec![vec![0u8; 10], vec![1u8; 16]],
            updated: vec![],
            psks: vec![],
        };

        Ok(Response::new(resp)) // TODO
    }

    async fn handle_pending_commit(
        &self,
        request: tonic::Request<HandlePendingCommitRequest>,
    ) -> Result<tonic::Response<HandleCommitResponse>, tonic::Status> {
        let obj = request.get_ref();
        if !self.known_state_id(obj.state_id) {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "Invalid state ID",
            ));
        }

        let resp = HandleCommitResponse {
            state_id: self.new_state_id(),
            added: vec![0, 1, 2],
            removed_indices: vec![0, 1],
            removed_leaves: vec![vec![0u8; 10], vec![1u8; 16]],
            updated: vec![],
            psks: vec![],
        };

        Ok(Response::new(resp)) // TODO
    }

    async fn handle_external_commit(
        &self,
        request: tonic::Request<HandleExternalCommitRequest>,
    ) -> Result<tonic::Response<HandleExternalCommitResponse>, tonic::Status> {
        let obj = request.get_ref();
        if !self.known_state_id(obj.state_id) {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "Invalid state ID",
            ));
        }

        let obj = request.get_ref();
        let commit = String::from("commit");
        let commit_in = String::from_utf8(obj.commit.clone()).unwrap();
        if commit != commit_in {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "Invalid commit",
            ));
        }

        let resp = HandleExternalCommitResponse {
            state_id: self.new_state_id(),
        };

        Ok(Response::new(resp)) // TODO
    }
}

#[derive(Parser)]
struct Opts {
    #[clap(short, long, value_parser, default_value = "::1")]
    host: IpAddr,

    #[clap(short, long, value_parser, default_value = "50003")]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts = Opts::parse();
    let mls_client_impl = MlsClientImpl::default();

    Server::builder()
        .add_service(MlsClientServer::new(mls_client_impl))
        .serve((opts.host, opts.port).into())
        .await?;

    Ok(())
}
