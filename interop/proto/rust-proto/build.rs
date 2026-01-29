fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::compile_protos("../mls_client.proto")?;
    Ok(())
}
