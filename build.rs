use std::io::Result;
fn main() -> Result<()> {
    prost_build::compile_protos(&["takproto/takmessage.proto"], &["takproto/"])?;
    Ok(())
}