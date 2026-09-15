//! Experimental, loopback-only recovery resource. Separate database from wallet backups.
#[path = "../recovery_prototype.rs"]
mod recovery;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        return Err(
            "usage: arkade-recovery-prototype DB LOOPBACK_ADDR PUBLIC_ORIGIN PUBLISHER_HEX".into(),
        );
    }
    let address: std::net::SocketAddr = args[2].parse()?;
    if !address.ip().is_loopback() {
        return Err("prototype must bind loopback".into());
    }
    let app = recovery::app(&args[1], args[3].clone(), args[4].clone())?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    eprintln!("experimental recovery resource listening on {address}");
    axum::serve(listener, app).await?;
    Ok(())
}
