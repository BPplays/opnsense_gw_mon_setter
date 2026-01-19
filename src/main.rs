use std::net::IpAddr;
use std::str::FromStr;
use trippy_core::Builder;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // target address
    let addr = IpAddr::from_str("2620:fe::555")?;

    // build default tracer and run with a per-round handler
    Builder::new(addr)
        .build()?
        .run_with(|round| {
            println!("{:#?}", round);
        })?;

    Ok(())
}
