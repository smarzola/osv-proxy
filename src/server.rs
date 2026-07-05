use crate::config::Config;

pub fn serve(config: &Config) -> anyhow::Result<()> {
    println!(
        "server configuration is valid for phase one; listen={} artifact_behavior=redirect",
        config.server.listen
    );
    Ok(())
}
