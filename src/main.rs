#[tokio::main]
async fn main() -> anyhow::Result<()> {
    osv_proxy::cli::run().await
}
