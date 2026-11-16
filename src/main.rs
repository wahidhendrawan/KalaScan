//! The `kalascan` binary. Everything lives in the library (src/lib.rs) so
//! the fuzz targets under fuzz/ can call the parsers directly.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    kalascan::run().await
}
