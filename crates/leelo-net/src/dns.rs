//! Patched asynchronous DNS without reqwest's older bundled resolver dependency.
use hickory_resolver::{TokioResolver, config::LookupIpStrategy};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::net::SocketAddr;

pub(super) struct DnsResolver;

impl Resolve for DnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            // Build in the calling runtime. The synchronous provider API creates
            // short-lived runtimes, so no resolver state may retain an old one.
            let mut builder = TokioResolver::builder_tokio()?;
            builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
            lookup(builder.build()?, name).await
        })
    }
}

async fn lookup(
    resolver: TokioResolver,
    name: Name,
) -> Result<Addrs, Box<dyn std::error::Error + Send + Sync>> {
    let result = resolver.lookup_ip(name.as_str()).await?;
    Ok(Box::new(
        result.into_iter().map(|ip| SocketAddr::new(ip, 0)),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::{
        config::{ConnectionConfig, NameServerConfig, ResolverConfig},
        net::runtime::TokioRuntimeProvider,
    };
    use std::time::Duration;

    #[test]
    fn abandoned_dns_lookup_stops_retrying() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let sink = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let address = sink.local_addr().unwrap();
            let mut connection = ConnectionConfig::udp();
            connection.port = address.port();
            let config = ResolverConfig::from_name_servers(vec![NameServerConfig::new(
                address.ip(),
                false,
                vec![connection],
            )]);
            let mut builder =
                TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
            builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4Only;
            builder.options_mut().timeout = Duration::from_millis(150);
            builder.options_mut().attempts = 3;
            let resolver = builder.build().unwrap();
            let task = tokio::spawn(lookup(
                resolver,
                "cancellation.example.com.".parse().unwrap(),
            ));
            let mut packet = [0; 2048];
            let received = tokio::time::timeout(Duration::from_secs(2), sink.recv(&mut packet))
                .await
                .unwrap()
                .unwrap();
            assert!(received > 0, "a DNS query must start before cancellation");
            task.abort();
            assert!(matches!(task.await, Err(error) if error.is_cancelled()));
            // Wait beyond two configured retry intervals. A detached lookup
            // would resend queries while the outer request had already ended.
            assert!(
                tokio::time::timeout(Duration::from_millis(400), sink.recv(&mut packet))
                    .await
                    .is_err()
            );
        });
    }
}
