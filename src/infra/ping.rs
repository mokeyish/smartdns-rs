// use std::sync::Arc;

// use futures_intrusive::sync::ManualResetEvent;
// use rnp::{self, PingRunnerCore, RnpPingRunnerConfig};

// fn tcp_ping() {
//     let stop_event: Arc<ManualResetEvent> = Arc::new(ManualResetEvent::new(false));
//     let config = RnpPingRunnerConfig {
//         worker_config: todo!(),
//         worker_scheduler_config: todo!(),
//         result_processor_config: todo!(),
//         external_ping_client_factory: todo!(),
//         extra_ping_result_processors: todo!(),
//     };

//     let runner = PingRunnerCore::new(config, stop_event.clone());

// }

pub use icmp_ping::icmp_ping_parallel;
pub use tcp_ping::{
    tcp_ping_parallel,
    ping,
};




mod tcp_ping {
    use std::net::SocketAddr;
    use std::time::{Instant, Duration};

    pub fn tcp_ping_parallel(addrs: &[SocketAddr], times: Option<u8>, timeout: Option<u64>) {

        for addr in addrs {
            ping(addr, times.unwrap_or(1), timeout.unwrap_or(3000));
        }
    }

    pub fn ping(addr: &SocketAddr, times: u8, timeout: u64) -> Option<Duration> {
        let start = Instant::now();
        for _ in 0..times {
            if let Err(_) = std::net::TcpStream::connect_timeout(addr, Duration::from_millis(timeout)) {
                return None;
            }
        }
        Some(start.elapsed())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_tcp_ping() {
            let ips = &[
                "8.8.8.8:80".parse().unwrap(),
                "119.29.29.29:80".parse().unwrap(),
                "9.9.9.9:80".parse().unwrap(),
                "1.1.1.1:80".parse().unwrap(),
            ];

            let ips2 = &[
                "8.8.8.8:443".parse().unwrap(),
                "119.29.29.29:443".parse().unwrap(),
                "9.9.9.9:443".parse().unwrap(),
                "1.1.1.1:443".parse().unwrap(),
            ];

            tcp_ping_parallel(ips, None, Some(1000));
            println!("##########");
            tcp_ping_parallel(ips2, None, None);

        }
    }
}

mod icmp_ping {
    use futures::future;
    use rand::random;
    use std::net::IpAddr;
    use std::time::Duration;
    use surge_ping::{Client, Config, IcmpPacket, PingIdentifier, PingSequence, ICMP};
    use tokio::time;

    pub async fn icmp_ping_parallel(ips: &[IpAddr]) -> Result<(), Box<dyn std::error::Error>> {
        let client_v4 = Client::new(&Config::default())?;
        let client_v6 = Client::new(&Config::builder().kind(ICMP::V6).build())?;

        let mut tasks = Vec::new();
        for ip in ips {
            match ip {
                addr @ IpAddr::V4(_) => {
                    tasks.push(tokio::spawn(ping(client_v4.clone(), addr.clone())))
                }
                addr @ IpAddr::V6(_) => {
                    tasks.push(tokio::spawn(ping(client_v6.clone(), addr.clone())))
                }
            }
        }

        future::join_all(tasks).await;
        Ok(())
    }

    async fn ping(client: Client, addr: IpAddr) {
        let payload = [0; 56];
        let mut pinger = client.pinger(addr, PingIdentifier(random())).await;
        pinger.timeout(Duration::from_secs(1));
        let mut interval = time::interval(Duration::from_secs(1));
        for idx in 0..5 {
            interval.tick().await;
            match pinger.ping(PingSequence(idx), &payload).await {
                Ok((IcmpPacket::V4(packet), dur)) => println!(
                    "No.{}: {} bytes from {}: icmp_seq={} ttl={} time={:0.2?}",
                    idx,
                    packet.get_size(),
                    packet.get_source(),
                    packet.get_sequence(),
                    packet.get_ttl(),
                    dur
                ),
                Ok((IcmpPacket::V6(packet), dur)) => println!(
                    "No.{}: {} bytes from {}: icmp_seq={} hlim={} time={:0.2?}",
                    idx,
                    packet.get_size(),
                    packet.get_source(),
                    packet.get_sequence(),
                    packet.get_max_hop_limit(),
                    dur
                ),
                Err(e) => println!("No.{}: {} ping {}", idx, pinger.host, e),
            };
        }
        println!("[+] {} done.", pinger.host);
    }

    trait IntoIpAddrSlice {}

    #[cfg(test)]
    mod tests {

        use super::*;

        #[test]
        fn test_icmp_ping() {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {

                    let ips = &[
                        "119.29.29.29".parse().unwrap(),
                        "8.8.8.8".parse().unwrap(),
                        "1.1.1.1".parse().unwrap(),
                    ];

                    icmp_ping_parallel(ips)
                    .await
                    .unwrap();

                });
        }
    }
}
