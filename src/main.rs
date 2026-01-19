use anyhow::Result;
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::Deserialize;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use trippy_core::{Builder, ProbeStatus, Round};

#[derive(Debug, Deserialize)]
struct Config {
    #[serde(flatten)]
    ifaces: HashMap<String, Vec<ProbeCfg>>,
}

#[derive(Debug, Deserialize, Clone)]
struct ProbeCfg {
    name: String,
    name_selector: Option<String>,
    #[serde(with = "humantime_serde")]
    max_rtt: Duration,
    #[serde(default)]
    ips: Option<Vec<String>>,
    #[serde(with = "humantime_serde")]
    #[serde(default = "default_keep_for")]
    keep_for: Duration,
}

fn default_keep_for() -> Duration { Duration::from_secs(30) }

#[derive(Debug, Clone)]
struct TraceRecord {
    ip: IpAddr,
    ts: DateTime<Utc>,
    rtt: Duration,
    loss: f64,   // percent 0.0 .. 100.0
    hops: u32,
}

type SharedList = Arc<Mutex<VecDeque<TraceRecord>>>;

fn main() -> Result<()> {
    // load config.yml from current dir
    let yaml = std::fs::read_to_string("config.yml")?;
    let cfg: Config = serde_yaml::from_str(&yaml)?;

    // For each interface we create a shared list and spawn a tracer + aggregator thread pair.
    for (ifname, probes) in cfg.ifaces.into_iter() {
        let shared: SharedList = Arc::new(Mutex::new(VecDeque::new()));

        // create distinct clones for each closure so we don't accidentally move `ifname`
        let ifname_for_tracer = ifname.clone();
        let ifname_for_aggregator = ifname.clone();

        // split probes for two closures (clone for tracer, move original into aggregator)
        let probes_for_tracer = probes.clone();
        let probes_for_aggregator = probes;

        let shared_for_tracer = shared.clone();
        let shared_for_agg = shared.clone();

        // Tracer thread: cycles through configured probes for this interface.
        thread::spawn(move || {
            if let Err(e) = tracer_thread(ifname_for_tracer.clone(), probes_for_tracer, shared_for_tracer) {
                eprintln!("tracer thread error for iface {}: {:#}", ifname_for_tracer, e);
            }
        });

        // Aggregator thread: periodically checks shared list and prints best candidates per probe.
        thread::spawn(move || {
            if let Err(e) = aggregator_thread(ifname_for_aggregator.clone(), probes_for_aggregator, shared_for_agg) {
                eprintln!("aggregator thread error for iface {}: {:#}", ifname_for_aggregator, e);
            }
        });
    }

    // keep main alive
    loop {
        thread::park();
    }
}

/// Tracer thread for a given interface:
fn tracer_thread(ifname: String, probes: Vec<ProbeCfg>, shared: SharedList) -> Result<()> {
    // default fallback list if probe doesn't provide ips
    let default_ips: Vec<IpAddr> = vec![
        "2620:fe::9".parse().unwrap(),
        "2001:4860:4860::8888".parse().unwrap(),
    ];

    loop {
        for probe in probes.iter() {
            let ips_to_try: Vec<IpAddr> = probe.ips.as_ref()
                .map(|v| v.iter().filter_map(|s| s.parse().ok()).collect())
                .unwrap_or_else(|| default_ips.clone());

            let mut succeeded_for_probe = false;

            for target in ips_to_try.into_iter() {
                println!("tracing: {}", target);
                // had_result flag will be set inside the run_with closure if a TraceRecord was produced/pushed
                let had_result = Arc::new(AtomicBool::new(false));
                let had_result_cloned = had_result.clone();
                let shared_cloned = shared.clone();
                let keep_for = probe.keep_for;

                // NOTE: max_rounds expects Option<usize>, not Option<u32>.
                let max_rounds_one: Option<usize> = Some(1);

                // Build tracer bound to interface and run exactly one round synchronously.
                let builder = Builder::new(target)
                    .interface(Some(ifname.as_str()))
                    .max_rounds(max_rounds_one);

                match builder.build() {
                    Ok(tracer) => {
                        // run one round and handle it inline
                        let run_res = tracer.run_with(|round: &Round<'_>| {
                            if let Some(rec) = round_to_trace_record(round) {
                                // push to shared list and evict old entries older than keep_for
                                println!("pfhsdjf");
                                {
                                    let mut q = shared_cloned.lock();
                                    q.push_back(rec);
                                    let cutoff = chrono::Utc::now() - chrono::Duration::from_std(keep_for).unwrap();
                                    while q.front().map(|r| r.ts < cutoff).unwrap_or(false) {
                                        q.pop_front();
                                    }
                                }
                                had_result_cloned.store(true, Ordering::SeqCst);
                            }
                        });

                        if let Err(e) = run_res {
                            eprintln!("tracer run error for target {} on iface {}: {:#}", target, ifname, e);
                            // treat as failure and try next IP
                            continue;
                        }

                        // run_with returned; check if we got a result
                        if had_result.load(Ordering::SeqCst) {
                            println!("tracer ok3");
                            succeeded_for_probe = true;
                            break; // stop trying other IPs for this probe until next cycle
                        } else {
                            // no result, try next IP
                            println!("tracer cont");
                            continue;
                        }

                    }
                    Err(e) => {
                        eprintln!("failed to build tracer for {} on iface {}: {:#}", target, ifname, e);
                        continue;
                    }
                }
            } // end for ips

            if !succeeded_for_probe {
                // nothing responded for this probe: you can log if desired
                // eprintln!("no IPs responded for probe {} on {}", probe.name, ifname);
            }

            // short pause between probes to avoid tight loop (tweak as needed)
            thread::sleep(Duration::from_secs(1));
        }

        // sleep a little between full cycles (tweak to change probing frequency)
        thread::sleep(Duration::from_secs(5));
    }
}

/// Aggregator thread: snapshots the shared list periodically...
fn aggregator_thread(ifname: String, probes: Vec<ProbeCfg>, shared: SharedList) -> Result<()> {
    let poll_interval = Duration::from_secs(5);

    loop {
        thread::sleep(poll_interval);

        let snapshot: Vec<TraceRecord> = {
            let q = shared.lock();
            q.iter().cloned().collect()
        };

        if snapshot.is_empty() {
            continue;
        }

        // group by ip
        let mut per_ip: HashMap<IpAddr, Vec<TraceRecord>> = HashMap::new();
        for rec in snapshot.into_iter() {
            per_ip.entry(rec.ip).or_default().push(rec);
        }

        // compute summaries
        let summaries: Vec<(IpAddr, Duration, f64, u32)> = per_ip.into_iter()
            .map(|(ip, vec)| {
                let n = vec.len() as f64;
                let avg_rtt_ms = vec.iter().map(|r| r.rtt.as_millis() as f64).sum::<f64>() / n;
                let avg_rtt = Duration::from_millis(avg_rtt_ms.round() as u64);
                let avg_loss = vec.iter().map(|r| r.loss).sum::<f64>() / n;
                let min_hops = vec.iter().map(|r| r.hops).min().unwrap_or(255);
                (ip, avg_rtt, avg_loss, min_hops)
            })
            .collect();

        // For each configured probe on this interface, find valid entries <= probe.max_rtt,
        // sort by loss then hops, and print the winner.
        for probe in probes.iter() {
            let mut candidates: Vec<_> = summaries.iter()
                .filter(|(_, avg_rtt, _, _)| *avg_rtt <= probe.max_rtt)
                .cloned()
                .collect();

            candidates.sort_by(|a, b| {
                a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| a.3.cmp(&b.3))
            });

            println!("iface={} probe={} candidates={}", ifname, probe.name, candidates.len());
            for (ip, avg_rtt, avg_loss, hops) in candidates.iter().take(5) {
                println!("  {} avg_rtt={:?} avg_loss={:.2}% hops={}", ip, avg_rtt, avg_loss, hops);
            }
        }
    }
}

/// Map a Round -> TraceRecord (returns None if no Complete probes)
fn round_to_trace_record(round: &Round<'_>) -> Option<TraceRecord> {
    let total = round.probes.len();
    if total == 0 {
        return None;
    }

    let mut complete_count = 0usize;
    let mut rtt_sum_micros: u128 = 0;
    let mut last_complete_host: Option<IpAddr> = None;
    let mut host_for_largest_ttl: Option<IpAddr> = None;

    // TimeToLive is a newtype; use .0 to access inner. If your version differs, adjust.
    let largest_ttl_u32: u32 = (round.largest_ttl.0 as u32);

    for p in round.probes.iter() {
        match p {
            ProbeStatus::Complete(pc) => {
                // compute rtt if possible
                if let Ok(dur) = pc.received.duration_since(pc.sent) {
                    rtt_sum_micros += dur.as_micros();
                    complete_count += 1;
                }
                last_complete_host = Some(pc.host);
                if (pc.ttl.0 as u32) == largest_ttl_u32 {
                    host_for_largest_ttl = Some(pc.host);
                }
            }
            _ => {}
        }
    }

    if complete_count == 0 {
        return None;
    }

    let chosen_ip = host_for_largest_ttl.or(last_complete_host).expect("complete_count > 0 so there is a host");

    let avg_rtt_micros = (rtt_sum_micros as f64 / complete_count as f64).round() as u128;
    let avg_rtt = Duration::from_micros(avg_rtt_micros as u64);

    let awaited = round.probes.iter().filter(|x| matches!(x, ProbeStatus::Awaited(_))).count();
    let loss_percent = (awaited as f64) / (total as f64) * 100.0;

    let hops = largest_ttl_u32;

    Some(TraceRecord {
        ip: chosen_ip,
        ts: chrono::Utc::now(),
        rtt: avg_rtt,
        loss: loss_percent,
        hops,
    })
}
