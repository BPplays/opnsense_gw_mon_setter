use anyhow::Result;
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::Deserialize;
use std::collections::{HashMap, VecDeque, HashSet};
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
    #[serde(default = "default_min_ttl")]
    min_ttl: u8,
}

fn default_keep_for() -> Duration { Duration::from_secs(30) }
fn default_min_ttl() -> u8 { 0 }

/// Owned representation of a single probe result inside a round.
/// We store the probe's *index* so we can compute per-ttl-index loss
/// even if the non-Complete probe variants don't expose TTL directly.
#[derive(Debug, Clone)]
enum ProbeKind {
    Complete { host: IpAddr, ttl: u8, rtt: Duration },
    Awaited,
    Other,
}

#[derive(Debug, Clone)]
struct ProbeResult {
    index: usize,
    kind: ProbeKind,
}

#[derive(Debug, Clone)]
struct TraceRound {
    /// the target we probed (destination IP)
    target: IpAddr,
    ts: DateTime<Utc>,
    probes: Vec<ProbeResult>,
    /// largest_ttl observed in that round (copied from Round.largest_ttl)
    largest_ttl: u8,
}

type SharedList = Arc<Mutex<VecDeque<TraceRound>>>;

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

            for target in ips_to_try.into_iter() {
                println!("tracing: {}", target);
                // had_result flag will be set inside the run_with closure if a TraceRound was produced/pushed
                let had_result = Arc::new(AtomicBool::new(false));
                let had_result_cloned = had_result.clone();
                let shared_cloned = shared.clone();
                let keep_for = probe.keep_for;

                // NOTE: max_rounds expects Option<usize>, not Option<u32>.
                let max_rounds_one: Option<usize> = Some(1);

                // Build tracer bound to interface and run exactly one round synchronously.
                let builder = Builder::new(target)
                    // .interface(Some(ifname.as_str()))
                    .max_rounds(max_rounds_one);

                match builder.build() {
                    Ok(tracer) => {
                        // run_with is synchronous and returns a Result — check it!
                        let run_res = tracer.run_with(|round: &Round<'_>| {
                            // convert the round to our owned TraceRound (always returns one even if no Complete)
                            let tr = round_to_trace_round(round, probe.clone(), target);
                            {
                                let mut q = shared_cloned.lock();
                                q.push_back(tr);
                                let cutoff = chrono::Utc::now() - chrono::Duration::from_std(keep_for).unwrap();
                                while q.front().map(|r| r.ts < cutoff).unwrap_or(false) {
                                    q.pop_front();
                                }
                            }
                            had_result_cloned.store(true, Ordering::SeqCst);
                        });

                        match run_res {
                            Ok(_) => {
                                // println!("run_with returned Ok for {}", target);
                                // move to next target (or next probe)
                            }
                            Err(e) => {
                                eprintln!("run_with returned Err for {} on iface {}: {:#}", target, ifname, e);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("failed to build tracer for {} on iface {}: {:#}", target, ifname, e);
                    }
                }

            } // end for ips

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

        let snapshot: Vec<TraceRound> = {
            let q = shared.lock();
            q.iter().cloned().collect()
        };

        if snapshot.is_empty() {
            continue;
        }

        // --- Build global aggregation structures ---
        // total_probes_at_index[i] = how many rounds contained a probe at index i
        let mut total_probes_at_index: HashMap<usize, usize> = HashMap::new();
        // successes[(host, index)] = number of times host replied at that probe index
        let mut successes: HashMap<(IpAddr, usize), usize> = HashMap::new();
        // rtts per host (for avg RTT)
        let mut rtts: HashMap<IpAddr, Vec<Duration>> = HashMap::new();
        // min hops per host
        let mut min_hops: HashMap<IpAddr, u32> = HashMap::new();
        // set of hosts seen
        let mut seen_hosts: HashSet<IpAddr> = HashSet::new();

        for round in snapshot.iter() {
            for probe_res in round.probes.iter() {
                // each probe index counts as "one attempt" (the probe was sent)
                *total_probes_at_index.entry(probe_res.index).or_insert(0) += 1;

                match &probe_res.kind {
                    ProbeKind::Complete { host, ttl: _, rtt } => {
                        seen_hosts.insert(*host);
                        *successes.entry((*host, probe_res.index)).or_insert(0) += 1;
                        rtts.entry(*host).or_default().push(*rtt);
                        let hops_val = round.largest_ttl as u32;
                        min_hops.entry(*host).and_modify(|m| *m = (*m).min(hops_val)).or_insert(hops_val);
                    }
                    _ => {
                        // Awaited / Other -> simply counts toward totals at that index (i.e. potential loss)
                    }
                }
            }
        }

        // --- compute per-host-per-index loss and overall stats ---
        // per-host-per-index loss: loss% = 100 * (1 - successes / total_for_index)
        let mut per_host_index_loss: HashMap<(IpAddr, usize), f64> = HashMap::new();
        for &host in seen_hosts.iter() {
            for (&index, &total_for_index) in total_probes_at_index.iter() {
                let suc = successes.get(&(host, index)).copied().unwrap_or(0) as f64;
                let tot = total_for_index as f64;
                let loss = if tot > 0.0 { (1.0 - suc / tot) * 100.0 } else { 100.0 };
                per_host_index_loss.insert((host, index), loss);
            }
        }

        // per-host aggregate loss (average of index losses weighted by totals at each index)
        let mut host_aggregate_loss: HashMap<IpAddr, f64> = HashMap::new();
        for &host in seen_hosts.iter() {
            let mut weighted_sum = 0.0f64;
            let mut weight = 0.0f64;
            for (&index, &total_for_index) in total_probes_at_index.iter() {
                let tot = total_for_index as f64;
                if tot == 0.0 { continue; }
                let loss = per_host_index_loss.get(&(host, index)).copied().unwrap_or(100.0);
                weighted_sum += loss * tot;
                weight += tot;
            }
            let avg = if weight > 0.0 { weighted_sum / weight } else { 100.0 };
            host_aggregate_loss.insert(host, avg);
        }

        // compute avg RTT per host
        let mut host_avg_rtt: HashMap<IpAddr, Duration> = HashMap::new();
        for (&host, vec) in rtts.iter() {
            if !vec.is_empty() {
                let sum_micros: u128 = vec.iter().map(|d| d.as_micros() as u128).sum();
                let avg_micros = (sum_micros as f64 / vec.len() as f64).round() as u128;
                host_avg_rtt.insert(host, Duration::from_micros(avg_micros as u64));
            }
        }

        // --- For each configured probe, pick candidates among hosts that replied to that probe's targets ---
        for probe in probes.iter() {
            // compute set of target IPs for this probe (same logic tracer used)
            // let ips_to_try: Vec<IpAddr> = probe.ips.as_ref()
            //     .map(|v| v.iter().filter_map(|s| s.parse().ok()).collect())
            //     .unwrap_or_else(|| vec![
            //         "2620:fe::9".parse().unwrap(),
            //         "2001:4860:4860::8888".parse().unwrap(),
            //     ]);

            // // We consider only rounds whose target is one of the probe's ips.
            // // Gather hosts that have any data from those rounds:
            // let mut hosts_for_probe: HashSet<IpAddr> = HashSet::new();
            // for round in snapshot.iter().filter(|r| ips_to_try.contains(&r.target)) {
            //     for probe_res in round.probes.iter() {
            //         if let ProbeKind::Complete { host, .. } = &probe_res.kind {
            //             hosts_for_probe.insert(*host);
            //         }
            //     }
            // }

            // Prepare candidate vector: (host, avg_rtt, avg_loss, min_hops)
            let mut candidates: Vec<(IpAddr, Duration, f64, u32)> = probe.ips.iter().filter_map(|&host| {
                let avg_rtt = host_avg_rtt.get(&host).copied().unwrap_or_else(|| Duration::from_millis(0));
                // only consider hosts that meet max_rtt
                if avg_rtt > probe.max_rtt {
                    return None;
                }
                let avg_loss = host_aggregate_loss.get(&host).copied().unwrap_or(100.0);
                let hops = min_hops.get(&host).copied().unwrap_or(255u32);
                Some((host, avg_rtt, avg_loss, hops))
            }).collect();

            candidates.sort_by(|a, b| {
                a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| a.3.cmp(&b.3))
            });

            println!("iface={} probe={} candidates={}", ifname, probe.name, candidates.len());
            for (ip, avg_rtt, avg_loss, hops) in candidates.iter() {
                println!("  {} avg_rtt={:?} avg_loss={:.2}% hops={}", ip, avg_rtt, avg_loss, hops);
            }

            // // Additionally, print per-index loss for top N hosts (useful to see how loss varies by TTL index)
            // for (ip, _, _, _) in candidates.iter().take(5) {
            //     print!("  per-index loss for {}: ", ip);
            //     // show losses sorted by index
            //     let mut pairs: Vec<(usize, f64)> = total_probes_at_index.keys().map(|&idx| {
            //         let l = per_host_index_loss.get(&(*ip, idx)).copied().unwrap_or(100.0);
            //         (idx, l)
            //     }).collect();
            //     pairs.sort_by_key(|p| p.0);
            //     let brief: Vec<String> = pairs.into_iter().map(|(i, l)| format!("[idx {}: {:.1}%]", i, l)).collect();
            //     println!("{}", brief.join(" "));
            // }
        }
    }
}

/// Convert a trippy-core Round<'_> into an owned TraceRound (always returns a TraceRound).
/// Note: we record the probe *index* for each probe result so the aggregator can compute
/// per-index (per-TTL-index) loss even if non-Complete variants don't expose TTL directly.
fn round_to_trace_round(round: &Round<'_>, cfg: ProbeCfg, target: IpAddr) -> TraceRound {
    let mut probes: Vec<ProbeResult> = Vec::with_capacity(round.probes.len());
    for (idx, p) in round.probes.iter().enumerate() {
        match p {
            ProbeStatus::Complete(pc) => {
                // compute rtt if possible
                let kind = if let Ok(dur) = pc.received.duration_since(pc.sent) {
                    ProbeKind::Complete {
                        host: pc.host,
                        ttl: pc.ttl.0,
                        rtt: dur,
                    }
                } else {
                    // if time travel / clocks make duration_since fail, mark as Other
                    ProbeKind::Other
                };
                probes.push(ProbeResult {
                    index: idx,
                    kind,
                });
            }
            ProbeStatus::Awaited(_) => {
                probes.push(ProbeResult {
                    index: idx,
                    kind: ProbeKind::Awaited,
                });
            }
            _ => {
                probes.push(ProbeResult {
                    index: idx,
                    kind: ProbeKind::Other,
                });
            }
        }
    }

    TraceRound {
        target,
        ts: chrono::Utc::now(),
        probes,
        largest_ttl: round.largest_ttl.0,
    }
}
