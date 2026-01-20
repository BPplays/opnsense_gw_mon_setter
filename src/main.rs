use anyhow::Result;
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::{HashMap, VecDeque, HashSet};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use clap::{Parser};
use std::str::FromStr;
use strum::{VariantNames};
use strum_macros::{AsRefStr, Display, EnumString, VariantNames};

use trippy_core::{Builder, ProbeStatus, Round};

#[derive(Debug, Deserialize)]
struct Config {
    pub api: ApiConfig,
    pub ifaces: HashMap<String, Vec<ProbeCfg>>,
}

#[derive(Debug, EnumString, VariantNames, AsRefStr, Display, Serialize)]
#[strum(serialize_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum ApiType {
    #[strum(serialize = "opnsense")]
    #[strum(serialize = "opn")]
    Opnsense,
}

impl<'de> Deserialize<'de> for ApiType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut s = String::deserialize(deserializer)?;
        s = s.to_lowercase();
        ApiType::from_str(&s).map_err(|_e| {
            serde::de::Error::unknown_variant(&s, &ApiType::VARIANTS)
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct ApiConfig {
    #[serde(rename = "type")]
    pub atype: ApiType,
    pub key: String,
    pub secret: String,
}

#[derive(Parser)]
#[command(name = "opnsense_gw_mon_setter")]
#[command(about = "opnsense_gw_mon_setter", long_about = None)]
struct Cli {
    #[arg(short = 'c', long = "config", default_value = "config.yml")]
    config: String,
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

#[derive(Debug, Clone)]
struct Candidate {
    ip: IpAddr,
    avg_rtt: Option<Duration>,
    loss: f64,
    hops: u32,
    avg_index: f64,
}

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
    let cli = Cli::parse();
    let yaml = std::fs::read_to_string(cli.config)?;
    let cfg: Config = serde_yaml::from_str(&yaml)?;
    println!("{:#?}", cfg.api);

    for (ifname, probes) in cfg.ifaces.into_iter() {
        // iterate probes and create per-probe shared lists
        for probe in probes.into_iter() {
            // create a shared list JUST for this probe
            let shared: SharedList = Arc::new(Mutex::new(VecDeque::new()));

            // clone what each closure needs
            let ifname_for_tracer = ifname.clone();
            let ifname_for_aggregator = ifname.clone();

            let probe_for_tracer = probe.clone();
            let probe_for_aggregator = probe.clone();

            let shared_for_tracer = shared.clone();
            let shared_for_agg = shared.clone();

            // Tracer thread: only cycles through the single configured probe for this interface.
            thread::spawn(move || {
                if let Err(e) = tracer_thread(ifname_for_tracer.clone(), vec![probe_for_tracer.clone()], shared_for_tracer) {
                    eprintln!("tracer thread error for iface {} probe {}: {:#}", ifname_for_tracer, probe_for_tracer.name, e);
                }
            });

            // Aggregator thread: periodically checks shared list and prints best candidates for this probe.
            thread::spawn(move || {
                if let Err(e) = aggregator_thread(ifname_for_aggregator.clone(), vec![probe_for_aggregator.clone()], shared_for_agg) {
                    eprintln!("aggregator thread error for iface {} probe {}: {:#}", ifname_for_aggregator, probe_for_aggregator.name, e);
                }
            });
        }
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

    // remember last target across iterations so we can clear rounds when target changes
    let mut last_target: Option<IpAddr> = None;

    loop {
        for probe in probes.iter() {
            let ips_to_try: Vec<IpAddr> = probe.ips.as_ref()
                .map(|v| v.iter().filter_map(|s| s.parse().ok()).collect())
                .unwrap_or_else(|| default_ips.clone());

            for target in ips_to_try.into_iter() {
                println!("tracing: {}", target);

                // If target changed since last time, clear shared rounds for a fresh start.
                if last_target.map(|ip| ip != target).unwrap_or(true) {
                    let mut q = shared.lock();
                    q.clear();
                }
                last_target = Some(target);

                // We'll re-run rounds for this target until we observe a round that
                // contains NO Complete probe entries. Only then do we move to next IP.
                //
                // had_result: whether run_with pushed a TraceRound at all.
                // had_complete: whether that TraceRound (the most recent one) contained any Complete probes.
                loop {
                    let had_result = Arc::new(AtomicBool::new(false));
                    let had_result_cloned = had_result.clone();

                    let had_complete = Arc::new(AtomicBool::new(false));
                    let had_complete_cloned = had_complete.clone();

                    let shared_cloned = shared.clone();
                    let keep_for = probe.keep_for;

                    let max_rounds_one: Option<usize> = Some(1);

                    // Build tracer bound to interface and run exactly one round synchronously.
                    let builder = Builder::new(target)
                        .interface(Some(ifname.as_str()))
                        .max_rounds(max_rounds_one);

                    match builder.build() {
                        Ok(tracer) => {
                            // run_with is synchronous and returns a Result — check it!
                            let run_res = tracer.run_with(|round: &Round<'_>| {
                                // convert the round to our owned TraceRound (always returns one even if no Complete)
                                let tr = round_to_trace_round(round, probe.clone(), target);

                                let min_index = probe.min_ttl.saturating_sub(1) as usize;
                                let contains_complete = tr.probes.iter().any(|p| {
                                    p.index >= min_index && matches!(p.kind, ProbeKind::Complete { .. })
                                });

                                {
                                    let mut q = shared_cloned.lock();
                                    q.push_back(tr);
                                    let cutoff = chrono::Utc::now() - chrono::Duration::from_std(keep_for).unwrap();
                                    while q.front().map(|r| r.ts < cutoff).unwrap_or(false) {
                                        q.pop_front();
                                    }
                                }

                                had_result_cloned.store(true, Ordering::SeqCst);
                                had_complete_cloned.store(contains_complete, Ordering::SeqCst);
                            });

                            match run_res {
                                Ok(_) => {
                                    // If run produced no result, move to next IP.
                                    if !had_result.load(Ordering::SeqCst) {
                                        break;
                                    }

                                    // If the most recent round had NO Complete entries -> move to next IP.
                                    // Otherwise keep probing the same target.
                                    if !had_complete.load(Ordering::SeqCst) {
                                        break;
                                    } else {
                                        // There were Complete entries: retry the same target (per your requirement).
                                        // small pause to avoid tight loop; adjust as needed
                                        thread::sleep(Duration::from_millis(200));
                                        continue;
                                    }
                                }
                                Err(e) => {
                                    eprintln!("run_with returned Err for {} on iface {}: {:#}", target, ifname, e);
                                    // On error, move to next IP
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("failed to build tracer for {} on iface {}: {:#}", target, ifname, e);
                            // On error, move to next IP
                            break;
                        }
                    }
                } // end loop probing same target

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

        // snapshot the rounds
        let mut snapshot: Vec<TraceRound> = {
            let q = shared.lock();
            q.iter().cloned().collect()
        };

        if snapshot.is_empty() {
            continue;
        }

        // make ordering deterministic by timestamp (oldest first)
        snapshot.sort_by_key(|r| r.ts);

        let total_rounds = snapshot.len() as f64;

        // Determine maximum probe index present so we can allocate indexed vectors (still useful).
        let max_index = snapshot.iter()
            .flat_map(|r| r.probes.iter().map(|p| p.index))
            .max()
            .unwrap_or(0);
        let index_count = max_index + 1;

        // Build FIRST-SEEN ordered host list (chronological across rounds).
        // IMPORTANT: include each round.target so non-responding targets appear with 100% loss.
        let mut seen_hosts: Vec<IpAddr> = Vec::new();
        for round in snapshot.iter() {
            // ensure target is present first (so the "target" shows up even if never Complete)
            if !seen_hosts.iter().any(|h| h == &round.target) {
                seen_hosts.push(round.target);
            }
            // then include any Complete responders seen in this round
            for probe_res in round.probes.iter() {
                if let ProbeKind::Complete { host, .. } = &probe_res.kind {
                    if !seen_hosts.iter().any(|h| h == host) {
                        seen_hosts.push(*host);
                    }
                }
            }
        }

        let host_count = seen_hosts.len();

        // Per-host accumulators indexed by host index:
        // - times_present: number of rounds where host appeared at least once (Complete)
        // - index_sum: sum of the (closest) indices where the host appeared (for average position)
        // - rtts: list of RTT samples for avg RTT
        // - min_hops: minimum hops observed for host
        let mut times_present: Vec<usize> = vec![0; host_count];
        let mut index_sum: Vec<usize> = vec![0; host_count];
        let mut rtts: Vec<Vec<Duration>> = vec![Vec::new(); host_count];
        let mut min_hops: Vec<Option<u32>> = vec![None; host_count];

        // For each round, note which hosts appeared and their closest index in that round.
        for round in snapshot.iter() {
            // Map host_idx -> closest index for this round (we'll compute with temporary vec)
            // Use Option<usize> to mark presence.
            let mut round_closest: Vec<Option<usize>> = vec![None; host_count];

            for probe_res in round.probes.iter() {
                if let ProbeKind::Complete { host, ttl: _, rtt } = &probe_res.kind {
                    if let Some(hidx) = seen_hosts.iter().position(|h| h == host) {
                        round_closest[hidx] = Some(match round_closest[hidx] {
                            Some(existing) => existing.min(probe_res.index),
                            None => probe_res.index,
                        });
                        // collect RTT samples and hops (we collect every sample; presence counted once per round below)
                        rtts[hidx].push(*rtt);
                        let hops_val = round.largest_ttl as u32;
                        min_hops[hidx] = Some(min_hops[hidx].map(|m| m.min(hops_val)).unwrap_or(hops_val));
                    }
                }
            }

            // Now increment times_present and index_sum for hosts that appeared in this round
            for hidx in 0..host_count {
                if let Some(idx) = round_closest[hidx] {
                    times_present[hidx] += 1;
                    index_sum[hidx] += idx;
                }
            }
        }

        // Compute per-host metrics:
        // - loss = 100 * (1 - times_present / total_rounds)
        // - avg_index = index_sum / times_present (or large sentinel if times_present == 0)
        // - avg_rtt from rtts vector (or None)
        let mut host_loss: Vec<f64> = vec![100.0; host_count];
        let mut host_avg_index: Vec<f64> = vec![f64::INFINITY; host_count];
        let mut host_avg_rtt: Vec<Option<Duration>> = vec![None; host_count];

        for hidx in 0..host_count {
            let present = times_present[hidx] as f64;
            if total_rounds > 0.0 {
                host_loss[hidx] = (1.0 - present / total_rounds) * 100.0;
            } else {
                host_loss[hidx] = 100.0;
            }

            if times_present[hidx] > 0 {
                host_avg_index[hidx] = index_sum[hidx] as f64 / times_present[hidx] as f64;
            } else {
                // host never seen (e.g. target that never replied) -> place it at the far end
                host_avg_index[hidx] = f64::INFINITY;
            }

            if !rtts[hidx].is_empty() {
                let sum_micros: u128 = rtts[hidx].iter().map(|d| d.as_micros() as u128).sum();
                let avg_micros = (sum_micros as f64 / rtts[hidx].len() as f64).round() as u128;
                host_avg_rtt[hidx] = Some(Duration::from_micros(avg_micros as u64));
            }
        }

        // --- For each configured probe, build candidates sorted by avg_index (closest -> furthest) ---
        for probe in probes.iter() {
            let mut logs: Vec<String> = vec![];
            // Build list of candidate tuples: (host, avg_rtt_opt, loss, hops, avg_index)
            // let mut candidates: Vec<(IpAddr, Option<Duration>, f64, u32, f64)> = Vec::new();
            let mut candidates: Vec<Candidate> = Vec::new();
            for (hidx, host) in seen_hosts.iter().enumerate() {
                // do not coerce missing RTT to 0 — keep Option so we can show "—"
                let avg_rtt_opt = host_avg_rtt[hidx];
                // respect probe.max_rtt: if a host has no RTT samples, we still include it (so failing targets show)
                if let Some(avg_rtt) = avg_rtt_opt {
                    if avg_rtt > probe.max_rtt {
                        continue;
                    }
                }
                let loss = host_loss[hidx];
                let hops = min_hops[hidx].unwrap_or(255u32);
                let avg_idx = host_avg_index[hidx];
                // candidates.push((*host, avg_rtt_opt, loss, hops, avg_idx));
                candidates.push(Candidate {
                    ip: (host.clone()),
                    avg_rtt: (avg_rtt_opt),
                    loss: loss,
                    hops: hops,
                    avg_index: (avg_idx),
                });
            }

            // sort by average index ascending (closest first). tie-break by loss then hops.
            candidates.sort_by(|a, b| {
                let cmp_idx = a.hops.partial_cmp(&b.hops).unwrap_or(std::cmp::Ordering::Equal);
                cmp_idx
                    .then_with(|| a.avg_index.partial_cmp(&b.avg_index).unwrap_or(std::cmp::Ordering::Equal))
                    .then_with(|| a.avg_rtt.partial_cmp(&b.avg_rtt).unwrap_or(std::cmp::Ordering::Equal))
                    .then_with(|| a.loss.total_cmp(&b.loss))
            });

            let s = format!(
                "iface={} probe={} candidates={}",
                ifname,
                probe.name,
                candidates.len(),
            );
            logs.push(s);
            for can in candidates.iter() {
                // show "—" for hosts with no RTT samples
                let avg_rtt_str = match can.avg_rtt {
                    Some(d) => format!("{:?}", d),
                    None => "—".to_string(),
                };

                let s = format!(
                    "  {} avg_rtt={} avg_loss={:.2}% hops={} avg_index={:.2}",
                    can.ip,
                    avg_rtt_str,
                    can.loss,
                    can.hops,
                    can.avg_index,
                );
                logs.push(s);
            }

            // let mut winner = IpAddr::V6(Ipv6Addr::UNSPECIFIED);

            let mut winner = Candidate {
                ip: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                avg_rtt: Some(Duration::new(0, 0)),
                loss: 0.0,
                hops: 0,
                avg_index: -99999.0,
            };

            for can in candidates.iter() {
                let mut ttl = can.avg_index.round() as u8;
                if ttl < 255 { ttl += 1 }

                if ttl < probe.min_ttl {
                    logs.push(format!("ttl too small {}", ttl));
                    continue;
                }
                if winner.ip.is_unspecified() {
                    winner = can.clone();
                    continue;
                }

                if can.avg_rtt > Some(probe.max_rtt) {
                    continue;
                }

                if can.loss < winner.loss {
                    winner = can.clone()
                }
            }
            logs.push(format!("[{}] winner is {}!", probe.name, winner.ip));
            println!("{}", logs.join("\n"))
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
