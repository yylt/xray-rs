use std::collections::VecDeque;
use std::fmt::Write;
use std::io;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::common::stats::TrafficSnapshot;

pub const SAMPLE_SECONDS: u64 = 5;
const MAX_RETENTION: u64 = 3 * 24 * 3600;

pub fn duration(value: &str) -> io::Result<Duration> {
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "duration must be a positive integer with s/m/h/d suffix, at most 3d",
        )
    };
    let (number, unit) = value
        .split_at_checked(value.len().saturating_sub(1))
        .ok_or_else(invalid)?;
    if number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }
    let multiplier = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => return Err(invalid()),
    };
    let seconds = number
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(multiplier))
        .filter(|n| *n > 0 && *n <= MAX_RETENTION)
        .ok_or_else(invalid)?;
    Ok(Duration::from_secs(seconds))
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Rate {
    uplink_bps: f64,
    downlink_bps: f64,
    uplink_peak_bps: f64,
    downlink_peak_bps: f64,
}

#[derive(Debug)]
struct Sample {
    at: Instant,
    timestamp_ms: u64,
    elapsed: f64,
    rates: Vec<Rate>,
    memory: Option<u64>,
}

#[derive(Debug, Serialize)]
struct Point {
    timestamp_ms: u64,
    series: Vec<Rate>,
    memory_bytes: Option<f64>,
    memory_peak_bytes: Option<u64>,
}

#[derive(Debug)]
pub struct History {
    retention: Duration,
    samples: VecDeque<Sample>,
    previous: Vec<TrafficSnapshot>,
    previous_at: Option<Instant>,
}

impl History {
    pub fn new(retention: Duration) -> Self {
        Self {
            retention,
            samples: VecDeque::new(),
            previous: Vec::new(),
            previous_at: None,
        }
    }

    pub fn sample(&mut self, snapshot: Vec<TrafficSnapshot>, now: Instant, timestamp_ms: u64, memory: Option<u64>) {
        let elapsed = self
            .previous_at
            .map(|at| now.duration_since(at).as_secs_f64())
            .unwrap_or(0.0);
        let rates = snapshot
            .iter()
            .enumerate()
            .map(|(i, current)| {
                let Some(previous) = self
                    .previous
                    .get(i)
                    .filter(|previous| previous.direction == current.direction && previous.tag == current.tag)
                else {
                    return Rate::default();
                };
                if elapsed == 0.0 {
                    return Rate::default();
                }
                let uplink_bps = current.uplink.saturating_sub(previous.uplink) as f64 / elapsed;
                let downlink_bps = current.downlink.saturating_sub(previous.downlink) as f64 / elapsed;
                Rate {
                    uplink_bps,
                    downlink_bps,
                    uplink_peak_bps: uplink_bps,
                    downlink_peak_bps: downlink_bps,
                }
            })
            .collect();
        self.samples.push_back(Sample {
            at: now,
            timestamp_ms,
            elapsed,
            rates,
            memory,
        });
        self.previous = snapshot;
        self.previous_at = Some(now);
        let capacity = self.retention.as_secs().div_ceil(SAMPLE_SECONDS) as usize + 1;
        while self
            .samples
            .front()
            .is_some_and(|sample| now.duration_since(sample.at) > self.retention)
            || self.samples.len() > capacity
        {
            self.samples.pop_front();
        }
    }

    pub fn response(&self, range: Duration, snapshot: &[TrafficSnapshot], now: Instant) -> serde_json::Value {
        let samples: Vec<_> = self
            .samples
            .iter()
            .filter(|sample| now.duration_since(sample.at) <= range)
            .collect();
        let chunk_size = samples.len().div_ceil(720).max(1);
        let points: Vec<_> = samples
            .chunks(chunk_size)
            .map(|chunk| {
                let mut series = vec![Rate::default(); snapshot.len()];
                let mut weight = 0.0;
                let mut memory_weight = 0.0;
                let mut memory_total = 0.0;
                let mut memory_peak = None;
                for sample in chunk {
                    let elapsed = sample.elapsed.max(f64::EPSILON);
                    weight += elapsed;
                    for (result, rate) in series.iter_mut().zip(&sample.rates) {
                        result.uplink_bps += rate.uplink_bps * elapsed;
                        result.downlink_bps += rate.downlink_bps * elapsed;
                        result.uplink_peak_bps = result.uplink_peak_bps.max(rate.uplink_peak_bps);
                        result.downlink_peak_bps = result.downlink_peak_bps.max(rate.downlink_peak_bps);
                    }
                    if let Some(memory) = sample.memory {
                        memory_total += memory as f64 * elapsed;
                        memory_weight += elapsed;
                        memory_peak = Some(memory_peak.unwrap_or(0).max(memory));
                    }
                }
                for rate in &mut series {
                    rate.uplink_bps /= weight;
                    rate.downlink_bps /= weight;
                }
                Point {
                    timestamp_ms: chunk.last().unwrap().timestamp_ms,
                    series,
                    memory_bytes: (memory_weight > 0.0).then(|| memory_total / memory_weight),
                    memory_peak_bytes: memory_peak,
                }
            })
            .collect();
        let series: Vec<_> = snapshot
            .iter()
            .enumerate()
            .map(|(i, snapshot)| {
                let mut value = serde_json::to_value(snapshot).unwrap();
                let rate = self
                    .samples
                    .back()
                    .and_then(|sample| sample.rates.get(i))
                    .cloned()
                    .unwrap_or_default();
                value["uplink_bps"] = rate.uplink_bps.into();
                value["downlink_bps"] = rate.downlink_bps.into();
                value
            })
            .collect();
        serde_json::json!({"retention_seconds": self.retention.as_secs(), "sample_interval_seconds": SAMPLE_SECONDS, "series": series, "points": points, "memory_bytes": self.samples.back().and_then(|sample| sample.memory)})
    }

    pub fn retention(&self) -> Duration {
        self.retention
    }

    pub fn prometheus(&self, snapshot: &[TrafficSnapshot]) -> String {
        let mut output = String::from("# HELP xray_traffic_bytes_total Forwarded payload bytes (inbound and outbound are separate views).\n# TYPE xray_traffic_bytes_total counter\n# HELP xray_traffic_bytes_per_second Average payload rate over the last sampling interval.\n# TYPE xray_traffic_bytes_per_second gauge\n# HELP xray_traffic_supported Whether payload accounting is supported for this endpoint.\n# TYPE xray_traffic_supported gauge\n");
        for (i, item) in snapshot.iter().enumerate() {
            let labels = format!(
                "direction=\"{}\",tag=\"{}\",proxy=\"{}\",transport=\"{}\",security=\"{}\"",
                escape(&item.direction),
                escape(&item.tag),
                escape(&item.proxy),
                escape(&item.transport),
                escape(&item.security)
            );
            writeln!(output, "xray_traffic_supported{{{labels}}} {}", u8::from(item.supported)).unwrap();
            if !item.supported {
                continue;
            }
            let rate = self
                .samples
                .back()
                .and_then(|sample| sample.rates.get(i))
                .cloned()
                .unwrap_or_default();
            for (flow, total, speed) in [
                ("uplink", item.uplink, rate.uplink_bps),
                ("downlink", item.downlink, rate.downlink_bps),
            ] {
                writeln!(output, "xray_traffic_bytes_total{{{labels},flow=\"{flow}\"}} {total}").unwrap();
                writeln!(output, "xray_traffic_bytes_per_second{{{labels},flow=\"{flow}\"}} {speed}").unwrap();
            }
        }
        output.push_str("# HELP xray_process_resident_memory_bytes Process resident set size.\n# TYPE xray_process_resident_memory_bytes gauge\n");
        if let Some(memory) = self.samples.back().and_then(|sample| sample.memory) {
            writeln!(output, "xray_process_resident_memory_bytes {memory}").unwrap();
        }
        output
    }
}

fn escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\n', "\\n").replace('"', "\\\"")
}

pub fn timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

pub fn resident_memory() -> Option<u64> {
    // /proc is intentionally optional: unsupported platforms report unavailable, not zero.
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let mut fields = status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))?
        .split_whitespace();
    let kib = fields.next()?.parse::<u64>().ok()?;
    (fields.next()? == "kB").then(|| kib.checked_mul(1024)).flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(bytes: u64) -> Vec<TrafficSnapshot> {
        vec![TrafficSnapshot {
            direction: "inbound".into(),
            tag: "test".into(),
            proxy: "socks".into(),
            transport: "tcp".into(),
            security: "none".into(),
            supported: true,
            uplink: bytes,
            downlink: bytes * 2,
        }]
    }

    #[test]
    fn live_rates_retention_and_peak_aggregation() {
        let start = Instant::now();
        let mut history = History::new(Duration::from_secs(4000));
        history.sample(snapshot(0), start, 0, None);
        for i in 1..=800 {
            history.sample(snapshot(i * 50), start + Duration::from_secs(i * 5), i * 5000, Some(i * 1024));
        }
        let now = start + Duration::from_secs(4000);
        let response = history.response(Duration::from_secs(4000), &snapshot(40000), now);
        let points = response["points"].as_array().unwrap();
        assert!(points.len() <= 720);
        assert_eq!(response["series"][0]["uplink_bps"], 10.0);
        assert_eq!(points.last().unwrap()["series"][0]["downlink_peak_bps"], 20.0);
        assert_eq!(points.last().unwrap()["memory_peak_bytes"], 800 * 1024);
        assert!(history.prometheus(&snapshot(40000)).contains("flow=\"uplink\"} 40000"));
        history.sample(snapshot(40000), now + Duration::from_secs(4001), 8001000, None);
        assert_eq!(history.samples.len(), 1);
        assert!(
            history.response(Duration::from_secs(1), &snapshot(40000), now + Duration::from_secs(4001))["memory_bytes"]
                .is_null()
        );
    }

    #[test]
    fn duration_bounds_and_label_escaping() {
        assert_eq!(duration("24h").unwrap(), Duration::from_secs(86400));
        assert_eq!(duration("3d").unwrap().as_secs(), MAX_RETENTION);
        for invalid in [
            "",
            "0h",
            "4d",
            "-1h",
            "1.5h",
            "1",
            "1w",
            "999999999999999999999d",
            "你好",
        ] {
            assert!(duration(invalid).is_err(), "{invalid}");
        }
        assert_eq!(escape("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }
}
