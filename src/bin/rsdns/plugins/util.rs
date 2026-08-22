//! Shared helpers for the rsdns plugins.
//!
//! Pure functions moved out of `server.rs` so that the chain plugins
//! (hosts / cache / rules / upstream) can reuse response construction,
//! caching, and upstream queries without pulling in the server type.

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, HTTPS, MX, TXT};
use hickory_proto::rr::RData;
use hickory_proto::rr::{Name, Record, RecordType};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::plugins::cache::{CacheEntry, CacheKey, CacheRecord, DnsCache};

/// Constructs a DNS query `Message` for `name`/`qtype` (used for upstream
/// resolution of cname targets and background refresh).
pub(crate) fn make_query_msg(name: &str, qtype: RecordType) -> io::Result<Message> {
    let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
    let mut q = Query::new();
    q.set_name(Name::from_utf8(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?);
    q.set_query_type(qtype);
    q.set_query_class(hickory_proto::rr::DNSClass::IN);
    msg.queries.push(q);
    msg.metadata.recursion_desired = true;
    Ok(msg)
}

/// Basic response skeleton mirroring the query's id and question.
pub(crate) fn make_response_base(msg: &Message) -> io::Result<Message> {
    let mut response = Message::new(msg.id, MessageType::Response, OpCode::Query);
    response.metadata.recursion_available = true;
    if let Some(q) = msg.queries.first() {
        response.queries.push(q.clone());
    }
    Ok(response)
}

/// Rewrites every answer TTL to `ttl`.
pub(crate) fn rewrite_ttl_in_response(msg: &mut Message, ttl: u32) {
    for answer in &mut msg.answers {
        answer.ttl = ttl;
    }
}

/// Extracts cacheable records (A / AAAA / CNAME / MX / TXT / HTTPS).
pub(crate) fn extract_cache_records(msg: &Message) -> Option<Vec<CacheRecord>> {
    let mut records = Vec::new();
    for answer in &msg.answers {
        match &answer.data {
            RData::A(ip) => records.push(CacheRecord::A(ip.0)),
            RData::AAAA(ip) => records.push(CacheRecord::Aaaa(ip.0)),
            RData::CNAME(cname) => records.push(CacheRecord::Cname(cname.0.to_ascii())),
            RData::MX(mx) => records.push(CacheRecord::Mx {
                preference: mx.preference,
                exchange: mx.exchange.to_ascii(),
            }),
            RData::TXT(txt) => {
                let strings: Vec<String> = txt
                    .txt_data
                    .iter()
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .collect();
                records.push(CacheRecord::Txt(strings))
            }
            RData::HTTPS(https) => records.push(CacheRecord::Https(https.0.clone())),
            _ => {}
        }
    }
    if records.is_empty() {
        None
    } else {
        Some(records)
    }
}

/// Minimum TTL across answers; default 300 for empty responses.
pub(crate) fn extract_min_ttl(msg: &Message) -> u32 {
    msg.answers.iter().map(|r| r.ttl).min().unwrap_or(300)
}

/// Writes an upstream response into the cache (positive + NXDOMAIN negative).
pub(crate) async fn cache_upstream_response(
    cache: &DnsCache,
    cache_key: &CacheKey,
    response: &Message,
    rewrite_ttl: Option<u32>,
) {
    if let Some(records) = extract_cache_records(response) {
        let ttl = extract_min_ttl(response);
        let final_ttl = rewrite_ttl.unwrap_or(ttl);
        cache.put(cache_key.clone(), records, final_ttl).await;
        return;
    }

    let rcode = response.metadata.response_code;
    let negative_record = match rcode {
        ResponseCode::NXDomain => Some(CacheRecord::NxDomain),
        ResponseCode::NoError => Some(CacheRecord::NoData),
        _ => None,
    };

    if let Some(record) = negative_record {
        let ttl = extract_min_ttl(response);
        let final_ttl = rewrite_ttl.unwrap_or(ttl);
        cache.put(cache_key.clone(), vec![record], final_ttl).await;
    }
}

/// Builds a response from a cache entry, decrementing TTLs.
pub(crate) fn build_response_from_cache(msg: &Message, entry: &CacheEntry, keep_ttl: bool) -> io::Result<Message> {
    let mut response = make_response_base(msg)?;
    let query = msg
        .queries
        .first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no question"))?;
    let name = query.name().clone();
    let reply_ttl = entry.remaining_ttl(keep_ttl);
    let records = &entry.records;
    for record in records.iter() {
        let r = match record {
            CacheRecord::A(ip) => Record::from_rdata(name.clone(), reply_ttl, RData::A(A(*ip))),
            CacheRecord::Aaaa(ip) => Record::from_rdata(name.clone(), reply_ttl, RData::AAAA(AAAA(*ip))),
            CacheRecord::Cname(target) => {
                let cname_name = Name::from_utf8(target).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                Record::from_rdata(name.clone(), reply_ttl, RData::CNAME(CNAME(cname_name)))
            }
            CacheRecord::Mx { preference, exchange } => {
                let exchange_name =
                    Name::from_utf8(exchange).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                Record::from_rdata(name.clone(), reply_ttl, RData::MX(MX::new(*preference, exchange_name)))
            }
            CacheRecord::Txt(txt_data) => {
                Record::from_rdata(name.clone(), reply_ttl, RData::TXT(TXT::new(txt_data.clone())))
            }
            CacheRecord::Https(svcb) => Record::from_rdata(name.clone(), reply_ttl, RData::HTTPS(HTTPS(svcb.clone()))),
            CacheRecord::NxDomain | CacheRecord::NoData => continue,
        };
        response.answers.push(r);
    }

    if let Some(CacheRecord::NxDomain) = records.first() {
        response.metadata.response_code = ResponseCode::NXDomain;
    }
    if let Some(CacheRecord::NoData) = records.first() {
        response.metadata.response_code = ResponseCode::NoError;
    }

    Ok(response)
}

/// Builds a hosts-style response from a static IP list.
pub(crate) fn build_hosts_response(
    msg: &Message,
    name: &str,
    qtype: RecordType,
    ips: &[IpAddr],
) -> io::Result<Message> {
    let mut response = make_response_base(msg)?;
    let rr_name = Name::from_utf8(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    for ip in ips {
        let record = match (ip, qtype) {
            (IpAddr::V4(v4), RecordType::A) | (IpAddr::V4(v4), RecordType::ANY) => {
                Record::from_rdata(rr_name.clone(), 300, RData::A(A(*v4)))
            }
            (IpAddr::V6(v6), RecordType::AAAA) | (IpAddr::V6(v6), RecordType::ANY) => {
                Record::from_rdata(rr_name.clone(), 300, RData::AAAA(AAAA(*v6)))
            }
            _ => continue,
        };
        response.answers.push(record);
    }

    Ok(response)
}

/// NXDOMAIN response.
pub(crate) fn build_nxdomain(msg: &Message) -> io::Result<Message> {
    let mut response = make_response_base(msg)?;
    response.metadata.response_code = ResponseCode::NXDomain;
    Ok(response)
}

/// Poison response (A=0.0.0.0, AAAA=::).
pub(crate) fn build_poison(msg: &Message, name: &str, qtype: RecordType) -> io::Result<Message> {
    let mut response = make_response_base(msg)?;
    let rr_name = Name::from_utf8(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    match qtype {
        RecordType::A | RecordType::ANY => {
            let record = Record::from_rdata(rr_name.clone(), 300, RData::A(A(Ipv4Addr::new(0, 0, 0, 0))));
            response.answers.push(record);
            response.metadata.response_code = ResponseCode::NoError;
        }
        _ => {
            response.metadata.response_code = ResponseCode::NoError;
        }
    }
    match qtype {
        RecordType::AAAA | RecordType::ANY => {
            let record = Record::from_rdata(rr_name, 300, RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED)));
            response.answers.push(record);
        }
        _ => {}
    }

    Ok(response)
}

/// SERVFAIL response.
pub(crate) fn build_servfail(msg: &Message) -> Message {
    let mut response = Message::new(0, MessageType::Response, OpCode::Query);
    response.metadata = msg.metadata;
    response.metadata.message_type = MessageType::Response;
    response.metadata.response_code = ResponseCode::ServFail;
    response.queries = msg.queries.clone();
    response
}

/// NoData response (empty answer, NOERROR).
pub(crate) fn build_nodata(msg: &Message) -> io::Result<Message> {
    make_response_base(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::cache::{CacheResult, DnsCache};

    #[tokio::test]
    async fn test_cache_upstream_response_nodata_a() {
        let cache = DnsCache::new_metric(10, 60, 3600, false, false);
        let key = CacheKey::new("nodata.example.com", RecordType::A);
        // 上游返回 NOERROR 空应答（NoData）
        let mut resp = make_query_msg("nodata.example.com", RecordType::A).unwrap();
        resp.metadata.response_code = ResponseCode::NoError;

        cache_upstream_response(&cache, &key, &resp, None).await;

        if let CacheResult::Fresh(entry) = cache.get_cached(&key).await {
            assert_eq!(entry.records.len(), 1);
            assert!(matches!(entry.records[0], CacheRecord::NoData));
            // 从缓存重建应答：NOERROR、无 answer
            let rebuilt = build_response_from_cache(&resp, &entry, false).unwrap();
            assert!(rebuilt.answers.is_empty());
            assert_eq!(rebuilt.metadata.response_code, ResponseCode::NoError);
        } else {
            panic!("expected Fresh NoData entry");
        }
    }

    #[tokio::test]
    async fn test_cache_upstream_response_nodata_for_mx_and_https() {
        for (name, qtype) in [
            ("mx.example.com", RecordType::MX),
            ("https.example.com", RecordType::HTTPS),
        ] {
            let cache = DnsCache::new_metric(10, 60, 3600, false, false);
            let key = CacheKey::new(name, qtype);
            // 上游返回 NOERROR 空应答（NoData）
            let mut resp = make_query_msg(name, qtype).unwrap();
            resp.metadata.response_code = ResponseCode::NoError;

            cache_upstream_response(&cache, &key, &resp, None).await;

            // 所有类型（MX/HTTPS 等）的空应答都做 NoData 负缓存
            if let CacheResult::Fresh(entry) = cache.get_cached(&key).await {
                assert_eq!(entry.records.len(), 1);
                assert!(matches!(entry.records[0], CacheRecord::NoData));
                let rebuilt = build_response_from_cache(&resp, &entry, false).unwrap();
                assert!(rebuilt.answers.is_empty());
                assert_eq!(rebuilt.metadata.response_code, ResponseCode::NoError);
            } else {
                panic!("expected Fresh NoData entry for {qtype}");
            }
        }
    }
}
