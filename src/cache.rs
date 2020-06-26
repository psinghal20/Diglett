use crate::{QueryType, DNSRecord, DNSPacket};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use std::sync::{Arc, Mutex};

#[derive(Debug,Clone)]
pub struct CacheEntry {
    pub records: Vec<DNSRecord>,
    pub timestamp: SystemTime,
}

#[derive(Debug,Clone)]
pub struct DNSCache {
    pub map: Arc<Mutex<HashMap<(String, QueryType), CacheEntry>>>
}

impl DNSCache {
    // pub fn get_nearest_a_record(&self, qname: &str, q_type: QueryType) -> Option<Ipv4Addr> {
    //     let qname_split = qname.split(".").collect::<Vec<&str>>();
    //     for (i, _) in qname_split.iter().enumerate() {
    //         let search_label = qname_split[i..].join(".");
    //         if let Some(entry) = self.map.lock().unwrap().get(&(search_label, q_type)) {
    //             let timestamp_now = SystemTime::now();
    //             let records = entry.records.iter().filter_map(|record| {
    //                 if Duration::new(record.get_ttl() as u64, 0) > timestamp_now.duration_since(entry.timestamp).unwrap() {
    //                     Some(record.clone())
    //                 } else {
    //                     None
    //                 }
    //             }).collect::<Vec<DNSRecord>>();
    //             if records.len() > 0 {
    //                 let packet: DNSPacket = records.into();
    //                 return packet.get_random_a();
    //             }
    //         }
    //     }
    //     None
    // }

    pub fn get_records(&self, qname: &str, q_type: QueryType) -> Option<DNSPacket> {
        if let Some(entry) = self.map.lock().unwrap().get(&(qname.to_owned(), q_type)) {
            let timestamp_now = SystemTime::now();
            let records = entry.records.iter().filter_map(|record| {
                if Duration::new(record.get_ttl() as u64, 0) > timestamp_now.duration_since(entry.timestamp).unwrap() {
                    Some(record.clone())
                } else {
                    None
                }
            }).collect::<Vec<DNSRecord>>();
            if records.len() == 0 {
                return None;
            }
            return Some(records.into());
        }
        None
    }

    pub fn set_records(&mut self, qname: &str, q_type: QueryType, mut packet: DNSPacket) {
        let timestamp = SystemTime::now();
        let mut records = packet.answers.clone();
        records.append(&mut packet.authority);
        records.append(&mut packet.addtional);
        let entry = CacheEntry {
            records,
            timestamp
        };
        self.map.lock().unwrap().insert((qname.to_owned(), q_type), entry);
    }
}