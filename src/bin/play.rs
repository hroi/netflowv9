use std::collections::HashMap;
use std::env;
use std::io::prelude::*;
use std::io;
use std::mem;
use std::net::{Ipv4Addr, IpAddr};
use std::process;

extern crate netflowv9;
use netflowv9::*;

extern crate flate2;
use flate2::read::ZlibDecoder;

extern crate time;

type TemplateId = u16;
type SourceId = u32;

fn print_record<W>(w: &mut W, header: &Header, rec: &Record) where W: Write {
    let protocol_name = match rec.protocol_identifier()  {
        Some(1)  => "ICMP",
        Some(6)  => "TCP",
        Some(17) => "UDP",
        Some(47) => "GRE",
        Some(50) => "ESP",
        Some(_)  => "unk",
        _ => panic!()
    };
    let source_ip = rec.source_ipv4_address()
        .map(|ip| IpAddr::V4(ip.into()))
        .or(rec.source_ipv6_address()
            .map(|ip| IpAddr::V6(ip.into()))).unwrap();
    let destination_ip = rec.destination_ipv4_address()
        .map(|ip| IpAddr::V4(ip.into()))
        .or(rec.destination_ipv6_address()
            .map(|ip| IpAddr::V6(ip.into()))).unwrap();

    let packet_time = header.seconds() as u64 * 1000;
    let sys_uptime = header.sys_uptime() as u64;
    let boot_time = packet_time - sys_uptime;
    let flow_start = boot_time + rec.flow_start_sys_uptime().unwrap_or(0) as u64;
    let flow_end = boot_time + rec.flow_end_sys_uptime().unwrap_or(0) as u64;

    let duration = flow_end - flow_start;

    let start = time::at_utc(time::Timespec{ sec: (flow_start / 1000) as i64, nsec: 0});
    //let end = time::at_utc(time::Timespec{ sec: (flow_end / 1000) as i64, nsec: 0});

    writeln!(w, "{} {:>5.1}s {:6} bytes {:5} pkts {:6} {}:{} -> {}:{}",
             start.rfc3339(),
             (duration as f64) / 1000.0,
             rec.octet_delta_count().unwrap_or(0),
             rec.packet_delta_count().unwrap_or(0),
             protocol_name,
             source_ip,
             rec.source_transport_port().unwrap_or(0),
             destination_ip,
             rec.destination_transport_port().unwrap_or(0),
    ).unwrap();
}

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stdinl = ZlibDecoder::new(stdin.lock());
    let mut out = stdout.lock();
    let mut buf = [0u8; 2048];
    let mut seq_nums: HashMap<SourceId, u32> = HashMap::new();
    let mut extractors: HashMap<TemplateId, FlowRecordExtractor> = HashMap::new();

    let interesting_ips: Vec<[u8; 4]> = env::args().skip(1)
        .map(|arg| arg.parse::<Ipv4Addr>().unwrap().octets())
        .collect();

    // stats
    let mut nflows = 0;
    let mut npdus = 0;
    let mut noctets = 0;
    let mut npackets = 0;
    let mut nskipped = 0;
    let mut nnonincr = 0;
    let mut nlates = 0;
    let mut ngaps = 0;

    let mut exit_status = 0;

    loop {
        let mut len = [0u8, 0];

        match stdinl.read_exact(&mut len[..]) {
            Ok(_) => (),
            Err(err) => {
                if err.kind() != std::io::ErrorKind::UnexpectedEof {
                    writeln!(out, "Error: {}", err).unwrap();
                    exit_status = -1;
                }
                break;
            }
        }

        let packet_length = unsafe {
            mem::transmute::<[u8;2], u16>(len).to_be() as usize
        };

        if packet_length > buf.len() {
            writeln!(out, "invalid packet length: {}", packet_length).unwrap();
            exit_status = -1;
            break;
        }

        if stdinl.read_exact(&mut buf[..packet_length]).is_err() {
            writeln!(out, "buf read err").unwrap();
            break;
        }

        if let Ok(packet) = Packet::from_bytes(&buf[..packet_length]) {
            let header = packet.header();
            let source_id = header.source_id();
            let seq_num = header.seq_num();
            let prev_seqnum = seq_nums.entry(source_id).or_insert(source_id - 1);

            if *prev_seqnum == seq_num {
                nnonincr += 1;
            }

            if seq_num < *prev_seqnum {
                nlates += 1;
            } else {
                let gap = seq_num - *prev_seqnum;
                if gap > 1 {
                    ngaps += 1;
                }
            }

            npdus += 1;
            *prev_seqnum = seq_num;

            for flowset in packet.flowsets() {
                match flowset {
                    FlowSet::DataTemplates(tpls) => {
                        for tpl in tpls {
                            extractors.insert(tpl.template_id, tpl.build_extractor());
                        }
                    }
                    FlowSet::DataRecords(ref data) => {
                        if let Some(extractor) = extractors.get(&data.template_id) {
                            for record in extractor.records(data) {
                                if let (Some(src_ip), Some(dst_ip)) =
                                    (record.source_ipv4_address(), record.destination_ipv4_address()) {
                                    for ip in &interesting_ips {
                                        if *ip == src_ip || *ip == dst_ip {
                                            // writeln!(out, "{:?}", record).unwrap();
                                            print_record(&mut out, &header, &record);
                                        }
                                    }
                                }

                                nflows += 1;
                                noctets += record.octet_delta_count().unwrap_or(0);
                                npackets += record.packet_delta_count().unwrap_or(0);
                            }
                        } else {
                            nskipped += 1;
                        }

                    },
                    _ => ()
                }
            }
        } else {
            writeln!(out, "packet decode err").unwrap();
            exit_status = -1;
            break;
        }
    }

    if interesting_ips.is_empty() {
        writeln!(out, "non-increasing sequence numbers: {}, gaps: {}, lates: {}",
                 nnonincr, ngaps, nlates).unwrap();
        writeln!(out, "pdus: {}, skipped flowsets: {}, flows: {}, octets: {}, packets: {}",
                 npdus, nskipped, nflows, noctets, npackets).unwrap();
    }
    process::exit(exit_status);

}

