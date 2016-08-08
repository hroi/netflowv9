use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::io;
use std::mem;
use std::net::{IpAddr, SocketAddr};

extern crate flate2;
use flate2::read::ZlibDecoder;

extern crate netflowv9;
use netflowv9::*;

fn main() {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    for arg in env::args().skip(1) {
        match File::open(&arg) {
            Ok(ref mut file) => dump_file(&mut out, file),
            Err(err) => writeln!(out, "Could not open {}: {}", arg, err).unwrap()
        }
    }
}

fn dump_file<F,W>(mut out: &mut W, mut file: &mut F) where F: Read + Seek, W: Write {
    let mut magic = [0u8; 8];
    let mut template_offset = [0u8; 8];

    file.read(&mut magic[..]).unwrap();
    file.read(&mut template_offset[..]).unwrap();

    if &magic[..] != b"NETFLO00" {
        writeln!(out, "Invalid file magic: {:?}.", magic).unwrap();
        return;
    }

    let template_offset: u64 = unsafe { mem::transmute::<[u8; 8], u64>(template_offset).to_be()};
    writeln!(out, "template_offset: {}", template_offset).unwrap();

    if template_offset == 0 {
        writeln!(out, "Incomplete file, skipping").unwrap();
        return;
    }

    let sought = file.seek(io::SeekFrom::Current(template_offset as i64)).unwrap();
    assert_eq!(sought, template_offset + 16);

    let mut extractors: HashMap<u16, FlowRecordExtractor> = HashMap::new();
    loop {
        let mut tid = [0u8; 2];
        let mut len = [0u8; 2];
        if let Ok(_) = file.read_exact(&mut tid[..]) {
            file.read_exact(&mut len[..]).unwrap();
            let template_id = unsafe { mem::transmute::<[u8;2], u16>(tid).to_be()};
            let template_length = unsafe { mem::transmute::<[u8;2], u16>(len).to_be() as usize};
            writeln!(out, "template_id: {}, template_length: {}", template_id, template_length).unwrap();
            let mut template_raw = Vec::with_capacity(template_length);
            file.take(template_length as u64).read_to_end(&mut template_raw).unwrap();
            //println!("raw template: {:?}", &template_raw[..]);
            let template: DataTemplate = DataTemplate {
                template_id: template_id,
                field_count: (template_length / 4) as u16,
                fields: TemplateFieldIter { raw: &template_raw[..]}
            };
            extractors.insert(template_id, template.build_extractor());
            // for (_len, field) in template.fields.clone() {
            //     println!("\tfield: {:?} ", field);
            // }
        } else {
            break;
        }
    }

    file.seek(io::SeekFrom::Start(16)).unwrap();
    let mut records = ZlibDecoder::new(file.take(template_offset));
    loop {
        let mut tid = [0u8; 2];
        let mut len = [0u8; 2];
        let mut buf = [0u8; 2048];
        if let Ok(_) = records.read_exact(&mut tid[..]) {
            records.read_exact(&mut len[..]).unwrap();
            let template_id = unsafe { mem::transmute::<[u8;2], u16>(tid).to_be()};
            let record_length = unsafe { mem::transmute::<[u8;2], u16>(len).to_be() as usize};
            records.read_exact(&mut buf[..record_length]).unwrap();
            // println!("record template id: {}", template_id);
            // println!("record length: {}", record_length);
            let data_records = DataRecords{ template_id: template_id, raw: &buf[..record_length]};
            if let Some(extractor) = extractors.get(&template_id) {
                for record in extractor.records(&data_records) {
                    // writeln!(out, "record: {:?}", record).unwrap();
                    print_record(&mut out, &record);
                }
            }
        } else {
            break;
        }
    }
}

fn print_record<W>(w: &mut W, rec: &Record) where W: Write {
    let strbuf: String;
    let protocol_name = match rec.protocol_identifier()  {
        Some(1)  => "ICMP",
        Some(4)  => "IPIP",
        Some(6)  => "TCP",
        Some(17) => "UDP",
        Some(41) => "IP6IP",
        Some(47) => "GRE",
        Some(50) => "ESP",
        Some(58) => "ICMP",
        Some(n)  => {
            strbuf = format!("{}", n);
            &strbuf
        },
        _ => return
    };
    let source_ip = rec.source_ipv4_address()
        .map(|ip| IpAddr::V4(ip.into()))
        .or(rec.source_ipv6_address()
            .map(|ip| IpAddr::V6(ip.into()))).unwrap();
    let destination_ip = rec.destination_ipv4_address()
        .map(|ip| IpAddr::V4(ip.into()))
        .or(rec.destination_ipv6_address()
            .map(|ip| IpAddr::V6(ip.into()))).unwrap();

    // let packet_time = header.seconds() as u64 * 1000;
    // let sys_uptime = header.sys_uptime() as u64;
    // let boot_time = packet_time - sys_uptime;
    let flow_start = rec.flow_start_sys_uptime().unwrap_or(0) as u64;
    let flow_end = rec.flow_end_sys_uptime().unwrap_or(0) as u64;

    let duration = flow_end - flow_start;

    // let start = time::at_utc(time::Timespec{ sec: (flow_start / 1000) as i64, nsec: 0});
    //let end = time::at_utc(time::Timespec{ sec: (flow_end / 1000) as i64, nsec: 0});

    writeln!(w, "{:>5.1}s {:6} bytes {:5} pkts {:6} {} -> {}",
             // start.rfc3339(),
             (duration as f64) / 1000.0,
             rec.octet_delta_count().unwrap_or(0),
             rec.packet_delta_count().unwrap_or(0),
             protocol_name,
             SocketAddr::new(source_ip,rec.source_transport_port().unwrap_or(0)) ,
             SocketAddr::new(destination_ip,rec.destination_transport_port().unwrap_or(0)) ,
    ).unwrap();
}
