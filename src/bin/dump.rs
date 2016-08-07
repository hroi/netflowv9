use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::io;
use std::mem;

extern crate flate2;
use flate2::read::ZlibDecoder;

extern crate netflowv9;
use netflowv9::*;

fn main() {
    for arg in env::args().skip(1) {
        match File::open(&arg) {
            Ok(ref mut file) => dump_file(file),
            Err(err) => println!("Could not open {}: {}", arg, err)
        }
    }
}

fn dump_file<F>(mut file: &mut F) where F: Read + Seek {
    let mut magic = [0u8; 8];
    let mut template_offset = [0u8; 8];

    file.read(&mut magic[..]).unwrap();
    file.read(&mut template_offset[..]).unwrap();

    if &magic[..] != b"NETFLO00" {
        println!("Invalid file magic: {:?}.", magic);
        return;
    }

    let template_offset: u64 = unsafe { mem::transmute::<[u8; 8], u64>(template_offset).to_be()};
    println!("template_offset: {}", template_offset);

    if template_offset == 0 {
        println!("Incomplete file, skipping");
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
            println!("template_id: {}, template_length: {}", template_id, template_length);
            let mut template_raw = Vec::with_capacity(template_length);
            file.take(template_length as u64).read_to_end(&mut template_raw).unwrap();
            //println!("raw template: {:?}", &template_raw[..]);
            let template: DataTemplate = DataTemplate {
                template_id: template_id,
                field_count: (template_length / 4) as u16,
                fields: TemplateFieldIter { raw: &template_raw[..]}
            };
            extractors.insert(template_id, template.build_extractor());
            for (_len, field) in template.fields.clone() {
                println!("\tfield: {:?} ", field);
            }
        } else {
            break;
        }
    }

    file.seek(io::SeekFrom::Start(16)).unwrap();
    let mut records = ZlibDecoder::new(file.take(template_offset));
    let stdout = io::stdout();
    let mut out = stdout.lock();
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
                    writeln!(out, "record: {:?}", record).unwrap();
                }
            }
        } else {
            break;
        }
    }
}
