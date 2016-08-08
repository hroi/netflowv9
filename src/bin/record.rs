use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use std::io::{BufWriter, SeekFrom};
use std::mem;
use std::net::{UdpSocket, IpAddr};
use std::time::{Duration, Instant};

extern crate flate2;
use flate2::write::ZlibEncoder;
use flate2::Compression;

extern crate netflowv9;
use netflowv9::*;

/* TODO:

 - Save exporter boot time etc. so flow timestamps can be calculated.
 - filter out options records, save to end of file

*/

fn main() {
    let compression = Compression::Best;
    let rotate_interval = Duration::from_secs(300);
    let mut file_map: HashMap<IpAddr, FlowFileWriter<IpAddr, _>> = HashMap::new();
    let socket = UdpSocket::bind("[::]:4013").unwrap();
    let mut recv_buf = [0u8; 2048];

    while let Ok((amt, src)) = socket.recv_from(&mut recv_buf[..]) {
        let mut output = file_map.entry(src.ip()).or_insert_with(|| {
            println!("New exporter: {}", src.ip());
            FlowFileWriter::compressed(src.ip(), compression, rotate_interval).unwrap()
        });

        output.maybe_rotate().unwrap();
        output.write(&recv_buf[..amt]).unwrap();
    }
}

type RawDataTemplateIter = Vec<u8>;

struct FlowFileWriter<D, W> where D: Display + Copy, W: Write {
    exporter_name: D,
    generation: usize,
    compression: Compression,
    last_rotation: Instant,
    rotation_interval: Duration,
    template_ids_seen: HashSet<u16>,
    templates: HashMap<u16, Vec<u8>>,
    output: W,
}

type Output = BufWriter<ZlibEncoder<File>>;

impl<D> FlowFileWriter<D, Output> where D: Display + Copy {

    fn compressed(exporter_name: D, compression: Compression, interval: Duration)
           -> Result<FlowFileWriter<D, Output>, std::io::Error> {
        let file = try!(Self::init_file(exporter_name, 0));
        Ok(
            FlowFileWriter {
                exporter_name: exporter_name,
                generation: 0,
                compression: compression,
                last_rotation: Instant::now(),
                rotation_interval: interval,
                template_ids_seen: HashSet::new(),
                templates: HashMap::new(),
                output: BufWriter::new(ZlibEncoder::new(file, compression))
            }
        )
    }

    fn init_file(exporter_name: D, generation: usize) -> Result<File, std::io::Error> {
        let mut file = try!(OpenOptions::new().create(true).write(true).read(true)
                            .open(format!("./data/{}.{:04}", exporter_name, generation)));
        // magic
        try!(file.write(b"NETFLO00"));
        // offset to metadata packets (updated in finalize_file)
        try!(file.write(&[0; 8])); 
        Ok(file)
    }

    /// Dump templates needed to decode flow records at end of file.
    /// Update template offset in header (bytes 8 - 15).
    fn finalize_file(&mut self, mut f: File) -> Result<(), std::io::Error> {
        let file_len = f.metadata().unwrap().len();
        let len: [u8; 8] = unsafe { mem::transmute((file_len - 16).to_be())};
        assert!(file_len > 0);

        f.seek(SeekFrom::Start(8)).unwrap();
        f.write(&len[..]).unwrap();
        f.seek(SeekFrom::Start(file_len)).unwrap();

        for template_id in &self.template_ids_seen {
            if let Some(raw_template) = self.templates.get(&template_id) {
                println!("saving template {}", template_id);
                unsafe {
                    let tid: [u8;2] = mem::transmute(template_id.to_be());
                    f.write(&tid[..]).unwrap();
                    let len: [u8;2] = mem::transmute((raw_template.len() as u16).to_be());
                    f.write(&len[..]).unwrap();
                }
                f.write(raw_template).unwrap();
            } else {
                println!("missing template {}", template_id);
            }
        }

        self.template_ids_seen.clear();

        Ok(())
    }

    fn rotate(&mut self) -> Result<(), std::io::Error> {
        println!("Rotating {}.{}", self.exporter_name, self.generation);
        self.generation += 1;
        self.last_rotation = Instant::now();

        let new_writer =  BufWriter::new(ZlibEncoder::new(
            try!(Self::init_file(self.exporter_name, self.generation)), self.compression));
        let writer = mem::replace(&mut self.output, new_writer);
        let zlibencoder = writer.into_inner().ok().unwrap();

        let old_file = zlibencoder.finish().unwrap();
        self.finalize_file(old_file)
    }

    fn maybe_rotate(&mut self) -> Result<(), std::io::Error> {
        if self.last_rotation.elapsed() > self.rotation_interval {
            self.rotate()
        } else {
            Ok(())
        }
    }
}

impl<D,W> Write for FlowFileWriter<D, W> where D: Display + Copy, W: Write {

    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let packet = match Packet::from_bytes(buf) {
            Ok(packet) => packet,
            Err(_) => return Ok(buf.len()),
        };

        for flowset in packet.flowsets() {
            match flowset {
                FlowSet::OptionsTemplates(templates) => {
                    for template in templates.clone() {
                        if self.templates.get(&template.template_id).is_none() {
                            self.templates.insert(template.template_id,
                                                  template.fields.raw.to_vec());
                        }
                    }
                }
                FlowSet::DataTemplates(templates) => {
                    for template in templates.clone() {
                        if self.templates.get(&template.template_id).is_none() {
                            self.templates.insert(template.template_id,
                                                  template.fields.raw.to_vec());
                        }
                    }
                }
                FlowSet::DataRecords(records) => {
                    self.template_ids_seen.insert(records.template_id);
                    let template_id: [u8; 2] = unsafe {
                        mem::transmute((records.template_id).to_be())
                    };
                    try!(self.output.write(&template_id[..]));
                    let length: [u8; 2] = unsafe {
                        mem::transmute((records.raw.len() as u16).to_be())
                    };
                    try!(self.output.write(&length[..]));
                    try!(self.output.write(records.raw));
                }
                _ => ()
            }
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()>{
        self.output.flush()
    }
}
