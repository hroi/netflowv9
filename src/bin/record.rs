use std::collections::HashMap;
use std::fmt::Display;
use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use std::io::BufWriter;
use std::mem;
use std::net::{UdpSocket, IpAddr};
use std::time::{Duration, Instant};

extern crate flate2;
use flate2::write::ZlibEncoder;
use flate2::Compression;

// This server indiscriminately saves any packet to a compressed, rotated,
// per-exporter file. No checking or parsing of PDUs is performed.

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

#[derive(Debug)]
enum Error {
    Io(std::io::Error)
}

struct FlowFileWriter<D, W> where D: Display + Copy, W: Write {
    exporter_name: D,
    generation: usize,
    compression: Compression,
    last_rotation: Instant,
    rotation_interval: Duration,
    output: W,
}

type Output = BufWriter<ZlibEncoder<File>>;

impl<D> FlowFileWriter<D, Output> where D: Display + Copy {

    fn compressed(exporter_name: D, compression: Compression, interval: Duration)
           -> Result<FlowFileWriter<D, Output>, Error> {
        Ok(
            FlowFileWriter {
                exporter_name: exporter_name,
                generation: 0,
                compression: compression,
                last_rotation: Instant::now(),
                rotation_interval: interval,
                output: BufWriter::new(
                    ZlibEncoder::new(
                        try!(OpenOptions::new()
                             .create(true)
                             .append(true)
                             .open(format!("./{}.{:04}.z", exporter_name, 0))
                             .map_err(|err| { Error::Io(err) })), compression))
            }
        )
    }

    fn rotate(&mut self) -> Result<(), Error> {
        self.generation += 1;
        self.output = BufWriter::new(ZlibEncoder::new(
            try!(OpenOptions::new()
                 .create(true)
                 .append(true)
                 .open(format!("./{}.{:04}.z", self.exporter_name, self.generation))
                 .map_err(|err| { Error::Io(err) })), self.compression));
        self.last_rotation = Instant::now();
        Ok(())
    }

    fn maybe_rotate(&mut self) -> Result<(), Error> {
        if self.last_rotation.elapsed() > self.rotation_interval {
            self.rotate()
        } else {
            Ok(())
        }
    }
}

impl<D,W> Write for FlowFileWriter<D, W> where D: Display + Copy, W: Write {

    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let length: [u8; 2] = unsafe { mem::transmute((buf.len() as u16).to_be()) };
        try!(self.output.write(&length[..]));
        self.output.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()>{
        self.output.flush()
    }
}
