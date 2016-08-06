use std::net::{UdpSocket, IpAddr};
use std::collections::HashMap;
use std::fmt::Display;
use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use std::io::BufWriter;
use std::mem;
use std::time::{Duration, Instant};

extern crate flate2;
use flate2::write::ZlibEncoder;
use flate2::Compression;

#[derive(Debug)]
enum Error {
    Io(std::io::Error)
}

struct FlowFileWriter<D> where D: Display + Copy {
    filename: D,
    generation: usize,
    last_rotation: Instant,
    rotation_interval: Duration,
    output: BufWriter<ZlibEncoder<File>>,
}

impl<D> FlowFileWriter<D> where D: Display + Copy {

    fn new(filename: D, interval: Duration) -> Result<FlowFileWriter<D>, Error> {
        Ok(FlowFileWriter{
            filename: filename,
            generation: 0,
            last_rotation: Instant::now(),
            rotation_interval: interval,
            output: BufWriter::new(ZlibEncoder::new(try!(OpenOptions::new()
                       .create(true) .append(true)
                       .open(format!("./{}.{:4}.z", filename, 0))
                       .map_err(|err| { Error::Io(err) })), Compression::Best))})
    }

    fn rotate(&mut self) -> Result<(), Error> {
        self.generation += 1;
        self.output = BufWriter::new(ZlibEncoder::new(
            try!(OpenOptions::new()
                 .create(true) .append(true)
                 .open(format!("./{}.{:4}.z", self.filename, self.generation))
                 .map_err(|err| { Error::Io(err) })), Compression::Best));
        self.last_rotation = Instant::now();
        Ok(())
    }

    fn maybe_rotate(&mut self) -> Result<(), Error>{
        if self.last_rotation.elapsed() > self.rotation_interval {
            self.rotate()
        } else {
            Ok(())
        }
    }
}

impl<D> Write for FlowFileWriter<D> where D: Display + Copy {

    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let length: [u8; 2] = unsafe { mem::transmute((buf.len() as u16).to_be()) };
        try!(self.output.write(&length[..]));
        self.output.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()>{
        self.output.flush()
    }
}

fn main() {

    let mut file_map: HashMap<IpAddr, FlowFileWriter<IpAddr>> = HashMap::new();
    let port = 4013;
    let socket = UdpSocket::bind(("::".parse::<IpAddr>().unwrap(), port)).unwrap();
    let mut recv_buf = [0u8; 2048];

    while let Ok((amt, src)) = socket.recv_from(&mut recv_buf[..]) {
        let mut output = file_map.entry(src.ip()).or_insert_with(|| {
            println!("New exporter: {}", src.ip());
            FlowFileWriter::new(src.ip(), Duration::from_secs(300)).unwrap()
        });

        output.maybe_rotate().unwrap();
        output.write(&recv_buf[..amt]).unwrap();
    }
}

