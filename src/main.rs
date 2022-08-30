use aya::maps::perf::PerfEventArrayBuffer;
use aya::maps::{MapRefMut, PerfEventArray};
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};

use bytes::BytesMut;
use clap::{crate_authors, crate_description, crate_version, App, Arg};
use lazy_static::lazy_static;
use mio::unix::SourceFd;
use mio::{Events, Interest, Token};
use slog::{crit, debug, info, o, warn, Drain, Logger};
use slog_term::TermDecorator;
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::error::Error;
use std::fmt::{Debug, Display, Formatter};
use std::os::unix::io::AsRawFd;
use std::time::Duration;

struct ProgramNotFoundError(String);

impl Debug for ProgramNotFoundError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Display for ProgramNotFoundError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for ProgramNotFoundError {}

lazy_static! {
    static ref LOGGER: Logger = Logger::root(
        slog_async::Async::new(
            slog_term::FullFormat::new(TermDecorator::new().build())
                .build()
                .fuse(),
        )
        .build()
        .fuse(),
        o!()
    );
}

fn poll_buffers(buf: Vec<PerfEventArrayBuffer<MapRefMut>>) {
    let mut poll = mio::Poll::new().unwrap();

    let mut out_bufs = [BytesMut::with_capacity(1024)];

    let mut tokens: HashMap<Token, PerfEventArrayBuffer<MapRefMut>> = buf
        .into_iter()
        .map(
            |p| -> Result<(Token, PerfEventArrayBuffer<MapRefMut>), Box<dyn Error>> {
                let token = Token(p.as_raw_fd() as usize);
                poll.registry().register(
                    &mut SourceFd(&p.as_raw_fd()),
                    token,
                    Interest::READABLE,
                )?;
                Ok((token, p))
            },
        )
        .collect::<Result<HashMap<Token, PerfEventArrayBuffer<MapRefMut>>, Box<dyn Error>>>()
        .unwrap();

    let mut events = Events::with_capacity(1024);
    loop {
        match poll.poll(&mut events, Some(Duration::from_millis(100))) {
            Ok(_) => {
                events
                    .iter()
                    .filter(|event| event.is_readable())
                    .map(|e| e.token())
                    .into_iter()
                    .for_each(|t| {
                        let buf = tokens.get_mut(&t).unwrap();
                        buf.read_events(&mut out_bufs).unwrap();
                        let pkt = out_bufs.get(0).unwrap();
                        if let Ok(msg) = String::from_utf8(pkt.to_vec()) {
                            let msg = msg.trim_matches('\0');
                            info!(LOGGER, "Filter Message: {:?}", msg);
                        }
                    });
            }
            Err(e) => {
                crit!(LOGGER, "critical error: {:?}", e);
                panic!()
            }
        }
    }
}

fn load_filter(interface_name: &str) -> Result<(), Box<dyn Error>> {
    let mut bpf = Bpf::load(include_bytes_aligned!("../bpf/filter_program_x86_64"))?;

    // Example: attaching a TC classifier
    if let Err(e) = tc::qdisc_add_clsact(interface_name) {
        warn!(LOGGER, "Interface already configured: {:?}", e);
        warn!(LOGGER, "You can probably ignore this.");
    }

    let program: &mut SchedClassifier = bpf.program_mut("your_program_name").unwrap().try_into()?;

    if let Err(e) = program.load() {
        crit!(LOGGER, "Program Loading Error: {:?}", e);
        Err(e)?;
    };
    debug!(LOGGER, "eBPF Filter loaded.");
    let _link_id = program.attach(interface_name, TcAttachType::Egress)?;
    debug!(LOGGER, "eBPF Filter attached.");

    let map = bpf.map_mut("if_you_have_a_perf_map_it_goes_here")?;
    let mut perf_array = PerfEventArray::try_from(map)?;

    let mut perf_buffers = Vec::new();
    for cpuid in online_cpus()? {
        perf_buffers.push(perf_array.open(cpuid, None)?);
    }

    poll_buffers(perf_buffers);

    Ok(())
}

fn main() {
    let matches = App::new("eBPF Playground")
        .version(crate_version!())
        .author(crate_authors!("\n"))
        .about(crate_description!())
        .arg(
            // Example argument
            Arg::with_name("interface")
                .short("i")
                .long("interface")
                .help("the interface to listen on")
                .takes_value(true)
                .required(true)
                .value_name("INTERFACE NAME"),
        )
        .get_matches();

    debug!(LOGGER, "Starting eBPF Playground.");
    let interface = matches.value_of("interface").unwrap();
    load_filter(interface).unwrap();
}
