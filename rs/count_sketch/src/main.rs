use aya::maps::{Array, PerCpuArray, PerCpuValues};
use aya::programs::{CgroupSkb, CgroupSkbAttachType, XdpFlags};
use aya::{Bpf, Pod};
use core::panic;
use rand_distr::{Distribution, Geometric};
use std::backtrace::Backtrace;
use std::borrow::{Borrow, BorrowMut};
use std::fs::File;
use std::mem;

use aya::programs::Xdp;
use aya::util::nr_cpus;

use hash::FastHash;
use colored::Colorize;


const K_FUNC: usize = 7;
const COLUMN: usize = 1024;
const HEAP_SIZE: usize = 15;
const LAYERS: usize = 1;

const P: f64 = 0.01;

const SEED_UNIVMON: u64 = 0x9747b28c;

const RND_CNT: usize = 4096;

#[derive(Copy, Clone, Default, PartialEq, Eq)]
#[repr(C, packed)]
struct T5 {
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(C, packed)]
struct Meta {
    rnd: [u32; RND_CNT],
    idx: u32,
    rnd_idx: u32,
    cnt: u32
}

impl Default for Meta {
    fn default() -> Self {
        Meta {
            rnd: [0; RND_CNT],
            idx: 0,
            rnd_idx: 0,
            cnt: 0
        }
    }
}

unsafe impl Pod for Meta {}

#[derive(Copy, Clone, Default, PartialEq, Eq)]
#[repr(C, packed)]
struct GlobalStats {
    total_pkts: u32,
}

unsafe impl Pod for GlobalStats {}

fn test_bit(x: u32, i: u32) -> bool {
    (x & (1 << i)) != 0
}

impl T5 {
    fn hash(&self, seed: u64) -> u64 {
        let hasher = FastHash::new(seed);
        // convert to byte array
        let buf = unsafe { mem::transmute::<T5, [u8; 13]>(*self) };
        hasher.fasthash64(&buf)
        /*
        let mut buf = [0u8; 13];
        buf[..4].copy_from_slice(&self.src_ip.to_be_bytes());
        buf[4..8].copy_from_slice(&self.dst_ip.to_be_bytes());
        buf[8..10].copy_from_slice(&self.src_port.to_be_bytes());
        buf[10..12].copy_from_slice(&self.dst_port.to_be_bytes());
        buf[12] = self.protocol;*/
    }

    fn hash32(&self, seed: u64) -> u32 {
        let hasher = FastHash::new(seed);
        /*

        let buf = unsafe { mem::transmute::<T5, [u8; 13]>(*self) };
        hasher.fasthash32(&buf)*/

        let mut buf = [0u8; 13];
        buf[..4].copy_from_slice(&self.src_ip.to_le_bytes());
        buf[4..8].copy_from_slice(&self.dst_ip.to_le_bytes());
        buf[8..10].copy_from_slice(&self.src_port.to_le_bytes());
        buf[10..12].copy_from_slice(&self.dst_port.to_le_bytes());
        buf[12] = self.protocol;
        hasher.fasthash32(&buf)
    }

    fn h(&self, i: usize) -> i32 {
        if test_bit(self.hash32(SEED_UNIVMON), i as u32) {
            0
        } else {
            1
        }
    }
}

// impl debug for T5, and print ip port
impl std::fmt::Debug for T5 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let src_ip = u32::from_be(self.src_ip);
        let dst_ip = u32::from_be(self.dst_ip);
        let src_port = u16::from_be(self.src_port);
        let dst_port = u16::from_be(self.dst_port);
        /*
        let src_ip = self.src_ip;
        let dst_ip = self.dst_ip;
        let src_port = self.src_port;
        let dst_port = self.dst_port;*/
        let protocol = self.protocol;
        write!(
            f,
            "src_ip: {}.{}.{}.{} src_port: {} dst_ip: {}.{}.{}.{} dst_port: {} protocol: {}",
            (src_ip >> 24) & 0xff,
            (src_ip >> 16) & 0xff,
            (src_ip >> 8) & 0xff,
            src_ip & 0xff,
            src_port,
            (dst_ip >> 24) & 0xff,
            (dst_ip >> 16) & 0xff,
            (dst_ip >> 8) & 0xff,
            dst_ip & 0xff,
            dst_port,
            protocol
        )
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
struct TopkEntry {
    value: i32,
    tuple: T5,
}

fn lookup(t5s: &[T5; HEAP_SIZE], t5: &T5) -> Option<i32> {
    for i in 0..t5s.len() {
        if t5s[i] == *t5 {
            return Some(i as i32);
        }
    }
    None
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct CountSketch {
    cnt: [[i32; COLUMN]; K_FUNC],
    topk: [TopkEntry; HEAP_SIZE],
}

impl CountSketch {
    fn print(&self) {
        for i in 0..self.topk.len() {
            println!("layer {}:", i);
            println!("{:?}", self.topk[i]);
        }
    }

    // lookup in top entry
    fn lookup(&self, t5: &T5) -> Option<i32> {
        for i in 0..self.topk.len() {
            if self.topk[i].tuple == *t5 {
                return Some(self.topk[i].value);
            }
        }
        None
    }
}

impl Default for CountSketch {
    fn default() -> Self {
        CountSketch {
            cnt: [[0; COLUMN]; K_FUNC],
            topk: [TopkEntry::default(); HEAP_SIZE],
        }
    }
}

unsafe impl Pod for CountSketch {}





fn load_bpf() -> Result<(), anyhow::Error> {


    let mut bpf = Bpf::load_file("../build/kernel/count_sketch.o").unwrap();

    println!("{:?}", bpf);
    
    let mut rnd: Array<&mut aya::maps::MapData, Meta> =
        Array::try_from(bpf.map_mut("meta").unwrap())?;

    let geo = Geometric::new(P).unwrap();
    let mut meta = Meta::default();
    for i in 0..RND_CNT {
        meta.rnd[i] = (geo.sample(&mut rand::thread_rng()) + 1) as u32;
    }
    println!("meta: {:?}", meta);
    rnd.set(0, &meta, 0)?;



    let ingress: &mut Xdp = bpf.program_mut("xdp_rcv").unwrap().try_into()?;
    ingress.load()?;
    
    let link_id = ingress.attach("veth0", XdpFlags::DRV_MODE).unwrap();

    //println!("hello\n");
    let array: Array<&aya::maps::MapData, CountSketch> =
        Array::try_from(bpf.map("um_sketch").unwrap()).unwrap();

    let meta_stat: Array<&aya::maps::MapData, Meta> =
        Array::try_from(bpf.map("meta").unwrap())?;   

    let zero = 0;
    loop {
        //print!("{}[2J", 27 as char);
        //println!("BEGIN\n");


        
        let tot = meta_stat.get(&zero, 0)?.cnt;
        print!("total pkts: {}\n", tot);
        // array to fixed sized sketch

        // get all array
        let idx: u32 = 0;
        let sketch: CountSketch = array.get(&idx, 0)?;
        println!("{:?}", sketch.topk);
        //println!("cnt: {:?}", sketch.cnt);
        
        
        std::thread::sleep(std::time::Duration::from_secs(2));
    }

    ingress.detach(link_id)?;
    //ingress.attach(cgroup, CgroupSkbAttachType::Ingress)?;
    Ok(())
}

fn main() {
    // zero initialize t5

    // load the BPF code
    load_bpf().unwrap();

    // print the value of the map
}
