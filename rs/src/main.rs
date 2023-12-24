
use std::fs::File;
use std::mem;
use aya::{Bpf, Pod};
use aya::maps::{PerCpuArray, PerCpuValues, Array};
use aya::programs::{CgroupSkb, CgroupSkbAttachType, XdpFlags};

use aya::programs::Xdp;
use aya::util::nr_cpus;

mod hash;
use hash::FastHash;


const K_FUNC: usize = 10;
const COLUMN: usize = 2048;
const HEAP_SIZE: usize = 35;
const LAYERS: usize = 32;


const SEED_UNIVMON: u64 = 0x9747b28c;

#[derive(Copy, Clone, Default, PartialEq, Eq)]
#[repr(C, packed)]
struct T5 {
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
}



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
        if test_bit(self.hash32(SEED_UNIVMON), i as u32) { 0 } else { 1 }
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
        write!(f, "src_ip: {}.{}.{}.{} src_port: {} dst_ip: {}.{}.{}.{} dst_port: {} protocol: {}", 
            (src_ip >> 24) & 0xff, (src_ip >> 16) & 0xff, (src_ip >> 8) & 0xff, src_ip & 0xff, src_port,
            (dst_ip >> 24) & 0xff, (dst_ip >> 16) & 0xff, (dst_ip >> 8) & 0xff, dst_ip & 0xff, dst_port,
            protocol)
    }
}


#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
struct TopkEntry {
    value: i32,
    tuple: T5,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct CountSketch {
    cnt: [[i32; COLUMN]; K_FUNC],
    topk: [TopkEntry; HEAP_SIZE],
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







fn estimate(sketches: &mut [CountSketch; LAYERS], g: impl Fn(i32) -> i32) -> i32 {
    
    // Your code logic here
    let mut y: [i32; LAYERS] = [0; LAYERS];
    for i in 0..LAYERS {
        for k in 0..HEAP_SIZE {
            y[i] += g(sketches[i].topk[k].value);
        }
    }

    for i in (0..LAYERS - 1).rev() {
        
        let mut yy = 0; 
        for k in 0..HEAP_SIZE {
            let hk = sketches[i].topk[k].tuple.h(i + 1);
            //println!("hash {:#x}", sketches[i].topk[k].tuple.hash32(SEED_UNIVMON));
            //println!("hk: {} on {} for t5 {:?}", hk, i + 1,  sketches[i].topk[k].tuple);

            yy += (1 - 2 * hk) * g(sketches[i].topk[k].value);
        }
        y[i] = y[i + 1] * 2 + yy;
    }
    y[0]
}



fn load_bpf() -> Result<(), anyhow::Error> {
    let mut bpf = Bpf::load_file("../build/kernel/kernel.o").unwrap();

    //println!("bpf: {:?}", bpf);
    //println!("success\n");
    let ingress: &mut Xdp = bpf.program_mut("xdp_rcv").unwrap().try_into()?;
    ingress.load()?;
    //println!("success\n");
    let linkId =  ingress.attach("veth0", XdpFlags::DRV_MODE ).unwrap();

    
    //println!("hello\n");
    let array: Array<&aya::maps::MapData, CountSketch>  = Array::try_from(bpf.map("um_sketch").unwrap()).unwrap();

    let stats_arr: Array<&aya::maps::MapData, GlobalStats>  = Array::try_from(bpf.map("stats").unwrap()).unwrap();
    let zero = 0;
    

    // set array[1] = 42 for all cpus
    let nr_cpus = nr_cpus()?;

    println!("nr_cpus: {}", nr_cpus);
    loop {

        //println!("BEGIN\n");
        let stats = stats_arr.get(&zero, 0)?;
        let tot = stats.total_pkts;
        // array to fixed sized sketch
        let mut sketches: [CountSketch; LAYERS] = [CountSketch::default(); LAYERS];
        // get all array
        for i in 0..LAYERS {
            let idx: u32 = i.try_into().unwrap();
            let sketch: CountSketch = array.get(&idx, 0)?;
            sketches[i] = sketch;
        }
        println!("total pkts: {}", tot);
        let r = estimate(&mut sketches, |x: i32| x);
        println!("estimated packet number: {}", r);
        let rr = estimate(&mut sketches, |x: i32| { if x == 0 { 0 } else { 1 } });
        println!("estimated unique k: {}", rr);
        let est_entropy = estimate(&mut sketches, |x: i32| { 
            if x == 0 || tot == 0 { 0 } else { 
                let x = x as f64;
                let n = tot as f64;
                let p = n / x;
                ((x * p.log2()) / n) as i32 
            }
        });
        //println!("estimated Shannon entropy: {}", est_entropy);
        
        for i in 0..LAYERS {
            // print sketch 
            let idx: u32 = i.try_into().unwrap();
            let sketch: CountSketch = array.get(&idx, 0)?;
            //println!("the {}th layer\n", i);
            
            // print each topk
            for j in 0..HEAP_SIZE {
                //println!("topk[{}]: {:?}", j, sketch.topk[j]);
            }
            
            //println!("sketch: {:?}", sketch.topk);
            //println!("sketch: {:?}", sketch);
        }

        std::thread::sleep(std::time::Duration::from_secs(3));
    }

    ingress.detach(linkId)?;
    //ingress.attach(cgroup, CgroupSkbAttachType::Ingress)?;
    Ok(())
}



fn main() {
    // zero initialize t5
    
    // load the BPF code
    load_bpf().unwrap();

    // print the value of the map
}
