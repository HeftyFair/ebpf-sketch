
use std::fs::File;
use aya::{Bpf, Pod};
use aya::maps::{PerCpuArray, PerCpuValues};
use aya::programs::{CgroupSkb, CgroupSkbAttachType, XdpFlags};

use aya::programs::Xdp;
use aya::util::nr_cpus;


const K_FUNC: usize = 5;
const COLUMN: usize = 5;
const HEAP_SIZE: usize = 5;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C, packed)]
struct T5 {
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
struct TopkEntry {
    value: i32,
    tuple: T5,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
struct CountSketch {
    cnt: [[i32; COLUMN]; K_FUNC],
    topk: [TopkEntry; HEAP_SIZE],
}

unsafe impl Pod for CountSketch {}



fn load_bpf() -> Result<(), anyhow::Error> {
    let mut bpf = Bpf::load_file("bpf.o")?;

    
    let ingress: &mut Xdp = bpf.program_mut("xdp_rcv").unwrap().try_into()?;
    ingress.load()?;
    ingress.attach("interface", XdpFlags::DRV_MODE)?;

    let array: PerCpuArray<aya::maps::MapRefMut, CountSketch>  = PerCpuArray::try_from(bpf.map_mut("ARRAY")?)?;

    // set array[1] = 42 for all cpus
    let nr_cpus = nr_cpus()?;
    //array.set(1, PerCpuValues::try_from(vec![42u32; nr_cpus])?, 0)?;

    loop {
        // retrieve the values at index 1 for all cpus
        let values = array.get(&1, 0)?;
        assert_eq!(values.len(), nr_cpus);
        for cpu_val in values.iter() {
            println!("cpu_val: {:?}", cpu_val);
            //cpu_val.topk.len();
        }
    }
    

    //ingress.attach(cgroup, CgroupSkbAttachType::Ingress)?;
    Ok(())
}



fn main() {
    println!("Hello, world!");
    // load the BPF code
    load_bpf().unwrap();

    // print the value of the map
    

}
