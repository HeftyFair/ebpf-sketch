use aya::maps::{Array, PerCpuArray, PerCpuValues};
use aya::programs::{CgroupSkb, CgroupSkbAttachType, XdpFlags};
use aya::{Bpf, Pod};


use aya::programs::Xdp;



fn load_bpf() -> Result<(), anyhow::Error> {

    let mut bpf = Bpf::load_file("../build/kernel/dummy.o").unwrap();

    let ingress: &mut Xdp = bpf.program_mut("xdp_drop").unwrap().try_into()?;
    ingress.load()?;
    
    let link_id = ingress.attach("veth0", XdpFlags::DRV_MODE).unwrap();

    loop {
 
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
