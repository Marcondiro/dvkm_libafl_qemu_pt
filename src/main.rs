use libafl_qemu::config::{Accelerator, Drive, Monitor, QemuConfig, RamSize};

fn main() {
    let qemu_config = QemuConfig::builder()
        .kernel("./linux/arch/x86_64/boot/bzImage")
        .initrd("initrd.img")
        .append_kernel_cmd("console=ttyS0")
        .accelerator(Accelerator::Kvm)
        .no_graphic(true)
        .monitor(Monitor::Null)
        .cpu("host")
        .ram_size(RamSize::GB(1))
        .drives([Drive::builder().file("dvkm.qcow2").build()]);
}
