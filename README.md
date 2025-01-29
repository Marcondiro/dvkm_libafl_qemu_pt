# dvkm_libafl_qemu_pt

[Damn_Vulnerable_Kernel_Module](https://github.com/hardik05/Damn_Vulnerable_Kernel_Module/) fuzzer based on [libafl](https://github.com/AFLplusplus/LibAFL) with Intel PT tracing.

## Requirements

- Rust
- [cargo-make](https://github.com/sagiegurari/cargo-make)
- linux build requirements
- linux 6.8.y (or update the submodule ecc accordingly)

## Build & Run

1. Clone the project including the submodules

```bash
git clone --recurse-submodules
```

2. Boot the target VM

```bash
cargo make boot_target
```

3. Install DVKM in the vm and disable ASLR

```bash
# inside the VM
mkdir /sda && \
mount /dev/sda /sda && \
insmod /sda/dvkm.ko && \
echo 0 | tee /proc/sys/kernel/randomize_va_space
```

4. In a new terminal attach gdb to the running VM and add a HW breakpoint at the liabafl needle address

```bash
gdb -ex "target remote localhost:1234" -ex "hb *0xaabb00" -ex "c"
```

5. Run the harness

```bash
# inside the VM
./sda/harness
```

6. In a new terminal take a snapshot of the VM using the monitor
```bash
echo "savevm pre_fuzz" | nc -q 0 localhost 4444
```

7. Quit `gdb` (with `quit`) and the VM (with CTRL+C)

TODO
