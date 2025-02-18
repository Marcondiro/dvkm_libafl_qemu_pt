# dvkm_libafl_qemu_pt

[Damn_Vulnerable_Kernel_Module](https://github.com/hardik05/Damn_Vulnerable_Kernel_Module/) fuzzer based on [libafl QEMU KVM](https://github.com/AFLplusplus/LibAFL) with Intel PT tracing.

## Requirements

- Rust
- [cargo-make](https://github.com/sagiegurari/cargo-make)
- linux build requirements
- linux 6.8.y (or update the submodule ecc accordingly)
- QEMU

## Build & Run

1. Clone the project including the submodules

    ```bash
    git clone --recurse-submodules
    ```

2. Boot the target VM

    ```bash
    cargo make boot_target
    ```

3. Install DVKM in the vm

    ```bash
    # inside the VM
    mkdir /sda && \
    mount /dev/sda /sda && \
    insmod /sda/dvkm.ko
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

7. In gdb remove the breakpoint and continue

    ```gdb
    delete 1
    c
    ```

8. In the VM copy the kernel module's section addresses and the error handlers addresses to the drive, then print out the .text section address

    ```bash
    # inside the VM
    mkdir -p /sda/kallsyms
    grep " oops_exit$" /proc/kallsyms | awk '{print $1}' > /sda/kallsyms/oops_exit
    grep " kasan_report$" /proc/kallsyms | awk '{print $1}' > /sda/kallsyms/kasan_report
    cp -r /sys/module/dvkm/sections/ /sda/sections
    umount /dev/sda
    cat /sys/module/dvkm/sections/.text
    ```

9. Dump the kernel module executable memory from gdb, **replace the addresses with the ouput of the previous step** (CTRL + C in gdb to interrupt the vm)

    ```gdb
    dump binary memory ./target/dump.bin <REPLACE WITH PREVIOUS POINT cat /sys/module/dvkm/sections/.text output> <REPLACE WITH /sys/module/dvkm/sections/.text adding 0x1000>
    ```

10. Quit `gdb` (with `quit` + `y`)

11. Exit the VM  with CTRL + C

12. Copy the sections addresses to the host

    ```bash
    sudo qemu-nbd --read-only -c /dev/nbd0 target/dvkm.qcow2
    sudo mount -o ro /dev/nbd0 /mnt/qcow2_mount
    sudo cp -r /mnt/qcow2_mount/sections target/
    sudo cp -r /mnt/qcow2_mount/kallsyms target/
    sudo chown -R "$(whoami)":"$(whoami)" target/sections
    sudo chown -R "$(whoami)":"$(whoami)" target/kallsyms
    sudo umount /mnt/qcow2_mount
    sudo qemu-nbd -d /dev/nbd0
    ```

13. Run the fuzzer

    ```bash
    cargo make run_fuzzer
    ```
