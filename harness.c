#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <unistd.h>

#define DVKM_IOCTL_MAGIC ('D')
#define IOCTL(NUM) _IOWR(DVKM_IOCTL_MAGIC, NUM, struct dvkm_obj)

#define INPUT_SIZE 1024
char libafl_qemu_input[INPUT_SIZE];

struct dvkm_obj
{
    int width;
    int height;
    int datasize;
    char *data;
} io_buffer;

// Easy to find function in .trigger_bp section
// naked attribute makes sure the function address will be == section start
void libafl_qemu_trigger_bp(void) __attribute__((section(".trigger_bp"), naked));
void libafl_qemu_trigger_bp(void)
{
    asm volatile(
        "nop\n"
        "retq\n");
}

// Easy to find function in .trigger_bp section
// naked attribute makes sure the function address will be == section start
void libafl_qemu_trigger_bp_2(void) __attribute__((section(".trigger_bp_2"), naked));
void libafl_qemu_trigger_bp_2(void)
{
    asm volatile(
        "nop\n"
        "retq\n");
}

int main()
{
    int fd, ioctl_num, ret;
    char *input_iter = libafl_qemu_input;

    printf("input buffer address: %p size %i\n", libafl_qemu_input, INPUT_SIZE);

    fd = open("/proc/dvkm", O_RDWR);
    if (fd < 0)
    {
        printf("Cann't open /proc/dvkm.\n");
        return 1;
    }

    printf("dvkm opened successfully, triggering libafl bp.\n");

    libafl_qemu_trigger_bp();

    for (size_t i = 0; i < INPUT_SIZE; i++) {
        printf("%02X ", libafl_qemu_input[i]);  // Print each byte in hex (2-digit format)
        if ((i % 16) == 15) {
            printf("\n");
        }
    }

    asm volatile(
        "mov $100, %%rcx\n"  // Load loop count into RCX
        "1:\n"               // Label for loop start
        "nop\n"              // No-operation instruction
        "loop 1b\n"          // Decrement RCX and loop if not zero
        :
        :
        : "rcx"              // Clobbered register
    );

    // possible IOCTLs fuzzed:
    // 0: DVKM_IOCTL_INTEGER_OVERFLOW IOCTL
    // 1: DVKM_IOCTL_INTEGER_UNDERFLOW IOCTL
    // 2: DVKM_IOCTL_STACK_BUFFER_OVERFLOW IOCTL
    // 3: DVKM_IOCTL_HEAP_BUFFER_OVERFLOW IOCTL
    ioctl_num = input_iter[0] % 4;
    ++input_iter;
    io_buffer.width = *((int *)input_iter);
    input_iter += sizeof(int);
    io_buffer.height = *((int *)input_iter);
    input_iter += sizeof(int);
    io_buffer.datasize = *((int *)input_iter);
    input_iter += sizeof(int);
    io_buffer.data = input_iter;

    ret = ioctl(fd, IOCTL(ioctl_num), &io_buffer);
 
    printf("dvkm ret: %d\nBye!\n", ret);

    asm volatile(
        "mov $100, %%rcx\n"  // Load loop count into RCX
        "1:\n"               // Label for loop start
        "nop\n"              // No-operation instruction
        "loop 1b\n"          // Decrement RCX and loop if not zero
        :
        :
        : "rcx"              // Clobbered register
    );

    libafl_qemu_trigger_bp_2();

    close(fd);
    return 0;
}
