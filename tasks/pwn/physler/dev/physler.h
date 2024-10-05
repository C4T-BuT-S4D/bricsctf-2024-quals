#include <linux/string.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/miscdevice.h>
#include <linux/random.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/io.h>
#include <linux/cdev.h>
#include <linux/device.h>


#define IOCTL_MAP_PHYS_ADDR 0x1001
#define IOCTL_READ_PHYS_MEM 0x2002
#define IOCTL_WRITE_PHYS_MEM 0x3003

#define BUF_SIZE 4096

int reg;

static unsigned long phys_addr = 0;
static unsigned long size = 0;
static void __iomem *mem = NULL;
static char kernel_buffer[BUF_SIZE];

static struct ioctl_map {
    unsigned long phys_addr;
    unsigned long size;
};

static struct ioctl_write {
    unsigned long size;
    unsigned char* in_data;
};


static noinline long ioctlHandler(struct file *file, unsigned int cmd, unsigned long arg);
static int __init init_dev(void);
static void __exit exit_dev(void);

static struct file_operations physler_fops = {.unlocked_ioctl = ioctlHandler};

struct miscdevice physler_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "physler",
    .fops = &physler_fops,
};

MODULE_LICENSE("WTF");
MODULE_AUTHOR("kaker@keker");
MODULE_DESCRIPTION("Same shit different day");