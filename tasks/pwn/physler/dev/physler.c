#include "physler.h"

static noinline long ioctlHandler(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct ioctl_map _map;
    struct ioctl_write _write;

    switch (cmd) {
        case IOCTL_MAP_PHYS_ADDR: {

            if (copy_from_user(&_map, (void*)arg, sizeof(_map))) {
                return -EFAULT;
            }

            if (mem)
                iounmap(mem);

            mem = ioremap(_map.phys_addr, _map.size);

            if (!mem) {
                return -EFAULT;
            }
            break;
        }
        case IOCTL_WRITE_PHYS_MEM: {
            if (!mem)
                return -EFAULT;

            if (copy_from_user(&_write, (void*)arg, sizeof(_write))) {
                return -EFAULT;
            }

            size = _write.size;

            if (size > sizeof(kernel_buffer))
                size = sizeof(kernel_buffer);

            if (copy_from_user(kernel_buffer, (char *)_write.in_data, size))
                return -EFAULT;

            memcpy_toio(mem, kernel_buffer, size);
            break;
        }
        default:
            return -EINVAL;
    }

    return 0;
}

static int __init init_dev(void){
    reg = misc_register(&physler_dev);
    if (reg < 0)
        printk("[-] Failed to register physler!");

    return 0;
};

static void __exit exit_dev(void){
    misc_deregister(&physler_dev);
}

module_init(init_dev);
module_exit(exit_dev);