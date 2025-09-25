#include <linux/module.h>
#include <linux/lsm_hooks.h>
#include <linux/fs.h>

static int my_file_open(struct file *file)
{
    // your check
    return 0;
}

static struct security_hook_list my_hooks[] __lsm_ro_after_init = {
    LSM_HOOK_INIT(file_open, my_file_open),
};

static int __init my_lsm_init(void)
{
    security_add_hooks(my_hooks, ARRAY_SIZE(my_hooks), "deny_so_loader");
    pr_info("deny_so_loader LSM initialized\n");
    return 0;
}

DEFINE_LSM(deny_so_loader) = {
    .name = "deny_so_loader",
    .init = my_lsm_init,
};

MODULE_LICENSE("GPL");
