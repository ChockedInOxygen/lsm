#include <linux/module.h>
#include <linux/lsm_hooks.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/namei.h>

#define BLOCKED_SO_PATH "/usr/lib/badlib.so"

static int block_specific_so(struct file *file, unsigned long prot, unsigned long flags)
{
    char *buf = NULL;
    char *path = NULL;

    if (!file || !file->f_path.dentry)
        return 0;

    buf = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
    if (!buf)
        return 0;

    path = d_path(&file->f_path, buf, PATH_MAX);
    if (IS_ERR(path)) {
        kfree(buf);
        return 0;
    }

    if (strcmp(path, BLOCKED_SO_PATH) == 0) {
        kfree(buf);
        pr_info("LSM: Blocked loading of %s\n", BLOCKED_SO_PATH);
        return -EACCES;
    }

    kfree(buf);
    return 0;
}

static struct security_hook_list mylsm_hooks[] __lsm_ro_after_init = {
    LSM_HOOK_INIT(mmap_file, block_specific_so),
};

static struct lsm_id blockso_lsm_id __lsm_ro_after_init = LSM_ID_INIT(blockso);

static int __init mylsm_init(void)
{
    security_add_hooks(mylsm_hooks, ARRAY_SIZE(mylsm_hooks), &blockso_lsm_id);
    pr_info("LSM: blockso loaded.\n");
    return 0;
}

DEFINE_LSM(blockso) = {
    .name = "blockso",
    .init = mylsm_init,
};

MODULE_LICENSE("GPL");
