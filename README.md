// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/lsm_hooks.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/namei.h>

#define BLOCKED_SO_PATH "/usr/lib/badlib.so"

static int block_specific_so(struct file *file, unsigned long reqprot,
                             unsigned long prot, unsigned long flags, unsigned long addr)
{
    char *buf = NULL;
    char *path = NULL;

    // 只检查有文件对象且为普通文件类型
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

    // 判断库路径是否命中
    if (strcmp(path, BLOCKED_SO_PATH) == 0) {
        kfree(buf);
        pr_info("LSM: Blocked loading of %s\n", BLOCKED_SO_PATH);
        return -EACCES;
    }

    kfree(buf);
    return 0;
}

static struct security_hook_list mylsm_hooks[] = {
    LSM_HOOK_INIT(file_mmap, block_specific_so),
};

static int __init mylsm_init(void)
{
    security_add_hooks(mylsm_hooks, ARRAY_SIZE(mylsm_hooks), "blockso");
    pr_info("LSM: blockso loaded.\n");
    return 0;
}

DEFINE_LSM(blockso) = {
    .name = "blockso",
    .init = mylsm_init,
};

MODULE_LICENSE("GPL");
