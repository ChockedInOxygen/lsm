#include <linux/lsm_hooks.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/cred.h>

static const char *deny_libs[] = {
    "/home/asd/lsm_test/badlib.so"
};

static int match_deny_lib(const char *filename)
{
    int i;
    if (!filename)
        return 0;
    for (i = 0; i < ARRAY_SIZE(deny_libs); i++) {
        if (strcmp(filename, deny_libs[i]) == 0)
            return 1;
    }
    return 0;
}

static int my_file_open(struct file *file)
{
    char *tmp;
    char *pathname = NULL;
    int ret = 0;
    /* 限制模块root也被禁止的话不用capable(CAP_SYSADMIN) */
    tmp = (char *)__get_free_page(GFP_KERNEL);
    if (!tmp)
        return 0;
    pathname = d_path(&file->f_path, tmp, PAGE_SIZE);
    if (!IS_ERR(pathname)) {
        if (match_deny_lib(pathname)) {
            pr_info("LSM: Denying load of %s\n", pathname);
            ret = -EACCES;
        }
    }
    free_page((unsigned long)tmp);
    return ret;
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
