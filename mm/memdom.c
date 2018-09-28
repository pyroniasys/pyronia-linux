#include <linux/smv.h>
#include <linux/smv_mm.h>
#include <linux/memdom.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/mman.h>

/* SLAB cache for smv_struct structure  */
static struct kmem_cache *memdom_cachep;

/* Get the smv's privileges in the given memdom.
 * Expects caller to hold memdom->memdom_mutex.
 */
static inline int memdom_priv_get_internal(struct memdom_struct *memdom,
                                    int smv_id) {
    int p = 0;
    if( test_bit(smv_id, memdom->smv_bitmapRead) ) {
        p = p | MEMDOM_READ;
    }
    if( test_bit(smv_id, memdom->smv_bitmapWrite) ) {
        p = p | MEMDOM_WRITE;
    }
    if( test_bit(smv_id, memdom->smv_bitmapExecute) ) {
        p = p | MEMDOM_EXECUTE;
    }
    if( test_bit(smv_id, memdom->smv_bitmapAllocate) ) {
        p = p | MEMDOM_ALLOCATE;
    }
    return p;
}

/* Convert the memdom access privileges into VMA page
 * protection values. */
static inline unsigned long memdom_privs_to_pgprot(int privs) {
    unsigned long vm_prot = 0;

    if( privs & MEMDOM_READ ) {
        vm_prot |= VM_READ;
    }
    if( privs & MEMDOM_WRITE ) {
        vm_prot |= VM_WRITE;
    }
    if( privs & MEMDOM_EXECUTE ) {
      //vm_prot |= PROT_EXEC;
    }
    if( privs & MEMDOM_ALLOCATE ) {
        vm_prot |= VM_WRITE;
    }

    return vm_prot;
}

/* Create a memdom and update metadata */
int memdom_create(void){
    int memdom_id = -1;
    struct mm_struct *mm = current->mm;
    struct memdom_struct *memdom = NULL;

    /* SMP: protect shared memdom bitmap */
    down_write(&mm->smv_metadataMutex);

    /* Are we having too many memdoms? */
    if( atomic_read(&mm->num_memdoms) == SMV_ARRAY_SIZE ) {
        goto err;
    }

    /* Find available slot in the bitmap for the new smv */
    memdom_id = find_first_zero_bit(mm->memdom_bitmapInUse, SMV_ARRAY_SIZE);
    if( memdom_id == SMV_ARRAY_SIZE ) {
        goto err;
    }

    /* Create the actual memdom struct */
    memdom = allocate_memdom();
    memdom->memdom_id = memdom_id;
    bitmap_zero(memdom->smv_bitmapRead, SMV_ARRAY_SIZE);
    bitmap_zero(memdom->smv_bitmapWrite, SMV_ARRAY_SIZE);
    bitmap_zero(memdom->smv_bitmapExecute, SMV_ARRAY_SIZE);
    bitmap_zero(memdom->smv_bitmapAllocate, SMV_ARRAY_SIZE);
    memset(memdom->pgprot, 0, sizeof(memdom->pgprot));
    mutex_init(&memdom->memdom_mutex);

    /* Record this new memdom to mm */
    mm->memdom_metadata[memdom_id] = memdom;

    /* Set bit in memdom bitmap */
    set_bit(memdom_id, mm->memdom_bitmapInUse);

    /* Increase total number of memdom count in mm_struct */
    atomic_inc(&mm->num_memdoms);

    slog(KERN_INFO, "Created new memdom with ID %d, #memdom: %d / %d\n",
            memdom_id, atomic_read(&mm->num_memdoms), SMV_ARRAY_SIZE);
    goto out;

err:
    printk(KERN_ERR "Too many memdoms, cannot create more.\n");
    memdom_id = -1;
out:
    up_write(&mm->smv_metadataMutex);
    return memdom_id;
}
EXPORT_SYMBOL(memdom_create);

/* Find the first (in bit order) smv in the memdom. Called by memdom_kill */
int find_first_smv(struct memdom_struct *memdom){
    int smv_id = 0;

    mutex_lock(&memdom->memdom_mutex);

    /* Check read permission */
    smv_id = find_first_bit(memdom->smv_bitmapRead, SMV_ARRAY_SIZE);
    if( smv_id != SMV_ARRAY_SIZE ) {
        goto out;
    }

    /* Check write permission */
    smv_id = find_first_bit(memdom->smv_bitmapWrite, SMV_ARRAY_SIZE);
    if( smv_id != SMV_ARRAY_SIZE ) {
        goto out;
    }

    /* Check allocate permission */
    smv_id = find_first_bit(memdom->smv_bitmapAllocate, SMV_ARRAY_SIZE);
    if( smv_id != SMV_ARRAY_SIZE ) {
        goto out;
    }

    /* Check execute permission */
    smv_id = find_first_bit(memdom->smv_bitmapExecute, SMV_ARRAY_SIZE);

out:
    mutex_unlock(&memdom->memdom_mutex);
    return smv_id;
}

/* Free a memory domain metadata and remove it from mm_struct */
int memdom_kill(int memdom_id, struct mm_struct *mm){
    struct memdom_struct *memdom = NULL;
    int smv_id = 0;

    if( memdom_id > LAST_MEMDOM_INDEX ) {
        printk(KERN_ERR "[%s] Error, out of bound: memdom %d\n", __func__, memdom_id);
        return -1;
    }

    /* When user space program calls memdom_kill, mm_struct is NULL
     * If free_all_memdoms calls this function, it passes the about-to-destroy mm_struct, not current->mm */
    if( !mm ) {
        mm = current->mm;
    }

    /* SMP: protect shared memdom bitmap */
    down_write(&mm->smv_metadataMutex);
    memdom = mm->memdom_metadata[memdom_id];

    /* TODO: check if current task has the permission to delete the memdom, only master thread can do this */

    /* Clear memdom_id-th bit in memdom_bitmapInUse */
    if( test_bit(memdom_id, mm->memdom_bitmapInUse) ) {
        clear_bit(memdom_id, mm->memdom_bitmapInUse);
        up_write(&mm->smv_metadataMutex);
    } else {
        printk(KERN_ERR "Error, trying to delete a memdom that does not exist: memdom %d, #memdoms: %d\n", memdom_id, atomic_read(&mm->num_memdoms));
        up_write(&mm->smv_metadataMutex);
        return -1;
    }

    /* Clear all smv_bitmapR/W/E/A bits for this memdom in all smvs */
    do {
        smv_id = find_first_smv(memdom);
        if( smv_id != SMV_ARRAY_SIZE ) {
            smv_leave_memdom(memdom_id, smv_id, mm);
        }
    } while( smv_id != SMV_ARRAY_SIZE );

    down_write(&mm->smv_metadataMutex);
    /* Free the actual memdom struct */
    free_memdom(memdom);
    mm->memdom_metadata[memdom_id] = NULL;

    /* Decrement memdom count */
    atomic_dec(&mm->num_memdoms);
    up_write(&mm->smv_metadataMutex);

    slog(KERN_INFO, "[%s] Deleted memdom with ID %d, #memdoms: %d / %d\n",
            __func__, memdom_id, atomic_read(&mm->num_memdoms), SMV_ARRAY_SIZE);

    return 0;
}
EXPORT_SYMBOL(memdom_kill);

static struct vm_area_struct *find_memdom_vma(struct mm_struct *mm,
					      int memdom_id) {
  struct vm_area_struct *vma = mm->mmap;

  while(vma) {
    if (vma->memdom_id == memdom_id)
      break;
    vma = vma->vm_next;
  }
  if (!vma)
    slog(KERN_ERR, "[%s] No mapped vmas for memdom %d\n", __func__, memdom_id);
  return vma;
}

/* Free all the memdoms in this mm_struct */
void free_all_memdoms(struct mm_struct *mm){
    int index = 0;
    while( atomic_read(&mm->num_memdoms) > 0 ){
        index = find_first_bit(mm->memdom_bitmapInUse, SMV_ARRAY_SIZE);
        slog(KERN_INFO, "[%s] killing memdom %d, remaining #memdom: %d\n", __func__, index, atomic_read(&mm->num_memdoms));
        memdom_kill(index, mm);
    }
}

/* Set bit in memdom->smv_bitmapR/W/E/A */
int memdom_priv_add(int memdom_id, int smv_id, int privs){
    struct smv_struct *smv;
    struct memdom_struct *memdom;
    struct mm_struct *mm = current->mm;
    struct vm_area_struct *vma;
    
    if( smv_id > LAST_SMV_INDEX || memdom_id > LAST_MEMDOM_INDEX ) {
        printk(KERN_ERR "[%s] Error, out of bound: smv %d / memdom %d\n", __func__, smv_id, memdom_id);
        return -1;
    }

    down_read(&mm->smv_metadataMutex);
    smv = current->mm->smv_metadata[smv_id];
    memdom = current->mm->memdom_metadata[memdom_id];
    up_read(&mm->smv_metadataMutex);

    if( !memdom || !smv ) {
        printk(KERN_ERR "[%s] memdom %p || smv %p not found\n", __func__, memdom, smv);
        return -1;
    }
    if( !smv_is_in_memdom(memdom_id, smv->smv_id) ) {
        printk(KERN_ERR "[%s] smv %d is not in memdom %d, please make smv join memdom first.\n", __func__, smv_id, memdom_id);
        return -1;
    }

    /* Only main thread can change the privileges to a memory domain. */
    if (current->smv_id != MAIN_THREAD) {
      printk(KERN_ERR "[%s] thread running in smv %d is not allowed to add privileges.\n", __func__, current->smv_id);
      return -1;
    }

    /* Set privileges in memdom's bitmap */
    mutex_lock(&memdom->memdom_mutex);
    if( privs & MEMDOM_READ ) {
        set_bit(smv_id, memdom->smv_bitmapRead);
        slog(KERN_INFO, "[%s] Added read privilege for smv %d in memdmo %d\n", __func__, smv_id, memdom_id);
    }
    if( privs & MEMDOM_WRITE ) {
        set_bit(smv_id, memdom->smv_bitmapWrite);
        slog(KERN_INFO, "[%s] Added write privilege for smv %d in memdmo %d\n", __func__, smv_id, memdom_id);
    }
    if( privs & MEMDOM_EXECUTE ) {
        set_bit(smv_id, memdom->smv_bitmapExecute);
        slog(KERN_INFO, "[%s] Added execute privilege for smv %d in memdmo %d\n", __func__, smv_id, memdom_id);
    }
    if( privs & MEMDOM_ALLOCATE ) {
        set_bit(smv_id, memdom->smv_bitmapAllocate);
        slog(KERN_INFO, "[%s] Added allocate privilege for smv %d in memdmo %d\n", __func__, smv_id, memdom_id);
    }
    // update the page protection for the smv
    if (memdom_id > MAIN_THREAD)
      memdom->pgprot[smv_id] = memdom_privs_to_pgprot(memdom_priv_get_internal(memdom, smv_id));

    // change the protection bits for this memdom's PTE
    if (memdom_id > MAIN_THREAD && (vma = find_memdom_vma(mm, memdom_id))) {
      set_pte_smv_protection(mm, vma->vm_start, vma,
			     smv_id, memdom->pgprot[smv_id]);
    }
    
    mutex_unlock(&memdom->memdom_mutex);

    // TODO: mprotect for MAIN_THREAD memdom, too
    
    /*if (memdom_id > MAIN_THREAD && smv_id == MAIN_THREAD)
      return memdom_mprotect_all_vmas(current, mm, memdom_id, smv_id);*/

    return 0;
}
EXPORT_SYMBOL(memdom_priv_add);

/* Clear bit in memdom->smv_bitmapR/W/E/A */
int memdom_priv_del(int memdom_id, int smv_id, int privs){
    struct smv_struct *smv = NULL;
    struct memdom_struct *memdom = NULL;
    struct mm_struct *mm = current->mm;
    struct vm_area_struct *vma;
    
    if( smv_id > LAST_SMV_INDEX || memdom_id > LAST_MEMDOM_INDEX ) {
        printk(KERN_ERR "[%s] Error, out of bound: smv %d / memdom %d\n", __func__, smv_id, memdom_id);
        return -1;
    }

    down_read(&mm->smv_metadataMutex);
    smv = current->mm->smv_metadata[smv_id];
    memdom = current->mm->memdom_metadata[memdom_id];
    up_read(&mm->smv_metadataMutex);

    if( !memdom || !smv ) {
        printk(KERN_ERR "[%s] memdom %p || smv %p not found\n", __func__, memdom, smv);
        return -1;
    }
    if( !smv_is_in_memdom(memdom_id, smv->smv_id) ) {
        printk(KERN_ERR "[%s] smv %d is not in memdom %d, please make smv join memdom first.\n", __func__, smv_id, memdom_id);
        return -1;
    }

    /* Only main thread can change the privileges to a memory domain. */
    if (current->smv_id != MAIN_THREAD) {
      printk(KERN_ERR "[%s] thread running in smv %d is not allowed to revoke privileges.\n", __func__, current->smv_id);
      return -1;	
    }

    /* Clear privileges in memdom's bitmap */
    mutex_lock(&memdom->memdom_mutex);
    if( privs & MEMDOM_READ ) {
        clear_bit(smv_id, memdom->smv_bitmapRead);
        slog(KERN_INFO, "[%s] Revoked read privilege for smv %d in memdmo %d\n", __func__, smv_id, memdom_id);
    }
    if( privs & MEMDOM_WRITE ) {
        clear_bit(smv_id, memdom->smv_bitmapWrite);
        slog(KERN_INFO, "[%s] Revoked write privilege for smv %d in memdmo %d\n", __func__, smv_id, memdom_id);
    }
    if( privs & MEMDOM_EXECUTE ) {
        clear_bit(smv_id, memdom->smv_bitmapExecute);
        slog(KERN_INFO, "[%s] Revoked execute privilege for smv %d in memdmo %d\n", __func__, smv_id, memdom_id);
    }
    if( privs & MEMDOM_ALLOCATE ) {
        clear_bit(smv_id, memdom->smv_bitmapAllocate);
        slog(KERN_INFO, "[%s] Revoked allocate privilege for smv %d in memdmo %d\n", __func__, smv_id, memdom_id);
    }
    // update the page protection for the smv
    if (memdom_id > MAIN_THREAD)
      memdom->pgprot[smv_id] = memdom_privs_to_pgprot(memdom_priv_get_internal(memdom, smv_id));

    // TODO: mprotect for MAIN_THREAD memdom, too
    // change the protection bits for this memdom's PTE
    if (memdom_id > MAIN_THREAD && (vma = find_memdom_vma(mm, memdom_id))) {
      set_pte_smv_protection(mm, vma->vm_start, vma,
			     smv_id, memdom->pgprot[smv_id]);
    }

    mutex_unlock(&memdom->memdom_mutex);

    return 0;
}
EXPORT_SYMBOL(memdom_priv_del);

/* Return smv's privileges in a given memdom and return to caller */
int memdom_priv_get(int memdom_id, int smv_id){
    struct smv_struct *smv = NULL;
    struct memdom_struct *memdom = NULL;
    struct mm_struct *mm = current->mm;
    int privs = 0;

    if( smv_id > LAST_SMV_INDEX || memdom_id > LAST_MEMDOM_INDEX ) {
        printk(KERN_ERR "[%s] Error, out of bound: smv %d / memdom %d\n", __func__, smv_id, memdom_id);
        return -1;
    }

    down_read(&mm->smv_metadataMutex);
    smv = current->mm->smv_metadata[smv_id];
    memdom = current->mm->memdom_metadata[memdom_id];
    up_read(&mm->smv_metadataMutex);

    if( !memdom || !smv ) {
        printk(KERN_ERR "[%s] memdom %p || smv %p not found\n", __func__, memdom, smv);
        return -1;
    }
    if( !smv_is_in_memdom(memdom_id, smv->smv_id) ) {
        printk(KERN_ERR "[%s] smv %d is not in memdom %d, please make smv join memdom first.\n", __func__, smv_id, memdom_id);
        return -1;
    }

    /* Get privilege info */
    mutex_lock(&memdom->memdom_mutex);
    privs = memdom_priv_get_internal(memdom, smv_id);
    mutex_unlock(&memdom->memdom_mutex);

    slog(KERN_INFO, "[%s] smv %d has privs %x in memdom %d\n", __func__, smv_id, privs, memdom_id);
    return privs;
}
EXPORT_SYMBOL(memdom_priv_get);

/* User space signals the kernel what memdom a mmap call is for */
int memdom_mmap_register(int memdom_id){
    struct memdom_struct *memdom;
    struct mm_struct *mm = current->mm;

    if( memdom_id > LAST_MEMDOM_INDEX ) {
        printk(KERN_ERR "[%s] Error, out of bound: memdom %d\n", __func__, memdom_id);
        return -1;
    }

    down_read(&mm->smv_metadataMutex);
    memdom = current->mm->memdom_metadata[memdom_id];
    up_read(&mm->smv_metadataMutex);

    if( !memdom ) {
        printk(KERN_ERR "[%s] memdom %p not found\n", __func__, memdom);
        return -1;
    }

    /* TODO: privilege checks */

    /* Record memdom_id for mmap to use */
    current->mmap_memdom_id = memdom_id;

    return 0;
}
EXPORT_SYMBOL(memdom_mmap_register);

unsigned long memdom_munmap(unsigned long addr){
  slog(KERN_ERR, "[%s] not implemented\n", __func__);
  return 0;
}
EXPORT_SYMBOL(memdom_munmap);

/* Return the memdom id used by the master thread (global memdom) */
int memdom_main_id(void){
    return MAIN_THREAD;
}
EXPORT_SYMBOL(memdom_main_id);

/* Query the memdom id of an address, return -1 if not memdom not found */
int memdom_query_id(unsigned long addr){
    int memdom_id = 0;
    int smv_id = 0;
    struct vm_area_struct *vma = NULL;

    /* Look for vma covering the address */
    vma = find_vma(current->mm, addr);
    if( !vma ) {
        /* Debugging info, should remove printk to avoid information leakage and just go to out label. */
        slog(KERN_INFO, "[%s] addr 0x%16lx is not in any memdom\n", __func__, addr);
        goto out;
    }

    /* Privilege check, only member smv can query */
    smv_id = current->smv_id;
    memdom_id = vma->memdom_id;
    if( smv_is_in_memdom(memdom_id, smv_id) ) {
        slog(KERN_INFO, "[%s] addr 0x%16lx is in memdom %d\n", __func__, addr, memdom_id);
    } else {
        /* Debugging info, should remove to avoid information leakage, just set memdom_id to 0 (lying to the caller)*/
        printk(KERN_ERR "[%s] hey you don't have the privilege to query this address (smv %d, memdom %d)\n",
               __func__, smv_id, memdom_id);
        memdom_id = 0;
    }
out:
    return memdom_id;
}
EXPORT_SYMBOL(memdom_query_id);

/* Get the calling thread's defualt memdom id */
int memdom_private_id(void){
    return current->mmap_memdom_id;
}
EXPORT_SYMBOL(memdom_private_id);

/// ---------------------------------------------------------------------------------------------  ///
/// ------------------ Functions called by kernel internally to manage memory space -------------  ///
/// ---------------------------------------------------------------------------------------------  ///

/** void memdom_init(void)
 *  Create slab cache for future memdom_struct allocation This
 *  is called by start_kernel in main.c
 */
void memdom_init(void){
    memdom_cachep = kmem_cache_create("memdom_struct",
                                      sizeof(struct memdom_struct), 0,
                                      SLAB_HWCACHE_ALIGN | SLAB_NOTRACK, NULL);
    if( !memdom_cachep ) {
        slog(KERN_INFO, "[%s] memdom slabs initialization failed...\n", __func__);
    } else{
        slog(KERN_INFO, "[%s] memdom slabs initialized\n", __func__);
    }
}

/* Initialize vma's owner to the main thread, only called by the main thread */
int memdom_claim_all_vmas(int memdom_id){
    struct vm_area_struct *vma;
    struct mm_struct *mm = current->mm;
    int vma_count = 0;

    if( memdom_id > LAST_MEMDOM_INDEX ) {
        printk(KERN_ERR "[%s] Error, out of bound: memdom %d\n", __func__, memdom_id);
        return -1;
    }

    down_write(&mm->mmap_sem);
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        vma->memdom_id = MAIN_THREAD;
        vma_count++;
    }
    up_write(&mm->mmap_sem);

    slog(KERN_INFO, "[%s] Initialized %d vmas to be in memdom %d\n", __func__, vma_count, memdom_id);
    return 0;
}

/* Return the memory domain's VMA page protection for the given smv.
 */
unsigned long memdom_get_pgprot(int memdom_id, int smv_id) {
    struct smv_struct *smv = NULL;
    struct memdom_struct *memdom = NULL;
    struct mm_struct *mm = current->mm;
    unsigned long prot = 0;

    if( memdom_id < 0 || memdom_id > LAST_MEMDOM_INDEX ) {
        printk(KERN_ERR "[%s] Error, out of bound: memdom %d\n", __func__, memdom_id);
        return 0;
    }

    if (smv_id < 0 || smv_id > LAST_SMV_INDEX) {
        printk(KERN_ERR "[%s] Error, out of bound: smv %d\n", __func__, smv_id);
        return 0;
    }

    down_read(&mm->smv_metadataMutex);
    smv = mm->smv_metadata[smv_id];
    memdom = mm->memdom_metadata[memdom_id];
    up_read(&mm->smv_metadataMutex);

    if (!memdom || !smv) {
        printk(KERN_ERR "[%s] memdom %p || smv %p not found\n", __func__, memdom, smv);
        return 0;
    }

    /* Get privilege info */
    mutex_lock(&memdom->memdom_mutex);
    prot = memdom->pgprot[smv_id];
    mutex_unlock(&memdom->memdom_mutex);

    slog(KERN_INFO, "[%s] smv %d has pgprot %lu in memdom %d\n", __func__, smv_id, prot, memdom_id);
    return prot;
}

/* mprotect all vmas belonging to the memdom_id using the
 * memdom's page protection value for the given smv.
*/
int memdom_mprotect_all_vmas(struct task_struct *tsk, struct mm_struct *mm,
			     int memdom_id, int smv_id) {
  /*   struct memdom_vma *vm_memdom = NULL;
    int error = 0;
    struct smv_struct *smv = NULL;
    struct memdom_struct *memdom = NULL;
    struct vm_area_struct *vma = NULL;

    if( memdom_id < 0 || memdom_id > LAST_MEMDOM_INDEX ) {
      printk(KERN_ERR "[%s] Error, out of bound: memdom %d\n", __func__, memdom_id);
      return -1;
    }
    
    //spin_lock(&mm->smv_metadataMutex);
    smv = mm->smv_metadata[smv_id];
    memdom = mm->memdom_metadata[memdom_id];

    if (!memdom || !smv) {
        printk(KERN_ERR "[%s] memdom %p || smv %p not found\n", __func__, memdom, smv);
        return -1;
    }

    //mutex_lock(&memdom->memdom_mutex);
    for (vm_memdom = mm->protected_vmas; vm_memdom ; vm_memdom = vm_memdom->next) {
      if (vm_memdom->vma->memdom_id == memdom_id) {
	vma = vm_memdom->vma;
	error = do_mprotect(tsk, vma->vm_start, vma->vm_end-vma->vm_start,
			    memdom->pgprot[smv_id]);
	if (error) {
	  slog(KERN_INFO, "[%s] Could not mprotect vma starting at 0x%16lx in memdom %d for smv %d: error = %d\n", __func__, vma->vm_start, memdom_id, smv_id, error);
	  goto out;
	}
	else {
	  slog(KERN_INFO, "[%s] New page protection for vma starting at 0x%16lx in memdom %d for smv %d = %lu\n", __func__, vma->vm_start, memdom_id, smv_id, (pgprot_val(vma->vm_page_prot)&(PROT_READ|PROT_WRITE|PROT_EXEC|PROT_NONE)));
	}
      }
    }
 out:
    //mutex_unlock(&memdom->memdom_mutex);
    //spin_unlock(&mm->smv_metadataMutex);
    return error;
  */
  return 0;
}
