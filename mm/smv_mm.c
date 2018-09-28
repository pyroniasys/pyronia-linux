#include <linux/smv_mm.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/rmap.h>
#include <linux/smv.h>
#include <linux/mman.h>
#include <linux/personality.h>
#include <asm/tlbflush.h>

#include "internal.h"

/* Check whether current fault is a valid smv page fault.
 * Return 1 if it's a valid smv fault, 0 to block access
 */
int smv_valid_fault(int smv_id, struct vm_area_struct *vma, unsigned long error_code){
    int memdom_id = vma->memdom_id;
    struct mm_struct *mm = current->mm;
    int privs = 0;
    int rv = 0;

    /* Skip checking for smv valid fault if
     * 1. current task is not using smv
     * 2. current task is using smv, but page fault triggered by Pthreads (smv_id == -1)
     */
    if ( !mm->using_smv || (mm->using_smv && current->smv_id == -1) ) {
         return 1;
    }

    /* A fault is valid only if the smv has joined this vma's memdom */
    if ( !smv_is_in_memdom(memdom_id, smv_id) ) {
        printk(KERN_ERR "[%s] smv %d is not in memdom %d\n", __func__, smv_id, memdom_id);
        return 0;
    }

    /* Get this smv's privileges */
    privs = memdom_priv_get(memdom_id, smv_id);

    printk(KERN_INFO "[%s] error code: %lu\n", __func__, error_code);

    /* Protection fault */
    if ( error_code & PF_PROT ) {
    }

    /* Write fault */
    if ( error_code & PF_WRITE ) {
        if ( privs & MEMDOM_WRITE ) {
            rv = 1;
        } else{
            printk(KERN_ERR "[%s] smv %d cannot write memdom %d\n", __func__, smv_id, memdom_id);
            rv = 0; // Try to write a unwritable address
        }
    }
    /* Read fault */
    else {
        if ( privs & MEMDOM_READ ) {
            rv = 1;
        } else{
            printk(KERN_ERR "[%s] smv %d cannot read memdom %d\n", __func__, smv_id, memdom_id);
            rv = 0; // Try to read a unreadable address
        }
    }

    /* kernel-/user-mode fault */
    if ( error_code & PF_USER ) {
    }

    /* Use of reserved bit detected */
    if ( error_code & PF_RSVD ) {
    }

    /* Fault was instruction fetch */
    if ( error_code & PF_INSTR ) {
    }

    return rv;
}

/* Counter statistics helper functions */
static inline void init_rss_vec(int *rss) {
    memset(rss, 0, sizeof(int) * NR_MM_COUNTERS);
}
static inline void add_mm_rss_vec(struct mm_struct *mm, int *rss) {
        int i;

        if (current->mm == mm)
                sync_mm_rss(mm);
        for (i = 0; i < NR_MM_COUNTERS; i++)
                if (rss[i])
                        add_mm_counter(mm, i, rss[i]);
}

static pmd_t *get_pte_smv(struct mm_struct *mm, unsigned long addr,
			  int smv_id) {
  pgd_t *pgd;
  pud_t *pud;
  pmd_t *pmd = NULL;

  pgd = pgd_offset_smv(mm, addr, smv_id);
  if (pgd_none(*pgd))
    goto out;

  pud = pud_offset(pgd, addr);
  if (pud_none(*pud))
    goto out;
  
  pmd = pmd_offset(pud, addr);

 out:
  return pmd;
}

void set_pte_smv_protection(struct mm_struct *mm, unsigned long address,
			    struct vm_area_struct *vma,
			    int smv_id, unsigned long prot) {
  pmd_t *pmd;
  pte_t *pte;
  pte_t ptent;
  bool rier;
  spinlock_t *ptl;

  pmd = get_pte_smv(mm, address, smv_id);
  if (!pmd || pmd_none(*pmd))
    return;

  pte = pte_offset_map(pmd, address);
  ptl = pte_lockptr(mm, pmd);

  if (pte_none(*pte) || !pte_present(*pte)) {
    return;
  }
    
  spin_lock(ptl);
  set_tlb_flush_pending(mm);
  rier = (current->personality & READ_IMPLIES_EXEC) && (prot & VM_READ);
  /* Does the application expect PROT_READ to imply PROT_EXEC */
  if (rier && (vma->vm_flags & VM_MAYEXEC))
    prot |= VM_EXEC;
  
  ptent = ptep_modify_prot_start(mm, address, pte);
  ptent = pte_modify(ptent, vm_get_page_prot(prot));
  
  /* Avoid taking write faults for known dirty pages */
  if (vma_wants_writenotify(vma) && pte_dirty(ptent) &&
      (pte_soft_dirty(ptent) ||
       !(vma->vm_flags & VM_SOFTDIRTY))) {
    ptent = pte_mkwrite(ptent);
  }
  
  ptep_modify_prot_commit(mm, address, pte, ptent);
  /* Only flush the TLB if we actually modified any entries: */
  flush_tlb_range(vma, vma->vm_start, vma->vm_end);
  clear_tlb_flush_pending(mm);
  spin_unlock(ptl);
  
  slog(KERN_INFO, "[%s] Set protection bits for smv %d in memdom %d for pte_val:0x%16lx\n", __func__, smv_id, vma->memdom_id, pte_val(*pte));
}

/* Copy pte of a fault address from src_smv to dst_smv
 * Return 0 on success, -1 otherwise.
 */
int copy_pgtable_smv(int dst_smv, int src_smv,
                     unsigned long address, unsigned int flags,
                     struct vm_area_struct *vma){

    struct mm_struct *mm = current->mm;
    pgd_t *src_pgd, *dst_pgd;
    pud_t *src_pud, *dst_pud;
    pmd_t *src_pmd, *dst_pmd;
    pte_t *src_pte, *dst_pte;
    spinlock_t *src_ptl, *dst_ptl;
    struct page *page;
    int rv;
    int rss[NR_MM_COUNTERS];
    unsigned long prot;

    // let's preemptively get this protection --> could be outdated?
    prot = memdom_get_pgprot(vma->memdom_id, dst_smv);

    /* Don't copy page table to the main thread */
    if ( dst_smv == MAIN_THREAD ) {
      slog(KERN_INFO, "[%s] smv %d attempts to overwrite main thread's page table. Skip\n", __func__, src_smv);
      return 0;
    }
    /* Source and destination smvs cannot be the same */
    if ( dst_smv == src_smv ) {
        slog(KERN_INFO, "[%s] smv %d attempts to copy its own page table. Skip.\n", __func__, src_smv);
        return 0;
    }
    /* Main thread should not call this function */
    if ( current->smv_id == MAIN_THREAD ) {
        slog(KERN_INFO, "[%s] main thread smv %d, skip\n", __func__, current->smv_id);
        return 0;
    }

    /* SMP protection */
    down_write(&mm->smv_metadataMutex);

    /* Source smv:
     * Page walk to obtain the source pte
     * We should hit each level as __handle_mm_fault has already handled the fault
     */
    src_pgd = pgd_offset_smv(mm, address, src_smv);
    src_pud = pud_offset(src_pgd, address);
    src_pmd = pmd_offset(src_pud, address);
    src_pte = pte_offset_map(src_pmd, address);
    src_ptl = pte_lockptr(mm, src_pmd);
    spin_lock(src_ptl);

    /* Destination smv:
     * Page walk to obtain the destination pte.
     * Allocate new entry as needed */
    dst_pgd = pgd_offset_smv(mm, address, dst_smv);
    dst_pud = pud_alloc(mm, dst_pgd, address);
    if ( !dst_pud ) {
        rv = VM_FAULT_OOM;
        printk(KERN_ERR "[%s] Error: !dst_pud, address 0x%16lx\n", __func__, address);
        goto unlock_src;
    }
    dst_pmd = pmd_alloc(mm, dst_pud, address);
    if ( !dst_pmd ) {
        rv = VM_FAULT_OOM;
        printk(KERN_ERR "[%s] Error: !dst_pmd, address 0x%16lx\n", __func__, address);
        goto unlock_src;
    }
    if ( unlikely(pmd_none(*dst_pmd)) &&
         unlikely(__pte_alloc(mm, dst_pmd, address))) {
         rv = VM_FAULT_OOM;
         printk(KERN_ERR "[%s] Error: pmd_none(*dst_pud) && __pte_alloc() failed, address 0x%16lx\n", __func__, address);
         goto unlock_src;
    }
    dst_pte = pte_offset_map(dst_pmd, address);
    dst_ptl = pte_lockptr(mm, dst_pmd);
    spin_lock_nested(dst_ptl, SINGLE_DEPTH_NESTING);

    /* Skip copying pte if two ptes refer to the same page and
     * specify the same access privileges */
    if ( !pte_same(*src_pte, *dst_pte) ) {

        page = vm_normal_page(vma, address, *src_pte);
        /* Update data page statistics */
        if ( page ) {
            init_rss_vec(rss);
            get_page(page);
            page_dup_rmap(page, false);
            rss[mm_counter(page)]++;
            add_mm_rss_vec(mm, rss);
        }

        slog(KERN_INFO, "[%s] src_pte 0x%16lx(smv %d) != dst_pte 0x%16lx (smv %d) for addr 0x%16lx\n", __func__, pte_val(*src_pte), src_smv, pte_val(*dst_pte), dst_smv, address);
    } else{
        slog(KERN_INFO, "[%s] src_pte (smv %d) == dst_pte (smv %d) for addr 0x%16lx\n", __func__, src_smv, dst_smv, address);
    }

    /* Set the actual value to be the same as the source
     * pgtables for destination  */
    set_pte_at(mm, address, dst_pte, *src_pte);

    printk(KERN_INFO "[%s] src smv %d: pgd_val:0x%16lx, pud_val:0x%16lx, pmd_val:0x%16lx, pte_val:0x%16lx\n",
                __func__, src_smv, pgd_val(*src_pgd), pud_val(*src_pud), pmd_val(*src_pmd), pte_val(*src_pte));
    printk(KERN_INFO "[%s] dst smv %d: pgd_val:0x%16lx, pud_val:0x%16lx, pmd_val:0x%16lx, pte_val:0x%16lx\n",
                __func__, dst_smv, pgd_val(*dst_pgd), pud_val(*dst_pud), pmd_val(*dst_pmd), pte_val(*dst_pte));

    spin_unlock(dst_ptl);

    // we only want to change the PTE protection bits of a new page if it's current
    // memdom access is write-only since mprotect clears the write bit
    if (vma->memdom_id > MAIN_THREAD && !(prot & VM_WRITE)) {
      set_pte_smv_protection(mm, address, vma, dst_smv, prot);
    }

    pte_unmap(dst_pte);
    
    /* By the time we get here, the page tables are set up correctly */
    rv = 0;

unlock_src:
    spin_unlock(src_ptl);
    pte_unmap(src_pte);

    if ( rv != 0 ) {
        printk(KERN_ERR "[%s] Error: !dst_pud, address 0x%16lx\n", __func__, address);
    } else{
        slog(KERN_INFO, "[%s] smv %d copied pte from MAIN_THREAD. addr 0x%16lx, *src_pte 0x%16lx, *dst_pte 0x%16lx\n",
               __func__, dst_smv, address, pte_val(*src_pte), pte_val(*dst_pte));
    }
    up_write(&mm->smv_metadataMutex);
    return rv;
}

