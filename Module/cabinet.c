/*
 * cabinet.c
 */
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <asm/pgtable.h>
#include <asm/page.h>
#include <linux/sched.h>
#include <linux/cabinet.h>
#include <linux/cred.h>


extern long (*inspect_cabinet_ptr)(int pid, unsigned long vaddr, 
		struct cab_info *inventory);
extern long (*inspect_cabinet_default)(int pid, unsigned long vaddr, 
		struct cab_info *inventory);

long copy_cabinet_to_user(unsigned long paddr,unsigned long pf_paddr,unsigned long pte_paddr,
			unsigned long pmd_paddr,unsigned long pud_paddr,unsigned long pgd_paddr,
			int modified,int refcount,struct cab_info *inventory)
{
	if(!inventory)
	    return -EFAULT;

	if(copy_to_user(&inventory->paddr, &paddr, sizeof(paddr))) 
            return -EFAULT;	
	if(copy_to_user(&inventory->pf_paddr, &pf_paddr, sizeof(pf_paddr))) 
            return -EFAULT;
	if(copy_to_user(&inventory->pte_paddr, &pte_paddr, sizeof(pte_paddr))) 
            return -EFAULT;
	if(copy_to_user(&inventory->pmd_paddr, &pmd_paddr, sizeof(pmd_paddr))) 
            return -EFAULT;
	if(copy_to_user(&inventory->pud_paddr, &pud_paddr, sizeof(pud_paddr))) 
            return -EFAULT;
	if(copy_to_user(&inventory->pgd_paddr, &pgd_paddr, sizeof(pgd_paddr))) 
            return -EFAULT;
	if(copy_to_user(&inventory->modified, &modified, sizeof(modified))) 
            return -EFAULT;
	if(copy_to_user(&inventory->refcount, &refcount, sizeof(refcount))) 
            return -EFAULT;

	return 0;
}

long inspect_cabinet(int pid, unsigned long vaddr, struct cab_info *inventory)
{
	/* implement here */
        pgd_t *pgd;
        pud_t *pud;
        pmd_t *pmd;
        pte_t *ptep;
	pte_t *pte;
	struct mm_struct *mm;
	//spinlock_t *ptl = &mm->page_table_lock;

	struct page *pgd_page;
	struct page *pf_page;
	struct page *pte_page;
	struct page *pmd_page;
	struct page *pud_page;
	//kuid_t uid;

	//return variables don't want to set until we are sure no errors
	unsigned long paddr;        // the physical address the virtual address is mapped to 
        unsigned long pf_paddr;     // the physical address of its page 
        unsigned long pte_paddr;    // the physical address of its PTE 
        unsigned long pmd_paddr;    // the physical address of its PMD 
        unsigned long pud_paddr;    // the physical address of its PUD 
        unsigned long pgd_paddr;    // the physical address of its PGD 
        int modified;               // 1 if modified, 0 otherwise 
        int refcount;               // number of processes sharing the address 

	//Tests before we set cab_info
	//paddr = virt_to_phys(vaddr);
	//ret = 0;
	//if(current_cred()->uid != 0)
		//return (long) EPERM;

	//if(pid < -1)
		//return (long) EINVAL;
	//If the pointer to the struct cab_info is invalid, return EFAULT
	//If the specified PID does not exist, return ESRCH
	//If the specified virtual address does not exist, return EINVAL

	mm = current->mm;
	pgd = pgd_offset(mm, vaddr);
        if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
                goto out;
	pr_info("Found pgd\n");

	pud = pud_offset(pgd, vaddr);
        if (pud_none(*pud) || unlikely(pud_bad(*pud)))
                goto out;
	pr_info("Found pud\n");

        pmd = pmd_offset(pud, vaddr);
        VM_BUG_ON(pmd_trans_huge(*pmd));
        if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd)))
                goto out;
	pr_info("Found pmd\n");

        ptep = pte_offset_map(pmd, vaddr);
        if (!ptep)
                goto out;
        if (!pte_present(*ptep))
                goto unlock;
        pte = ptep;
	//pte_unmap_unlock(ptep, &mm->page_table_lock);

	pr_info("Found pte\n");

	//Find pages
	paddr     = (unsigned long) virt_to_phys(&vaddr);
	pgd_page  = virt_to_page(pgd);
	pf_page   = pte_page(*pte);
	pte_page  = pmd_page(*pmd);
	pmd_page  = pud_page(*pud);
	pud_page  = pgd_page(*pgd);
	
	pgd_paddr = page_to_phys(pgd_page);
	pf_paddr  = page_to_phys(pf_page);
	pmd_paddr = page_to_phys(pmd_page);
	pud_paddr = page_to_phys(pud_page);
	pte_paddr = page_to_phys(pte_page);
	modified  = pte_dirty(*pte);
	refcount  = 69;
	
        return copy_cabinet_to_user(paddr,pf_paddr,pte_paddr,pmd_paddr,
				    pud_paddr,pgd_paddr,modified,refcount,
				    inventory);
unlock:
        //pte_unmap_unlock(ptep, &mm->page_table_lock);

out:
	//pmd_paddr, pte_paddr, pf_paddr, paddr, modified, and refcount 
	//should all be set to 0, and inspect_cabinet() should return 0
	copy_cabinet_to_user(0,0,0,0,0,0,0,0,inventory);

        return -EINVAL;
}


int cabinet_init(void)
{
	pr_info("Installing cabinet\n");
	inspect_cabinet_ptr = inspect_cabinet;
	return 0;
}

void cabinet_exit(void)
{
	pr_info("Removing cabinet\n");
	inspect_cabinet_ptr = inspect_cabinet_default;
}

module_init(cabinet_init);
module_exit(cabinet_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Cabinet: a virtual to physical memory mapper");
MODULE_AUTHOR("W4118");
