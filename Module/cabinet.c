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
#include <linux/pid.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/mmu_context.h>
#include <linux/slab.h>

extern long (*inspect_cabinet_ptr)(int pid, unsigned long vaddr, 
		struct cab_info *inventory);
extern long (*inspect_cabinet_default)(int pid, unsigned long vaddr, 
		struct cab_info *inventory);

//extern struct pid *find_get_pid(int nr);
static struct task_struct *task  = NULL;
static struct mm_struct   *mm    = NULL;


long copy_cabinet_to_user(unsigned long paddr,unsigned long pf_paddr,unsigned long pte_paddr,
			unsigned long pmd_paddr,unsigned long pud_paddr,unsigned long pgd_paddr,
			int modified,int refcount,struct cab_info *inventory)
{
	//pr_info("Begining to copy inventory...\n");

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

	//pr_info("Returning from copy\n");

	return (long) 0;
}

//From memory.c
static int 
follow_pte_helper(struct mm_struct *mm, unsigned long address, spinlock_t **ptlp,
		  struct cab_info *inventoryTemp)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep;

	unsigned long offset;

	struct page *pgd_page;
	struct page *pf_page;
	struct page *pte_page;
	struct page *pmd_page;
	struct page *pud_page;

	offset = address;

	if(virt_addr_valid(address))
		return -EINVAL;

	pgd = pgd_offset(mm, address);
	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
		goto out;

	pud = pud_offset(pgd, address);
	if (pud_none(*pud) || unlikely(pud_bad(*pud)))
		goto out;

	pmd = pmd_offset(pud, address);
	VM_BUG_ON(pmd_trans_huge(*pmd));
	if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd)))
		goto out;

	//pr_info("Locking pte...\n");

	ptep = pte_offset_map_lock(mm, pmd, address, ptlp);
	if (!ptep)
		goto out;
	if (!pte_present(*ptep))
		goto out;

	//pr_info("	Found pte\n");
	//Find pages
	pgd_page  = virt_to_page(pgd);
	pf_page   = pte_page(*ptep);
	pte_page  = pmd_page(*pmd);
	pmd_page  = pud_page(*pud);
	pud_page  = pgd_page(*pgd);

	//pr_info("	Found pages\n");

	inventoryTemp->paddr     = (unsigned long) pte_pfn(*ptep) << PAGE_SHIFT;
	offset                   = offset & ~PAGE_MASK;
	inventoryTemp->paddr     = inventoryTemp->paddr | offset;
	
	inventoryTemp->pgd_paddr = page_to_phys(pgd_page);
	inventoryTemp->pf_paddr  = page_to_phys(pf_page);
	inventoryTemp->pmd_paddr = page_to_phys(pmd_page);
	inventoryTemp->pud_paddr = page_to_phys(pud_page);
	inventoryTemp->pte_paddr = page_to_phys(pte_page);
	inventoryTemp->modified  = pte_dirty(*ptep);
	inventoryTemp->refcount  = (int) atomic_read(&mm->mm_users);  //Needs lock

	pte_unmap_unlock(ptep, *ptlp);
	
	//pr_info("Unlocked pte\n");

	return 0;

out:
	pte_unmap_unlock(ptep, *ptlp);

	inventoryTemp->paddr     = 0;
	inventoryTemp->pgd_paddr = 0;
	inventoryTemp->pf_paddr  = 0;
	inventoryTemp->pmd_paddr = 0;
	inventoryTemp->pud_paddr = 0;
	inventoryTemp->pte_paddr = 0;
	inventoryTemp->modified  = 0;
	inventoryTemp->refcount  = 0;

	return 0;
}

static int 
follow_pte(struct mm_struct *mm, unsigned long address, spinlock_t **ptlp,
	   struct cab_info *inventoryTemp)
{
	int res;

	/* (void) is needed to make gcc happy */
	(void) __cond_lock(*ptlp,!(res = follow_pte_helper(mm, address, ptlp,inventoryTemp)));

	return res;
}

long inspect_cabinet(int pid, unsigned long vaddr, struct cab_info *inventory)
{
	/* implement here */
	struct cab_info *inventoryTemp;
	struct pid *pid_struct;
	mm_segment_t old_fs;
	spinlock_t *ptlp;
	int err = 0;

	if(current_cred()->uid.val != 0)
		return -EPERM;
	if(pid < -1)
		return -EINVAL;
	if(!inventory)
		return -EFAULT;

	inventoryTemp = (struct cab_info*) kmalloc(sizeof(struct cab_info), GFP_KERNEL);
	if(!inventoryTemp)
		return -EFAULT;

	//pr_info("Begining PID SEARCH...\n");

	rcu_read_lock();
	{ // lock RCU

		if((pid_t) pid == -1){
			mm = get_task_mm(current);
		}
		else{
			//pr_info("	Searching for pid %d\n", pid);
			pid_struct = find_vpid((pid_t) pid);
			if(!pid_struct){
				err = -ESRCH;
				rcu_read_unlock();
				goto out;
			}
			//pr_info("	Found PID\n");
			task = pid_task(pid_struct, PIDTYPE_PID);
			if (!task){
				err = 0;
				rcu_read_unlock();
				goto out;
			}
			//pr_info("	Found TASK\n");
			mm = get_task_mm(task);
			//pr_info("	Found mm\n");
		}

	}
	rcu_read_unlock();

	//pr_info("Found mm and unlocked pid: %d\n", pid);

	if(mm) 
	{
		old_fs = get_fs();
		set_fs(USER_DS);
		{
			err = follow_pte(mm, vaddr, &ptlp, inventoryTemp);					
			if(err){
				set_fs(old_fs);
				mmput(mm);
				goto out;
			}
			err = copy_cabinet_to_user(inventoryTemp->paddr,inventoryTemp->pf_paddr,
				  	      inventoryTemp->pte_paddr,inventoryTemp->pmd_paddr,
					      inventoryTemp->pud_paddr,inventoryTemp->pgd_paddr,
					      inventoryTemp->modified,inventoryTemp->refcount, 
					      inventory);
		}
		set_fs(old_fs);
		mmput(mm);

		//pr_info("Put mm\n");

	}
	else{
		//pr_err("BAD mm for: %d\n", pid);
		err = -EINVAL;
		goto out;
	}
	
	//pr_info("Succedded for %d\n", pid);

out:
	//If the pointer to the struct cab_info is invalid, return EFAULT -!
	//If the specified PID does not exist, return ESRCH               -!
	//If the specified virtual address does not exist, return EINVAL 
        //pmd_paddr, pte_paddr, pf_paddr, paddr, modified, and refcount 
	//should all be set to 0, and inspect_cabinet() should return 0
	kfree(inventoryTemp);

	//pr_info("Returning with value: %d\n", err);

	return err;
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
