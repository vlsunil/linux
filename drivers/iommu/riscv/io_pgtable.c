// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2022 Rivos Inc.
 * Author: Tomasz Jeznach <tjeznach@rivosinc.com>
 */

#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/io-pgtable.h>
#include <linux/kernel.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/dma-mapping.h>

#include "iommu.h"

#define io_pgtable_ops_to_domain(x) \
	container_of(container_of((x), struct io_pgtable, ops), \
			     struct riscv_iommu_domain, pgtbl)

#define io_pgtable_to_domain(x) \
	container_of((x), struct riscv_iommu_domain, pgtbl)

static inline size_t get_page_size(size_t size)
{
       if (size >= IOMMU_PAGE_SIZE_512G)
               return IOMMU_PAGE_SIZE_512G;

       if (size >= IOMMU_PAGE_SIZE_1G)
               return IOMMU_PAGE_SIZE_1G;

       if (size >= IOMMU_PAGE_SIZE_2M)
               return IOMMU_PAGE_SIZE_2M;

       return IOMMU_PAGE_SIZE_4K;
}

static void riscv_iommu_pt_walk_free(pmd_t *ptp, unsigned shift, bool root)
{
	pmd_t *pte, *pt_base;
	int i;

	if (shift == PAGE_SHIFT)
		return;

	if (root)
		pt_base = ptp;
	else
		pt_base = (pmd_t *)pfn_to_virt(__page_val_to_pfn(pmd_val(*ptp)));

	for (i = 0; i < PTRS_PER_PMD; i++) {
		pte = pt_base + i;
		// Recursively free all sub page table pages
		if (pmd_present(*pte) && !pmd_leaf(*pte))
			riscv_iommu_pt_walk_free(pte, shift - 9, false);
	}

	// Now free the current page table page
	if (!root && pmd_present(*pt_base))
		free_page((unsigned long)pt_base);
}

static void riscv_iommu_free_pgtable(struct io_pgtable *iop)
{
	struct riscv_iommu_domain *domain = io_pgtable_to_domain(iop);
	riscv_iommu_pt_walk_free((pmd_t *)domain->pgd_root, PGDIR_SHIFT, true);
}

static pte_t *riscv_iommu_pt_walk_alloc(pmd_t *ptp,
				   unsigned long iova,
				   unsigned shift, bool root, size_t pgsize,
				   unsigned long (*pd_alloc)(gfp_t), gfp_t gfp)
{
	pmd_t *pte;
	unsigned long pfn;

	if (root)
		pte = ptp + ((iova >> shift) & (PTRS_PER_PMD - 1));
	else
		pte = (pmd_t *)pfn_to_virt(__page_val_to_pfn(pmd_val(*ptp))) +
				((iova >> shift) & (PTRS_PER_PMD - 1));

	if ((1ULL << shift) <= pgsize) {
		if (pmd_present(*pte)) {
			if (!pmd_leaf(*pte))
				riscv_iommu_pt_walk_free(pte, shift - 9, false);
		}
		return (pte_t *)pte;
	}

	if (pmd_none(*pte)) {
		pfn = pd_alloc ? virt_to_pfn(pd_alloc(gfp)) : 0;
		if (!pfn)
			return NULL;
		set_pmd(pte, __pmd((pfn << _PAGE_PFN_SHIFT) | _PAGE_TABLE));
	}

	return riscv_iommu_pt_walk_alloc(pte, iova, shift - 9, false,
									 pgsize, pd_alloc, gfp);
}

static pte_t *riscv_iommu_pt_walk_fetch(pmd_t *ptp,
				   unsigned long iova, unsigned shift, bool root)
{
	pmd_t *pte;

	if (root)
		pte = ptp + ((iova >> shift) & (PTRS_PER_PMD - 1));
	else
		pte = (pmd_t *)pfn_to_virt(__page_val_to_pfn(pmd_val(*ptp))) +
				((iova >> shift) & (PTRS_PER_PMD - 1));

	if (pmd_leaf(*pte))
		return (pte_t *)pte;
	else if (pmd_none(*pte))
		return NULL;
	else if (shift == PAGE_SHIFT)
		return NULL;

	return riscv_iommu_pt_walk_fetch(pte, iova, shift - 9, false);
}

static int riscv_iommu_map_pages(struct io_pgtable_ops *ops,
				 unsigned long iova, phys_addr_t phys,
				 size_t pgsize, size_t pgcount, int prot,
				 gfp_t gfp, size_t *mapped)
{
	struct riscv_iommu_domain *domain = io_pgtable_ops_to_domain(ops);
	size_t size = 0;
	size_t page_size = get_page_size(pgsize);
	pte_t *pte;
	pte_t pte_val;
	pgprot_t pte_prot;

	if (domain->domain.type == IOMMU_DOMAIN_BLOCKED)
		return -ENODEV;

	if (domain->domain.type == IOMMU_DOMAIN_IDENTITY) {
		// TODO: should we be here ?
		*mapped = pgsize * pgcount;
		return 0;
	}

	pte_prot = (prot & IOMMU_WRITE) ?
		__pgprot(_PAGE_BASE | _PAGE_READ | _PAGE_WRITE | _PAGE_DIRTY) :
		__pgprot(_PAGE_BASE | _PAGE_READ);

	while (pgcount--) {
		pte = riscv_iommu_pt_walk_alloc((pmd_t *)domain->pgd_root,
										iova,
										PGDIR_SHIFT,
										true,
										page_size,
										get_zeroed_page,
										gfp);
		if (!pte) {
			*mapped = size;
			return -ENOMEM;
		}

		pte_val = pfn_pte(phys_to_pfn(phys), pte_prot);

		set_pte(pte, pte_val);

		size += page_size;
		iova += page_size;
		phys += page_size;
	}

	*mapped = size;
	return 0;
}

static size_t riscv_iommu_unmap_pages(struct io_pgtable_ops *ops,
				      unsigned long iova, size_t pgsize,
				      size_t pgcount,
				      struct iommu_iotlb_gather *gather)
{
	struct riscv_iommu_domain *domain = io_pgtable_ops_to_domain(ops);
	size_t size = 0;
	size_t page_size = get_page_size(pgsize);
	pte_t *pte;

	if (domain->domain.type == IOMMU_DOMAIN_IDENTITY)
		return pgsize * pgcount;

	while (pgcount--) {
		pte = riscv_iommu_pt_walk_fetch((pmd_t *)domain->pgd_root,
										iova, PGDIR_SHIFT, true);
		if (!pte)
			return size;

		// release pages
		set_pte(pte, __pte(0));

		size += page_size;
		iova += page_size;
	}

	return size;
}

static phys_addr_t riscv_iommu_iova_to_phys(struct io_pgtable_ops *ops,
					    unsigned long iova)
{
	struct riscv_iommu_domain *domain = io_pgtable_ops_to_domain(ops);
	pte_t *pte;

	if (domain->domain.type == IOMMU_DOMAIN_IDENTITY)
		return (phys_addr_t) iova;

	pte = riscv_iommu_pt_walk_fetch((pmd_t *)domain->pgd_root,
									iova, PGDIR_SHIFT, true);
	if (!pte || !pte_present(*pte))
		return 0;

	return (pfn_to_phys(pte_pfn(*pte)) | (iova & PAGE_MASK));
}

static void riscv_iommu_tlb_inv_all(void *cookie)
{
	printk("IOMMU TLB INVAL ALL\n");
}

static void riscv_iommu_tlb_inv_walk(unsigned long iova, size_t size,
				     size_t granule, void *cookie)
{
	printk("IOMMU TLB INVAL\n");
}

static void riscv_iommu_tlb_add_page(struct iommu_iotlb_gather *gather,
				     unsigned long iova, size_t granule,
				     void *cookie)
{
	printk("IOMMU TLB ADD PAGE\n");
}

static const struct iommu_flush_ops riscv_iommu_flush_ops = {
	.tlb_flush_all	= riscv_iommu_tlb_inv_all,
	.tlb_flush_walk	= riscv_iommu_tlb_inv_walk,
	.tlb_add_page	= riscv_iommu_tlb_add_page,
};

/* NOTE: cfg should point to riscv_iommu_domain structure member pgtbl.cfg */
static struct io_pgtable *riscv_iommu_alloc_pgtable(struct io_pgtable_cfg *cfg,
						    void *cookie)
{
//	struct riscv_iommu_domain *domain = cookie;
	struct io_pgtable *iop = container_of(cfg, struct io_pgtable, cfg);

	cfg->pgsize_bitmap = SZ_4K,
	cfg->ias = 57;	// va mode, SvXX -> ias
	cfg->oas = 57;	// pa mode, or SvXX+4 -> oas
        cfg->tlb = &riscv_iommu_flush_ops;

	iop->ops.map_pages    = riscv_iommu_map_pages;
	iop->ops.unmap_pages  = riscv_iommu_unmap_pages;
	iop->ops.iova_to_phys = riscv_iommu_iova_to_phys;

	printk("io-pgtable for riscv allocated\n");

	return iop;
}

struct io_pgtable_init_fns io_pgtable_riscv_init_fns = {
	.alloc = riscv_iommu_alloc_pgtable,
	.free = riscv_iommu_free_pgtable,
};
