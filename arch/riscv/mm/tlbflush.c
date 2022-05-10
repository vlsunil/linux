// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt) "riscv: " fmt
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/sched.h>
#include <asm/sbi.h>
#include <asm/mmu_context.h>

static unsigned long tlb_flush_all_threshold __read_mostly = PTRS_PER_PTE;

static inline void local_flush_tlb_all_asid(unsigned long asid)
{
	__asm__ __volatile__ ("sfence.vma x0, %0"
			:
			: "r" (asid)
			: "memory");
}

static inline void local_flush_tlb_page_asid(unsigned long addr,
		unsigned long asid)
{
	__asm__ __volatile__ ("sfence.vma %0, %1"
			:
			: "r" (addr), "r" (asid)
			: "memory");
}

static inline void riscv_sfence_inval_ir(void)
{
	/*
	 * SFENCE.INVAL.IR
	 * 0001100 00001 00000 000 00000 1110011
	 */
	asm volatile (".word 0x18100073" ::: "memory");
}

static inline void riscv_sfence_w_inval(void)
{
	/*
	 * SFENCE.W.INVAL
	 * 0001100 00000 00000 000 00000 1110011
	 */
	asm volatile (".word 0x18000073" ::: "memory");
}

static inline void riscv_sinval_vma_asid(unsigned long vma, unsigned long asid)
{
	/*
	 * rs1 = a0 (VMA)
	 * rs2 = a1 (asid)
	 * SINVAL.VMA a0, a1
	 * 0001011 01011 01010 000 00000 1110011
	 */
	asm volatile ("srli a0, %0, 2\n"
			"add a1, %1, zero\n"
			".word 0x16B50073\n"
			:: "r" (vma), "r" (asid)
			: "a0", "a1", "memory");
}

static inline void riscv_sinval_vma(unsigned long vma)
{
	/*
	 * rs1 = a0 (VMA)
	 * rs2 = 0
	 * SINVAL.VMA a0
	 * 0001011 00000 01010 000 00000 1110011
	 */
	asm volatile ("srli a0, %0, 2\n"
			".word 0x16050073\n"
			:: "r" (vma) : "a0", "memory");
}

static inline void local_flush_tlb_range(unsigned long start,
		unsigned long size, unsigned long stride)
{
	if ((size / stride) <= tlb_flush_all_threshold) {
		if (riscv_use_flush_tlb_svinval()) {
			riscv_sfence_w_inval();
			while (size) {
				riscv_sinval_vma(start);
				start += stride;
				if (size > stride)
					size -= stride;
				else
					size = 0;
			}
			riscv_sfence_inval_ir();
		} else {
			while (size) {
				local_flush_tlb_page(start);
				start += stride;
				if (size > stride)
					size -= stride;
				else
					size = 0;
			}
		}
	} else {
		local_flush_tlb_all();
	}
}

static inline void local_flush_tlb_range_asid(unsigned long start,
		unsigned long size, unsigned long stride, unsigned long asid)
{
	if ((size / stride) <= tlb_flush_all_threshold) {
		if (riscv_use_flush_tlb_svinval()) {
			riscv_sfence_w_inval();
			while (size) {
				riscv_sinval_vma_asid(start, asid);
				start += stride;
				if (size > stride)
					size -= stride;
				else
					size = 0;
			}
			riscv_sfence_inval_ir();
		} else {
			while (size) {
				local_flush_tlb_page_asid(start, asid);
				start += stride;
				if (size > stride)
					size -= stride;
				else
					size = 0;
			}
		}
	} else {
		local_flush_tlb_all_asid(asid);
	}
}

static void __ipi_flush_tlb_all(void *info)
{
	local_flush_tlb_all();
}

void flush_tlb_all(void)
{
	if (riscv_use_ipi_for_rfence())
		on_each_cpu(__ipi_flush_tlb_all, NULL, 1);
	else
		sbi_remote_sfence_vma(NULL, 0, -1);
}

struct flush_tlb_range_data {
	unsigned long asid;
	unsigned long start;
	unsigned long size;
	unsigned long stride;
};

static void __ipi_flush_tlb_range_asid(void *info)
{
	struct flush_tlb_range_data *d = info;

	local_flush_tlb_range_asid(d->start, d->size, d->stride, d->asid);
}

static void __ipi_flush_tlb_range(void *info)
{
	struct flush_tlb_range_data *d = info;

	local_flush_tlb_range(d->start, d->size, d->stride);
}

static void __flush_tlb_range(struct mm_struct *mm, unsigned long start,
			      unsigned long size, unsigned long stride)
{
	struct flush_tlb_range_data ftd;
	struct cpumask *cmask = mm_cpumask(mm);
	unsigned int cpuid;
	bool broadcast;

	if (cpumask_empty(cmask))
		return;

	cpuid = get_cpu();
	/* check if the tlbflush needs to be sent to other CPUs */
	broadcast = cpumask_any_but(cmask, cpuid) < nr_cpu_ids;
	if (static_branch_unlikely(&use_asid_allocator)) {
		unsigned long asid = atomic_long_read(&mm->context.id);

		if (broadcast) {
			if (riscv_use_ipi_for_rfence()) {
				ftd.asid = asid;
				ftd.start = start;
				ftd.size = size;
				ftd.stride = stride;
				on_each_cpu_mask(cmask,
						 __ipi_flush_tlb_range_asid,
						 &ftd, 1);
			} else
				sbi_remote_sfence_vma_asid(cmask,
							   start, size, asid);
		} else {
			local_flush_tlb_range_asid(start, size, stride, asid);
		}
	} else {
		if (broadcast) {
			if (riscv_use_ipi_for_rfence()) {
				ftd.asid = 0;
				ftd.start = start;
				ftd.size = size;
				ftd.stride = stride;
				on_each_cpu_mask(cmask,
						 __ipi_flush_tlb_range,
						 &ftd, 1);
			} else
				sbi_remote_sfence_vma(cmask, start, size);
		} else {
			local_flush_tlb_range(start, size, stride);
		}
	}

	put_cpu();
}

void flush_tlb_mm(struct mm_struct *mm)
{
	__flush_tlb_range(mm, 0, -1, PAGE_SIZE);
}

void flush_tlb_page(struct vm_area_struct *vma, unsigned long addr)
{
	__flush_tlb_range(vma->vm_mm, addr, PAGE_SIZE, PAGE_SIZE);
}

void flush_tlb_range(struct vm_area_struct *vma, unsigned long start,
		     unsigned long end)
{
	__flush_tlb_range(vma->vm_mm, start, end - start, PAGE_SIZE);
}
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
void flush_pmd_tlb_range(struct vm_area_struct *vma, unsigned long start,
			unsigned long end)
{
	__flush_tlb_range(vma->vm_mm, start, end - start, PMD_SIZE);
}
#endif

DEFINE_STATIC_KEY_FALSE(riscv_flush_tlb_svinval);
EXPORT_SYMBOL_GPL(riscv_flush_tlb_svinval);

void riscv_tlbflush_init(void)
{
	if (riscv_isa_extension_available(NULL, SVINVAL)) {
		pr_info("Svinval extension supported\n");
		static_branch_enable(&riscv_flush_tlb_svinval);
	} else {
		static_branch_disable(&riscv_flush_tlb_svinval);
	}
}
