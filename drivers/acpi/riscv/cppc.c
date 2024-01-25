// SPDX-License-Identifier: GPL-2.0-only
/*
 * Implement CPPC FFH helper routines for RISC-V.
 *
 * Copyright (C) 2024 Ventana Micro Systems Inc.
 */

#include <asm/sbi.h>
#include <acpi/cppc_acpi.h>
#include <asm/csr.h>

static int cppc_ext_present = -1;

static bool sbi_cppc_ext_present(void)
{
	if (cppc_ext_present < 0) {
		if (sbi_spec_version >= sbi_mk_version(2, 0) &&
		    sbi_probe_extension(SBI_EXT_CPPC) > 0) {
			pr_info("SBI CPPC extension detected\n");
			cppc_ext_present = 1;
		} else {
			pr_info("SBI CPPC extension NOT detected!!\n");
			cppc_ext_present = 0;
		}
	}

	return cppc_ext_present ? true : false;
}

static void cppc_ffh_csr_read(void *read_data)
{
	struct sbi_cppc_data *data = (struct sbi_cppc_data *)read_data;

	switch (data->reg) {
	/* Support only TIME CSR for now */
	case CSR_TIME:
		data->ret.value = csr_read(CSR_TIME);
		data->ret.error = 0;
		break;
	default:
		data->ret.error = -EINVAL;
		break;
	}
}

static void cppc_ffh_csr_write(void *write_data)
{
	struct sbi_cppc_data *data = (struct sbi_cppc_data *)write_data;

	data->ret.error = -EINVAL;
}

/*
 * Refer to drivers/acpi/cppc_acpi.c for the description of the functions
 * below.
 */
bool cpc_ffh_supported(void)
{
	return true;
}

int cpc_read_ffh(int cpu, struct cpc_reg *reg, u64 *val)
{
	struct sbi_cppc_data data;

	if (WARN_ON_ONCE(irqs_disabled()))
		return -EPERM;

	if (FFH_CPPC_TYPE(reg->address) == FFH_CPPC_SBI) {
		if (!sbi_cppc_ext_present())
			return -EINVAL;

		data.reg = FFH_CPPC_SBI_REG(reg->address);

		smp_call_function_single(cpu, sbi_cppc_read, &data, 1);

		*val = data.ret.value;

		return (data.ret.error) ? sbi_err_map_linux_errno(data.ret.error) : 0;
	} else if (FFH_CPPC_TYPE(reg->address) == FFH_CPPC_CSR) {
		data.reg = FFH_CPPC_CSR_NUM(reg->address);

		smp_call_function_single(cpu, cppc_ffh_csr_read, &data, 1);

		*val = data.ret.value;

		return (data.ret.error) ? sbi_err_map_linux_errno(data.ret.error) : 0;
	}

	return -EINVAL;
}

int cpc_write_ffh(int cpu, struct cpc_reg *reg, u64 val)
{
	struct sbi_cppc_data data;

	if (WARN_ON_ONCE(irqs_disabled()))
		return -EPERM;

	if (FFH_CPPC_TYPE(reg->address) == FFH_CPPC_SBI) {
		if (!sbi_cppc_ext_present())
			return -EINVAL;

		data.reg = FFH_CPPC_SBI_REG(reg->address);
		data.val = val;

		smp_call_function_single(cpu, sbi_cppc_write, &data, 1);

		return (data.ret.error) ? sbi_err_map_linux_errno(data.ret.error) : 0;
	} else if (FFH_CPPC_TYPE(reg->address) == FFH_CPPC_CSR) {
		data.reg = FFH_CPPC_CSR_NUM(reg->address);
		data.val = val;

		smp_call_function_single(cpu, cppc_ffh_csr_write, &data, 1);

		return (data.ret.error) ? sbi_err_map_linux_errno(data.ret.error) : 0;
	}

	return -EINVAL;
}
