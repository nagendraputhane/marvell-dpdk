/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdarg.h>

#include "roc_api.h"
#include "roc_priv.h"

__attribute__((__format__(__printf__, 2, 0))) static inline void
dpi_dump(FILE *file, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	if (file == NULL)
		vfprintf(stdout, fmt, args);
	else
		vfprintf(file, fmt, args);
	va_end(args);
}

#define DPI_PF_MBOX_SYSFS_ENTRY "dpi_device_config"

static inline int
send_msg_to_pf(struct plt_pci_addr *pci_addr, const char *value, int size)
{
	char buf[255] = {0};
	int res, fd;

	res = snprintf(
		buf, sizeof(buf), "/sys/bus/pci/devices/" PCI_PRI_FMT "/%s",
		pci_addr->domain, pci_addr->bus, DPI_PF_DBDF_DEVICE & 0x7,
		DPI_PF_DBDF_FUNCTION & 0x7, DPI_PF_MBOX_SYSFS_ENTRY);

	if ((res < 0) || ((size_t)res > sizeof(buf)))
		return -ERANGE;

	fd = open(buf, O_WRONLY);
	if (fd < 0)
		return -EACCES;

	res = write(fd, value, size);
	close(fd);
	if (res < 0)
		return -EACCES;

	return 0;
}

static inline int
recv_msg_from_pf(struct plt_pci_addr *pci_addr, char *value, int size)
{
	char buf[255] = {0};
	int res, fd;

	res = snprintf(
		buf, sizeof(buf), "/sys/bus/pci/devices/" PCI_PRI_FMT "/%s",
		pci_addr->domain, pci_addr->bus, DPI_PF_DBDF_DEVICE & 0x7,
		DPI_PF_DBDF_FUNCTION & 0x7, DPI_PF_MBOX_SYSFS_ENTRY);

	if ((res < 0) || ((size_t)res > sizeof(buf)))
		return -ERANGE;

	fd = open(buf, O_RDONLY);
	if (fd < 0)
		return -EACCES;

	res = read(fd, value, size);
	close(fd);
	if (res < 0)
		return -EACCES;

	return 0;
}

int
roc_dpi_wait_queue_idle(struct roc_dpi *roc_dpi)
{
	const uint64_t cyc = (DPI_QUEUE_IDLE_TMO_MS * plt_tsc_hz()) / 1E3;
	const uint64_t start = plt_tsc_cycles();
	uint64_t reg;

	/* Wait for SADDR to become idle */
	reg = plt_read64(roc_dpi->rbase + DPI_VDMA_SADDR);
	while (!(reg & BIT_ULL(63))) {
		reg = plt_read64(roc_dpi->rbase + DPI_VDMA_SADDR);
		if (plt_tsc_cycles() - start == cyc)
			return -ETIMEDOUT;
	}

	return 0;
}

int
roc_dpi_enable(struct roc_dpi *dpi)
{
	plt_write64(0x1, dpi->rbase + DPI_VDMA_EN);
	return 0;
}

int
roc_dpi_disable(struct roc_dpi *dpi)
{
	plt_write64(0x0, dpi->rbase + DPI_VDMA_EN);
	return 0;
}

int
roc_dpi_configure(struct roc_dpi *roc_dpi, uint32_t chunk_sz, uint64_t aura, uint64_t chunk_base)
{
	struct plt_pci_device *pci_dev;
	dpi_mbox_msg_t mbox_msg;
	uint64_t reg;
	int rc;

	if (!roc_dpi) {
		plt_err("roc_dpi is NULL");
		return -EINVAL;
	}

	pci_dev = roc_dpi->pci_dev;

	roc_dpi_disable(roc_dpi);
	reg = plt_read64(roc_dpi->rbase + DPI_VDMA_SADDR);
	while (!(reg & BIT_ULL(63)))
		reg = plt_read64(roc_dpi->rbase + DPI_VDMA_SADDR);

	plt_write64(0x0, roc_dpi->rbase + DPI_VDMA_REQQ_CTL);
	plt_write64(chunk_base, roc_dpi->rbase + DPI_VDMA_SADDR);
	mbox_msg.u[0] = 0;
	mbox_msg.u[1] = 0;
	/* DPI PF driver expects vfid starts from index 0 */
	mbox_msg.s.vfid = roc_dpi->vfid;
	mbox_msg.s.cmd = DPI_QUEUE_OPEN;
	mbox_msg.s.csize = chunk_sz;
	mbox_msg.s.aura = aura;
	mbox_msg.s.sso_pf_func = idev_sso_pffunc_get();
	mbox_msg.s.npa_pf_func = idev_npa_pffunc_get();
	mbox_msg.s.wqecsoff = idev_dma_cs_offset_get();
	if (mbox_msg.s.wqecsoff)
		mbox_msg.s.wqecs = 1;

	rc = send_msg_to_pf(&pci_dev->addr, (const char *)&mbox_msg, sizeof(dpi_mbox_msg_t));
	if (rc < 0)
		plt_err("Failed to send mbox message %d to DPI PF, err %d", mbox_msg.s.cmd, rc);

	return rc;
}

int
roc_dpi_configure_v2(struct roc_dpi *roc_dpi, uint32_t chunk_sz, uint64_t aura, uint64_t chunk_base)
{
	struct plt_pci_device *pci_dev;
	dpi_mbox_msg_t mbox_msg;
	uint64_t reg;
	int rc;

	if (!roc_dpi) {
		plt_err("roc_dpi is NULL");
		return -EINVAL;
	}

	pci_dev = roc_dpi->pci_dev;

	roc_dpi_disable(roc_dpi);
	reg = plt_read64(roc_dpi->rbase + DPI_VDMA_SADDR);
	while (!(reg & BIT_ULL(63)))
		reg = plt_read64(roc_dpi->rbase + DPI_VDMA_SADDR);

	plt_write64(0x0, roc_dpi->rbase + DPI_VDMA_REQQ_CTL);
	plt_write64(chunk_base, roc_dpi->rbase + DPI_VDMA_SADDR);
	mbox_msg.u[0] = 0;
	mbox_msg.u[1] = 0;
	/* DPI PF driver expects vfid starts from index 0 */
	mbox_msg.s.vfid = roc_dpi->vfid;
	mbox_msg.s.cmd = DPI_QUEUE_OPEN_V2;
	mbox_msg.s.csize = chunk_sz / 8;
	mbox_msg.s.aura = aura;
	mbox_msg.s.sso_pf_func = idev_sso_pffunc_get();
	mbox_msg.s.npa_pf_func = idev_npa_pffunc_get();
	mbox_msg.s.wqecsoff = idev_dma_cs_offset_get();
	if (mbox_msg.s.wqecsoff)
		mbox_msg.s.wqecs = 1;

	rc = send_msg_to_pf(&pci_dev->addr, (const char *)&mbox_msg, sizeof(dpi_mbox_msg_t));
	if (rc < 0)
		plt_err("Failed to send mbox message %d to DPI PF, err %d", mbox_msg.s.cmd, rc);

	return rc;
}

int
roc_dpi_dev_init(struct roc_dpi *roc_dpi, uint8_t offset)
{
	struct plt_pci_device *pci_dev = roc_dpi->pci_dev;
	uint16_t vfid;

	roc_dpi->rbase = pci_dev->mem_resource[0].addr;
	vfid = ((pci_dev->addr.devid & 0x1F) << 3) | (pci_dev->addr.function & 0x7);
	vfid -= 1;
	roc_dpi->vfid = vfid;
	idev_dma_cs_offset_set(offset);

	return 0;
}

int
roc_dpi_dev_fini(struct roc_dpi *roc_dpi)
{
	struct plt_pci_device *pci_dev = roc_dpi->pci_dev;
	dpi_mbox_msg_t mbox_msg;
	uint64_t reg;
	int rc;

	/* Wait for SADDR to become idle */
	reg = plt_read64(roc_dpi->rbase + DPI_VDMA_SADDR);
	while (!(reg & BIT_ULL(63)))
		reg = plt_read64(roc_dpi->rbase + DPI_VDMA_SADDR);

	mbox_msg.u[0] = 0;
	mbox_msg.u[1] = 0;
	mbox_msg.s.vfid = roc_dpi->vfid;
	mbox_msg.s.cmd = DPI_QUEUE_CLOSE;

	rc = send_msg_to_pf(&pci_dev->addr, (const char *)&mbox_msg, sizeof(dpi_mbox_msg_t));
	if (rc < 0)
		plt_err("Failed to send mbox message %d to DPI PF, err %d", mbox_msg.s.cmd, rc);

	return rc;
}

void
roc_dpi_dev_dump(struct roc_dpi *dpi, FILE *file)
{
	struct plt_pci_device *pci_dev = dpi->pci_dev;
	char buff[16384];
	int rc;

	dpi_dump(file, "VF %d DPI_VDMA_EN     \t0x%" PRIx64 "\n", dpi->vfid,
		 plt_read64(dpi->rbase + DPI_VDMA_EN));
	dpi_dump(file, "VF %d DPI_VDMA_DBELL  \t0x%" PRIx64 "\n", dpi->vfid,
		 plt_read64(dpi->rbase + DPI_VDMA_DBELL));
	dpi_dump(file, "VF %d DPI_VDMA_SADDR  \t0x%" PRIx64 "\n", dpi->vfid,
		 plt_read64(dpi->rbase + DPI_VDMA_SADDR));
	dpi_dump(file, "VF %d DPI_VDMA_COUNTS \t0x%" PRIx64 "\n", dpi->vfid,
		 plt_read64(dpi->rbase + DPI_VDMA_COUNTS));
	dpi_dump(file, "VF %d DPI_VDMA_NADDR  \t0x%" PRIx64 "\n", dpi->vfid,
		 plt_read64(dpi->rbase + DPI_VDMA_NADDR));
	dpi_dump(file, "VF %d DPI_VDMA_IWBUSY \t0x%" PRIx64 "\n", dpi->vfid,
		 plt_read64(dpi->rbase + DPI_VDMA_IWBUSY));
	rc = recv_msg_from_pf(&pci_dev->addr, buff, 16384);
	if (rc < 0) {
		plt_err("Failed to receive mbox message from DPI PF, err %d", rc);
		return;
	}
	dpi_dump(file, "%s\n", buff);
}
