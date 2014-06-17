/*
 * Copyright (c) 2012 Citrix Systems, Inc.
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef __AHCI_H
#define __AHCI_H


/*
 * AHCI HBA Memory Registers.
 */

enum ahci_regs {
	GHC_CAP = 0,
	GHC_GHC = 0x4,
	GHC_IS = 0x8,
	GHC_PI = 0xc,
	GHC_VS = 0x10,
	GHC_CCC_CTL = 0x14,
	GHC_CCC_PORTS = 0x18,
	GHC_EM_LOC = 0x1c,
	GHC_EM_CTL = 0x20,
	GHC_CAP2 = 0x24,
	GHC_BOHC = 0x28,
	GHC_SIZE = 0x30,

	PORT0_START = 0x100
};

/* GHC Bits */
enum ahci_regs_bits {
	/* HBA Capabilities */
	GHC_CAP_S64A = 31,
	GHC_CAP_SNCQ = 30,
	GHC_CAP_SSNTF = 29,
	GHC_CAP_SMPS = 28,
	GHC_CAP_SSS = 27,
	GHC_CAP_SALP = 26,
	GHC_CAP_SAL = 25,
	GHC_CAP_SCLO = 24,
	GHC_CAP_ISS = 20,
	GHC_CAP_SAM = 18,
	GHC_CAP_SPM = 17,
	GHC_CAP_FBSS = 16,
	GHC_CAP_PMD = 15,
	GHC_CAP_SSC = 14,
	GHC_CAP_PSC = 13,
	GHC_CAP_NCS = 8,
	GHC_CAP_CCCS = 7,
	GHC_CAP_EMS = 6,
	GHC_CAP_SXS = 5,
	GHC_CAP_NP = 0,

	/* Global HBA Control */
	GHC_GHC_AE = 31,
	GHC_GHC_MRSM = 2,
	GHC_GHC_IE = 1,
	GHC_GHC_HR = 0,
};

/* Port Control Register offsets */
enum ahci_port_regs {
	PxCLB = 0,
	PxCLBU = 0x4,
	PxFB = 0x8,
	PxFBU = 0xc,
	PxIS = 0x10,
	PxIE = 0x14,
	PxCMD = 0x18,
	PxTFD = 0x20,
	PxSIG = 0x24,
	PxSSTS = 0x28,
	PxSCTL = 0x2c,
	PxSERR = 0x30,
	PxSACT = 0x34,
	PxCI = 0x38,
	PxSNTF = 0x4c,
	PxFBS = 0x40,
	PxVS = 0x70,
	PxSIZE = 0x80,
};

enum ahci_port_reg_bits {
	PxCMD_CR = 15,
	PxCMD_FR = 14,
	PxCMD_FRE = 4,
	PxCMD_POD = 2,
	PxCMD_SUD = 1,
	PxCMD_ST = 0,

	PxTFD_STS_BSY = 7,
	PxTFD_STS_DRQ = 3,
	PxTFD_STS_ERR = 0,

	PxSERR_ERR_P = 10,
	PxSERR_ERR_E = 11,
};

enum ahci_port_vals {
	PxSSTS_PWR =	0x100,
	PxSSTS_SPD1 =	0x010,
	PxSSTS_SPD2 =	0x020,
	PxSSTS_SPD3 =	0x030,
	PxSSTS_NOPHY =	0x001,
	PxSSTS_DETD =	0x003,
	PxSSTS_ON = (PxSSTS_PWR|PxSSTS_SPD1|PxSSTS_DETD),

	PxSIG_ATAPI =	0xeb140001,
	PxSIG_ATA =	0x00000001,
};

enum ahci_intr {
	PxIS_TFES = 30,
	PxIS_HBFS = 29,
	PxIS_IFS = 27,
	PxIS_SDBS = 3,
	PxIS_DSS = 2,
	PxIS_PSS = 1,
	PxIS_DHRS = 0,
};

enum ahci_fb {
	FB_DMAFIS_OFFSET = 0x00,
	FB_PIOFIS_OFFSET = 0x20,
	FB_REGFIS_OFFSET = 0x40,
	FB_SDBFIS_OFFSET = 0x58,
};

enum ahci_cmdhdr {
	CMDHDR_C = 10,
	CMDHDR_BIST = 9,
	CMDHDR_R = 8,
	CMDHDR_P = 7,
	CMDHDR_W = 6,
	CMDHDR_A = 5,

	CMDHDR_SIZE = 8 * sizeof(uint32_t),

	CMDTBL_CFIS_OFFSET = 0x0,
	CMDTBL_ACMD_OFFSET = 0x40,
	CMDTBL_PRDT_OFFSET = 0x80,

	PRDT_SIZE = 4,
};

#define MMIO_PORT(__n, __port) (PORT0_START + ((__n) * PxSIZE) + (__port))
#define MMIO_PORTNO(__off) (((__off) - PORT0_START) >> 7)
#define MMIO_PORTOFF(__off) (((__off) - PORT0_START) & 0x7f)
#define IS_PORT_MMIO(__off) ((__off) >= PORT0_START)

/* AHCI Emulation Configuration */

#define AHCI_MAX_PORTS 30 /* Must leave one free to support CCC */
#define AHCI_MAX_CMDS 31
#define AHCI_MMIO_SIZE (GHC_SIZE + AHCI_MAX_PORTS * PxSIZE)


/* MMIO Register access helper functions */

#define MMIO_PTR(__type, __i8off) ((__type *)(mmio + (__i8off)))

static inline void mmio_w32(uint8_t *mmio, size_t offset, uint32_t data)
{
	if ( offset + 3 >= AHCI_MMIO_SIZE )
		return;
	*MMIO_PTR(uint32_t, offset) = data;
}

static inline void mmio_w16(uint8_t *mmio, size_t offset, uint32_t data)
{
	if ( offset + 1 >= AHCI_MMIO_SIZE )
		return;
	*MMIO_PTR(uint16_t, offset) = data;
}

static inline void mmio_w8(uint8_t *mmio, size_t offset, uint32_t data)
{
	if ( offset >= AHCI_MMIO_SIZE )
		return;
	*MMIO_PTR(uint8_t, offset) = data;
}

static inline uint32_t mmio_r32(uint8_t *mmio, size_t offset)
{
	if ( offset + 3 >= AHCI_MMIO_SIZE )
		return ~0;
	return *MMIO_PTR(uint32_t, offset);
}

static inline uint16_t mmio_r16(uint8_t *mmio, size_t offset)
{
	if ( offset + 1 >= AHCI_MMIO_SIZE )
		return ~0;
	return *MMIO_PTR(uint16_t, offset);
}

static inline uint8_t mmio_r8(uint8_t *mmio, size_t offset)
{
	if ( offset >= AHCI_MMIO_SIZE )
		return ~0;
	return *MMIO_PTR(uint8_t, offset);
}

static inline void mmio_nand32(uint8_t *mmio, size_t offset, uint32_t mask)
{
	if ( offset + 3 >= AHCI_MMIO_SIZE )
		return;
	*MMIO_PTR(uint32_t, offset) &= ~mask;
}

static inline void mmio_or32(uint8_t *mmio, size_t offset, uint32_t mask)
{
	if ( offset + 3 >= AHCI_MMIO_SIZE )
		return;
	*MMIO_PTR(uint32_t, offset) |= mask;
}

#undef MMIO_PTR



/*
 * PCI Config Space
 */

/* Standard PCI config header */
enum {
	PCICFG_ID = 0,
	PCICFG_CMD = 0x4,
	PCICFG_STS = 0x6,
	PCICFG_RID = 0x8,
	PCICFG_CC = 0x9,
	PCICFG_CLS = 0xc, 
	PCICFG_MLT = 0xd,
	PCICFG_HTYPE = 0xe,
	PCICFG_BIST = 0xf,
	PCICFG_BARS = 0x10,
	PCICFG_ABAR = 0x24,
	PCICFG_SS = 0x2c,
	PCICFG_EROM = 0x30,
	PCICFG_CAP = 0x34,
	PCICFG_INTR = 0x3c,
	PCICFG_MGNT = 0x3e,
	PCICFG_MLAT = 0x3f,
};

/* AHCI PCI config header */
enum pcicfg_ahci {
	PCICFG_PMCAP = 0x40,
	PCICFG_PMCAP_PC = PCICFG_PMCAP + 2,
	PCICFG_PMCAP_PMCS = PCICFG_PMCAP + 4,
	
	PCICFG_SIZE = 0xff
};


enum pccfg_bits {
	PCICFG_CMD_ID = 10,
	PCICFG_CMD_BME = 2,
	PCICFG_CMD_MSE = 1,
	PCICFG_CMD_IOSE = 0,
	PCICFG_CMD_RW = 0x47,

	PCICFG_STS_CL = 4,

	PCICFG_HTYPE_MFD = 7,
};

enum pcicfg_values {
	PCICFG_CC_SCC_RAID = 4,
	PCICFG_CC_SCC_AHCI = 6,
};

#define PCICFG_PTR(__type, __i8off) ((__type *)(pcicfg + (__i8off)))

static inline void pcicfg_w32(uint8_t *pcicfg, size_t offset, uint32_t data)
{
	if ( offset + 3 >= PCICFG_SIZE )
		return;
	*PCICFG_PTR(uint32_t, offset) = data;
}

static inline void pcicfg_w16(uint8_t *pcicfg, size_t offset, uint16_t data)
{
	if ( offset + 1 >= PCICFG_SIZE )
		return;
	*PCICFG_PTR(uint16_t, offset) = data;
}

static inline void pcicfg_w8(uint8_t *pcicfg, size_t offset, uint16_t data)
{
	if ( offset >= PCICFG_SIZE )
		return;
	pcicfg[offset] = data;
}

static inline uint32_t pcicfg_r32(uint8_t *pcicfg, size_t offset)
{
	if ( (offset + 3) >= PCICFG_SIZE )
		return ~0;
	return *PCICFG_PTR(uint32_t, offset);
}

static inline uint16_t pcicfg_r16(uint8_t *pcicfg, size_t offset)
{
	if ( (offset + 1) >= PCICFG_SIZE )
		return ~0;
	return *PCICFG_PTR(uint16_t, offset);
}

static inline uint8_t pcicfg_r8(uint8_t *pcicfg, size_t offset)
{
	if ( (offset + 0) >= PCICFG_SIZE )
		return ~0;
	return pcicfg[offset];
}

#undef PCICFG_PTR

/*
 * Block I/O
 */

struct blkdev {
	int fd;
	io_context_t ioctx;

	int efd;
	struct event event;

	int is_block;

	int64_t buf_off;
	uint8_t *buf;
	void *cbarg0;
};

#define BLKTYPE_BUFFER 0
#define BLKTYPE_VECTOR 1
#define BLKTYPE_IOMASK 0x000f
#define BLKTYPE_BUFFEROP (1 << 8)

#define blkio_buffer(_t) (((_t) & BLKTYPE_IOMASK) == BLKTYPE_BUFFER)
#define blkio_vector(_t) (((_t) & BLKTYPE_IOMASK) == BLKTYPE_VECTOR)
#define blkio_bufferop(_t) ((_t) & BLKTYPE_BUFFEROP)

struct blkop {
	struct iocb iocb; /* Must be first */

	unsigned type;
	off_t off;
	union {
		uint8_t *buf;		/* BLKIOTYPE_BUFFER */
		struct iovec *iov;	/* BLKIOTYPE_VECTOR */

	};
	union {
		size_t buflen;		/* BLKIOTYPE_BUFFER */
		size_t iovcnt;		/* BLKIOTYPE_VECTOR */
	};
	size_t iovlen;			/* BLKIOTYPE_VECTOR */

	union {
		void (*cb)(struct blkdev *, void *, uint64_t);
		struct blkop *orig_op;	/* BLKIOTYPE_CACHEOP */
	};
};

/*
 * SATA
 */

enum {
	FIS_TYPE_OFFSET = 	0,
	FIS_TYPE_REGH2D =	0x27,
	FIS_TYPE_REGD2H =	0x34,
	FIS_TYPE_DMA =		0x41,
	FIS_TYPE_PIO =		0x5f,
	FIS_TYPE_SDB =		0xa1,

	FIS_SIZE_REGD2H =	(5 * sizeof(uint32_t)),
	FIS_SIZE_PIO =		(5 * sizeof(uint32_t)),
	FIS_SIZE_SDB = 		(2 * sizeof(uint32_t)),
	FIS_SIZE_MAX =		(5 * sizeof(uint32_t)),
};

enum {
	ATA_CMD_READSECTOR =	0x20,
	ATA_CMD_WRITESECTOR = 	0x30,
	ATA_CMD_READDMAQUEUE = 	0x60,
	ATA_CMD_WRITEDMAQUEUE = 0x61,
	ATA_CMD_INITDEVPARM =	0x91,
	ATA_CMD_READDMA = 	0xc8,
	ATA_CMD_WRITEDMA = 	0xca,

	ATA_CMD_STANDBYIMM = 	0xe0,
	ATA_CMD_IDLEIMM = 	0xe1,
	ATA_CMD_STANDBY = 	0xe2,
	ATA_CMD_IDLE =		0xe3,
	ATA_CMD_SLEEP = 	0xe6,
	ATA_CMD_FLUSHCACHE = 	0xe7,
	ATA_CMD_SETFEATURES = 	0xef,

	ATA_CMD_IDENT =		0xec,

	ATA_STS_ERR =		0,
	ATA_STS_DRQ =		3,
	ATA_STS_RDY =		6,
	ATA_STS_BSY =		7,

	ATA_ERR_ABRT =		2,

	ATA_SECTOR_SIZE = 	512,
};

static inline uint32_t regfis_to_sig(uint32_t *fis)
{
	uint32_t lbaregs = fis[1] & 0x00ffffff;
	uint32_t sectcnt = fis[3] & 0x000000ff;
	return ((lbaregs << 8) | sectcnt);
}

static inline uint32_t regfis_to_tfd(uint32_t *fis)
{
	return ((fis[0] & 0xffff0000) >> 16);
}

static inline uint32_t piofis_ests_to_tfd(uint32_t *fis)
{
	return ((fis[3] & 0xff000000) >> 24);
}

static inline uint32_t sdbfis_to_tfd(uint32_t *fis)
{
	return ((fis[0] & 0xffff0000) >> 16);
}

static inline int regfis_intr(uint32_t *fis)
{
	return !!(fis[0] & 0x00004000);
}

struct sata_command {
	struct blkop 	op; /* Must be first */
	int 		intr;
	uint8_t		tag;
	unsigned	cmd;
};

static inline void
sata_command_set_intr(struct sata_command *sc)
{
	sc->intr = 1;
}

static inline int
sata_command_get_intr(struct sata_command *sc)
{
	return sc->intr;
}

static inline void
sata_command_set_cmd(struct sata_command *sc, unsigned cmd)
{
	sc->cmd = cmd;
}

static inline unsigned
sata_command_get_cmd(struct sata_command *sc)
{
	return sc->cmd;
}

static inline void
sata_command_set_iovlen(struct sata_command *sc, unsigned iovlen)
{
	sc->op.iovlen = iovlen;
}

static inline unsigned
sata_command_get_iovlen(struct sata_command *sc)
{
	return sc->op.iovlen;
}

static inline void
sata_command_set_iovector(struct sata_command *sc,
			struct iovec *iov, size_t iovcnt)
{
	sc->op.type = BLKTYPE_VECTOR;
	sc->op.iov = iov;
	sc->op.iovcnt = iovcnt;
}

static inline void
sata_command_get_iovector(struct sata_command *sc,
			struct iovec **iovp, size_t *iovcntp)
{
	*iovp = sc->op.iov;
	*iovcntp = sc->op.iovcnt;
}

struct vsata {
	const char	*name;
	struct vahci	*ahci;
	unsigned	port;
	struct blkdev 	dev;
};

struct vahci_port {
	uint64_t	gclb;
	uint8_t		*clb;
	uint64_t	gfb;
	uint8_t		*fb;
	int		cmdlist_act;
	struct vsata	*sata;
	struct sata_command scs[AHCI_MAX_CMDS];
};

struct vahci {
	struct device dev;

	uint8_t pci_bus, pci_dev, pci_fun;
	uint8_t pcicfg[PCICFG_SIZE];	
	uint8_t pcicfg_rw[PCICFG_SIZE];
	uint8_t pcicfg_wc[PCICFG_SIZE];

	uint8_t mmio[AHCI_MMIO_SIZE];
	uint8_t mmio_rw[AHCI_MMIO_SIZE];
	uint8_t mmio_wc[AHCI_MMIO_SIZE];
	uint8_t mmio_w1[AHCI_MMIO_SIZE];
	struct vahci_port ports[AHCI_MAX_PORTS];

	uint32_t ioaddr;
	iohandle_t iohdl;
	mapper_t mpr;
	struct event ioev;
};


#endif /* __AHCI_H */
