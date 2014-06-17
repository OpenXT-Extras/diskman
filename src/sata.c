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

#include "project.h"
#include <sys/stat.h>

#define BMSK(__boff) ((uint32_t)1 << (__boff))

static uint32_t ata_initfis[4] = {
	[0] = 0x01000034,
	[1] = 0x00000001,
	[3] = 0x00000001,
};

static uint16_t ata_identify_base[ATA_SECTOR_SIZE/2] = {
	/* 0: bit 7 => removable device */
	[2] = 0x8c73,
	/* 10-19: Serial Number */
	[21] = 1024,
	/* 23-26: Firmware Version */
	/* 27-46: Model Number */
	[47] = 0x8010, 
	[49] = 0x0f00,
	[50] = 0x4001,
	[53] = 0x0006, /* Bits in 88 and 64-70 valid */
	[59] = 0x010f, 
	/* 60-61: Numbers of addressable sectors */
	[63] = 0x0007, /* DMA modes and selection */
	[64] = 0x0003, /* PIO Mode 3-4 supported */
	[65] = 120,
	[66] = 120,
	[67] = 120,
	[68] = 120,
	/* 69: TRIM support! */
	[75] = 0x001f, /* Queue Depth 32 */
	[76] = 0x0100, /* NCQ Supported! */
	[80] = 0x00f0, /* ATA supported */
	[81] = 0x0016, /* ATA5 ? */
	[82] = 0x0060, /* Write cache, lookahead. */
	[83] = 0x3402, /* FLUSH, 48b, R/WQUEUED */
	[84] = 0x0000, /* Mandatory bit. */
	[85] = 0x7000, /* NOP, READB, WRITEB enabled */
	[86] = 0x0402, /* R/W DMA QUEUED supported */
	[88] = 0x040f, /* UDMA modes */
	[93] = 0x1,
	/* 100-103: W: Max LBA48 sectors */
	[106] = 0x6000,
};

struct fis {
	int 		i;
	int		w; 
	uint8_t 	sts;
	uint8_t		e_sts;
	uint8_t 	err;
	uint8_t		dev;
	uint64_t 	lba;
	uint16_t	count;
	uint8_t		tag;
};

static void
send_fis(struct vsata *s, unsigned type, struct fis *fis)
{
	uint8_t fisbuf[FIS_SIZE_MAX];
	size_t fis_size = 0;

	memset(fisbuf, 0, FIS_SIZE_MAX);
	fisbuf[0] = type;

	switch ( type ) {
	case FIS_TYPE_PIO:
		if ( fis->w )
			fisbuf[1] |= (1 << 5);
		if ( fis->i )
			fisbuf[1] |= (1 << 6);
		fisbuf[2] = fis->sts;
		fisbuf[3] = fis->err;
		fisbuf[7] = fis->dev;
		*(uint16_t *)(fisbuf + 12) = fis->count;
		fisbuf[15] = fis->e_sts;
		fis_size = FIS_SIZE_PIO;

		ahci_port_recv_fis_pio(s->ahci, s->port, (uint32_t *)fisbuf);
		break;
	case FIS_TYPE_SDB:
		if ( fis->i )
			fisbuf[1] |= (1 << 6);
		fisbuf[2] = fis->sts;
		fisbuf[3] = fis->err;
		*(uint32_t *)(fisbuf + 4) = BMSK(fis->tag);
		ahci_port_recv_fis_sdb(s->ahci, s->port, (uint32_t *)fisbuf);
		break;
	case FIS_TYPE_REGD2H:
		if ( fis->i )
			fisbuf[1] |= (1 << 6);
		fisbuf[2] = fis->sts;
		fisbuf[3] = fis->err;
		fisbuf[7] = fis->dev;
		*(uint16_t *)(fisbuf + 12) = fis->count;
		ahci_port_recv_fis_reg(s->ahci, s->port, (uint32_t *)fisbuf);
		break;
	default:
		error("unknown fis type!");
	}
}

void
send_piofis_ok(struct vsata *sata, size_t count, int direction, int intr)
{
	struct fis fis;

	memset(&fis, 0, sizeof(struct fis));
	fis.i = intr;
	fis.w = direction;
	fis.sts = BMSK(ATA_STS_BSY)|BMSK(ATA_STS_DRQ);
	fis.e_sts = BMSK(ATA_STS_RDY);
	fis.count = count;
	send_fis(sata, FIS_TYPE_PIO, &fis);
}

void
send_sdbfis_ok(struct vsata *sata, uint8_t tag, int intr)
{
	struct fis fis;
	fis.err = 0;
	fis.sts = BMSK(ATA_STS_RDY);
	fis.i = intr;
	fis.tag = tag;
	send_fis(sata, FIS_TYPE_SDB, &fis);
}

void
send_regfis_ok(struct vsata *sata, size_t count, int intr)
{
	struct fis fis;

	memset(&fis, 0, sizeof(struct fis));
	fis.i = !!intr;
	fis.sts = BMSK(ATA_STS_RDY);
	fis.count = count;
	send_fis(sata, FIS_TYPE_REGD2H, &fis);
}

void
send_regfis_err(struct vsata *sata, uint8_t err, int intr)
{
	struct fis fis;

	memset(&fis, 0, sizeof(struct fis));
	fis.i = !!intr;
	fis.sts = BMSK(ATA_STS_ERR);
	fis.err = err;
	send_fis(sata, FIS_TYPE_REGD2H, &fis);
}


static int
sata_cmd_identify(struct vsata *sata, struct iovec *iov, size_t iovcnt)
{
	uint16_t idsect[ATA_SECTOR_SIZE/2];
	uint16_t geo_cyls, geo_heads, geo_sects;
	uint64_t sectors = blkdev_get_sectors(&sata->dev);

	blkdev_get_geo(&sata->dev, &geo_cyls, &geo_heads, &geo_sects);
	info("CHS: %x, %x, %x", geo_cyls, geo_heads, geo_sects);

	memcpy(idsect, ata_identify_base, ATA_SECTOR_SIZE);	
	idsect[1] = geo_cyls;
	idsect[3] = geo_heads;
	idsect[6] = geo_sects;
	idsect[54] = geo_cyls;
	idsect[55] = geo_heads;
	idsect[56] = geo_sects;
	idsect[57] = (uint16_t)(geo_cyls * geo_heads * geo_sects);
	idsect[58] = (uint16_t)((geo_cyls * geo_heads * geo_sects) >> 16);
	idsect[60] = (uint16_t)sectors;
	idsect[61] = (uint16_t)(sectors >> 16);
	idsect[100] = (uint16_t)sectors;
	idsect[101] = (uint16_t)(sectors >> 16);
	idsect[102] = (uint16_t)(sectors >> 32);
	idsect[103] = (uint16_t)(sectors >> 48);
	mem_to_iov(iov, iovcnt, (uint8_t *)idsect, ATA_SECTOR_SIZE);

	send_piofis_ok(sata, 1, 1, 1);
	return 1; /* Command completed */
}

static void dmaq_cb(struct vsata *sata, struct sata_command *sc, uint64_t ret)
{
//	info("completed queue %d", sc->tag);
	send_sdbfis_ok(sata, sc->tag, 1);
	ahci_port_cmd_done(sata->ahci, sata->port, sc);
}

static int
sata_cmd_readdmaqueue(struct vsata *sata,
		uint64_t lba, uint16_t count,
		uint8_t tag, struct sata_command *sc)
{

	sc->tag = tag;
	sc->op.cb = dmaq_cb;
	sc->op.off = lba * ATA_SECTOR_SIZE;
	iovtrunc(sc->op.iov, sc->op.iovcnt, count * ATA_SECTOR_SIZE);
	if ( blkdev_read_async(&sata->dev, &sc->op) ) {
		send_sdbfis_ok(sata, sata_command_get_iovlen(sc), 1);
		return 1;
	}
	return 2;
}

static int
sata_cmd_writedmaqueue(struct vsata *sata,
		uint64_t lba, uint16_t count,
		uint8_t tag, struct sata_command *sc)
{
//	info("write queue %d, %"PRIx64", %d", tag, lba, count);
	sc->tag = tag;
	sc->op.cb = dmaq_cb;
	sc->op.off = lba * ATA_SECTOR_SIZE;
	iovtrunc(sc->op.iov, sc->op.iovcnt, count * ATA_SECTOR_SIZE);
	blkdev_write_async(&sata->dev, &sc->op);
	return 2;
}

static void dma_cb(struct vsata *sata, struct sata_command *sc, uint64_t ret)
{
	send_regfis_ok(sata, sata_command_get_iovlen(sc), 1);
	ahci_port_cmd_done(sata->ahci, sata->port, sc);
}

static int
sata_cmd_writedma(struct vsata *sata,
		uint64_t lba, uint16_t count,
		struct sata_command *sc)
{
	sc->op.cb = dma_cb;
	sc->op.off = lba * ATA_SECTOR_SIZE;
	iovtrunc(sc->op.iov, sc->op.iovcnt, count * ATA_SECTOR_SIZE);
	blkdev_write_async(&sata->dev, &sc->op);
	return 0;
}

static int
sata_cmd_readdma(struct vsata *sata,
		uint64_t lba, uint64_t count,
		struct sata_command *sc)
{
	sc->op.cb = dma_cb;
	sc->op.off = lba * ATA_SECTOR_SIZE;
	iovtrunc(sc->op.iov, sc->op.iovcnt, count * ATA_SECTOR_SIZE);
	if ( blkdev_read_async(&sata->dev, &sc->op) ) {
		send_regfis_ok(sata, sata_command_get_iovlen(sc), 1);
		return 1;
	}
	return 0;
}

#if 0
static int
sata_cmd_writesect(struct vsata *sata, uint64_t lba, uint16_t count, 
		struct iovec *iov, size_t iovcnt)
{
	iovtrunc(iov, iovcnt, count * ATA_SECTOR_SIZE);
	iovwrite_sync(sata, iov, iovcnt, lba * ATA_SECTOR_SIZE);
	send_piofis_ok(sata, count, 1, 1);
	return 1;
}

static int
sata_cmd_readsect(struct vsata *sata, uint64_t lba, uint16_t count, 
		struct iovec *iov, size_t iovcnt)
{
	iovtrunc(iov, iovcnt, count * ATA_SECTOR_SIZE);
	iovread_sync(sata, iov, iovcnt, lba * ATA_SECTOR_SIZE);
	send_piofis_ok(sata, count, -1, 1);
	return 1; /* Command completed */
}
#endif

void
sata_comreset(struct vsata *sata)
{
	ahci_port_recv_fis_init(sata->ahci, sata->port, ata_initfis);
}

static uint16_t
cfis_ncq_count(uint32_t *cfis)
{
	uint16_t count = 0;

	count = (cfis[0] & 0xff000000) >> 24;
	count |= (cfis[2] & 0xff000000) >> 16;
	return count;
}

static uint8_t
cfis_ncq_tag(uint32_t *cfis)
{
	return (cfis[3] >> 3) & 0xff;
}

static uint64_t
cfis_lba48(uint32_t *cfis)
{
	uint64_t lba = 0;
	lba |= cfis[1] & 0x00ffffff;
	lba |= (((uint64_t)cfis[2] & 0x00ffffff) << 24);
	return lba;
}

static uint64_t
cfis_lba(uint32_t *cfis)
{
	return (cfis[1] & 0x0fffffff);
}

static uint16_t
cfis_count(uint32_t *cfis)
{
	uint16_t cnt = cfis[3] & 0x0000ffff;
	return cnt == 0 ? 256 : cnt;
}

int
sata_recvfis(struct vsata *sata, uint8_t *cfis, size_t cfissz,
		struct sata_command *sc)
{
	int rc = 1;
	//info("CMDFIS: %x, %x, %x", cfis[0] & 0xff, cfis[1], cfis[2]);
	/* XXX: MORE CHECKS! */
	switch ( cfis[2] ) {

#if 0
	case ATA_CMD_READSECTOR:
		rc = sata_cmd_readsect(sata, cfis_lba(cfis),
					cfis_count(cfis), iov, iovcnt);
		break;
	case ATA_CMD_WRITESECTOR:
		rc = sata_cmd_writesect(sata, cfis_lba(cfis),
					cfis_count(cfis), iov, iovcnt);
		break;
#endif
	case ATA_CMD_READDMAQUEUE:
		rc = sata_cmd_readdmaqueue(sata, cfis_lba48(cfis),
				cfis_ncq_count(cfis), cfis_ncq_tag(cfis), sc);
		 break;
	case ATA_CMD_WRITEDMAQUEUE:
		rc = sata_cmd_writedmaqueue(sata, cfis_lba48(cfis),
				cfis_ncq_count(cfis), cfis_ncq_tag(cfis), sc);
		break;
	case ATA_CMD_READDMA:
		rc = sata_cmd_readdma(sata, cfis_lba(cfis),
					cfis_count(cfis), sc);
		break;
	case ATA_CMD_WRITEDMA:
		rc = sata_cmd_writedma(sata, cfis_lba(cfis),
					cfis_count(cfis), sc);
		break;
	case ATA_CMD_SETFEATURES:
		info("setfeatures");
		send_regfis_ok(sata, 0, 1);
		rc = 1;
		break;
	case ATA_CMD_INITDEVPARM:
		info("initdevparm");
		send_regfis_ok(sata, 0, 1);
		rc = 1;
		break;

	/* Power Management commands. */
	case ATA_CMD_STANDBYIMM:
	case ATA_CMD_IDLEIMM:
	case ATA_CMD_STANDBY:
	case ATA_CMD_IDLE:
	case ATA_CMD_SLEEP:
		/* Ignored. */
		send_regfis_ok(sata, 0, 1);
		rc = 1;
		break;

	case ATA_CMD_IDENT:
		info("IDENT");
		rc = sata_cmd_identify(sata, sc->op.iov, sc->op.iovcnt);
		break;

	default:
		error("Unknown command %x", cfis[2]);
		send_regfis_err(sata, BMSK(ATA_ERR_ABRT), 1);
		rc = 1;
		break;
	}
	return rc;
}

int
sata_attach(struct vsata *sata, struct vahci *ahci, unsigned port)
{
	sata->ahci = ahci;
	sata->port = port;
	return 1;
}

int
sata_setup(struct vsata *sata, const char *name, const char *file)
{
	memset(sata, 0, sizeof(struct vsata));
	sata->name = name;

	blkdev_setup(&sata->dev, file, sata);
	return 0;
}
