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

/*
 * AHCI specification compliant device emulation.
 */


/*
 * Helper Functions.
 */

#define BMSK(__boff) ((uint32_t)1 << (__boff))

static inline void
reg_write(struct vahci *ahci, unsigned off, uint32_t val)
{
	mmio_w32(ahci->mmio, off, val);
}

static inline uint32_t
reg_read(struct vahci *ahci, unsigned off)
{
	return mmio_r32(ahci->mmio, off);
} 

static inline uint32_t
reg_clearbits(struct vahci *ahci, unsigned off, uint32_t mask)
{
	mmio_nand32(ahci->mmio, off, mask);
	return reg_read(ahci, off);
}

static inline uint32_t
reg_setbits(struct vahci *ahci, unsigned off, uint32_t mask)
{
	mmio_or32(ahci->mmio, off, mask);
	return reg_read(ahci, off);
}

static inline void
port_reg_write(struct vahci *ahci, unsigned port,
		enum ahci_port_regs reg, uint32_t val)
{
	reg_write(ahci, MMIO_PORT(port, reg), val);
}

static inline uint32_t
port_reg_read(struct vahci *ahci, unsigned port, enum ahci_port_regs reg)
{
	return reg_read(ahci, MMIO_PORT(port, reg));
}

static inline void
port_reg_clearbits(struct vahci *ahci, unsigned port,
		enum ahci_port_regs reg, uint32_t mask)
{
	reg_clearbits(ahci, MMIO_PORT(port, reg), mask);
}

static inline void
port_reg_setbits(struct vahci *ahci, unsigned port,
		enum ahci_port_regs reg, uint32_t mask)
{
	reg_setbits(ahci, MMIO_PORT(port, reg), mask);
}

static inline unsigned
is_port_implemented(struct vahci *ahci, unsigned port)
{
	return !!(reg_read(ahci, GHC_PI) & BMSK(port));
}

static inline void
foreach_port_implemented(struct vahci *ahci,
			void (*fn)(struct vahci *, unsigned))
{
	unsigned cur_port = 0;
	uint32_t pi = reg_read(ahci, GHC_PI);

	/* XXX: FFS is your friend. _GNU_SOURCE is not. */
	while ( pi != 0 )  {
		if ( pi & 1 ) 
			fn(ahci, cur_port);
		cur_port++;
		pi >>= 1;
	}
}


/*
 * HBA Interrupts Emulation.
 */

static void
ahci_port_check_intr(struct vahci *ahci, unsigned port)
{
	int level = 0;
	uint32_t ghc = reg_read(ahci, GHC_GHC);
	uint32_t pis = port_reg_read(ahci, port, PxIS);
	uint32_t pie = port_reg_read(ahci, port, PxIE);

	if ( (pis & pie) && (ghc & BMSK(GHC_GHC_IE)) ) {
		/* Interrupt condition and interrupts enabled */
		reg_setbits(ahci, GHC_IS, BMSK(port));
		level = 1;
	}
	ahci_pci_set_interrupt_level(ahci, level);
}

static void
ahci_port_set_intr(struct vahci *ahci, unsigned port, enum ahci_intr intr)
{
	port_reg_write(ahci, port, PxIS, BMSK(intr));
	ahci_port_check_intr(ahci, port);
}

static void
ahci_port_set_tfd(struct vahci *ahci, unsigned port, uint32_t tfd)
{
	if ( tfd & BMSK(PxTFD_STS_ERR) )
		ahci_port_set_intr(ahci, port, PxIS_TFES);
	port_reg_write(ahci, port, PxTFD, tfd);
}


/*
 * HBA errors handling.
 *
 * All AHCI emulation bugs are treated through the AHCI host
 * error interface. It will be driver's responsibility to try
 * to reset the controller and driver's fault if it keeps
 * issuing commands to us.
 * By the standard, if the driver doesn't recover an error
 * condition the result will be an undefined behaviour, and
 * that is _exactly_ what will happen. :-)
 */

static void
ahci_port_host_fatal_error(struct vahci *ahci, unsigned port)
{
	port_reg_write(ahci, port, PxSERR, BMSK(PxSERR_ERR_E));
	ahci_port_set_intr(ahci, port, PxIS_HBFS);
}

static void
ahci_port_iface_fatal_error(struct vahci *ahci, unsigned port)
{
	port_reg_write(ahci, port, PxSERR, BMSK(PxSERR_ERR_P));
	ahci_port_set_intr(ahci, port, PxIS_IFS);
}


/*
 * SATA Interface.
 */

static int
ahci_port_sata_attach(struct vahci *ahci, unsigned port, struct vsata *sata)
{
	if ( !sata_attach(sata, ahci, port) ) {
		warning("Attaching sata disk %s to port %d failed",
			sata->name, port);
		return 0;
	}
	ahci->ports[port].sata = sata;
	info("Attaching sata disk %s to port %d.", sata->name, port);
	return 1;
}

static void
ahci_port_sata_comreset(struct vahci *ahci, unsigned port)
{
	struct vsata *sata = ahci->ports[port].sata;
	sata_comreset(sata);
	port_reg_setbits(ahci, port, PxCMD, BMSK(PxCMD_POD)|BMSK(PxCMD_SUD));
	port_reg_write(ahci, port, PxSSTS, PxSSTS_ON);
}

static int
ahci_port_sata_sendfis(struct vahci *ahci, unsigned port, uint32_t *fis,
			unsigned fissize, struct sata_command *sc)
{
	struct vsata *sata = ahci->ports[port].sata;
	return sata_recvfis(sata, (uint8_t *)fis, fissize, sc);
}

/* Called from SATA */
void
ahci_port_recv_fis_reg(struct vahci *ahci, unsigned port, uint32_t *fis)
{
	if ( (fis[FIS_TYPE_OFFSET] & 0xff) != FIS_TYPE_REGD2H ) {
		ahci_port_iface_fatal_error(ahci, port);
		return;
	}

	if ( port_reg_read(ahci, port, PxCMD) & BMSK(PxCMD_FR) ) {
		ahci_port_set_tfd(ahci, port, regfis_to_tfd(fis));
		memcpy(ahci->ports[port].fb + FB_REGFIS_OFFSET,
			fis, FIS_SIZE_REGD2H);
	}

	if ( regfis_intr(fis) )
		ahci_port_set_intr(ahci, port, PxIS_DHRS);
}


/* PIO I/O is synchronous at the moment. I.e., when the device send
 * this FIS the I/O operation has already been completed.
 * We copy directly the E_STATUS field of the FIS into the task register. */
/* Called from SATA */
void
ahci_port_recv_fis_pio(struct vahci *ahci, unsigned port, uint32_t *fis)
{
	if ( (fis[FIS_TYPE_OFFSET] & 0xff) != FIS_TYPE_PIO ) {
		ahci_port_iface_fatal_error(ahci, port);
		return;
	}

	if ( port_reg_read(ahci, port, PxCMD) & BMSK(PxCMD_FR) ) {
		ahci_port_set_tfd(ahci, port, piofis_ests_to_tfd(fis));
		memcpy(ahci->ports[port].fb + FB_PIOFIS_OFFSET,
			fis, FIS_SIZE_PIO);
	}

	if ( regfis_intr(fis) )
		ahci_port_set_intr(ahci, port, PxIS_PSS);
}

void
ahci_port_recv_fis_sdb(struct vahci *ahci, unsigned port, uint32_t *fis)
{
	if ( (fis[FIS_TYPE_OFFSET] & 0xff) != FIS_TYPE_SDB ) {
		ahci_port_iface_fatal_error(ahci, port);
		return;
	}

	if ( port_reg_read(ahci, port, PxCMD) & BMSK(PxCMD_FR) ) {
		uint32_t tfd;
		tfd = port_reg_read(ahci, port, PxTFD) & 0x00000077;
		tfd |= sdbfis_to_tfd(fis) & 0x0000ff88;
		ahci_port_set_tfd(ahci, port, tfd);
		memcpy(ahci->ports[port].fb + FB_SDBFIS_OFFSET,
			fis, FIS_SIZE_SDB);
	}

	port_reg_clearbits(ahci, port, PxSACT, fis[1]);

	if ( regfis_intr(fis) )
		ahci_port_set_intr(ahci, port, PxIS_SDBS);
}

/* Called from SATA */
void
ahci_port_recv_fis_init(struct vahci *ahci, unsigned port, uint32_t *fis)
{
	if ( (fis[FIS_TYPE_OFFSET] & 0xff) != FIS_TYPE_REGD2H )
		ahci_port_iface_fatal_error(ahci, port);

	port_reg_write(ahci, port, PxSIG, regfis_to_sig(fis));
	ahci_port_recv_fis_reg(ahci, port, fis);
}


/*
 * Command List handling.
 */

static inline uint16_t
cmdhdr_prdtsize(uint32_t *cmdhdr)
{
	return (cmdhdr[0] & 0xffff0000) >> 16;
}

static inline unsigned
cmdhdr_cfissize(uint32_t *cmdhdr)
{
	return (cmdhdr[0] & 0x1f);
}

static inline uint64_t
cmdhdr_cmdtbl(uint32_t *cmdhdr)
{
	uint64_t ret;
	ret = (uint64_t)(cmdhdr[2] & 0xffffff80);
	ret |= ((uint64_t)cmdhdr[3]) << 32;
	return ret;
}

static inline uint64_t
cmdhdr_cfis(uint32_t *cmdhdr)
{
	return cmdhdr_cmdtbl(cmdhdr);
}

static inline uint64_t
cmdhdr_prdt(uint32_t *cmdhdr)
{
	return cmdhdr_cmdtbl(cmdhdr) + CMDTBL_PRDT_OFFSET;
}

static int
cmdhdr_check(uint32_t *cmdhdr)
{
#define CMDHDR_UNSUPP (BMSK(CMDHDR_A)|BMSK(CMDHDR_BIST))
	size_t cfissize = cmdhdr_cfissize(cmdhdr);

	if ( cmdhdr[0] & CMDHDR_UNSUPP ) {
		info("Unsupported CMDHDR bits: %08x", cmdhdr[0]);
		return 0;
	}
	if ( cfissize < 2 ) {
		info("Invalid CFIS size: %d", cfissize);
		return 0;
	}
	return 1;
#undef CMDHDR_UNSUPP
}

static void
cmdhdr_freeprdt(struct vahci *ahci, struct sata_command *sc)
{
	size_t i, iovcnt;
	struct iovec *iov;

	sata_command_get_iovector(sc, &iov, &iovcnt);

	for ( i = 0; i < iovcnt; i++ )
		if ( iov[i].iov_base != NULL ) {
//			info("Freeing %x", iov[i].iov_base);
			mapper_put(ahci->mpr, iov[i].iov_base);
		}
	free(iov);
}

static int
cmdhdr_parseprdt(struct vahci *ahci, uint32_t *cmdhdr, struct sata_command *sc)
{
	int intr;
	struct iovec *iov;
	size_t iovcnt, length;
	uint32_t *dba, *prdt, *ptr;
	uint64_t gdba, gprdt = cmdhdr_prdt(cmdhdr);
	size_t i, gdbasize, prdtsize = cmdhdr_prdtsize(cmdhdr);

	prdt = mapper_get(ahci->mpr, gprdt, prdtsize * PRDT_SIZE);
	if ( prdt == NULL )
		return 0;

	iov = calloc(prdtsize, sizeof(struct iovec));
	if (iov == NULL ) {
		error("Could not allocate iov for PRDT (size %d)", prdtsize);
		mapper_put(ahci->mpr, prdt);
		return 0;
	}
	iovcnt = prdtsize;

	for ( i = 0, ptr = prdt; i < prdtsize; i++, ptr += 4) {
//		info("PRDT %d = %08x%08x%08x%08x", i,
//			prdt[0], prdt[1], prdt[2], prdt[3]);

		gdba = (uint64_t)ptr[0] | ((uint64_t)ptr[1] << 32);
		gdbasize = (ptr[3] & 0x001fffff) + 1;
		dba = mapper_get(ahci->mpr, gdba, gdbasize);
		if ( dba == NULL )
			goto prdt_cancel;


		iov[i].iov_base = dba;
		iov[i].iov_len = gdbasize;
		if ( prdt[3] & 0x80000000 )
			sata_command_set_intr(sc);
		intr |= prdt[3] & 0x80000000;
		length += gdbasize;
	}
//	info("Created IOCB (len: %d, intr: %d)", length, intr);
	mapper_put(ahci->mpr, prdt);

	if ( intr )
		sata_command_set_intr(sc);
	sata_command_set_iovlen(sc, length);
	sata_command_set_iovector(sc, iov, iovcnt);
	return 1;

prdt_cancel:
	error("could not map PRDT entry %d: %s", i, strerror(errno));
	info("gdba[%d] = %"PRIx64" (%d)", i, gdba, gdbasize);
	for ( i = 0; i < prdtsize; i++ ) {
		if ( iov[i].iov_base != NULL )
			mapper_put(ahci->mpr, iov[i].iov_base);
	}
	free(iov);
	mapper_put(ahci->mpr, prdt);
	return 0;
}

static int
command_transmit(struct vahci *ahci, unsigned port, unsigned cmd)
{
	int cmd_done = 0;
	size_t cfissz;
	uint32_t *cmdhdr, *cfis;
	struct sata_command *sc;

	sc = ahci->ports[port].scs + cmd;
	sata_command_set_cmd(sc, cmd);

	cmdhdr = (uint32_t *)(ahci->ports[port].clb + CMDHDR_SIZE*cmd);
	if ( !cmdhdr_check(cmdhdr) ) {
		ahci_port_iface_fatal_error(ahci, port);
		return 0;
	}

	if ( !cmdhdr_parseprdt(ahci, cmdhdr, sc) ) {
		ahci_port_host_fatal_error(ahci, port);
		return 0;
	}

	cfissz = cmdhdr_cfissize(cmdhdr);
	cfis = mapper_get(ahci->mpr, cmdhdr_cfis(cmdhdr), cfissz);
	if ( cfis == NULL ) {
		ahci_port_host_fatal_error(ahci, port);
		return 0;
	}

	port_reg_setbits(ahci, port, PxTFD, BMSK(PxTFD_STS_BSY));
	switch ( ahci_port_sata_sendfis(ahci, port, cfis, cfissz, sc) ) {
	case -1:
		/* Error sending FIS. */
		ahci_port_host_fatal_error(ahci, port);
		return 0;
	case 0:
		/* FIS sent, command queued. */
		cmd_done = 0;
		break;
	case 1:
		/* FIS sent, command executed. */
		cmd_done = 1;
		cmdhdr_freeprdt(ahci, sc);
		break;
	case 2:
		/* FIS sent, command queued but process new command. */
		cmd_done = 1;
		break;
	}

	mapper_put(ahci->mpr, cfis);
	/* If the C bit is set, from the AHCI POV the command is
	 * done. Tell the caller to issue a new one. */
	if ( cmd_done == 1 || (cmdhdr[0] & BMSK(CMDHDR_C)) ) {
		port_reg_clearbits(ahci, port, PxTFD, BMSK(PxTFD_STS_BSY));
		port_reg_clearbits(ahci, port, PxCI, BMSK(cmd));
		return 1;
	}

	/* Command sent. Callback from SATA will do the rest. */
	return 0;
}
static void
cmdlist_process(struct vahci *ahci, unsigned port)
{
	int cmd;
	uint8_t *cmdhdr;
	uint32_t ci;

	do {
		ci = port_reg_read(ahci, port, PxCI);

		if ( ci == 0 ) {
			/* All commands processed. Stop the engine. */
			ahci->ports[port].cmdlist_act = 0;
			return;
		}

		/* XXX: FIXME: assumes sizeof(int) >= sizeof(uint32_t) */
		cmd = ffs(ci) - 1;

//		info("Selected Command %d", cmd);
		/* Signal the device is busy on the AHCI side. */

	} while ( command_transmit(ahci, port, cmd) );
}

void
ahci_port_cmd_done(struct vahci *ahci, unsigned port, struct sata_command *sc)
{
	cmdhdr_freeprdt(ahci, sc);
	port_reg_clearbits(ahci, port, PxTFD, BMSK(PxTFD_STS_BSY));
	port_reg_clearbits(ahci, port, PxCI, BMSK(sata_command_get_cmd(sc)));
	cmdlist_process(ahci, port);
}


/*
 * HBA host emulation.
 */

static void
ahci_port_reset(struct vahci *ahci, unsigned port)
{
	/*
	 * "Resets all port specific register fields (for all ports) except
	 * those fields marked as HwInit and the PxFB/PxFBU/PxCLB/PxCLBU
	 * registers."
	 * NB: HwInit is us so we just skip the FB? and CLB? registers.
	 */
	port_reg_write(ahci, port, PxIS,   0x00000000);
	port_reg_write(ahci, port, PxIE,   0x00000000);
	port_reg_write(ahci, port, PxCMD,  0x00000000); /* XXX: POD,SUD set */
	port_reg_write(ahci, port, PxCI,   0x00000000);
	port_reg_write(ahci, port, PxSNTF, 0x00000000);
	port_reg_write(ahci, port, PxFBS,  0x00000000);

	/* These are reset values. Should be updated on COMRESET. */
	port_reg_write(ahci, port, PxTFD,  0x0000007f);
	port_reg_write(ahci, port, PxSIG,  0xffffffff);
	port_reg_write(ahci, port, PxSSTS, 0x00000000);
	port_reg_write(ahci, port, PxSCTL, 0x00000000);
	port_reg_write(ahci, port, PxSERR, 0x00000000);
	port_reg_write(ahci, port, PxSACT, 0x00000000);

	/* XXX: Check for zeroed bits and call functions? */
	ahci_port_sata_comreset(ahci, port);
}

static void
ahci_port_fisreceive_enable(struct vahci *ahci, unsigned port)
{
	info("enabling fis receive");
	/* Do not set PxCMD.FR if FIS buffer is not set. */
	if ( ahci->ports[port].fb == NULL ) {
		port_reg_clearbits(ahci, port, PxCMD, BMSK(PxCMD_FRE));
		return;
	}
	port_reg_setbits(ahci, port, PxCMD, BMSK(PxCMD_FR));
	info("enabled");
}

static void
ahci_port_fisreceive_disable(struct vahci *ahci, unsigned port)
{
	info("disabling fis receive");
	port_reg_clearbits(ahci, port, PxCMD, BMSK(PxCMD_FR));
	info("disabled");

}

static void
ahci_port_cmdlist_enable(struct vahci *ahci, unsigned port)
{
	info("Enabling cmdlist!");
	/* Do not set PxCMD.SR if Command List buffer is not set. */
	if ( ahci->ports[port].clb == NULL ) {
		port_reg_clearbits(ahci, port, PxCMD, BMSK(PxCMD_ST));
		return;
	}

	/* Guest can write to CI. */
	mmio_w32(ahci->mmio_w1, MMIO_PORT(port, PxCI), 0xffffffff);
	/* Notify the start of Command List DMA engine. */
	port_reg_setbits(ahci, port, PxCMD, BMSK(PxCMD_CR));
	info("cmdlist Enabled %08x", port_reg_read(ahci, port, PxCMD));
	cmdlist_process(ahci, port);
}

static void
ahci_port_cmdlist_disable(struct vahci *ahci, unsigned port)
{
	uint32_t tfd = port_reg_read(ahci, port, PxTFD);
	uint32_t msk = BMSK(PxTFD_STS_BSY)
			|BMSK(PxTFD_STS_DRQ)
			|BMSK(PxTFD_STS_ERR);

	info ("Disabling cmdlist!");
	/* Check for Requests to be clear. */
	if ( tfd & msk ) {
		port_reg_setbits(ahci, port, PxCMD, BMSK(PxCMD_ST));
		return;
	}

	/* Guest cannot write anymore to CI, which is zeroed. */
	port_reg_write(ahci, port, PxCI, 0);
	mmio_w32(ahci->mmio_w1, MMIO_PORT(port, PxCI), 0x00000000);

	/* Notify the stop of Command List DMA engine */
	port_reg_clearbits(ahci, port, PxCMD, BMSK(PxCMD_CR));
	info("cmdlist Disabled");
}

static void
ahci_port_process_clb(struct vahci *ahci, unsigned port)
{
	uint64_t gclb;

	gclb = (uint64_t)port_reg_read(ahci, port, PxCLBU) << 32;
	gclb |= (uint64_t)port_reg_read(ahci, port, PxCLB);

	if ( ahci->ports[port].gclb == gclb )
		return;

	if ( ahci->ports[port].clb != NULL )
		mapper_put(ahci->mpr, ahci->ports[port].clb);

	ahci->ports[port].gclb = gclb;
	ahci->ports[port].clb = mapper_get(ahci->mpr, gclb, CMDHDR_SIZE * AHCI_MAX_CMDS);

	if ( ahci->ports[port].clb == NULL ) {
		error("Mapping of CLB 0x%08x for port %d failed!",
			gclb, port);
		/* Mapping failed. Clear the register and 
		 * signal the HBA error. */
		port_reg_write(ahci, port, PxCLB, 0);
		ahci_port_host_fatal_error(ahci, port);
	}
	info("Setting gclb to %"PRIx64" (%08x)", gclb, ahci->ports[port].clb);
}

static void
ahci_port_process_fb(struct vahci *ahci, unsigned port)
{
	uint64_t gfb;

	gfb = (uint64_t)port_reg_read(ahci, port, PxFBU) << 32;
	gfb |= (uint64_t)port_reg_read(ahci, port, PxFB);

	info("called with %"PRIx64, gfb);
	if ( ahci->ports[port].gfb == gfb )
		return;

	if ( ahci->ports[port].fb != NULL )
		mapper_put(ahci->mpr, ahci->ports[port].fb);

	ahci->ports[port].gfb = gfb;
	ahci->ports[port].fb = mapper_get(ahci->mpr, gfb, 0x100);


	if ( ahci->ports[port].fb == NULL ) {
		error("Mapping of FB 0x%08x for port %d failed!",
			gfb, port);
		/* Mapping failed. Clear the register and
		 * signal the HBA error. */
		port_reg_write(ahci, port, PxFB, 0);
		ahci_port_host_fatal_error(ahci, port);
	}
	info("Setting gfb to %"PRIx64" (%08x)", gfb, ahci->ports[port].fb);
}

static void
ahci_port_process_cmd(struct vahci *ahci, unsigned port)
{
	unsigned new, old;
	uint32_t cmd = port_reg_read(ahci, port, PxCMD);

	/* Check changes in FIS Receival */
	new = !!(cmd & BMSK(PxCMD_FRE));
	old = !!(cmd & BMSK(PxCMD_FR));
	if ( new ^ old )  {
		if ( new )
			ahci_port_fisreceive_enable(ahci, port);
		else
			ahci_port_fisreceive_disable(ahci, port);
	}

	/* Check changes in Command Processing. */
	new = !!(cmd & BMSK(PxCMD_ST));
	old = !!(cmd & BMSK(PxCMD_CR));
	if ( new ^ old ) {
		if ( new )
			ahci_port_cmdlist_enable(ahci, port);
		else
			ahci_port_cmdlist_disable(ahci, port);
	}
}

static void
ahci_port_process_sctl(struct vahci *ahci, unsigned port)
{
	uint32_t sctl = port_reg_read(ahci, port, PxSCTL);
	unsigned det = sctl & 0xf;
	/* XXX: SPD, IPM ignored */

	switch ( det ) {
	case 1:
		ahci_port_reset(ahci, port);
		break;
	case 4:
		/* XXX: Disable */
		info("port %d disable request. Ignoring", port);
		break;
	default:
		warning("port %d: SControl request %d unsupported.",
			port, det);
	case 0:
		break;
	}
}

static void
ahci_port_process_ci(struct vahci *ahci, unsigned port)
{
	if ( ahci->ports[port].cmdlist_act )
		return;

	ahci->ports[port].cmdlist_act = 1;
	cmdlist_process(ahci, port);
}

static void
ahci_hba_reset(struct vahci *ahci)
{
	unsigned i;

	info("Resetting HBA");

	/* Reset GHC.AE, GHC.IE and IS. (GHC.AE is RO to 1 as CAP.SAM is 1) */
	reg_clearbits(ahci, GHC_GHC, BMSK(GHC_GHC_IE));

	reg_write(ahci, GHC_IS, 0);

	for ( i = 0; i <= AHCI_MAX_PORTS; i++ ) 
		if ( is_port_implemented(ahci, i) )
			ahci_port_reset(ahci, i);

	/* Clear GHC_GHC_HR to indicate HBA reset completion. */
	reg_clearbits(ahci, GHC_GHC, BMSK(GHC_GHC_HR));
}

static void
ahci_process_ghc(struct vahci *ahci)
{
	uint32_t ghc = reg_read(ahci, GHC_GHC);

	if ( ghc & BMSK(GHC_GHC_HR) )  {
		ahci_hba_reset(ahci);
		/* No other operations. */
		return;
	}

	/* XXX: FIXME: Check for interrupt enabling, call check intr! */
}

void
ahci_mmio_read(struct vahci *ahci, io_t *io)
{
	uint32_t off = io->addr - ahci->ioaddr;

	switch ( io->size ) {
	case 1:
		*(uint8_t *)io->data = mmio_r8(ahci->mmio, off);
		break;
	case 2:
		*(uint16_t *)io->data = mmio_r16(ahci->mmio, off);
		break;
	case 4:
		*(uint32_t *)io->data = mmio_r32(ahci->mmio, off);
		break;
	default:
		error("unexpected size (%d)", io->size);
		break;
	}
}

void
ahci_mmio_write(struct vahci *ahci, io_t *io)
{
	uint32_t off = io->addr - ahci->ioaddr;
	uint32_t data, old_val, new_val;
	uint32_t rw_mask, wc_mask, w1_mask;
	int port = -1;
	uint32_t poff = 0;

	if ( IS_PORT_MMIO(off) ) {
		port = MMIO_PORTNO(off);
		poff = MMIO_PORTOFF(off);

		if ( !is_port_implemented(ahci, port) ) {
			info("Port not implemented (%d, 0x%x)", port, poff);
			return;
		}
	}

	switch ( io->size ) {
	case 1:
		data = *(uint8_t *)io->data;
		old_val = mmio_r8(ahci->mmio, off);
		rw_mask = mmio_r8(ahci->mmio_rw, off);
		wc_mask = mmio_r8(ahci->mmio_wc, off);
		w1_mask = mmio_r8(ahci->mmio_w1, off);
		break;
	case 2:
		data = *(uint16_t *)io->data;
		old_val = mmio_r16(ahci->mmio, off);
		rw_mask = mmio_r16(ahci->mmio_rw, off);
		wc_mask = mmio_r16(ahci->mmio_wc, off);
		w1_mask = mmio_r16(ahci->mmio_w1, off);
		break;
	case 4:
		data = *(uint32_t *)io->data;
		old_val = mmio_r32(ahci->mmio, off);
		rw_mask = mmio_r32(ahci->mmio_rw, off);
		wc_mask = mmio_r32(ahci->mmio_wc, off);
		w1_mask = mmio_r32(ahci->mmio_w1, off);
		break;
	default:
		error("Unexpected size (%d)", off);
		return;
	}

	new_val = old_val & ~rw_mask;
	new_val |= data & (rw_mask | w1_mask);
	new_val &= ~(data & wc_mask);

	switch ( io->size ) {
	case 1:
		mmio_w8(ahci->mmio, off, new_val);
		break;
	case 2:
		mmio_w16(ahci->mmio, off, new_val);
		break;
	case 4:
		mmio_w32(ahci->mmio, off, new_val);
		break;
	default:
		error("unexpected size (%d)", off);
		return;
	}

#define MMIO_OVERLAP(__off, __cmdoff, __cmdsz) \
	!!((__off) >= (__cmdoff) && ((__off - __cmdoff) < (__cmdsz)))

	if ( MMIO_OVERLAP(off, GHC_GHC, 4) ) 
		ahci_process_ghc(ahci);

	/* Port MMIO */
	if ( port >= 0 ) {
		if ( MMIO_OVERLAP(poff, PxCLB, 4) )
			ahci_port_process_clb(ahci, port);
		if ( MMIO_OVERLAP(poff, PxFB, 4) )
			ahci_port_process_fb(ahci, port);
		if ( MMIO_OVERLAP(poff, PxCMD, 4) )
			ahci_port_process_cmd(ahci, port);
		if ( MMIO_OVERLAP(poff, PxSCTL, 4) ) {
			ahci_port_process_sctl(ahci, port);
		}
		if ( MMIO_OVERLAP(poff, PxCI, 4) )
			ahci_port_process_ci(ahci, port);
		if ( MMIO_OVERLAP(poff, PxIS, 4) )
			ahci_port_check_intr(ahci, port);
		if ( MMIO_OVERLAP(poff, PxIE, 4) )
			ahci_port_check_intr(ahci, port);
#if 0
		if ( MMIO_OVERLAP(poff, PxSACT, 4) )
			ahci_port_process_sact(ahci, port);

		if ( MMIO_OVERLAP(poff, PxFBS, 4) )
			ahci_port_process_fbs(ahci, port);
#endif
	}
#undef MMIO_OVERLAP
}

void
ahci_mmio_setaddr(struct vahci *ahci, uint32_t ioaddr)
{
	if ( ahci->ioaddr )  {
		info("removing iorange %x", ahci->ioaddr);
		iohandle_remove_iorange(ahci->iohdl, ahci->ioaddr,
					SURFMAN_IOHANDLE_MMIO);
	}

	ahci->ioaddr = ioaddr;
	if ( ahci->ioaddr ) {
		info("adding iorange %x", ahci->ioaddr);
		iohandle_add_iorange(ahci->iohdl,
				     ahci->ioaddr,
				     AHCI_MMIO_SIZE,
				     SURFMAN_IOHANDLE_MMIO, NULL);
	}
	info("Setting ABAR address to %x", ahci->ioaddr);
}

static void
_mmio_event(int fd, short event, void *opq)
{
	io_t io;
	struct vahci *ahci = (struct vahci *)opq;
	while ( iohandle_pending_io(ahci->iohdl, &io) == 0 ) {
		/* XXX: Check IO req */
		switch ( io.direction ) {
		case SURFMAN_IO_READ:
			ahci_mmio_read(ahci, &io);
			break;
		case SURFMAN_IO_WRITE:
			ahci_mmio_write(ahci, &io);
			break;
		default:
			warning("wrong ioreq direction (%d)", io.direction);
			break;
		}
		iohandle_complete_io(ahci->iohdl, &io);
	}
}

void
ahci_mmio_init(struct vahci *ahci, iohandle_t iohdl)
{
	int i;
	ahci->iohdl = iohdl;
	event_set(&ahci->ioev, iohandle_get_fd(iohdl),
		EV_READ | EV_PERSIST, _mmio_event, ahci);
	event_add(&ahci->ioev, NULL);

	/*
	 * NB: Following code is based on the non-trivial assumption
	 *     that mmio memory is zeroed on allocation.
	 */

	/*
	 * HBA Global Registers configuration.
	 */

	/* Set: S64A | SNCQ | IS 6Gbps | SAM | PMD */
	reg_write(ahci, GHC_CAP, 0xc0348000 
				| (AHCI_MAX_CMDS << GHC_CAP_NCS)
				| (AHCI_MAX_PORTS << GHC_CAP_NP));
	/* Set: AE, always enabled as CAP.SAM is on. */
	reg_write(ahci, GHC_GHC, 0x80000000);
	reg_write(ahci, GHC_PI,  0x00000000);

	/* MMIO RW/WC Registers configurations */
	mmio_w32(ahci->mmio_rw, GHC_GHC, 0x00000002);
	mmio_w32(ahci->mmio_w1, GHC_GHC, 0x00000001);
	mmio_w32(ahci->mmio_wc, GHC_IS,  0xffffffff);

	/*
	 * HBA Ports Registers configuration.
	 */
	for ( i = 0; i <= AHCI_MAX_PORTS; i++ ) {
		port_reg_write(ahci, i, PxCMD, 0x00000000);
		port_reg_write(ahci, i, PxTFD, 0x0000007f);
		port_reg_write(ahci, i, PxSIG, 0xffffffff);

		/* MMIO RW/WC Registers configurations */
		mmio_w32(ahci->mmio_rw, MMIO_PORT(i, PxCLB),  0xfffffc00);
		mmio_w32(ahci->mmio_rw, MMIO_PORT(i, PxCLBU), 0xffffffff);
		mmio_w32(ahci->mmio_rw, MMIO_PORT(i, PxFB),   0xfffffc00);
		mmio_w32(ahci->mmio_rw, MMIO_PORT(i, PxFBU),  0xffffffff);
		mmio_w32(ahci->mmio_wc, MMIO_PORT(i, PxIS),   0xfd8000af);
		mmio_w32(ahci->mmio_rw, MMIO_PORT(i, PxIE),   0x7dc0007f);
		mmio_w32(ahci->mmio_rw, MMIO_PORT(i, PxCMD),  0xf3800011);
		mmio_w32(ahci->mmio_rw, MMIO_PORT(i, PxSCTL), 0x00000fff);
		mmio_w32(ahci->mmio_wc, MMIO_PORT(i, PxSERR), 0xffffffff);
		mmio_w32(ahci->mmio_w1, MMIO_PORT(i, PxSACT), 0xffffffff);

		mmio_w32(ahci->mmio_wc, MMIO_PORT(i, PxSNTF), 0x0000ffff);
		/* PxFBS Not set to RW/W1, disabled. */
	}
}

int
ahci_port_attach_disk(struct vahci *ahci, unsigned port, struct vsata *sata)
{
	if ( !ahci_port_sata_attach(ahci, port, sata) )
		return 0;

	reg_setbits(ahci, GHC_PI, BMSK(port));
	ahci_port_sata_comreset(ahci, port);
	return 1;
}

struct vsata sata_test;

void
ahci_attach(struct vahci *ahci, iohandle_t iohdl,
	uint8_t bus, uint8_t dev, uint8_t fun)
{
	info("Device attached as %d:%d.%d", bus, dev, fun);
	ahci_pci_init(ahci, bus, dev, fun);
	ahci_mmio_init(ahci, iohdl);
	ahci->mpr = mapper_create(ahci->dev.d->domid);

	/* XXX: HACK: attach one disk */
	sata_setup(&sata_test, "Sata TEST disk", "/dev/xen/blktap-2/tapdev3");
	ahci_port_attach_disk(ahci, 0, &sata_test);
}

void
ahci_detach(struct vahci *ahci)
{
	event_del(&ahci->ioev);
	mapper_destroy(ahci->mpr);
}

