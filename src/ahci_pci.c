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
 * PCI Configuration.
 */


#define AHCI_VID 0x5853 /* Citrix/XenSource */
#define AHCI_DID 0xf000 /* Foo! */


/*
 * PCI Commands affecting device operations.
 * NB: Happily ignored for now.
 */

static void
pci_enable_slot(struct vahci *ahci)
{
	warning("Ignored.");
}

static void
pci_disable_slot(struct vahci *ahci)
{
	warning("Ignored.");
}

static void
pci_enable_interrupts_slot(struct vahci *ahci)
{
	warning("Ignored.");
}

static void
pci_disable_interrupts_slot(struct vahci *ahci)
{
	warning("Ignored.");
}

static void
pci_enable_mmio_slot(struct vahci *ahci)
{
	warning("Ignored.");
}

static void
pci_disable_mmio_slot(struct vahci *ahci)
{
	warning("Ignored.");
}


/*
 * PCI Interrupt handling.
 */

void
ahci_pci_set_interrupt_level(struct vahci *ahci, int level)
{
	xc_hvm_set_pci_intx_level(xch, ahci->dev.d->domid,  0,
				ahci->pci_bus, ahci->pci_dev, 0, level);
}

/*
 * PCI Configuration functions.
 */

static void
ahci_pcicfg_set_cmd(struct vahci *ahci, uint32_t old_val, uint32_t new_val)
{
	uint32_t diff = old_val ^ new_val;

	if ( diff & PCICFG_CMD_ID ) {
		if ( new_val & PCICFG_CMD_ID ) 
			pci_disable_interrupts_slot(ahci);
		else
			pci_enable_interrupts_slot(ahci);
	}
	if ( diff & PCICFG_CMD_BME ) {
		if ( new_val & PCICFG_CMD_BME )
			pci_enable_slot(ahci);
		else
			pci_disable_slot(ahci);
	}
	if ( diff & PCICFG_CMD_MSE ) {
		if ( new_val & PCICFG_CMD_MSE )
			pci_enable_mmio_slot(ahci);
		else
			pci_disable_mmio_slot(ahci);
	}
}

static void
ahci_pcicfg_set_abar(struct vahci *ahci, uint32_t old_val, uint32_t new_val)
{
	uint32_t ioaddr = new_val & 0xffffe000;

	ahci_mmio_setaddr(ahci, ioaddr);
}

uint32_t
ahci_pcicfg_read(struct vahci *ahci, size_t offset, size_t size)
{
	uint32_t data;

	if ( offset + size - 1 >= PCICFG_SIZE ) {
		error("Requested offset %d, higher than max offset %d", offset, PCICFG_SIZE);
		return ~0;
	}

	switch ( size ) {
		case 1:
			data = pcicfg_r8(ahci->pcicfg, offset);
			break;
		case 2:
			data = pcicfg_r16(ahci->pcicfg, offset);
			break;
		case 4:
			data = pcicfg_r32(ahci->pcicfg, offset);
			break;
		default:
			error("Unsupported data size (%d)", size);
			data = ~0;
			break;
	}


	return data;
}

#define PCICFG_OVERLAP(__offset, __cmdoff, __cmdsz) \
	!!((__offset) >= (__cmdoff) && ((__offset - __cmdoff) < (__cmdsz)))

void
ahci_pcicfg_write(struct vahci *ahci, size_t offset, 
		size_t size, uint32_t data)
{
	uint32_t rw_mask = 0;
	uint32_t wc_mask = 0;
	uint32_t old_val = 0;
	uint32_t new_val = 0;

	/* Support for unaligned MMIO operations. */
	int cmd_changed = 0; 
	uint32_t old_cmd, new_cmd;
	int abar_changed = 0;
	uint32_t old_abar, new_abar;

	if ( offset + size - 1 >= PCICFG_SIZE ) {
		error("Requested offset %d, higher than max offset %d",
			offset, PCICFG_SIZE);
		return;
	}

	cmd_changed = PCICFG_OVERLAP(offset, PCICFG_CMD, 2);
	abar_changed = PCICFG_OVERLAP(offset, PCICFG_ABAR, 4);

	switch ( size ) {
	case 1:
		data &= 0xff;
		old_val = pcicfg_r8(ahci->pcicfg, offset);
		rw_mask = pcicfg_r8(ahci->pcicfg_rw, offset);
		wc_mask = pcicfg_r8(ahci->pcicfg_wc, offset);
		break;
	case 2:
		data &= 0xffff;
		old_val = pcicfg_r16(ahci->pcicfg, offset);
		rw_mask = pcicfg_r16(ahci->pcicfg_rw, offset);	
		wc_mask = pcicfg_r16(ahci->pcicfg_wc, offset);
		break;
	case 4:
		old_val = pcicfg_r32(ahci->pcicfg, offset);
		rw_mask = pcicfg_r32(ahci->pcicfg_rw, offset);
		wc_mask = pcicfg_r32(ahci->pcicfg_wc, offset);
		break;
	default:
		error("Unsupported data size (%d)", size);
		return;
	}

	if ( cmd_changed )
		old_cmd = pcicfg_r16(ahci->pcicfg, PCICFG_CMD);
	if ( abar_changed )
		old_abar = pcicfg_r32(ahci->pcicfg, PCICFG_ABAR);

	new_val |= old_val & ~rw_mask;
	new_val |= data & rw_mask;
	new_val &= ~(data & wc_mask);

	info("Writing data at offset %d, %d ->[%d]-> %d",
		offset, data, old_val, new_val);

	switch ( size ) {
	case 1:
		pcicfg_w8(ahci->pcicfg, offset, new_val);
		break;
	case 2:
		pcicfg_w16(ahci->pcicfg, offset, new_val);
		break;
	case 4:
		pcicfg_w32(ahci->pcicfg, offset, new_val);
		break;
	default:
		error("Unsupported data size (%d)", size);
		return;
	}

	if ( cmd_changed )  {
		new_cmd = pcicfg_r16(ahci->pcicfg, PCICFG_CMD);
		ahci_pcicfg_set_cmd(ahci, old_cmd, new_cmd);
	}
	if ( abar_changed ) {
		new_abar = pcicfg_r32(ahci->pcicfg, PCICFG_ABAR);
		ahci_pcicfg_set_abar(ahci, old_abar, new_abar);
	}
}

static void
ahci_pcicfg_init(struct vahci *ahci)
{
	/*
	 * Set up values
	 */
	pcicfg_w32(ahci->pcicfg, PCICFG_ID, (AHCI_DID << 16)| AHCI_VID);
	pcicfg_w16(ahci->pcicfg, PCICFG_STS, (1 << PCICFG_STS_CL));
	pcicfg_w32(ahci->pcicfg, PCICFG_CC, 1 << 16 | PCICFG_CC_SCC_AHCI << 8 | 1);
	pcicfg_w8(ahci->pcicfg, PCICFG_CAP, 0x0); /* XXX: DISABLE PMCAP */
	pcicfg_w16(ahci->pcicfg, PCICFG_INTR, (1 << 8));

	pcicfg_w16(ahci->pcicfg, PCICFG_PMCAP, 1); /* No NEXT, PMCAP ID */
	pcicfg_w16(ahci->pcicfg, PCICFG_PMCAP_PC, (1 << 14)|3); /* D3HOT (req), Version 3 */

	/*
	 * Set up R/W Bitmap
	 */
	int i;
	pcicfg_w16(ahci->pcicfg_rw, PCICFG_CMD, PCICFG_CMD_RW);
	pcicfg_w8(ahci->pcicfg_rw, PCICFG_CLS, 0xff);
	pcicfg_w8(ahci->pcicfg_rw, PCICFG_MLT, 0xff);
	pcicfg_w32(ahci->pcicfg_rw, PCICFG_ABAR, 0xffffe000);
	pcicfg_w16(ahci->pcicfg_rw, PCICFG_INTR, 0x00ff);
	pcicfg_w16(ahci->pcicfg_rw, PCICFG_PMCAP_PMCS, 0x0103);

	/*
	 * Set up RWC Bitmap
	 */
	pcicfg_w16(ahci->pcicfg_wc, PCICFG_STS, 0xf900);
	pcicfg_w16(ahci->pcicfg_wc, PCICFG_PMCAP_PMCS, 0x8000);
}

void
ahci_pci_init(struct vahci *ahci, uint8_t bus, uint8_t dev, uint8_t fun)
{
	ahci->pci_bus = bus;
	ahci->pci_dev = dev;
	ahci->pci_fun = fun;

	ahci_pcicfg_init(ahci);
}
