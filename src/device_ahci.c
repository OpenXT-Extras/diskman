/*
 * Copyright (c) 2011 Citrix Systems, Inc.
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
 * Specification-compliant AHCI-only device.
 */

static int
device_ahci_config_read(void *priv, struct msg_config_io_read *msg,
			size_t msglen, struct msg_config_io_reply *out)
{
	struct vahci *ahci = priv;

	if ( !ahci ) {
		error("priv is NULL!");
		return -1;
	}

	out->data = ahci_pcicfg_read(ahci, msg->offset, msg->size);
	return 0;
}

static int
device_ahci_config_write(void *priv, struct msg_config_io_write *msg,
		size_t msglen, struct msg_empty_reply *out)
{
	struct vahci *ahci = priv;

	if ( !ahci ) {
		error("priv is NULL!");
		return -1;
	}

	ahci_pcicfg_write(ahci, msg->offset, msg->size, msg->data);
	return 0;
}

static int
device_ahci_attach_device(void *priv,struct msg_attach_pci_device *msg,
			size_t msglen, struct msg_empty_reply *out)
{
	iohandle_t iohdl;
	struct vahci *ahci = priv;

	if ( !ahci ) {
		error("priv is NULL!");
		return -1;
	}

	iohdl = iohandle_create(ahci->dev.d->domid);
	if ( !iohdl ) {
		error("could not create iohandle");
		return -1;
	}


	ahci_attach(ahci, iohdl, msg->bus, msg->device, msg->function);

	return 0;
}

struct dmbus_rpc_ops ahci_dmbus_ops = {
	.config_io_read = device_ahci_config_read,
	.config_io_write = device_ahci_config_write,
	.attach_pci_device = device_ahci_attach_device,
};

static void
device_ahci_takedown(void *priv)
{
	struct vahci *ahci = priv;

	if ( !ahci ) {
		error("priv is NULL!");
		return;
	}

	ahci_detach(ahci);	
	iohandle_destroy(ahci->iohdl);
}

struct device_ops device_ahci_ops = {
	.takedown = device_ahci_takedown,
};

struct device *
device_ahci_create(struct domain *d, struct dmbus_rpc_ops **opsp)
{
	struct vahci *ahci;

	info("Creating AHCI interface for domain %d", d->domid);

	ahci = device_create(d, &device_ahci_ops, sizeof(*ahci));
	if ( !ahci )
		return NULL;

	*opsp = &ahci_dmbus_ops;
	return &ahci->dev;
}
