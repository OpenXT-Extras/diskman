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

static struct event rpc_connect_event;

static void
rpc_handler(int fd, short event, void *priv)
{
	struct device *dev = priv;

	dmbus_handle_events(dev->client);
}

static int
rpc_connect(dmbus_client_t client, int domain, DeviceType type,
            int dm_domain, int fd, struct dmbus_rpc_ops **ops, void **priv)
{
        struct domain *d;
	struct device *dev;

	info("DM connected. domid %d device type %d", domain, type);

	d = domain_by_domid(domain);
	if ( !d )
		d = domain_create(domain, dm_domain);

	switch ( type )
	{
	case DEVICE_TYPE_AHCI:
		dev = device_ahci_create(d, ops);
		break;
	default:
		dev = NULL;
	}

	if ( !dev )
		return -1;

	dev->device_type = type;
	dev->client = client;

	event_set(&dev->ev, fd, EV_READ | EV_PERSIST, rpc_handler, dev);
	event_add(&dev->ev, NULL);

	*priv = dev;
	return 0;
}

static void
rpc_disconnect(dmbus_client_t client, void *priv)
{
	struct device *dev = priv;
	struct domain *d = dev->d;

	event_del(&dev->ev);
	device_takedown(dev);
	info("DM disconnected. domid %d", dev->d->domid);

	device_destroy(dev);
	if ( LIST_EMPTY(&d->devices) )
		domain_destroy(d);
}

static struct dmbus_service_ops service_ops = {
	.connect = rpc_connect,
	.disconnect = rpc_disconnect,
};

int
rpc_init(void)
{
	int fd = dmbus_init(DMBUS_SERVICE_DISKMAN, &service_ops);
	if ( fd == -1 )
	{
		error("Failed to initialize dmbus");
		return fd;
	}

	event_set(&rpc_connect_event, fd, EV_READ | EV_PERSIST,
		  (void *)dmbus_handle_connect, NULL);
	event_add(&rpc_connect_event, NULL);

	return 0;
}
