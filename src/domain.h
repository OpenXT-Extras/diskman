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

#ifndef __DOMAIN_H
#define __DOMAIN_H

struct device_ops {
	void	(*takedown)(void *opqdev);
};

struct device {
	LIST_ENTRY(device) link;
	struct domain *d;

	int device_type;
	struct device_ops *ops;

	struct event ev;
	dmbus_client_t client;
};

struct domain
{
	LIST_ENTRY(domain) link;

	int domid;
	int dm_domid;

	LIST_HEAD(devices, device) devices;
};

#endif /* __DOMAIN_H */
