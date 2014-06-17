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

static LIST_HEAD(, domain) domain_list = LIST_HEAD_INITIALIZER(domain);

/* Generic domain handling. */

int
domain_exists(struct domain *d)
{
	return xc_domid_exists(d->domid);
}

int
domain_dying(struct domain *d)
{
	xc_dominfo_t info;

	if ( xc_domain_getinfo(xch, d->domid, 1, &info) == 1 ) {
		return info.dying;
	}
	return 0;
}

struct domain *
domain_by_domid(int domid)
{
	struct domain *d;

	LIST_FOREACH(d, &domain_list, link) {
		if ( d->domid == domid )
			return d;
	}

	return NULL;
}

struct domain *
domain_create(int domid, int dm_domid)
{
	struct domain *ret;

	if ( domain_by_domid(domid) ) {
		error("Domain %d already exists", domid);
		return NULL;
	}

	ret = xcalloc(1, sizeof(*ret));
	ret->domid = domid;
	ret->dm_domid = dm_domid;
	LIST_INIT(&ret->devices);
	LIST_INSERT_HEAD(&domain_list, ret, link);

	return ret;
}

void
domain_destroy(struct domain *d)
{
	if  ( LIST_EMPTY(&d->devices) ) {
		LIST_REMOVE(d, link);
		free(d);
	}
}

/* Device handling. */

void *
device_create(struct domain *d, struct device_ops *ops, size_t size)
{
	struct device *ret;

	ret = xcalloc(1, size);
	ret->d = d;
	ret->ops = ops;
	LIST_INSERT_HEAD(&d->devices, ret, link);	

	return (void *)ret;
}

void
device_takedown(struct device *dev)
{
	if ( dev->ops->takedown )
		dev->ops->takedown((void *)dev);
}

void
device_destroy(struct device *device)
{
	LIST_REMOVE(device, link);
	free(device);
}
