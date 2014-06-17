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

#define _GNU_SOURCE
#include <search.h>

/*
 * Simple, yet fast and sane mapper cache.
 */

#define CHUNK_SHIFT 15
#define CHUNK_SIZE (1 << CHUNK_SHIFT)
#define CHUNK_MASK ~(CHUNK_SIZE - 1)

static struct mapper_globals {
	xc_interface *xcif;
	LIST_HEAD(, mapper) mappers;
} globals = { 
	.xcif = NULL,
	.mappers = LIST_HEAD_INITIALIZER(mappers),
};

struct mpc_entry {
	STAILQ_ENTRY(mpc_entry) link;

	uint64_t	gaddr;
	uint8_t 	*addr;
	size_t		 size;
	unsigned	  ref;
	int	  in_freelist;
};


#define ADDR_IN_RANGE(_a, _b) \
	( ((_a)->addr >= (_b)->addr) \
	  && ((_a)->addr < (_b)->addr + (_b)->size) )
	
#define IN_RANGE(_a, _b) \
	( ((_a)->gaddr >= (_b)->gaddr) \
	  && ((_a)->gaddr + (_a)->size <= (_b)->gaddr + (_b)->size) )


#define MAX_CACHED_ENTRIES 15

/*
 * Tree comparing functions 
 * NOT as straigforward as you might think. Modify at your own risk.
 */

static int
_compare_equal(const void *a, const void *b)
{
	struct mpc_entry *ea, *eb;
	ea = (struct mpc_entry *)a;
	eb = (struct mpc_entry *)b;


	if ( ea->gaddr < eb->gaddr )
		return -1;

	if ( ea->gaddr == eb->gaddr  ) {
		if ( ea->size < eb->size )
			return -1;
		if ( ea->size == eb->size )
			return 0;
	}

	return 1;
}

static int
_compare_rev_equal(const void *a, const void *b)
{
	struct mpc_entry *ea, *eb;
	ea = (struct mpc_entry *)a;
	eb = (struct mpc_entry *)b;

	if ( ea->size == eb->size
	     && ea->gaddr == eb->gaddr
	     && ea->addr == eb->addr )
		return 0;

	if ( ea->addr <= eb->addr )
		return -1;

	return 1;
}

static int
_compare(const void *a, const void *b)
{
	struct mpc_entry *ea, *eb;
	ea = (struct mpc_entry *)a;
	eb = (struct mpc_entry *)b;

	if ( ea->gaddr < eb->gaddr )
		return -1;

	if ( IN_RANGE(ea, eb) )
		return 0;

	return 1;
}

static int
_compare_rev(const void *a, const void *b)
{
	struct mpc_entry *ea, *eb;
	ea = (struct mpc_entry *)a;
	eb = (struct mpc_entry *)b;

	if ( ADDR_IN_RANGE(ea, eb) )
		return 0;

	if ( ea->addr <= eb->addr )
		return -1;

	return 1;
}


struct mapper {
	LIST_ENTRY(mapper) link;

	int domid;

	void *root;
	void *rev_root;

	unsigned free_count;
	STAILQ_HEAD(, mpc_entry) free;
};


static struct mpc_entry *
entry_revlookup(mapper_t mpr, void *addr)
{
	struct mpc_entry key, **ptr;
	key.addr = addr;

	ptr = tfind(&key, &mpr->rev_root, _compare_rev);
	if ( ptr == NULL ) 
		return  NULL;

	return *ptr;
}

static struct mpc_entry *
entry_search(mapper_t mpr, uint64_t gaddr, size_t size)
{
	struct mpc_entry *e;
	struct mpc_entry key, **ptr;
	key.gaddr = gaddr;
	key.size = size;

	ptr = tfind(&key, &mpr->root, _compare);
	if ( ptr != NULL ) {
		return *ptr;
	}

	/* Not found. Add. */
	e = calloc(1, sizeof(struct mpc_entry));
	if ( e == NULL ) {
		error("could not allocate struct mpc_entry");
		return NULL;
	}
	e->gaddr = gaddr;
	e->size = size;
	e->ref = 0;
	e->in_freelist = 0;
	e->addr = xc_map_foreign_range(globals.xcif, mpr->domid, size,
					PROT_READ|PROT_WRITE, gaddr >> XC_PAGE_SHIFT);
	if ( e->addr == NULL ) {
		free(e);
		return NULL;
	}

	tsearch(e, &mpr->root, _compare);
	tsearch(e, &mpr->rev_root, _compare_rev);
	return e;
}


static void
entry_destroy(struct mpc_entry *e)
{
	munmap(e->addr, e->size);
	free(e);
}

static unsigned
entry_incref(struct mpc_entry *e)
{
	e->ref++;
	if ( e->ref == 0 ) {
		error("reference counting overflow (%"PRIx64")!", e->gaddr);
		/* Bad things will happen. */
		e->ref = ~0;
	}
	return e->ref;
}

static int 
entry_decref(struct mpc_entry *e)
{
	if ( e->ref == 0 ) {
		error("reference counting underflow (%08x)", e->gaddr);
		return 0;
	}
	return --e->ref;
}

mapper_t mapper_lookup(int domid)
{
	struct mapper *m;
	LIST_FOREACH(m, &globals.mappers, link) {
		if ( m->domid == domid )
			return m;
	}
	return NULL;
}

mapper_t mapper_create(int domid)
{
	mapper_t mpr;

	if ( globals.xcif == NULL ) {
		globals.xcif = xc_interface_open(0,0,0);
	}

	if ( globals.xcif == NULL ) {
		error("XC interface open error.");
		return NULL;
	}

	mpr = mapper_lookup(domid);
	if ( mpr != NULL )
		return mpr;

	mpr = (mapper_t)calloc(1, sizeof(struct mapper));
	if ( mpr == NULL ) {
		error("could not allocate mapper for domain %d", domid);
		return NULL;
	}

	mpr->domid = domid;
	mpr->root = NULL;
	mpr->rev_root = NULL;

	mpr->free_count = 0;
	STAILQ_INIT(&mpr->free);
	return mpr;
}

static void
mapper_freelist_remove_tail(mapper_t mpr)
{
	struct mpc_entry *t = STAILQ_LAST(&mpr->free, mpc_entry, link);

	if ( t == NULL  ) {
		error("Freelist is full but it appears to be empty!");
		return;
	}


	STAILQ_REMOVE(&mpr->free, t, mpc_entry, link);	
	tdelete(t, &mpr->root, _compare_equal);
	tdelete(t, &mpr->rev_root, _compare_rev_equal);
#if 0 /* DEBUG */
	if ( tfind(t, &mpr->root, _compare_equal) != NULL )
		info("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA! compare_ptr");
	if ( tfind(t, &mpr->rev_root, _compare_rev_equal) != NULL )
		info("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA MOOOOOOH");
#endif
	entry_destroy(t);
	mpr->free_count--;
}

static void
mapper_freelist_remove(mapper_t mpr, struct mpc_entry *e)
{
	STAILQ_REMOVE(&mpr->free, e, mpc_entry, link);
	e->in_freelist = 0;
	mpr->free_count--;
}

static void
mapper_freelist_add(mapper_t mpr, struct mpc_entry *e)
{
	e->in_freelist = 1;
	STAILQ_INSERT_HEAD(&mpr->free, e, link);
	mpr->free_count++;

	if ( mpr->free_count >= MAX_CACHED_ENTRIES )
		mapper_freelist_remove_tail(mpr);
}

void *
mapper_get(mapper_t mpr, uint64_t gaddr, size_t size)
{
	struct mpc_entry *e;
	uint64_t aln_gaddr;
	size_t offset, aln_size;

	aln_gaddr = gaddr & CHUNK_MASK;
	offset = gaddr - aln_gaddr;
	aln_size = (offset + size + CHUNK_SIZE - 1) & CHUNK_MASK;

	e = entry_search(mpr, aln_gaddr, aln_size);
	if ( e == NULL ) {
		/* Something very bad happened. Duck and cover. */
		error("mapping failed for domain %d", mpr->domid);
		return NULL;
	}

	entry_incref(e);
	if ( e->in_freelist )
		mapper_freelist_remove(mpr, e);

	return e->addr + (gaddr - e->gaddr);
}

void
mapper_put(mapper_t mpr, void *addr)
{
	struct mpc_entry *e;

	e = entry_revlookup(mpr, addr);
	if ( e == NULL ) {
		/* Releasing a non-existent mapping. Bad. */
		error("releasing a non-existing mapping at addr %08x", addr);
		return;
	}

	if ( entry_decref(e) == 0 ) {
		/* Add to Free List. */
		mapper_freelist_add(mpr, e);
	}
}

static void _nop(void *a)
{
}

void mapper_destroy(mapper_t mpr)
{
	tdestroy(mpr->root, entry_destroy);
	tdestroy(mpr->rev_root, _nop);
	free(mpr);
}
