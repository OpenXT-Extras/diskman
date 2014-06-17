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

void
iovtrunc(struct iovec *iov, size_t iovcnt, size_t size)
{
	size_t i, offset = 0;
	for ( i = 0; i < iovcnt; i++ ) {
		if ( offset + iov[i].iov_len > size )
			iov[i].iov_len = (size - offset > 0) ? 
						size - offset : 0;
		offset += iov[i].iov_len;
	}
}

size_t
iov_to_mem(uint8_t *dst, size_t len, struct iovec *iov, size_t iovcnt)
{
	int offset = 0, i = 0;
	void *iobase;
	size_t iolen, towrite;

	while ( offset < len && i < iovcnt ) {
		if ( offset > len )
			break;
		iobase = iov[i].iov_base;
		iolen = iov[i].iov_len;
		towrite = len - offset;
		memcpy(dst + offset, iobase,
			iolen < towrite ?  iolen : towrite);
		offset += iolen;
		i++;
	}

	return len < offset ? len : offset;	
}

size_t
mem_to_iov(struct iovec *iov, size_t iovcnt, uint8_t *src, size_t len)
{
	int offset = 0, i = 0;
	void *iobase;
	size_t iolen, towrite;

	while ( offset < len && i < iovcnt ) {
		if ( offset > len )
			break;
		iobase = iov[i].iov_base;
		iolen = iov[i].iov_len;
		towrite = len - offset;
		memcpy(iobase, src + offset,
			iolen < towrite ?  iolen : towrite);
		offset += iolen;
		i++;
	}

	return len < offset ? len : offset;	
}

