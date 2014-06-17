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
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <linux/hdreg.h>
#include <linux/fs.h>
#include <fcntl.h>
#include <unistd.h>

#include <libaio.h>

#define AIO_EVENTS AHCI_MAX_CMDS


#define BLKDEV_BUF_SIZE 2*1024*1024
#define BLKDEV_BUF_THRESHOLD 256*1024

static void blkio_buffer_cb(struct blkdev *, struct blkop *, uint64_t val);

static void
blkio_event(int fd, short event, void *arg)
{
	int nev, i;
	struct blkop *op;
	struct io_event aio_evs[AIO_EVENTS];
	struct blkdev *dev = (struct blkdev *)arg;

	while ( 1 ) {
		ssize_t ret;
		uint64_t val;

		do {
			ret = read(dev->efd, &val, sizeof(val));
		} while ( ret == -1 && errno == EINTR );

		if ( ret == -1 || ret != sizeof(val) )
			break;

		do {
			nev = io_getevents(dev->ioctx, val,
					AIO_EVENTS, aio_evs, NULL);
		} while ( nev == -EINTR );	


		for ( i = 0; i < nev; i++ ) {
			op = (struct blkop *)aio_evs[i].obj;
			if ( blkio_bufferop(op->type) )
				blkio_buffer_cb(dev, op, val);
			else
				op->cb(dev->cbarg0, op, val);
		}
	}
}

static void
blkio_write_async(struct blkdev *dev, struct blkop *op)
{
	struct iocb *iocb = &op->iocb;

	if ( blkio_vector(op->type) )
		io_prep_pwritev(iocb, dev->fd, op->iov, op->iovcnt, op->off);
	else
		io_prep_pwrite(iocb, dev->fd, op->buf, op->buflen, op->off);

	io_set_eventfd(iocb, dev->efd);
	io_submit(dev->ioctx, 1, &iocb);
}

static void
blkio_read_async(struct blkdev *dev, struct blkop *op)
{
	struct iocb *iocb = &op->iocb;

	errno=0;
	if ( blkio_vector(op->type) ) {
		io_prep_preadv(iocb, dev->fd, op->iov, op->iovcnt, op->off);
	} else {
		//info("BUH %x: (%x) %s", op->type, op->buf, strerror(errno));
		io_prep_pread(iocb, dev->fd, op->buf, op->buflen, op->off);
	}
	io_set_eventfd(iocb, dev->efd);
	io_submit(dev->ioctx, 1, &iocb);
}

static void
blkio_read_mem(struct blkdev *dev, struct blkop *op, void *mem, size_t len)
{
	if ( blkio_vector(op->type) ) 
		mem_to_iov(op->iov, op->iovcnt, mem, len);
	else {
		size_t cpylen = len < op->buflen ? len : op->buflen;
		memcpy(op->buf, mem, cpylen);
	}
}

static void
blkio_buffer_invalidate(struct blkdev *dev)
{
	dev->buf_off = -1;
}

static void
blkio_buffer_cb(struct blkdev *dev, struct blkop *bufop, uint64_t val)
{
	struct blkop *op = bufop->orig_op;
	void (*cb)(struct blkdev *, void *, uint64_t);
	size_t len = blkio_vector(op->type) ? op->iovlen : op->buflen;

	dev->buf_off = bufop->off;
	blkio_read_mem(dev, op, dev->buf, len);
	cb = op->cb;
	cb(dev->cbarg0, op, val);
	free(bufop);
}

static int
blkio_buffer_read(struct blkdev *dev, struct blkop *op)
{
	struct blkop *bufop;

	size_t len = blkio_vector(op->type) ? op->iovlen : op->buflen;

	if ( (dev->buf_off != -1) 
	     && (op->off >= dev->buf_off)
	     && (op->off + len <= dev->buf_off + BLKDEV_BUF_SIZE) ) {
		size_t off = op->off - dev->buf_off;
//		info("Offset %"PRIx64" found at buffer offset %x (%"PRIx64")", 
//			op->off, off, dev->buf_off);
		blkio_read_mem(dev, op, dev->buf + off, len);
		return 1;
	}

	bufop = calloc(1, sizeof(struct blkop));
	if ( bufop == NULL ) {
		error("Could not allocate buffer blkop, using async read");
		blkio_buffer_invalidate(dev);
		blkio_read_async(dev, op);
		return 0; //queued
	}

//	info("populating buffer at offset %"PRIx64, op->off);
	bufop->type = BLKTYPE_BUFFER | BLKTYPE_BUFFEROP;
	bufop->buf = dev->buf;
	bufop->buflen = BLKDEV_BUF_SIZE;
	bufop->off = op->off;
	bufop->orig_op = op;
	blkio_read_async(dev, bufop);
	return 0;
}

int
blkdev_read_async(struct blkdev *dev, struct blkop *op)
{
	size_t len = blkio_vector(op->type) ? op->iovlen : op->buflen;
#if 0
	if ( len < BLKDEV_BUF_THRESHOLD )
		return blkio_buffer_read(dev, op);
	else {
#endif
		blkio_buffer_invalidate(dev);
		blkio_read_async(dev, op);
		return 0;
#if 0
	}
#endif
}

void
blkdev_write_async(struct blkdev *dev, struct blkop *op)
{
	blkio_buffer_invalidate(dev);
	blkio_write_async(dev, op);
}

uint64_t
blkdev_get_sectors(struct blkdev *dev)
{
	struct stat st;
	uint64_t bytes = 0;
	uint32_t sectors; 

	if ( dev->is_block ) {
#ifdef BLKGETSIZE64

		info("bytes: %"PRIx64, bytes);
		if ( !ioctl(dev->fd, BLKGETSIZE64, &bytes) ) {
			info("bytes: %"PRIx64, bytes);
			return bytes/ATA_SECTOR_SIZE;
		}
#endif
		if ( !ioctl(dev->fd, BLKGETSIZE, &sectors) )
			return sectors;

		error("ioctl(BLKGETSIZE) failed. Returing size 0");
		return 0;
	}

	/* Not a block device. Use stat. */
	if ( !fstat(dev->fd, &st) )
		return st.st_size/ATA_SECTOR_SIZE;	

	error("stat failed. Returning size 0");
	return 0;
}

void
blkdev_get_geo(struct blkdev *dev, uint16_t *cyls, uint16_t *heads, uint16_t *sects)
{
	uint64_t sectors;
	struct hd_geometry geo;

	sectors = blkdev_get_sectors(dev);
	if ( dev->is_block && !ioctl(dev->fd, HDIO_GETGEO, &geo)) {
			*cyls = geo.cylinders;
			*heads = geo.heads;
			*sects = geo.sectors;
	} else {
		/* Guess using LBA size. */
		*cyls = sectors / (15 * 63);
		*heads = 15;
		*sects = 63;
	}

	/* Fix cylinders for block devices. */
	if ( ((uint64_t)*cyls * *heads * *sects) < sectors )
		*cyls = sectors / (*heads * *sects);
}

int
blkdev_setup(struct blkdev *dev, const char *file, void *cbarg0)
{
	struct stat st;
	if ( io_setup(AIO_EVENTS, &dev->ioctx) != 0 ) {
		error("Could not setup AIO");
		return -1;
	}

	dev->fd = open(file, O_RDWR);
	if ( dev->fd < 0 ) {
		error("Could not open file %s", file);
		io_destroy(dev->ioctx);
		return -1;
	}

	dev->efd = eventfd(0, 0);
	fcntl(dev->efd, F_SETFL, O_NONBLOCK);
	if ( dev->efd < 0 ) {
		error("Could not get event fd for AIO");
		io_destroy(dev->ioctx);
		close(dev->fd);
		return -1;
	}

	dev->buf = mmap(NULL, BLKDEV_BUF_SIZE, PROT_READ|PROT_WRITE,
			MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if ( dev->buf == MAP_FAILED ) {
		error("Could not allocate IO buffer");
		close(dev->efd);
		io_destroy(dev->ioctx);
		close(dev->fd);
		return -1;
	}
	dev->buf_off = -1;

	if ( !fstat(dev->fd, &st) )
		dev->is_block = S_ISBLK(st.st_mode);
	else
		warning("stat failed.");

	event_set(&dev->event, dev->efd, EV_READ|EV_PERSIST, blkio_event, dev);
	event_add(&dev->event, NULL);
	dev->cbarg0 = cbarg0;
	return 0;
}
