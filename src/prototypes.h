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

/* diskman.c */
int main(int argc, char *argv[]);
/* dm_rpc.c */
int rpc_init(void);
/* domain.c */
int domain_exists(struct domain *d);
int domain_dying(struct domain *d);
struct domain *domain_by_domid(int domid);
struct domain *domain_create(int domid, int dm_domid);
void domain_destroy(struct domain *d);
void *device_create(struct domain *d, struct device_ops *ops, size_t size);
void device_takedown(struct device *dev);
void device_destroy(struct device *device);
/* device_ahci.c */
struct dmbus_rpc_ops ahci_dmbus_ops;
struct device_ops device_ahci_ops;
struct device *device_ahci_create(struct domain *d, struct dmbus_rpc_ops **opsp);
/* ahci.c */
void ahci_port_recv_fis_reg(struct vahci *ahci, unsigned port, uint32_t *fis);
void ahci_port_recv_fis_pio(struct vahci *ahci, unsigned port, uint32_t *fis);
void ahci_port_recv_fis_sdb(struct vahci *ahci, unsigned port, uint32_t *fis);
void ahci_port_recv_fis_init(struct vahci *ahci, unsigned port, uint32_t *fis);
void ahci_port_cmd_done(struct vahci *ahci, unsigned port, struct sata_command *sc);
void ahci_mmio_read(struct vahci *ahci, io_t *io);
void ahci_mmio_write(struct vahci *ahci, io_t *io);
void ahci_mmio_setaddr(struct vahci *ahci, uint32_t ioaddr);
void ahci_mmio_init(struct vahci *ahci, iohandle_t iohdl);
int ahci_port_attach_disk(struct vahci *ahci, unsigned port, struct vsata *sata);
struct vsata sata_test;
void ahci_attach(struct vahci *ahci, iohandle_t iohdl, uint8_t bus, uint8_t dev, uint8_t fun);
void ahci_detach(struct vahci *ahci);
/* ahci_pci.c */
void ahci_pci_set_interrupt_level(struct vahci *ahci, int level);
uint32_t ahci_pcicfg_read(struct vahci *ahci, size_t offset, size_t size);
void ahci_pcicfg_write(struct vahci *ahci, size_t offset, size_t size, uint32_t data);
void ahci_pci_init(struct vahci *ahci, uint8_t bus, uint8_t dev, uint8_t fun);
/* sata.c */
void send_piofis_ok(struct vsata *sata, size_t count, int direction, int intr);
void send_sdbfis_ok(struct vsata *sata, uint8_t tag, int intr);
void send_regfis_ok(struct vsata *sata, size_t count, int intr);
void send_regfis_err(struct vsata *sata, uint8_t err, int intr);
void sata_comreset(struct vsata *sata);
int sata_recvfis(struct vsata *sata, uint8_t *cfis, size_t cfissz, struct sata_command *sc);
int sata_attach(struct vsata *sata, struct vahci *ahci, unsigned port);
int sata_setup(struct vsata *sata, const char *name, const char *file);
/* map.c */
mapper_t mapper_lookup(int domid);
mapper_t mapper_create(int domid);
void *mapper_get(mapper_t mpr, uint64_t gaddr, size_t size);
void mapper_put(mapper_t mpr, void *addr);
void mapper_destroy(mapper_t mpr);
/* blockio.c */
int blkdev_read_async(struct blkdev *dev, struct blkop *op);
void blkdev_write_async(struct blkdev *dev, struct blkop *op);
uint64_t blkdev_get_sectors(struct blkdev *dev);
void blkdev_get_geo(struct blkdev *dev, uint16_t *cyls, uint16_t *heads, uint16_t *sects);
int blkdev_setup(struct blkdev *dev, const char *file, void *cbarg0);
/* iov-helpers.c */
void iovtrunc(struct iovec *iov, size_t iovcnt, size_t size);
size_t iov_to_mem(uint8_t *dst, size_t len, struct iovec *iov, size_t iovcnt);
size_t mem_to_iov(struct iovec *iov, size_t iovcnt, uint8_t *src, size_t len);
