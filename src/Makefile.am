#
#
# Makefile.am:
#
#
# $Id:$
#
# $Log:$
#
#
#

#
# Copyright (c) 2012 Citrix Systems, Inc.
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#


CPROTO=cproto
INCLUDES = ${LIBSURFMAN_INC} ${LIBXC_INC} ${LIBDMBUS_INC}
noinst_HEADERS=project.h prototypes.h

bin_PROGRAMS= diskman

SRCS=diskman.c dm_rpc.c domain.c device_ahci.c ahci.c ahci_pci.c sata.c map.c blockio.c iov-helpers.c
diskman_SOURCES = ${SRCS}
diskman_LDADD = ${LIBSURFMAN_LIB} ${LIBXC_LIB} ${LIBDMBUS_LIB} -laio -lv4v

AM_CFLAGS=-g 

diskman_LDFLAGS =

BUILT_SOURCES = version.h

VFD=${srcdir}/..
VF=${shell cat ${VFD}/version-files}
VFS=${VF:%=${VFD}/%}
VCHK=${shell cat ${VFS} | @MD5SUM@ | @AWK@ '{print $$1 }' }
VNUM=${shell @GREP@ ${VCHK} ${VFD}/version-md5sums | @AWK@ '{ print $$2 }'  }
VDEF=${shell echo `cat ${VFD}/version-major`.`cat ${VFD}/version-minor`.`cat ${VFD}/version-micro` }

protos:
	echo > prototypes.h
	${CPROTO} -v ${SRCS} > prototypes.tmp 2> /dev/null
	mv -f prototypes.tmp prototypes.h



version.h: $(VFD)/version-files $(VFD)/version-major \
	$(VFD)/version-minor $(VFD)/version-micro \
	$(VFD)/version-md5sums ${VFS} Makefile
	if [ .${VNUM} = . ]; then \
		echo "#define VERSION \"diskman Version ${VDEF} + Edits\"" > version.h; \
		echo ${VDEF}-E > version-num; \
	else \
		echo "#define VERSION \"diskman Version ${VNUM}\"" > version.h; \
		echo ${VNUM} > version-num; \
	fi

