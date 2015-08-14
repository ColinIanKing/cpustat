#
# Copyright (C) 2011-2015 Canonical
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
#
# Author: Colin Ian King <colin.king@canonical.com>
#

VERSION=0.01.20

CFLAGS += -Wall -Wextra -DVERSION='"$(VERSION)"' -O2

#
# Some useful optimisation settings for GCC
#
# -Winline \
# -fwhole-program -freciprocal-math -ffast-math \
# --param max-reload-search-insns=32768 \
# --param max-cselib-memory-locations=32768
#
BINDIR=/usr/bin
MANDIR=/usr/share/man/man8

cpustat: cpustat.o Makefile
	$(CC) $(CPPFLAGS) $(CFLAGS)  $< -lm -o $@ $(LDFLAGS)

cpustat.o: cpustat.c Makefile

cpustat.8.gz: cpustat.8
	gzip -c $< > $@

dist:
	rm -rf cpustat-$(VERSION)
	mkdir cpustat-$(VERSION)
	cp -rp Makefile cpustat.c cpustat.8 COPYING cpustat-$(VERSION)
	tar -zcf cpustat-$(VERSION).tar.gz cpustat-$(VERSION)
	rm -rf cpustat-$(VERSION)

clean:
	rm -f cpustat cpustat.o cpustat.8.gz

install: cpustat cpustat.8.gz
	mkdir -p ${DESTDIR}${BINDIR}
	cp cpustat ${DESTDIR}${BINDIR}
	mkdir -p ${DESTDIR}${MANDIR}
	cp cpustat.8.gz ${DESTDIR}${MANDIR}
