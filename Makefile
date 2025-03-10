#
# Copyright (C) 2011-2021 Canonical
# Copyright (C) 2021-2025 Colin Ian King
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
# Author: Colin Ian King <colin.i.king@gmail.com>
#

VERSION=0.03.00

CFLAGS += -Wall -Wextra -DVERSION='"$(VERSION)"' -O2 -g

#
# Pedantic flags
#
ifeq ($(PEDANTIC),1)
CFLAGS += -Wabi -Wcast-qual -Wfloat-equal -Wmissing-declarations \
	-Wmissing-format-attribute -Wno-long-long -Wpacked \
	-Wredundant-decls -Wshadow -Wno-missing-field-initializers \
	-Wno-missing-braces -Wno-sign-compare -Wno-multichar
endif
#
# Some useful optimisation settings for GCC
#
# -Winline \
# -fwhole-program -freciprocal-math -ffast-math \
# --param max-reload-search-insns=32768 \
# --param max-cselib-memory-locations=32768
#
BINDIR=/usr/sbin
MANDIR=/usr/share/man/man8
BASHDIR=/usr/share/bash-completion/completions

cpustat: cpustat.o Makefile
	$(CC) $(CPPFLAGS) $(CFLAGS)  $< -lm -lncurses -o $@ $(LDFLAGS)

cpustat.o: cpustat.c Makefile

cpustat.8.gz: cpustat.8
	gzip -c $< > $@

dist:
	rm -rf cpustat-$(VERSION)
	mkdir cpustat-$(VERSION)
	cp -rp README.md Makefile cpustat.c cpustat.8 COPYING mascot \
		.travis.yml snap bash-completion cpustat-$(VERSION)
	tar -Jcf cpustat-$(VERSION).tar.xz cpustat-$(VERSION)
	rm -rf cpustat-$(VERSION)

clean:
	rm -f cpustat cpustat.o cpustat.8.gz
	rm -f cpustat-$(VERSION).tar.xz


install: cpustat cpustat.8.gz
	mkdir -p ${DESTDIR}${BINDIR}
	cp cpustat ${DESTDIR}${BINDIR}
	mkdir -p ${DESTDIR}${MANDIR}
	cp cpustat.8.gz ${DESTDIR}${MANDIR}
	mkdir -p ${DESTDIR}${BASHDIR}
	cp bash-completion/cpustat ${DESTDIR}${BASHDIR}
