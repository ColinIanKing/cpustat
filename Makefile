VERSION=0.01.10

CFLAGS += -Wall -Wextra -DVERSION='"$(VERSION)"'

BINDIR=/usr/bin
MANDIR=/usr/share/man/man8

cpustat: cpustat.o
	$(CC) $(CPPFLAGS) $(CFLAGS)  $< -lm -o $@ $(LDFLAGS)

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
