VERSION=0.01.03

CFLAGS += -Wall -DVERSION='"$(VERSION)"'

BINDIR=/usr/bin
MANDIR=/usr/share/man/man8

cpustat: cpustat.o
	$(CC) $< -lm -o $@

cpustat.8.gz: cpustat.8
	gzip -c $< > $@

dist:
	 git archive --format=tar --prefix="cpustat-$(VERSION)/" V$(VERSION) | \
		gzip > cpustat-$(VERSION).tar.gz

clean:
	rm -f cpustat cpustat.o cpustat.8.gz

install: cpustat cpustat.8.gz
	mkdir -p ${DESTDIR}${BINDIR}
	cp cpustat ${DESTDIR}${BINDIR}
	mkdir -p ${DESTDIR}${MANDIR}
	cp cpustat.8.gz ${DESTDIR}${MANDIR}
