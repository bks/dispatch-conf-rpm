SUBDIRS = man dispatch_conf
PYFILES = $(wildcard *.py)

PKGNAME = dispatch-conf
VERSION=$(shell awk '/Version:/ { print $$2 }' ${PKGNAME}.spec)
RELEASE=$(shell awk '/Release:/ { print $$2 }' ${PKGNAME}.spec)
PYTHON=python

all: subdirs

clean:
	rm -f *.pyc *.pyo *~ *.bak
	for d in $(SUBDIRS); do make -C $$d clean ; done

subdirs:
	for d in $(SUBDIRS); do make PYTHON=$(PYTHON) -C $$d; [ $$? = 0 ] || exit 1 ; done

install:
	mkdir -p $(DESTDIR)/usr/bin
	install -m 755 dispatch-conf $(DESTDIR)/usr/bin/dispatch-conf
	for d in $(SUBDIRS); do make PYTHON=$(PYTHON) DESTDIR=`cd $(DESTDIR); pwd` -C $$d install; [ $$? = 0 ] || exit 1; done
