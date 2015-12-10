PROJECT_DIR := $(shell pwd)
VERSION := $(shell cat VERSION|tr -d '\n';)
RELEASE := $(shell cat RELEASE|tr -d '\n';)

default: source

source:
	(python setup.py sdist; \
	rm -rf MANIFEST; \
	)

clean: clean-debs clean-rpms clean-source
	rm -rf *.egg-info *~

clean-debs:
	find . -name "*.pyc" -exec rm -rf {} \;
	rm -f MANIFEST
	rm -f build/f5-bigip-common_*.deb
	( \
	rm -rf deb_dist; \
	rm -rf build; \
	)

clean-rpms:
	find . -name "*.pyc" -exec rm -rf {} \;
	rm -f MANIFEST
	rm -rf f5-bigip-common*
	rm -f build/f5-bigip-common-*.rpm
	( \
	rm -rf dist; \
	rm -rf build; \
	)

clean-source:
	rm -rf build/*.tar.gz
	rm -rf common/*.tar.gz
	rm -rf common/dist
