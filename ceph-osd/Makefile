#!/usr/bin/make

lint:
	@flake8 --exclude hooks/charmhelpers hooks
	@charm proof || true

sync:
	@charm-helper-sync -c charm-helpers-sync.yaml

publish: lint
	bzr push lp:charms/ceph-osd
	bzr push lp:charms/trusty/ceph-osd
