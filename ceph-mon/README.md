# Overview

[Ceph][ceph-upstream] is a unified, distributed storage system designed for
excellent performance, reliability, and scalability.

The ceph-mon charm deploys Ceph monitor nodes, allowing one to create a monitor
cluster. It is used in conjunction with the [ceph-osd][ceph-osd-charm] charm.
Together, these charms can scale out the amount of storage available in a Ceph
cluster.

# Usage

## Deployment

A cloud with three MON nodes is a typical design whereas three OSD nodes are
considered the minimum. For example, to deploy a Ceph cluster consisting of
three OSDs and three MONs:

    juju deploy -n 3 --config ceph-osd.yaml ceph-osd
    juju deploy --to lxd:0 ceph-mon
    juju add-unit --to lxd:1 ceph-mon
    juju add-unit --to lxd:2 ceph-mon
    juju add-relation ceph-osd ceph-mon

Here, a containerised MON is running alongside each OSD.

By default, the monitor cluster will not be complete until three ceph-mon units
have been deployed. This is to ensure that a quorum is achieved prior to the
addition of storage devices.

See the [Ceph documentation][ceph-docs-monitors] for notes on monitor cluster
deployment strategies.

> **Note**: Refer to the [Install OpenStack][cdg-install-openstack] page in the
  OpenStack Charms Deployment Guide for instructions on installing a monitor
  cluster for use with OpenStack.

## Network spaces

This charm supports the use of Juju [network spaces][juju-docs-spaces] (Juju
`v.2.0`). This feature optionally allows specific types of the application's
network traffic to be bound to subnets that the underlying hardware is
connected to.

> **Note**: Spaces must be configured in the backing cloud prior to deployment.

The ceph-mon charm exposes the following Ceph traffic types (bindings):

- 'public' (front-side)
- 'cluster' (back-side)

For example, providing that spaces 'data-space' and 'cluster-space' exist, the
deploy command above could look like this:

    juju deploy -n 3 --config ceph-mon.yaml ceph-mon \
       --bind "public=data-space cluster=cluster-space"

Alternatively, configuration can be provided as part of a bundle:

```yaml
    ceph-mon:
      charm: cs:ceph-mon
      num_units: 1
      bindings:
        public: data-space
        cluster: cluster-space
```

Refer to the [Ceph Network Reference][ceph-docs-network-ref] to learn about the
implications of segregating Ceph network traffic.

> **Note**: Existing ceph-mon units configured with the `ceph-public-network`
  or `ceph-cluster-network` options will continue to honour them. Furthermore,
  these options override any space bindings, if set.

## Monitoring

The charm supports Ceph metric monitoring with Prometheus. Add relations to the
[prometheus][prometheus-charm] application in this way:

    juju deploy prometheus2
    juju add-relation ceph-mon prometheus2

> **Note**: Prometheus support is available starting with Ceph Luminous
  (xenial-queens UCA pocket).

## Actions

This section lists Juju [actions][juju-docs-actions] supported by the charm.
Actions allow specific operations to be performed on a per-unit basis. To
display action descriptions run `juju actions ceph-mon`. If the charm is not
deployed then see file `actions.yaml`.

* `copy-pool`
* `create-cache-tier`
* `create-crush-rule`
* `create-erasure-profile`
* `create-pool`
* `crushmap-update`
* `delete-erasure-profile`
* `delete-pool`
* `get-erasure-profile`
* `get-health`
* `list-erasure-profiles`
* `list-pools`
* `pause-health`
* `pool-get`
* `pool-set`
* `pool-statistics`
* `remove-cache-tier`
* `remove-pool-snapshot`
* `rename-pool`
* `resume-health`
* `security-checklist`
* `set-noout`
* `set-pool-max-bytes`
* `show-disk-free`
* `snapshot-pool`
* `unset-noout`

# Bugs

Please report bugs on [Launchpad][lp-bugs-charm-ceph-mon].

For general charm questions refer to the OpenStack [Charm Guide][cg].

<!-- LINKS -->

[ceph-upstream]: https://ceph.io
[cg]: https://docs.openstack.org/charm-guide
[ceph-osd-charm]: https://jaas.ai/ceph-osd
[juju-docs-actions]: https://jaas.ai/docs/actions
[juju-docs-spaces]: https://jaas.ai/docs/spaces
[ceph-docs-network-ref]: http://docs.ceph.com/docs/master/rados/configuration/network-config-ref
[ceph-docs-monitors]: https://docs.ceph.com/docs/master/dev/mon-bootstrap
[lp-bugs-charm-ceph-mon]: https://bugs.launchpad.net/charm-ceph-mon/+filebug
[cdg-install-openstack]: https://docs.openstack.org/project-deploy-guide/charm-deployment-guide/latest/install-openstack.html
[prometheus-charm]: https://jaas.ai/prometheus2
