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

    juju deploy --config ceph-osd.yaml -n 3 ceph-osd
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

    juju deploy --config ceph-mon.yaml -n 3 ceph-mon \
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

## Actions

This section lists Juju [actions][juju-docs-actions] supported by the charm.
Actions allow specific operations to be performed on a per-unit basis.

### copy-pool

Copy contents of a pool to a new pool.

### create-cache-tier

Create a new cache tier.

### create-crush-rule

Create a new replicated CRUSH rule to use on a pool.

### create-erasure-profile

Create a new erasure code profile to use on a pool.

### create-pool

Create a pool.

### crushmap-update

Apply a new CRUSH map definition.

> **Warning**: This action can break your cluster in unexpected ways if
  misused.

### delete-erasure-profile

Delete an erasure code profile.

### delete-pool

Delete a pool.

### get-erasure-profile

Display an erasure code profile.

### get-health

Display cluster health.

### list-erasure-profiles

List erasure code profiles.

### list-pools

List pools.

### pause-health

Pause the cluster's health operations.

### pool-get

Get a value for a pool.

### pool-set

Set a value for a pool.

### pool-statistics

Display a pool's utilisation statistics.

### remove-cache-tier

Remove a cache tier.

### remove-pool-snapshot

Remove a pool's snapshot.

### rename-pool

Rename a pool.

### resume-health

Resume the cluster's health operations.

### security-checklist

Validate the running configuration against the OpenStack security guides
checklist.

### set-noout

Set the cluster's 'noout' flag.

### set-pool-max-bytes

Set a pool's quota for the maximum number of bytes.

### show-disk-free

Show disk utilisation by host and OSD.

### snapshot-pool

Create a pool snapshot.

### unset-noout

Unset the cluster's 'noout' flag.

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
