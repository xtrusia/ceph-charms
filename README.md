# Overview
Charmed Ceph is a software-defined storage solution that provides object, block and file storage on commodity hardware.

Charmed Ceph makes it easy to use and deploy [Ceph](https://ceph.com/en/). It provides a simpler way to deliver Ceph to users using a set of scripts called charms that are deployed with [Juju](https://juju.is/).

Corporate users can benefit from the robust and manageable full-suite storage solution, and the ease with which their Ceph clusters can be deployed with Charmed Ceph.

# Ceph charms monorepo

This is a monolithic repository, or monorepo, that contains the core charms used in Ceph deployment.
It also contains other associated charm libraries and utilities that make up the Ceph ecosystem that
can be deployed via Juju.

In the past, each charm resided in its own repository, making changes, especially larger changes that
involved multiple components, difficult to make. We decided to consolidate all these charms and their
associated components into this single repository to make handling changes easier.

## The charm index

Each of the charms define a specific Ceph application that can be deployed. The charms usually work
together, i.e: they are often deployed together via Juju integrations.

1. [ceph dashboard](https://github.com/canonical/ceph-charms/tree/main/ceph-dashboard)
2. [ceph-fs](https://github.com/canonical/ceph-charms/tree/main/ceph-fs)
3. [ceph-mon](https://github.com/canonical/ceph-charms/tree/main/ceph-mon)
3. [ceph-nfs](https://github.com/canonical/ceph-charms/tree/main/ceph-nfs)
5. [ceph-nvme](https://github.com/canonical/ceph-charms/tree/main/ceph-nvme)
6. [ceph-osd](https://github.com/canonical/ceph-charms/tree/main/ceph-osd)
7. [ceph-proxy](https://github.com/canonical/ceph-charms/tree/main/ceph-proxy)
8. [ceph-radosgw](https://github.com/canonical/ceph-charms/tree/main/ceph-radosgw)
9. [ceph-rbd-mirror](https://github.com/canonical/ceph-charms/tree/main/ceph-rbd-mirror)

## Additional sub-projects

In addition to the charms, the monorepo also contains libraries, dependencies, modules and test scripts, including:

- [charms.ceph](https://github.com/canonical/ceph-charms/tree/main/charms.ceph): Common support library used by the charms.
- [constraints](https://github.com/canonical/ceph-charms/tree/main/constraints): List of common dependencies shared by the charms.
- [terraform](https://github.com/canonical/ceph-charms/tree/main/terraform): Maintains terraform modules used for charm deployments.
- [tests](https://github.com/canonical/ceph-charms/tree/main/tests): Miscellaneous scripts used to facilitate testing.

## Documentation

Each individual charm contains a README section with details about the specific charm, including its description, functionality, usage and contributing guide.

See [charmhub](https://charmhub.io/?q=ceph) for more information about the charms.

The [OpenStack charm guide](https://docs.openstack.org/charm-guide)provides guides for working with charms, including development and support notes.

The [OpenStack charms deployment guide](https://docs.openstack.org/project-deploy-guide/charm-deployment-guide) demonstrates how to deploy and configure charms manually to build an OpenStack cloud.

## Project and community

We warmly welcome community contributions, suggestions, fixes, and constructive feedback.
If you find any errors or have suggestions for improvements, please [report a bug on launchpad](https://bugs.launchpad.net/) on the specific component (For example, [report a ceph-dashboard charm bug](https://bugs.launchpad.net/charm-ceph-dashboard) in the Ceph Dashboard charm project on Launchpad..

> [!NOTE]

Please read [the guide for submitting a software bug](https://docs.openstack.org/charm-guide/latest/community/software-bug.html) before doing so. This will considerably reduce the time needed to triage your bug.

[Join our Matrix forum](https://matrix.to/#/#ceph-general:ubuntu.com) to engage with our community and get support.

We abide by the [Ubuntu Code of Conduct](https://ubuntu.com/community/ethos/code-of-conduct).

## Contribute to Ceph charms

If you’re interested in contributing to the code or documentation for any of the repositories in this monorepo, our [community section](https://docs.openstack.org/charm-guide/latest/community/) is the best place to start.

The [software contributions](https://docs.openstack.org/charm-guide/latest/community/software-contrib) section has software contribution guidelines, while [documentation contributions](https://docs.openstack.org/charm-guide/latest/community/doc-contrib) contains guidelines for documentation contributions.

## License and copyright

See the LICENSE file in each charm for license information.

© 2025 Canonical Ltd.

