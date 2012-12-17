Overview
========

Ceph is a distributed storage and network file system designed to provide
excellent performance, reliability, and scalability.

This charm deploys additional Ceph OSD storage service units and should be
used in conjunction with the 'ceph' charm to scale out the amount of storage
available in a Ceph cluster.

Usage
=====
       
The charm also supports specification of the storage devices to use in the ceph
cluster::

    osd-devices:
        A list of devices that the charm will attempt to detect, initialise and
        activate as ceph storage.
        
        This this can be a superset of the actual storage devices presented to
        each service unit and can be changed post ceph-osd deployment using
        `juju set`.

For example::        

    ceph-osd:
        osd-devices: /dev/vdb /dev/vdc /dev/vdd /dev/vde
        
Boot things up by using::

    juju deploy -n 3 --config ceph.yaml ceph
    
You can then deploy this charm by simple doing::

    juju deploy -n 10 --config ceph.yaml ceph-osd
    juju add-relation ceph-osd ceph
    
Once the ceph charm has bootstrapped the cluster, it will notify the ceph-osd
charm which will scan for the configured storage devices and add them to the
pool of available storage.

Contact Information
===================

Author: James Page <james.page@ubuntu.com>
Report bugs at: http://bugs.launchpad.net/charms/+source/ceph-osd/+filebug
Location: http://jujucharms.com/charms/ceph-osd