# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

module "ceph_mon" {
  source = "./ceph_mon"

  model       = var.model
  base        = coalesce(module.ceph_mon_config.config.base, var.k8s.config.base)
  constraints = coalesce(module.ceph_mon_config.config.constraints, var.k8s.config.constraints)
  channel     = coalesce(module.ceph_mon_config.config.channel, var.k8s.config.channel)

  config    = coalesce(module.ceph_mon_config.config.config, {})
  resources = module.ceph_mon_config.config.resources
  revision  = module.ceph_mon_config.config.revision
  units     = module.ceph_mon_config.config.units
}

module "ceph_osd" {
  source = "./ceph_osd"

  model       = var.model
  base        = coalesce(module.ceph_osd_config.config.base, var.k8s.config.base)
  constraints = coalesce(module.ceph_osd_config.config.constraints, var.k8s.config.constraints)
  channel     = coalesce(module.ceph_osd_config.config.channel, var.k8s.config.channel)

  config    = coalesce(module.ceph_osd_config.config.config, {})
  resources = module.ceph_osd_config.config.resources
  storage   = coalesce(module.ceph_osd_config.config.storage, {})
  revision  = module.ceph_osd_config.config.revision
  units     = module.ceph_osd_config.config.units
}
