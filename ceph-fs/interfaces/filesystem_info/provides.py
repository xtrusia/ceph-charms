# Copyright 2025 Canonical Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Library to expose a Ceph filesystem through the `filesystem` integration.

This library is an adaptation of the [`filesystem_info`] charm library, which provides common classes for managing an
integration between a filesystem server operator and a filesystem client operator. The library only
exposes the classes related with the provider side of the integration, and only the Ceph-related
classes.

[`filesystem_info`]: https://github.com/charmed-hpc/filesystem-charms/blob/main/charms/filesystem-client/lib/charms/filesystem_client/v0/filesystem_info.py
```
"""

from dataclasses import dataclass
from urllib.parse import quote, urlencode, urlunsplit

from charms.reactive import when, set_flag, clear_flag
from charms.reactive.endpoints import Endpoint

from charmhelpers.core import hookenv

__all__ = [
    "FilesystemInfoError",
    "FilesystemProvides",
]


class FilesystemInfoError(Exception):
    """Exception raised when an operation failed."""


# Design-wise, this class represents the grammar that relations use to
# share data between providers and requirers:
#
# key = 1*( unreserved )
# value = 1*( unreserved / ":" / "/" / "?" / "#" / "[" / "]" / "@" / "!" / "$"
#       / "'" / "(" / ")" / "*" / "+" / "," / ";" )
# options = key "=" value ["&" options]
# host-port = host [":" port]
# hosts = host-port [',' hosts]
# authority = [userinfo "@"] "(" hosts ")"
# URI = scheme "://" authority path-absolute ["?" options]
#
# Unspecified grammar rules are given by [RFC 3986](https://datatracker.ietf.org/doc/html/rfc3986#appendix-A).
#
# This essentially leaves 5 components that the library can use to share data:
# - scheme: representing the type of filesystem.
# - hosts: representing the list of hosts where the filesystem lives. For NFS it should be a single element,
#   but CephFS and Lustre use more than one endpoint.
# - user: Any kind of authentication user that the client must specify to mount the filesystem.
# - path: The internally exported path of each filesystem. Could be optional if a filesystem exports its
#   whole tree, but at the very least NFS, CephFS and Lustre require an export path.
# - options: Some filesystems will require additional options for its specific mount command (e.g. Ceph).
#
# Putting all together, this allows sharing the required data using simple URI strings:
# ```
# <scheme>://<user>@(<host>,*)/<path>/?<options>
#
# ceph://fsuser@(192.168.1.1,192.168.1.2,192.168.1.3)/export?fsid=asdf1234&auth=plain:QWERTY1234&filesystem=fs_name
# ```
#
# Note how in the Lustre URI we needed to escape the `@` symbol on the hosts to conform with the URI syntax.
@dataclass(init=False, frozen=True)
class _UriData:
    """Raw data from the endpoint URI of a relation."""

    scheme: str
    """Scheme used to identify a filesystem.

    This will mostly correspond to the option `fstype` for the `mount` command.
    """

    hosts: list[str]
    """List of hosts where the filesystem is deployed on."""

    user: str
    """User to connect to the filesystem."""

    path: str
    """Path exported by the filesystem."""

    options: dict[str, str]
    """Additional options that could be required to mount the filesystem."""

    def __init__(
        self,
        scheme: str,
        hosts: list[str],
        user: str = "",
        path: str = "/",
        options: dict[str, str] = {},
    ) -> None:
        if not scheme:
            raise FilesystemInfoError("scheme cannot be empty")
        if not hosts:
            raise FilesystemInfoError("list of hosts cannot be empty")
        path = path or "/"

        object.__setattr__(self, "scheme", scheme)
        object.__setattr__(self, "hosts", hosts)
        object.__setattr__(self, "user", user)
        object.__setattr__(self, "path", path)
        object.__setattr__(self, "options", options)

    def __str__(self) -> str:
        user = quote(self.user)
        hostname = quote(",".join(self.hosts))
        path = quote(self.path)
        netloc = f"{user}@({hostname})" if user else f"({hostname})"
        query = urlencode(self.options)
        return urlunsplit((self.scheme, netloc, path, query, None))


class FilesystemProvides(Endpoint):
    """Provider-side interface of filesystem integrations."""

    @when("endpoint.{endpoint_name}.joined")
    def handle_joined(self):
        if hookenv.is_leader():
            set_flag(self.expand_name("{endpoint_name}.available"))

    def manage_flags(self):
        if not self.is_joined:
            clear_flag(self.expand_name("{endpoint_name}.available"))

    def set_info(self, fsid: str, name: str, path: str, monitor_hosts: list[str], user: str, key: str) -> None:
        """Set information to mount a Ceph filesystem.

        Args:
            - fsid: ID of the Ceph cluster.
            - name: Name of the exported Ceph filesystem.
            - path: Exported path of the Ceph filesystem.
            - monitor_hosts: Address list of the available Ceph MON nodes.
            - user: Name of the user authorized to access the Ceph filesystem.
            - key: Cephx key for the authorized user.

        Notes:
            Only the application leader unit can set the filesystem data.
        """
        if hookenv.is_leader():
            for relation in self.relations:
                relation.to_publish_app_raw.update(
                    {
                        "endpoint": str(_UriData(
                            scheme="cephfs",
                            hosts=monitor_hosts,
                            path=path,
                            user=user,
                            options={
                                "fsid": fsid,
                                "name": name,
                                "auth": f"plain:{key}"
                            }
                        )),
                    }
                )
