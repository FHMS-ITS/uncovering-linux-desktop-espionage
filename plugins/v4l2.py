# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
import datetime
import dataclasses
from typing import List, Callable, Tuple, Iterable

from volatility3.framework import renderers, interfaces, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.symbols import linux
from volatility3.plugins.linux import pslist, lsof
from volatility3.plugins import timeliner

vollog = logging.getLogger(__name__)


class V4l2(plugins.PluginInterface):
    """Lists processes with handles to V4L devices."""

    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 2)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(4, 0, 0)
            ),
            requirements.PluginRequirement(
                name="lsof", plugin=pslist.PsList, version=(4, 0, 0)
            ),
            requirements.VersionRequirement(
                name="linuxutils", component=linux.LinuxUtilities, version=(2, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                description="Filter on specific process IDs",
                element_type=int,
                optional=True,
            ),
        ]


    def _generator(self, pids, vmlinux_module_name):
        filter_func = pslist.PsList.create_pid_filter(pids)

        for fd_internal in lsof.Lsof.list_fds(
            self.context, vmlinux_module_name, filter_func=filter_func
        ):
            fd_user = fd_internal.to_user()

            # or filter /dev/video?
            if "/dev/video" in fd_user.full_path:
                yield (0, dataclasses.astuple(fd_user))

    def run(self):
        pids = self.config.get("pid", None)
        vmlinux_module_name = self.config["kernel"]

        tree_grid_args = [
            ("PID", int),
            ("TID", int),
            ("Process", str),
            ("FD", int),
            ("Path", str),
            ("Device", str),
            ("Inode", int),
            ("Type", str),
            ("Mode", str),
            ("Changed", datetime.datetime),
            ("Modified", datetime.datetime),
            ("Accessed", datetime.datetime),
            ("Size", int),
        ]

        return renderers.TreeGrid(
            tree_grid_args, self._generator(pids, vmlinux_module_name)
        )
