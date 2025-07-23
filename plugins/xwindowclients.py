import datetime
import dataclasses
import contextlib
import abc
import collections.abc
from typing import Any, Callable, Iterable, List, Optional, Iterator

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.linux.extensions import elf
from volatility3.plugins import timeliner
from volatility3.plugins.linux import elfs
from volatility3.framework import exceptions, constants, interfaces, objects, symbols
from volatility3.framework.exceptions import PagedInvalidAddressException
from .xorg_memory import XorgMemory, Window, OtherClients

from volatility3.plugins.linux import pslist
import logging
import binascii
import json
import numbers

vollog = logging.getLogger(__name__)


class XorgWindowClients(interfaces.plugins.PluginInterface):
    """Lists the clients of an X.org server that are connected and have windows associated."""

    _required_framework_version = (2, 13, 0)
    _version = (4, 0, 0)

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        config_path: str,
        progress_callback: constants.ProgressCallback = None,
    ) -> None:
        """
        Args:
            context: The context that the plugin will operate within
            config_path: The path to configuration data within the context configuration data
            progress_callback: A callable that can provide feedback at progress points
        """
        super().__init__(context, config_path, progress_callback)
        self.xorg_table_name = intermed.IntermediateSymbolTable.create(self.context, self.config_path, '', 'xsym')

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(name='pslist', plugin=pslist.PsList, version=(4, 0, 0)),
            requirements.ListRequirement(
                name="name",
                description="Filter on specific process names",
                element_type=str,
                optional=True,
            )
        ]

    def create_proc_filter(self):
        """Constructs a filter function for process names.

        Args:
            name_list: List of process names that are acceptable (or None if all are acceptable)

        Returns:
            Function which, when provided a process object, returns True if the process is to be filtered out of the list
        """
        name_list = self.config.get('name', None) 
        print(name_list)
        if name_list:
            def filter_func(x):
                return utility.array_to_string(x.comm) not in name_list

            return filter_func
        else:
            return lambda _: False

    def extract(self, proc_layer_name, task):
        """
        Iterates over process heap and initiates probing for screen structure.

        If found, use the root window to evaluate all windows for capturing clients.

        The way is:              
        screenInfo.screens[0].root.firstChild.nextSib <- Iterator
                    ^           ^- root window
                    | 
                    we probe for the screen, then use the root window


        window.optional.otherClients <- contains mask and id for all non-creating clients
        """

        vollog.info("Volatility 3 - Extract X.org clients with associated windows.")
        xorg_symbols = self.context.symbol_space[self.xorg_table_name]
        struct_size = xorg_symbols.get_type("Window").size

        # define memory search regions 
        regions = task.get_process_memory_sections(heap_only=True)
        #regions = task.get_process_memory_sections()
        regions = list(regions)
        total_size = 0
        bytes_scanned = 0
        structs_found = 0

        screen = None
        client_list = None

        for region in regions:
            total_size += region[1]

        for region in regions:
            region_start = region[0]
            region_end = region[0] + region[1]
            ptr = region_start

            while ptr + struct_size < region_end:
                if ptr % 0x1000 == 0:
                    self._progress_callback((bytes_scanned / total_size) * 100, "Found {} clients scanning memory of #{} ({})".format(
                        structs_found, task.pid, utility.array_to_string(task.comm)))
                # get Screen & ClientList
                if screen is None:
                    screen_obj = self.context.object(self.xorg_table_name + constants.BANG + "Screen", offset=ptr, layer_name=proc_layer_name)
                    screen = XorgMemory.probe_screen(screen_obj)

                # we found a screen and a client list, now follow the pointer chain to evaluate windows and capturing clients
                if screen is not None:
                    structs_found += 1
                    root_window = screen.root.dereference()
                    #print(f"Root Window ID: 0x{root_window.drawable.id:x} at 0x{root_window.vol.offset:x}")
                    #print(f"Root Window FirstChild: 0x{root_window.firstChild:x}")
                    #print(f"Root Window NextSib: 0x{root_window.nextSib:x}")
                    #print(f"FirstChild NextSib: 0x{root_window.firstChild.dereference().nextSib:x}")
                    window = root_window.firstChild.dereference() 

                    window_siblings = list(window)
                    vollog.info(f"Found {len(window_siblings)} top-level windows.")

                    # returns clients that have windows associated
                    for window_sibling in window_siblings:
                        try:
                            # we have to map the fakeID to the client index, 
                            # see CLIENT_ID(id) in /xserver/include/resource.h
                            # clientAsMask encodes the client index i:
                            # client->clientAsMask = ((Mask) i) << CLIENTOFFSET;
                            # Constants 
                            RESOURCE_AND_CLIENT_COUNT = 29
                            RESOURCE_CLIENT_BITS = 8
                            CLIENTOFFSET = RESOURCE_AND_CLIENT_COUNT - RESOURCE_CLIENT_BITS
                            RESOURCE_CLIENT_MASK = ((1 << RESOURCE_CLIENT_BITS) - 1) << CLIENTOFFSET

                            # from /xserver/include/windowstr.h
                            # define wClient(w)              (clients[CLIENT_ID((w)->drawable.id)])
                                    
                            client_index = ((window_sibling.drawable.id & RESOURCE_CLIENT_MASK)) >> CLIENTOFFSET
                            vollog.info(f"Found client: 0x{client_index} owning a Window.")
                            
                            # if we found client ids using xclients that are not in the following list, then we have a client without window
                            yield client_index
                        except PagedInvalidAddressException:
                            pass 

                    return
                # TODO: works in 64bit - should we always expect 8 byte alignment?
                ptr += 8
                bytes_scanned += 8

    def _generator(self, tasks):
        """
        For every task (process), initiate structure probing.
        """
        self._context.symbol_space._dict["xsym1"].set_type_class("Window", Window)
        self._context.symbol_space._dict["xsym1"].set_type_class("OtherClients", OtherClients)

        # not that pretty, but we introduce another symbol space when calling this plugin from xclients 
        if "xsym2" in self._context.symbol_space._dict:
            self._context.symbol_space._dict["xsym2"].set_type_class("Window", Window)
            self._context.symbol_space._dict["xsym2"].set_type_class("OtherClients", OtherClients)

        result = []
        kernel = self.context.modules[self.config['kernel']]

        for task in tasks:
            if not task.mm:
                continue

            name = utility.array_to_string(task.comm)
            vollog.info("Scanning process #{} ({} {})".format(task.pid, name, ""))
            proc_layer_name = task.add_process_layer()

            # call extract method
            clients = self.extract(proc_layer_name, task)
            result.extend(clients)

        return result


    def run(self):
        vollog.info("Volatility 3 - Identify X.org clients that have a window associated.")

        filter_func = self.create_proc_filter()
        tasks = pslist.PsList.list_tasks(self.context, self.config['kernel'], filter_func=filter_func)
        vollog.info(f"Tasks: {tasks}")
        clients = set([client for client in self._generator(tasks)])
        #vollog.info(f"{clients}")

        columns = [
            ("Index", int),
            ("Client ID (with Window)", int),
        ]
        
        results = [(0, (index, client)) for index, client in enumerate(clients)]

        return renderers.TreeGrid(columns, results)



