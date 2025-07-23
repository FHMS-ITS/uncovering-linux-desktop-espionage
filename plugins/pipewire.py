from volatility3.framework.configuration import requirements
from volatility3.framework import interfaces, renderers, symbols, objects, constants
from volatility3.framework.symbols import intermed
from volatility3.framework.objects import utility, Pointer
from volatility3.framework.exceptions import PagedInvalidAddressException
from typing import Callable, Iterable, List, Any
from volatility3.plugins.linux import pslist
import logging
import binascii
import json
import numbers

vollog = logging.getLogger(__name__)


class PWPAServerExtractor(object):
    def __init__(self, context, symbol_table_name, proc_layer_name, task, progress_callback):
        self.context = context
        self.table_name = symbol_table_name
        self.proc_layer_name = proc_layer_name
        self.proc_layer = self.context.layers[proc_layer_name]
        self.task = task
        self.task_name = utility.array_to_string(task.comm)
        self.symbols = self.context.symbol_space[symbol_table_name]
        self.progress_callback = progress_callback

    def probe_address(self, ptr):
        obj = self.context.object(self.table_name + constants.BANG + "pw_impl_node",
                                  offset=ptr, layer_name=self.proc_layer_name)

        if not obj.context.is_readable():
            return None
        
        if not (-1 <= obj.info.state <= 3):  # enum contains 4 different states
            return None

        if not (0 < obj.info.id):
            return None

        if not obj.info.props.is_readable():
            return None

        if not obj.info.params.is_readable():
            return None

        if not obj.info.props.items.is_readable():
            return None

        if not (obj.info.props.n_items > 0):
            return None

        client = (obj.info.id, {})

        for i in range(obj.info.props.n_items):
            item_offset = obj.info.props.items + (i * 16)
            item = self.context.object(self.table_name + constants.BANG + "spa_dict_item",
                                       offset=item_offset, layer_name=self.proc_layer_name)
            if not item.key.is_readable():
                return
            key_string = utility.pointer_to_string(item.key, 256)

            if not item.value.is_readable():
                return
            value_string = utility.pointer_to_string(item.value, 256)

            if not (key_string.isascii() and value_string.isascii()):
                return None
            client[1][key_string] = value_string

        if not (client[1]["object.id"] == str(client[0])):
            return None
        return client

    def extract(self):
        struct_size = self.symbols.get_type("pw_impl_node").size
        regions = self.task.get_process_memory_sections(heap_only=True)
        regions = list(regions)
        total_size = 0
        bytes_scanned = 0
        clients_found = 0

        for region in regions:
            total_size += region[1]

        for region in regions:
            region_start = region[0]
            region_end = region[0] + region[1]
            ptr = region_start
            while ptr + struct_size < region_end:
                try:
                    client = self.probe_address(ptr)
                    if client is not None:
                        clients_found += 1
                        yield client
                except PagedInvalidAddressException:
                    pass
                ptr += 8
                bytes_scanned += 8


class PipewireNodes(interfaces.plugins.PluginInterface):
    """
    Lists the clients of a Pipewire server that record audio streams.
    """
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(name='pslist', plugin=pslist.PsList, version=(4, 0, 0)),
            requirements.ListRequirement(name='pid',
                                         element_type=int,
                                         description="Process IDs to include (all other processes are excluded)",
                                         optional=True),
            requirements.ListRequirement(name='name',
                                         element_type=str,
                                         description="Process name to include (all other processes are excluded)",
                                         optional=True),
            requirements.StringRequirement(name='out',
                                           description="JSON output file",
                                           optional=True)
        ]

    def create_proc_filter(self) -> Callable[[Any], bool]:
        """Constructs a filter function for process IDs.

        Args:
            pid_list: List of process IDs that are acceptable (or None if all are acceptable)

        Returns:
            Function which, when provided a process object, returns True if the process is to be filtered out of the list
        """
        pid_list = self.config.get('pid', None) or []
        name_list = self.config.get('name', None) or []
        pid_list = [x for x in pid_list if x is not None]
        name_list = [x for x in name_list if x is not None]

        def filter_func(x):
            name = utility.array_to_string(x.comm)
            return (x.pid not in pid_list) and (name not in name_list)

        return filter_func

    def _generator(self, tasks):
        result = []
        kernel = self.context.modules[self.config['kernel']]

        table_name = intermed.IntermediateSymbolTable.create(self.context, self.config_path, '', 'pwsym')

        for task in tasks:
            if not task.mm:
                continue

            name = utility.array_to_string(task.comm)
            vollog.info("Scanning process #{} ({} {})".format(task.pid, name, ""))
            proc_layer_name = task.add_process_layer()
            extractor = PWPAServerExtractor(self.context, table_name,
                                            proc_layer_name, task, self._progress_callback)
            clients = extractor.extract()
            result.extend(clients)
        return result

    def run(self):

        filter_func = self.create_proc_filter()
        tasks = pslist.PsList.list_tasks(self.context, self.config['kernel'], filter_func=filter_func)

        clients = [client for client in self._generator(tasks)]

        results = []
        for id, client_info in clients:
            if "media.class" in client_info:
                if "Stream/Input/Audio" in client_info["media.class"]:
                    results.append((client_info["application.process.id"],
                                    client_info["application.process.binary"],
                                    client_info["media.class"],
                                    client_info["media.name"],
                                    client_info["client.api"])
                    )

        headers = [
            ("PID", str),
            ("Process", str),
            ("media.class", str),
            ("media.name", str),
            ("client.api", str),
        ]

        return renderers.TreeGrid(headers, [(0, result) for result in results])
