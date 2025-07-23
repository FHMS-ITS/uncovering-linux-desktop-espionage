from volatility3.framework.configuration import requirements
from volatility3.framework import interfaces, renderers, symbols, objects, constants
from volatility3.framework.symbols import intermed
from volatility3.framework.objects import utility
from volatility3.framework.exceptions import PagedInvalidAddressException
from typing import Callable, Iterable, List, Any
from volatility3.plugins.linux import pslist
from .xorg_memory import XorgMemory, Window, OtherClients
from .xwindowclients import XorgWindowClients
import logging
import binascii
import json
import numbers

vollog = logging.getLogger(__name__)


class ScrapedClient(object):
    def __init__(self, task, cpid, cmdname, cmdargs, addr, mnMask, nknMask, xkbFlags, idx):
        self.task = task
        self.task_name = utility.array_to_string(task.comm)
        self.client_pid = cpid
        self.cmdname = cmdname
        self.cmdargs = cmdargs
        self.addr = addr
        self.mnMask = mnMask
        self.nknMask = nknMask
        self.xkbFlags = xkbFlags
        self.idx = idx

    def dict(self):
        return {
            'task': self.task,
            'task_name': self.task_name,
            'client_pid': self.client_pid,
            'cmdname': self.cmdname,
            'cmdargs': self.cmdargs,
            'addr': self.addr,
            'mnMask': self.mnMask,
            'nknMask': self.nknMask,
            'xkbFlags': self.xkbFlags,
            'idx': self.idx
        }


class XorgClientExtractor(object):
    def __init__(self, context, xorg_table_name, proc_layer_name, task, progress_callback):
        self.context = context
        self.xorg_table_name = xorg_table_name
        self.proc_layer_name = proc_layer_name
        self.proc_layer = self.context.layers[proc_layer_name]
        self.task = task
        self.task_name = utility.array_to_string(task.comm)
        self.xorg_symbols = self.context.symbol_space[xorg_table_name]
        self.progress_callback = progress_callback

    def probe_address(self, ptr):
        client_s = self.context.object(self.xorg_table_name + constants.BANG + "client",
                                       offset=ptr, layer_name=self.proc_layer_name)

        a = client_s.requestbuffer.is_readable()
        b = client_s.osprivate.is_readable()

        if not (a and b):
            return None

        n = client_s.index
        if not (0 < n < 2048):  # max number of clients, ignore 0 (Xorg)
            return None

        g = client_s.clientIds.is_readable()
        if not g:
            return None
        cid = client_s.clientIds.dereference()
        pid = cid.pid
        if not (0 < pid < 4194304):  # max pid
            return None

        if not cid.cmdname.is_readable():
            return None

        cname: str = str(utility.pointer_to_string(cid.cmdname, 256))

        if cid.cmdargs.is_readable():
            cargs: str = str(utility.pointer_to_string(cid.cmdargs, 256))
        else:
            cargs = ""

        if not (cname.isprintable() and len(cname) > 0):
            return None

        vollog.info("Found possible candidate: pid=%s, cmdname={'%s'} at {0x%x} with index {%s}", pid, cname, ptr, n)

        return ScrapedClient(self.task, pid, cname, cargs, ptr, client_s.mapNotifyMask, client_s.newKeyboardNotifyMask, client_s.xkbClientFlags, n)

    def extract(self):
        struct_size = self.xorg_symbols.get_type("client").size
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
                if ptr % 0x1000 == 0:
                    self.progress_callback((bytes_scanned / total_size) * 100, "Found {} clients scanning memory of #{} ({})".format(
                        clients_found, self.task.pid, self.task_name))
                try:
                    xorg_client = self.probe_address(ptr)
                    if xorg_client is not None:
                        clients_found += 1
                        yield xorg_client
                except PagedInvalidAddressException:
                    pass
                ptr += 8
                bytes_scanned += 8

                # TODO: Only for testing! Remove this for investigations
                if (bytes_scanned / total_size) * 100 > 24.0:
                    break


class XorgClients(interfaces.plugins.PluginInterface):
    """Lists all clients connected to the X server."""
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

    def _format_fields(self, c, window_clients):
        # check if we have a client without a window
        if c.idx in window_clients:
            with_window = "Client has a window associated"
        else:
            with_window = "Suspicious - windowless client"

        return (
            c.task_name,
            c.task.pid,
            renderers.format_hints.Hex(c.addr),
            c.client_pid,
            c.cmdname,
            c.cmdargs,
            c.mnMask,
            c.nknMask,
            int(c.xkbFlags),
            c.idx,
            with_window
        )

    def _generator(self, tasks) -> List[ScrapedClient]:
        result = []
        kernel = self.context.modules[self.config['kernel']]

        xorg_table_name = intermed.IntermediateSymbolTable.create(self.context, self.config_path, '', 'xsym')

        for task in tasks:
            if not task.mm:
                continue

            name = utility.array_to_string(task.comm)
            vollog.info("Scanning process #{} ({} {})".format(task.pid, name, ""))
            proc_layer_name = task.add_process_layer()
            extractor = XorgClientExtractor(self.context, xorg_table_name,
                                            proc_layer_name, task, self._progress_callback)
            clients = extractor.extract()
            result.extend(clients)
        return result

    def write_output_file(self, filepath, clients):
        fp = open(filepath, "w")
        for c in clients:
            c_dict = c.as_dict()  # fix: not implemented dict function
            json.dump(c_dict, fp)
            fp.write("\n")
        fp.close()

    def run(self):
        headers = [
            ("Name", str),
            ("X server PID", int),
            ("Addr", renderers.format_hints.Hex),
            ("Client PID", int),
            ("Command", str),
            ("Arguments", str),
            ("mnMask", int),
            ("nknMask", int),
            ("xkbFlags", int),
            ("Client ID", int),
            ("Window Association", str),
        ]

        filter_func = self.create_proc_filter()
        tasks = [task for task in pslist.PsList.list_tasks(self.context, self.config['kernel'], filter_func=filter_func)]

        # scrape all connected clients
        all_clients = self._generator(tasks)

        # get all clients with windows associated 
        self._context.symbol_space._dict["xsym1"].set_type_class("Window", Window)
        self._context.symbol_space._dict["xsym1"].set_type_class("OtherClients", OtherClients)
        window_clients = set([client for client in XorgWindowClients(self.context, self.config_path)._generator(tasks)])

        result = [(0, self._format_fields(c, window_clients)) for c in all_clients]

        return renderers.TreeGrid(headers, result)
