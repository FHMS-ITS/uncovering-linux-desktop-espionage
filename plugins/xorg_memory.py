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
from volatility3.framework.exceptions import PagedInvalidAddressException, InvalidAddressException
import logging
import binascii
import json
import numbers

vollog = logging.getLogger(__name__)

class XorgMemory:

    #def probe_clients(cls, client_object):

    @classmethod
    def probe_screen(cls, screen_object):
        """
        Probe for screen struct at address in process layer.
        We assume only one screen struct here, however extending is possible.

        Expects an empty screen object initiated at a specific address *ptr*:
        screen = self.context.object(self.xorg_table_name + constants.BANG + "Screen", offset=ptr, layer_name=layer_name)

        Returns screen object.
        """
        #screen = self.context.object(self.xorg_table_name + constants.BANG + "Screen",
                                       #offset=ptr, layer_name=layer_name)
        try:
            screen = screen_object

            if((screen.x == 0 and screen.y == 0) and 
                screen.myNum == 0 and
                (screen.width > 900 and screen.width < 10000) and
                (screen.height > 640 and screen.width < 10000) and
                screen.root.is_readable() and
                screen.root.dereference().firstChild.is_readable() and
                screen.root.dereference().firstChild.dereference().parent == screen.root):

                try:
                    root_window = screen.root.dereference()
                    #print(root_window.__dir__())
                    if(root_window.drawable.width == screen.width and
                       root_window.drawable.height == screen.height):
                        vollog.info("Found possible candidate at offset={0x%x}", screen.vol.offset)
                        vollog.info("Screen: {%d}x{%d}", screen.width, screen.height)
                except:
                    vollog.info("Error screen candidate at offset={0x%x}", screen.vol.offset)

                return screen
            else:
                return None
        except PagedInvalidAddressException:
            return None 

    @classmethod
    def probe_client(self, client_obj):
        """
        Probe for client structures in process layer. 

        Expects an empty client object initiated at a specific address *ptr*:
        screen = self.context.object(self.xorg_table_name + constants.BANG + "Client", offset=ptr, layer_name=layer_name)

        Returns client object.
        """

        try:
            client_s = client_obj

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
    
            return client_s
        except PagedInvalidAddressException:
            return None 

    @classmethod
    def probe_client_list(self, client_array, client_type):
        """
        Probe for client structures in process layer. (ClientPtr clients[MAXCLIENTS];)
        Expects a list containing pointers to client objects initiated at a specific address *ptr*:

        Returns object referring to clients[].
        """
        
        # clients is a static global variable -> not on heap -> evaluation of all memory runs a long time
        if client_array[0] < 0x10000:
            return None

        try:
            xorg_client = client_array[0].dereference().cast(client_type)
            first_client = client_array[1].dereference().cast(client_type)
            second_client = client_array[2].dereference().cast(client_type)
            #print(xorg_client.__dir__())

            if(xorg_client.index == 0 and
               XorgMemory.probe_client(first_client) and
               XorgMemory.probe_client(second_client)):
                vollog.info(f"Client List found at 0x{xorg_client.vol.offset:x}")
                client_cmd = utility.pointer_to_string(second_client.clientIds.dereference().cmdname, 256)
                vollog.info(f"{client_cmd}")
                return client_array
            else:
               return None
        except (InvalidAddressException, PagedInvalidAddressException) as e:
            #vollog.info(e)
            return None


# we extend the parsed symbol objects with custom classes, so we can use an iterator
# for usage in plugins, register class in run() with: 
#        self._context.symbol_space._dict["xsym1"].set_type_class("Window", Window)
#        self._context.symbol_space._dict["xsym1"].set_type_class("OtherClients", OtherClients)
#        self._context.symbol_space._dict["xsym1"].set_type_class("InputClients", InputClients)

class Window(objects.StructType, collections.abc.Iterable):
    def siblings(self) -> Iterator[interfaces.objects.ObjectInterface]:
        """
        Returns an iterator of sibling windows.

        Yields:
            Sibling windows of the type Window.
        """
        layer = self.vol.layer_name

        #print(f"firstSibling: ID {self.drawable.id:x} at 0x{self.vol.offset:x} with Parent Window at 0x{self.parent:x}")
        previous_sibling = self
        yield self
        #print(f"nextSibling: 0x{self.nextSib:x}")
        next_sibling = previous_sibling.nextSib.dereference()
        #offsets = list()

        # list does not end with 0 value, but is circular at the end
        #while next_sibling.nextSib not in offsets:
        while next_sibling.nextSib !=0:
            try:
                #offsets.append(previous_sibling.vol.offset)
                previous_sibling = next_sibling
                next_sibling = previous_sibling.nextSib
                #vollog.info("Sibling Window at 0x%x with Parent 0x%x at 0x%x", previous_sibling.vol.offset, previous_sibling.parent.dereference().drawable.id, previous_sibling.parent)
                yield next_sibling.dereference()
            except exceptions.InvalidAddressException:
                break

    def __iter__(self) -> Iterator[interfaces.objects.ObjectInterface]:
        return self.siblings()

class OtherClients(objects.StructType, collections.abc.Iterable):
    def to_list(self) -> Iterator[interfaces.objects.ObjectInterface]:
        """
        Returns an iterator of otherClients.

        Yields:
            clients
        """
        layer = self.vol.layer_name

        client = self
        #print(f"otherClient start: ID {self.resource:x} with mask 0x{self.mask:x}")

        # list does not end with 0 value, but is circular at the end
        while client.vol.offset != 0:
            #obj = self._context.object(
            #    self.vol.type_name, layer, offset=sibling.vol.offset 
            #)
            try:
                yield client
                client = client.otherClients.dereference()
            except exceptions.InvalidAddressException:
                break

    def __iter__(self) -> Iterator[interfaces.objects.ObjectInterface]:
        return self.to_list()


class InputClients(objects.StructType, collections.abc.Iterable):
    def to_list(self) -> Iterator[interfaces.objects.ObjectInterface]:
        """
        Returns an iterator of sibling windows.

        Yields:
            Sibling windows of the type Window.
        """
        layer = self.vol.layer_name

        client = self
        #print(f"otherClient start: ID {self.resource:x} with mask 0x{self.mask:x}")

        # list does not end with 0 value, but is circular at the end
        while client.vol.offset != 0:
            #obj = self._context.object(
            #    self.vol.type_name, layer, offset=sibling.vol.offset 
            #)
            try:
                yield client
                client = client.next.dereference()
            except exceptions.InvalidAddressException:
                break

    def __iter__(self) -> Iterator[interfaces.objects.ObjectInterface]:
        return self.to_list()

