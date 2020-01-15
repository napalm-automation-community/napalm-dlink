# -*- coding: utf-8 -*-
# Copyright 2016 Dravetech AB. All rights reserved.
#
# The contents of this file are licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

"""
Napalm driver for Dlink.

Read https://napalm.readthedocs.io for more information.
"""
import socket
import telnetlib

from napalm.base import NetworkDriver
from napalm.base.exceptions import (
    ConnectionException,
    SessionLockedException,
    MergeConfigException,
    ReplaceConfigException,
    CommandErrorException,
    ConnectionClosedException
)
from napalm.base.helpers import (
    canonical_interface_name,
    transform_lldp_capab,
    textfsm_extractor,
)
from napalm.base.netmiko_helpers import netmiko_args
from napalm.base.utils import py23_compat


class DlinkDriver(NetworkDriver):
    """Napalm driver for Dlink."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """NAPALM Dlink Handler.."""
        self.device = None
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout

        if optional_args is None:
            optional_args = {}

        self.transport = optional_args.get("transport", "ssh")

        if self.transport == "telnet":
            # Telnet only supports inline_transfer
            self.inline_transfer = True

        self.netmiko_optional_args = netmiko_args(optional_args)

        # Set the default port if not set
        default_port = {"ssh": 22, "telnet": 23}
        self.netmiko_optional_args.setdefault("port", default_port[self.transport])

    def open(self):
        """Open a connection to the device."""
        device_type = "dlink_ds"
        if self.transport == "telnet":
            device_type = "dlink_ds_telnet"
        self.device = self._netmiko_open(
            device_type, netmiko_optional_args=self.netmiko_optional_args
        )

    def close(self):
        """Close the connection to the device and do the necessary cleanup."""
        self._netmiko_close()

    def _send_command(self, command):
        """Wrapper for self.device.send.command().
        If command is a list will iterate through commands until valid command.
        """
        try:
            if isinstance(command, list):
                for cmd in command:
                    output = self.device.send_command(cmd)
                    if "Available commands" not in output and "Next possible" not in output:
                        break
            else:
                output = self.device.send_command(command)
            return output
        except (socket.error, EOFError) as e:
            raise ConnectionClosedException(str(e))

    def is_alive(self):
        """Returns a flag with the state of the connection."""
        null = chr(0)
        if self.device is None:
            return {"is_alive": False}
        if self.transport == "telnet":
            try:
                # Try sending IAC + NOP (IAC is telnet way of sending command
                # IAC = Interpret as Command (it comes before the NOP)
                self.device.write_channel(telnetlib.IAC + telnetlib.NOP)
                return {"is_alive": True}
            except AttributeError:
                return {"is_alive": False}
        else:
            # SSH
            try:
                # Try sending ASCII null byte to maintain the connection alive
                self.device.write_channel(null)
                return {"is_alive": self.device.remote_conn.transport.is_active()}
            except (socket.error, EOFError):
                # If unable to send, we can tell for sure that the connection is unusable
                return {"is_alive": False}

    def get_optics(self):
        """ I am not found universal command. Add this method in future. """
        pass

    def get_lldp_neighbors(self):
        """Dlink implementation of get_lldp_neighbors."""

        lldp = {}
        neighbors_detail = self.get_lldp_neighbors_detail()
        for intf_name, entries in neighbors_detail.items():
            lldp[intf_name] = []
            for lldp_entry in entries:
                hostname = lldp_entry["remote_system_name"]
                # Match Dlink behaviour of taking remote chassis ID
                # When lacking a system name (in show lldp neighbors)
                if not hostname:
                    hostname = lldp_entry["remote_chassis_id"]
                lldp_dict = {"port": lldp_entry["remote_port"], "hostname": hostname}
                lldp[intf_name].append(lldp_dict)

        return lldp

    def get_lldp_neighbors_detail(self, interface=""):
        lldp = {}

        if interface:
            command = "show lldp remote_ports {} mode detailed".format(interface)
        else:
            command = "show lldp remote_ports mode detailed"
        lldp_entries = self._send_command(command)
        lldp_entries = textfsm_extractor(
            self, "show_lldp_remote_ports_detail", lldp_entries
        )

        if len(lldp_entries) == 0:
            return {}

        for idx, lldp_entry in enumerate(lldp_entries):
            local_intf = lldp_entry.pop("local_interface")
            # Add fields missing on Dlink
            lldp_entry["parent_interface"] = lldp_entry["remote_system_enable_capab"] = ""

            # Standarding "remote system capab"
            if lldp_entry["remote_system_capab"] and isinstance(
                                                                lldp_entry["remote_system_capab"],
                                                                py23_compat.string_types
                                                               ):
                lldp_entry["remote_system_capab"] = sorted(lldp_entry["remote_system_capab"].strip().lower().split(","))
            else:
                lldp_entry["remote_system_capab"] = []
            # Turn the interfaces into their long version
            local_intf = canonical_interface_name(local_intf)
            lldp.setdefault(local_intf, [])
            lldp[local_intf].append(lldp_entry)

        return lldp
