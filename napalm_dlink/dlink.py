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
import re
import socket
import telnetlib
import tempfile
import uuid
import os
from netaddr import IPAddress

# from netmiko import FileTransfer, InLineTransfer
# import tftpy

from napalm.base import NetworkDriver
from napalm.base.exceptions import (
    ConnectionException,
    SessionLockedException,
    MergeConfigException,
    ReplaceConfigException,
    CommandErrorException,
    ConnectionClosedException
)

import napalm.base.constants as C
from napalm.base.helpers import (
    canonical_interface_name,
    transform_lldp_capab,
    textfsm_extractor,
)
from napalm.base.netmiko_helpers import netmiko_args
from napalm.base.helpers import mac
from napalm.base import constants as c

HOUR_SECONDS = 3600
DAY_SECONDS = 24 * HOUR_SECONDS
WEEK_SECONDS = 7 * DAY_SECONDS
YEAR_SECONDS = 365 * DAY_SECONDS


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

        # Retrieve file names
        self.candidate_cfg = optional_args.get("candidate_cfg", "candidate_config.txt")
        self.merge_cfg = optional_args.get("merge_cfg", "merge_config.txt")
        self.rollback_cfg = optional_args.get("rollback_cfg", "rollback_config.txt")
        self.inline_transfer = optional_args.get("inline_transfer", True)

        self.netmiko_optional_args = netmiko_args(optional_args)

        # Set the default port if not set
        default_port = {"ssh": 22, "telnet": 23}
        self.netmiko_optional_args.setdefault("port", default_port[self.transport])

        self.config_replace = False

        self.tftp_server = optional_args.get("tftp_server")

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

    @staticmethod
    def _create_tmp_file(config):
        """Write temp file and for use with inline config and SCP."""
        tmp_dir = tempfile.gettempdir()
        rand_fname = str(uuid.uuid4())
        filename = os.path.join(tmp_dir, rand_fname)
        with open(filename, "wt") as fobj:
            fobj.write(config)
        return filename

    def _dlink_format_config(self, config):
        return "command-start\n" + config + "\ncommand-end"

    def _load_candidate_wrapper(
        self, source_file=None, source_config=None, dest_file=None
    ):
        """
        Transfer file to remote device for either merge or replace operations

        Returns (return_status, msg)
        """
        return_status = False
        remote_file = dest_file or "1"
        if source_file and source_config:
            raise ValueError("Cannot simultaneously set source_file and source_config")

        if source_config:
            source_config = self._dlink_format_config(source_config)
            tmp_file = self._create_tmp_file(source_config)
            command = "download cfg_fromTFTP {} {} config_id {}".format(self.tftp_server, tmp_file, remote_file)
            if self.config_replace:
                command += " increment"
            output = self._send_command(command)
            if tmp_file and os.path.isfile(tmp_file):
                os.remove(tmp_file)
        elif source_file:
            command = "download cfg_fromTFTP {} {} config_id {}".format(self.tftp_server, source_file, remote_file)
            if self.config_replace:
                command += " increment"
            output = self._send_command(command)

        msg = output
        if "successful" in output:
            return_status = True

        return (return_status, msg)

    def load_replace_candidate(self, filename=None, config=None):
        """
        file to device filesystem, defaults to candidate_config.

        Return None or raise exception
        """
        self.config_replace = True
        return_status, msg = self._load_candidate_wrapper(
            source_file=filename,
            source_config=config,
            dest_file=self.candidate_cfg,
        )
        if not return_status:
            raise ReplaceConfigException(msg)

    def load_merge_candidate(self, filename=None, config=None):
        """
        SCP file to remote device.

        Merge configuration in: copy <file> running-config
        """
        self.config_replace = False
        return_status, msg = self._load_candidate_wrapper(
            source_file=filename,
            source_config=config,
            dest_file=self.merge_cfg,
        )
        if not return_status:
            raise MergeConfigException(msg)

    def compare_config(self):
        """ TODO: I will add in the future. """
        # running_config = self.get_config()
        # if self.config_replace:
        #     new_file = self.candidate_cfg
        # else:
        #     new_file = self.merge_cfg
        #
        # from difflib import ndiff
        # diff = ndiff(running_config.splitlines(keepends=True), new_file.splitlines(keepends=True))
        # return ''.join(diff)

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
            if lldp_entry["remote_system_capab"]:
                lldp_entry["remote_system_capab"] = sorted(lldp_entry["remote_system_capab"].strip().lower().split(","))
            else:
                lldp_entry["remote_system_capab"] = []
            # Turn the interfaces into their long version
            local_intf = canonical_interface_name(local_intf)
            lldp.setdefault(local_intf, [])
            lldp[local_intf].append(lldp_entry)

        return lldp

    @staticmethod
    def parse_uptime(uptime_str):
        """
        Extract the uptime string from the given Cisco IOS Device.

        Return the uptime in seconds as an integer
        """
        # Initialize to zero
        days = hours = minutes = seconds = 0

        uptime_str = uptime_str.strip()
        time_list = uptime_str.split(",")
        for element in time_list:
            if re.search("days", element):
                days = int(element.split()[0])
            elif re.search("hrs", element):
                hours = int(element.split()[0])
            elif re.search("min", element):
                minutes = int(element.split()[0])
            elif re.search("secs", element):
                seconds = int(element.split()[0])

        uptime_sec = (
            (days * DAY_SECONDS)
            + (hours * 3600)
            + (minutes * 60)
            + seconds
        )
        return uptime_sec

    def get_facts(self):
        """ Return a set of facts from the devices. """
        # default values.
        serial_number, fqdn, os_version, hostname, domain_name = ("Unknown",) * 5

        output = self._send_command("show switch")
        show_switch = textfsm_extractor(
            self, "show_switch", output
        )[0]

        uptime = self.parse_uptime(show_switch["uptime"])
        vendor = "Dlink"
        os_version = show_switch["os_version"]
        serial_number = show_switch["serial_number"]
        model = show_switch["model"]
        # In Dlink device can't change hostname. Add system_name.
        hostname = fqdn = show_switch["system_name"]

        # Get interface list
        show_ports = self._send_command("show ports")
        interface_list = re.findall(r'^\d+', show_ports, re.MULTILINE)

        return {
            "uptime": uptime,
            "vendor": vendor,
            "os_version": str(os_version),
            "serial_number": str(serial_number),
            "model": str(model),
            "hostname": str(hostname),
            "fqdn": fqdn,
            "interface_list": interface_list,

            # Additional data
            "mac_addr": mac(show_switch["mac_addr"]),
            "ip_addr": show_switch["ip_addr"],
            "vlan_name": show_switch["vlan_name"],
            "subnet_mask": show_switch["subnet_mask"],
            "gateway": show_switch["gateway"],
            "boot_version": show_switch["boot_version"],
            "protocol_version": show_switch["protocol_version"],
            "hardware_version": show_switch["hardware_version"],
            "system_time": show_switch["system_time"],
            "location": show_switch["location"],
            "contact": show_switch["contact"],
            "stp": show_switch["stp"],
            "gvrp": show_switch["gvrp"],
            "igmp_snooping": show_switch["igmp_snooping"],
            "radius": show_switch["radius"],
            "telnet": show_switch["telnet"],
            "web": show_switch["web"],
            "rmon": show_switch["rmon"],
            "ssh": show_switch["ssh"],
            "vlan_trunk": show_switch["vlan_trunk"],
            "syslog": show_switch["syslog"],
            "cli_paging": show_switch["cli_paging"],
            "password_encryption": show_switch["password_encryption"],
        }

    def get_interfaces(self):
        """
         Get interface details.
         last_flapped and mac_address is not implemented
         Example Output:
         {   u'Vlan1': {   'description': u'N/A',
                       'is_enabled': True,
                       'is_up': True,
                       'last_flapped': -1.0,
                       'mac_address': u'a493.4cc1.67a7',
                       'speed': 100},
         u'Vlan100': {   'description': u'Data Network',
                         'is_enabled': True,
                         'is_up': True,
                         'last_flapped': -1.0,
                         'mac_address': u'a493.4cc1.67a7',
                         'speed': 100},
         u'Vlan200': {   'description': u'Voice Network',
                         'is_enabled': True,
                         'is_up': True,
                         'last_flapped': -1.0,
                         'mac_address': u'a493.4cc1.67a7',
                         'speed': 100}}
         """
        interface_dict = {}

        command = "show ports description"
        output = self._send_command(command)

        raw_interfaces = textfsm_extractor(self, "show_ports", output)

        for raw_interface in raw_interfaces:
            interface_dict[raw_interface["interface"]] = {
                "is_enabled": True if raw_interface["is_enabled"] == "Enabled" else False,
                "is_up": True if "Down" not in raw_interface["is_up"] else False,
                "description": raw_interface["description"].strip(),
                "mac_address": "",
                "last_flapped": -1.0,
                "speed": raw_interface["speed"],
            }

        return interface_dict

    def get_interfaces_ip(self):
        """
        Get interface ip details.
        Returns a dict of dicts
        Example Output:
        {   u'FastEthernet8': {   'ipv4': {   u'10.66.43.169': {   'prefix_length': 22}}},
            u'Loopback555': {   'ipv4': {   u'192.168.1.1': {   'prefix_length': 24}},
                                'ipv6': {   u'1::1': {   'prefix_length': 64},
                                            u'2001:DB8:1::1': {   'prefix_length': 64},
                                            u'2::': {   'prefix_length': 64},
                                            u'FE80::3': {   'prefix_length': 10}}},
            u'Tunnel0': {   'ipv4': {   u'10.63.100.9': {   'prefix_length': 24}}},
            u'Tunnel1': {   'ipv4': {   u'10.63.101.9': {   'prefix_length': 24}}},
            u'Vlan100': {   'ipv4': {   u'10.40.0.1': {   'prefix_length': 24},
                                        u'10.41.0.1': {   'prefix_length': 24},
                                        u'10.65.0.1': {   'prefix_length': 24}}},
            u'Vlan200': {   'ipv4': {   u'10.63.176.57': {   'prefix_length': 29}}}}
        """
        interfaces = {}

        command = "show ipif"
        output = self._send_command(command)
        raw_interfaces = textfsm_extractor(self, "show_ports_ip", output)

        for raw_interface in raw_interfaces:
            interfaces[raw_interface["interface"]] = {
                "ipv4": {raw_interface["ipv4"]:
                              {"prefix_length": IPAddress(raw_interface["ipv4_mask"]).netmask_bits()}
                          },
                "ipv6": {raw_interface["ipv6"]:
                             {"prefix_length": raw_interface["ipv6_mask"]}
                         }
            }
        return interfaces

    def get_interfaces_counters(self):
        """
        Return interface counters and errors.
        'tx_errors': int,
        'rx_errors': int,
        'tx_discards': int,
        'rx_discards': int,
        'tx_octets': int,
        'rx_octets': int,
        'tx_unicast_packets': int,
        'rx_unicast_packets': int,
        'tx_multicast_packets': int,
        'rx_multicast_packets': int,
        'tx_broadcast_packets': int,
        'rx_broadcast_packets': int,
        Currently doesn't determine output broadcasts, multicasts
        """
        counters = {}
        interface_count = len(self.get_interfaces())

        command_counters = "show packet ports 1-{}".format(interface_count)
        output_counter = self._send_command(command_counters)
        raw_counters = textfsm_extractor(self, "get_interfaces_counters", output_counter)
        raw_counters = {row.pop("interface"): row for row in raw_counters}

        command_errors = "show error ports 1-{}".format(interface_count)
        output_errors = self._send_command(command_errors)
        raw_errors = textfsm_extractor(self, "get_interfaces_errors", output_errors)
        for raw_error in raw_errors:
            interface = raw_error.pop("interface")
            counters[interface] = {**raw_counters[interface], **raw_error}

        return counters

    def get_environment(self):
        pass

    def get_arp_table(self, vrf=""):
        """
        Device does not support VRF. Using age as is configured on device, not real aging time.
        Get arp table information.

        Return a list of dictionaries having the following set of keys:
            * interface (string)
            * mac (string)
            * ip (string)
            * age (float)

        For example::
            [
                {
                    'interface' : 'MgmtEth0/RSP0/CPU0/0',
                    'mac'       : '5c:5e:ab:da:3c:f0',
                    'ip'        : '172.17.17.1',
                    'age'       : 1454496274.84
                },
                {
                    'interface': 'MgmtEth0/RSP0/CPU0/0',
                    'mac'       : '66:0e:94:96:e0:ff',
                    'ip'        : '172.17.17.2',
                    'age'       : 1435641582.49
                }
            ]
        """
        arp_table = []

        output = self._send_command("show arpentry")
        show_arpentry = textfsm_extractor(self, "show_arpentry", output)

        for line in show_arpentry:
            line["mac"] = mac(line["mac"])
            line["age"] = int(line["age"]) * 60
            arp_table.append(line)

        return arp_table

    def cli(self, commands):
        """
        Execute a list of commands and return the output in a dictionary format using the command
        as the key.

        Example input:
        ['show clock', 'show calendar']

        Output example:
        {   'show calendar': u'22:02:01 UTC Thu Feb 18 2016',
            'show clock': u'*22:01:51.165 UTC Thu Feb 18 2016'}

        """
        cli_output = dict()
        if type(commands) is not list:
            raise TypeError("Please enter a valid list of commands!")

        for command in commands:
            output = self._send_command(command)
            cli_output.setdefault(command, {})
            cli_output[command] = output

        return cli_output

    # def get_ntp_peers(self):
    #     """D-Link doesn't support this option"""

    def get_ntp_servers(self):
        """Support only SNTP"""
        command = "show sntp"
        output = self._send_command(command)
        sntp_servers = textfsm_extractor(self, "get_ntp_servers", output)
        return {server: {} for server in sntp_servers[0]["servers"]}

    def get_ntp_stats(self):
        pass

    def get_mac_address_table(self):
        """
        Returns a lists of dictionaries. Each dictionary represents an entry in the MAC Address
        Table, having the following keys
            * mac (string)
            * interface (string)
            * vlan (int)
            * active (boolean)
            * static (boolean)
            * moves (int)
            * last_move (float)

        Format:
        VID  VLAN Name                        MAC Address       Port Type
        ---- -------------------------------- ----------------- ---- ---------------
        903  ACswmgmt              C0-A0-BB-DB-7D-C5 CPU  Self
        903  ACswmgmt             28-8A-1C-A8-1A-96 25   Dynamic
        903  ACswmgmt              70-62-B8-A8-94-13 25   Dynamic
        """
        mac_address_table = []

        output = self._send_command("show fdb")
        show_fdb = textfsm_extractor(self, "show_fdb", output)

        for line in show_fdb:
            mac_addr = mac(line["mac"])
            interface = line["interface"]
            vlan = int(line["vlan"])
            static = False

            if line["mac_type"].lower() in ["self", "static", "system"]:
                static = True

            if (line["interface"].lower() == "cpu"
                or re.search(r"router", line["mac_type"].lower())
                or re.search(r"switch", line["mac_type"].lower())
            ):
                interface = ""

            mac_address_table.append({
                "mac": mac_addr,
                "interface": interface,
                "vlan": vlan,
                "static": static,
                "active": True,
                "moves": -1,
                "last_move": -1.0,
            })

        return mac_address_table

    def get_snmp_information(self):
        """
        Returns a dict of dicts

        Example Output:

        {   'chassis_id': u'Asset Tag 54670',
        'community': {   u'private': {   'acl': u'12', 'mode': u'rw'},
                         u'public': {   'acl': u'11', 'mode': u'ro'},
                         u'public_named_acl': {   'acl': u'ALLOW-SNMP-ACL',
                                                  'mode': u'ro'},
                         u'public_no_acl': {   'acl': u'N/A', 'mode': u'ro'}},
        'contact': u'Joe Smith',
        'location': u'123 Anytown USA Rack 404'}

        """
        # TODO: Command 'show config current_config include snmp' too slow. Maybe require to use separated commands.
        # TODO: Add output from 'create snmp group...'
        # show_switch = self.get_facts()
        #
        #
        #
        # snmp_dict = {
        #     "chassis_id": "unknown",
        #     "community": {},
        #     "contact": show_switch["contact"] or "unknown",
        #     "location": show_switch["location"] or "unknown",
        # }
        #
        # return snmp_dict
        mode_short = {
            "ReadOnly": "ro",
            "ReadWrite": "rw"
        }

        command = "show config current_config include snmp"
        output = self._send_command(command)
        snmp = textfsm_extractor(self, "snmp", output)[0]
        communities = textfsm_extractor(self, "snmp_community", output)

        chassis_id = snmp["chassis_id"] or "unknown"
        contact = snmp["contact"] or "unknown"
        location = snmp["location"] or "unknown"
        community_dict = {}

        for line in communities:
            community_name = line["community"]
            mode = line["mode"]

            community_dict[community_name] = {
                "acl": "N/A",
                "mode": mode_short[mode]
            }

        return {
            "chassis_id": chassis_id,
            "community": community_dict,
            "contact": contact,
            "location": location,
        }

    def get_users(self):
        """
        Returns a dictionary with the configured users.
        The keys of the main dictionary represents the username.
        The values represent the details of the user,
        represented by the following keys:

            * level (int)
            * password (str)
            * sshkeys (list)

        *Note: sshkeys on ios is the ssh key fingerprint

        The level is an integer between 0 and 15, where 0 is the
        lowest access and 15 represents full access to the device.
        """
        users = {}
        int_levels = {
            "admin": 15,
            "operator": 10,
            "power-user": 5,
            "user": 0,
        }
        command = "show config current_config"
        output = self._send_command(command)
        user_fsm = textfsm_extractor(self, "users", output)

        for line in user_fsm:
            user = line["user"]
            level = line["level"]

            users[user] = {
                "level": int_levels.get(level, -1),
                "sshkeys": "N/A"
            }

        return users

    def ping(
        self,
        destination,
        source=C.PING_SOURCE,
        ttl=C.PING_TTL,
        timeout=C.PING_TIMEOUT,
        size=C.PING_SIZE,
        count=C.PING_COUNT,
        vrf=C.PING_VRF,
    ):
        """
                Execute ping on the device and returns a dictionary with the result.

                Output dictionary has one of following keys:
                    * success
                    * error
                In case of success, inner dictionary will have the following keys:
                    * probes_sent (int)
                    * packet_loss (int)
                    * rtt_min (float)
                    * rtt_max (float)
                    * rtt_avg (float)
                    * rtt_stddev (float)
                    * results (list)
                'results' is a list of dictionaries with the following keys:
                    * ip_address (str)
                    * rtt (float)

                    This device does not permit more than two keys in the same time with command 'ping'.
                """
        ping_dict = {}

        command = "ping {}".format(destination)
        command += " size {}".format(size)
        command += " times {}".format(count)
        command += " timeout {}".format(timeout)

        output = self._send_command(command)
        if "Reply Not Received" in output or "% Ping Failed" in output:
            ping_dict["error"] = output
        else:
            ping_dict["success"] = {
                "probes_sent": 0,
                "packet_loss": 0,
                "rtt_min": 0.0,
                "rtt_max": 0.0,
                "rtt_avg": 0.0,
                "rtt_stddev": 0.0,
                "results": [],
            }

            rtt = re.findall(r'TimeTaken : <?(\d+) (\S+)', output, re.M)
            rtt_stat = []
            for r in list(rtt):
                rtt_time = int(r[0])
                if "secs" in r:
                    rtt_stat.append(rtt_time * 1000)
                else:
                    rtt_stat.append(rtt_time)

            statistic = re.search(
                r"(?P<probes_sent>\d+) Packets Transmitted, "
                r"(?P<probes_received>\d+) Packets Received, ",
                output
            ).groupdict()

            probes_sent = int(statistic["probes_sent"])
            probes_received = int(statistic["probes_received"])
            ping_dict["success"]["probes_sent"] = probes_sent
            ping_dict["success"]["packet_loss"] = probes_sent - probes_received

            rtt_min = min(rtt_stat)
            rtt_max = max(rtt_stat)
            rtt_avg = sum(rtt_stat) // len(rtt_stat)

            ping_dict["success"].update(
                {
                    "rtt_min": rtt_min,
                    "rtt_avg": rtt_avg,
                    "rtt_max": rtt_max,
                }
            )

            results_array = []
            for r in rtt_stat:
                results_array.append(
                    {
                        "ip_address": str(destination),
                        "rtt": r,
                    }
                )
            ping_dict["success"].update({"results": results_array})

        return ping_dict

    def get_config(self, retrieve="all", full=False):
        """Implementation of get_config for Dlink """
        command = "show config current_config"
        output = self._send_command(command)

        return output

    # def traceroute(
    #     self,
    #     destination,
    #     source=c.TRACEROUTE_SOURCE,
    #     ttl=c.TRACEROUTE_TTL,
    #     timeout=c.TRACEROUTE_TIMEOUT,
    #     vrf=c.TRACEROUTE_VRF,
    # ):
    #     """Ignored options 'source' and 'VRF' because D-Link doesn't support it."""
    #
    #     command = f"traceroute {destination} max-ttl {ttl} timeout {timeout}".format(
    #         destination=destination,
    #         ttl=ttl,
    #         timeout=timeout
    #     )
    #     output = self._send_command(command)
