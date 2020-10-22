# napalm-dlink
Requirements
************
For driver needs a preconfigured TFTP server because Dlink devices can download config only from TFTP/FTP server. 
Default path: /tmp
************
Tested on device Dlink 1210-28
************

Сompletion status:
- [x] _send_command
- [x] is_alive
- [x] load_replace_candidate
- [x] load_merge_candidate
- [x] compare_config - This device doesn't contain a builtin function for compare config.
- [ ] commit_config
- [ ] discard_config
- [ ] rollback
- [ ] get_optics
- [x] get_lldp_neighbors
- [x] get_lldp_neighbors_detail
- [x] get_facts
- [x] get_interfaces
- [x] get_interfaces_ip
- [x] get_interfaces_counters
- [ ] get_environment
- [x] get_arp_table
- [x] cli
- [ ] get_ntp_peers
- [ ] get_ntp_servers
- [ ] get_ntp_stats
- [x] get_mac_address_table
- [ ] get_probes_config
- [x] get_snmp_information
- [x] get_users
- [x] ping
- [ ] traceroute
- [x] get_config
