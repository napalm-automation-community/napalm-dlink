Value MODEL (\S+)
Value MAC_ADDR (\S+)
Value IP_ADDR ((\d{1,3}\.){3}\d{1,3})
Value VLAN_NAME (\S+)
Value SUBNET_MASK ((\d{1,3}\.){3}\d{1,3})
Value GATEWAY ((\d{1,3}\.){3}\d{1,3})
Value BOOT_VERSION (\S+)
Value PROTOCOL_VERSION (\S+)
Value OS_VERSION (\S+)
Value HARDWARE_VERSION (\S+)
Value SERIAL_NUMBER (\S+)
Value SYSTEM_NAME (\S+)
Value LOCATION (.+)
Value UPTIME (.+)
Value CONTACT (.+)
Value SYSTEM_TIME (.+)
Value STP (\S+)
Value GVRP (\S+)
Value IGMP_SNOOPING (\S+)
Value RADIUS (\S+)
Value TELNET (\S+)
Value WEB (\S+)
Value RMON (\S+)
Value SSH (\S+)
Value VLAN_TRUNK (\S+)
Value SYSLOG (\S+)
Value CLI_PAGING (\S+)
Value PASSWORD_ENCRYPTION (\S+)

Start
  ^Device Type +: ${MODEL}
  ^MAC Address + : ${MAC_ADDR}
  ^IP Address +: ${IP_ADDR}
  ^VLAN Name +: ${VLAN_NAME}
  ^Subnet Mask +: ${SUBNET_MASK}
  ^Default Gateway +: ${GATEWAY}
  ^.*Boot Version +: ${BOOT_VERSION}
  ^.*Protocol Version +: ${PROTOCOL_VERSION}
  ^.*Firmware Version +: ${OS_VERSION}
  ^.*Hardware Version +: ${HARDWARE_VERSION}
  ^.*Serial Number +: ${SERIAL_NUMBER}
  ^.*Name +: ${SYSTEM_NAME}
  ^.*Location +: ${LOCATION}
  ^.*[uU]p ?time +: ${UPTIME}
  ^.*Contact +: ${CONTACT}
  ^Time +: ${SYSTEM_TIME}
  ^STP +: ${STP}
  ^GVRP +: ${GVRP}
  ^IGMP Snooping +: ${IGMP_SNOOPING}
  ^VLAN Trunk +: ${VLAN_TRUNK}
  ^802.1X Status +: ${RADIUS}
  ^Telnet +: ${TELNET}
  ^Web +: ${WEB}
  ^RMON +: ${RMON}
  ^SSH +: ${SSH}
  ^Syslog Global State +: ${SYSLOG}
  ^CLI Paging +: ${CLI_PAGING}
  ^Password Encryption State +: ${PASSWORD_ENCRYPTION} -> Record
