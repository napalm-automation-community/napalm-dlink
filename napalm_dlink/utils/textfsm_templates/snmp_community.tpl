Value COMMUNITY (\S+)
# Value VERSION (\S+)
# Value List ACL (read_view|notify_view|write_view)
Value MODE (\S+)

Start
  # ^create snmp group ${COMMUNITY} ${VERSION} (${ACL} ${MODE} ?)+ -> Record
  ^create snmp community ${COMMUNITY} ${MODE} -> Record
