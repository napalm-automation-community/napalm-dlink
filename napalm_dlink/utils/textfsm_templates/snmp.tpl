Value CONTACT (.+)
Value LOCATION (.+)
Value CHASSIS_ID (.+)

Start
  ^config snmp engineID ${CHASSIS_ID}
  ^config snmp system_location "?${CONTACT}"?
  ^config snmp system_contact "?${LOCATION}"?
