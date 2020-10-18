Value VLAN (\d+)
Value MAC (\S+)
Value INTERFACE (\d+)
Value MAC_TYPE (\S+)

Start
  ^${VLAN} +\S+ +${MAC} +${INTERFACE} +${MAC_TYPE} -> Record