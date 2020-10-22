Value interface (.+)
Value ipv4 (.+)
Value ipv4_mask (.+)
Value ipv6 (.+)
Value ipv6_mask (.+)


Start
  ^Interface VLAN Name +: ${interface}
  ^IP Address +: ${ipv4}
  ^Subnet Mask +: ${ipv4_mask}
  ^IPv6 Link-Local Address +: ${ipv6}/${ipv6_mask} -> Record