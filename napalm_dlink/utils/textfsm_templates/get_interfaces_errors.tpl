Value interface (\d+)
Value rx_errors (\d+)
Value tx_excessive_deferral (\d+)
Value rx_udersize (\d+)
Value tx_errors (\d+)
Value rx_oversize (\d+)
Value tx_late_collision (\d+)
Value rx_fragment (\d+)
Value tx_excessive_collision (\d+)
Value rx_jabber (\d+)
Value tx_single_collision (\d+)
Value rx_buffer_drop (\d+)
Value tx_buffer_drop (\d+)
Value rx_vlan_ingress_drop (\d+)
Value rx_stp_drop (\d+)


Start
  ^ ?Port Number : +${interface}
  ^ ?CRC Error +${rx_errors} +Excessive Deferral +${tx_excessive_deferral}
  ^ ?Undersize +${rx_udersize} +CRC Error +${tx_errors}
  ^ ?Oversize +${rx_oversize} +Late Collision +${tx_late_collision}
  ^ ?Fragment +${rx_fragment} +Excessive Collision +${tx_excessive_collision}
  ^ ?Jabber +${rx_jabber} +Single Collision +${tx_single_collision}
  ^ ?Buffer Full Drop +${rx_buffer_drop} +Buffer Full Drop +${tx_buffer_drop}
  ^ ?VLAN Ingress Drop +${rx_vlan_ingress_drop}
  ^ ?STP Drop +${rx_stp_drop} -> Record