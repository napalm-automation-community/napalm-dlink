Value interface (\d+)
# 'tx_errors': int,
# 'rx_errors': int,
# 'tx_discards': int,
# 'rx_discards': int,
Value rx_octets (\d+)
Value tx_octets (\d+)
Value rx_unicast_packets (\d+)
Value rx_multicast_packets (\d+)
Value rx_broadcast_packets (\d+)
Value tx_unicast_packets (\d+)
Value tx_multicast_packets (\d+)
Value tx_broadcast_packets (\d+)


Start
  ^ ?Port Number : +${interface}
  ^.+RX Bytes +${rx_octets}
  ^.+TX Bytes +${tx_octets}
  ^ ?Unicast RX +${rx_unicast_packets}
  ^ ?Multicast RX +${rx_multicast_packets}
  ^ ?Broadcast RX +${rx_broadcast_packets}
  ^ ?Unicast TX +${tx_unicast_packets}
  ^ ?Multicast TX +${tx_multicast_packets}
  ^ ?Broadcast TX +${tx_broadcast_packets} -> Record