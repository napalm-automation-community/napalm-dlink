Value INTERFACE (\S*)
Value Required MAC (\S+)
Value Required IP ((\d{1,3}\.){3}\d{1,3})
Value Filldown AGE (\d+)

Start
  ^ARP Aging Time = ${AGE} -> Start
  ^${INTERFACE} +${IP} +${MAC} -> Record

# System         10.30.0.11       c0-a0-bb-db-7d-c5  Local
#                10.30.0.1        28-8a-1c-a8-1a-96  Dynamic