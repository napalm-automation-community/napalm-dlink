Value Required USER (\S+)
Value Required LEVEL (\S+)
Value Required PASSWORD (.+)

Start
  ^create account ${LEVEL} ${USER}
  ^${PASSWORD} -> Record
