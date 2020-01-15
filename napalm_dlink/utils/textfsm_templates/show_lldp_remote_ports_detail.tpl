Value LOCAL_INTERFACE (\d+)
Value Required REMOTE_CHASSIS_ID (.*)
Value REMOTE_PORT (.*)
Value REMOTE_PORT_DESCRIPTION (.+)
Value REMOTE_SYSTEM_NAME (.*)
Value REMOTE_SYSTEM_DESCRIPTION (.+)
Value REMOTE_SYSTEM_CAPAB (.*)

Start
  ^Port ID : +${LOCAL_INTERFACE}
  ^ +Chassis Id +: ${REMOTE_CHASSIS_ID}
  ^ +Port ID +: ${REMOTE_PORT}
  ^ +Port Description +: ${REMOTE_PORT_DESCRIPTION}
  ^ +System Name +: ${REMOTE_SYSTEM_NAME}
  ^ +System Description +: ${REMOTE_SYSTEM_DESCRIPTION}
  ^ +System Capabilities +: ${REMOTE_SYSTEM_CAPAB} -> Record
