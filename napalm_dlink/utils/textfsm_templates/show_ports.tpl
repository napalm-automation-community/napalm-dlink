Value interface (\d+)
Value is_enabled (Enabled|Disable)
Value is_up (Link Down)
Value speed (\d+)
Value description (.+)


Start
  ^${interface} +${is_enabled} +Auto/Disabled +(${is_up}|${speed})
  ^Desc: ${description}? -> Record