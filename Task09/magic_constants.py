# magic number constants from malicious make binary
MAGIC_START = b"\x14\x42\x40\x73"
MAGIC_END = b"\xe6\x4f\x14\x95"

CMD_LENGTH = b"\x00\x02"
UUID_LENGTH = b"\x00\x10"

PARAM_CMD = b"\x4e\x00"
PARAM_UUID = b"\x4e\x08"
PARAM_DIRNAME = b"\x4e\x14"
PARAM_FILENAME = b"\x4e\x1c"
PARAM_CONTENTS = b"\x4e\x20"
PARAM_MORE = b"\x4e\x24"
PARAM_CODE = b"\x4e\x28"
PARAM_TASKNAME = b"\x4e\x18"

COMMAND_INIT = b"\x00\x02"
COMMAND_REQUEST = b"\x00\x03"
COMMAND_LS = b"\x00\x04"
COMMAND_CAT = b"\x00\x05"
COMMAND_UPLOAD = b"\x00\x06"
COMMAND_FIN = b"\x00\x07"
