from binaryninja.architecture import Architecture
from binaryninja.binaryview import BinaryView
from binaryninja.log import log_error, log_debug, log_info, log_alert, log_warn, log_to_stderr, log_to_stdout
from binaryninja.enums import SegmentFlag

from enum import Enum
import struct

# The Enum values below are taken from https://github.com/grumpycoders/pcsx-redux/blob/main/tools/psyq-obj-parser/psyq-obj-parser.cc
# Copyright (C) 2020 PCSX-Redux authors
class PsyqOpcode(Enum):
    END = 0
    BYTES = 2
    SWITCH = 6
    ZEROES = 8
    RELOCATION = 10
    EXPORTED_SYMBOL = 12
    IMPORTED_SYMBOL = 14
    SECTION = 16
    LOCAL_SYMBOL = 18
    FILENAME = 28
    PROGRAMTYPE = 46
    UNINITIALIZED = 48
    INC_SLD_LINENUM = 50
    INC_SLD_LINENUM_BY_BYTE = 52
    INC_SLD_LINENUM_BY_WORD = 54
    SET_SLD_LINENUM = 56
    SET_SLD_LINENUM_FILE = 58
    END_SLD = 60
    FUNCTION = 74
    FUNCTION_END = 76
    BLOCK_START = 78
    BLOCK_END = 80
    SECTION_DEF = 82
    SECTION_DEF2 = 84
    FUNCTION_START2 = 86


class PsyqRelocType(Enum):
    REL32_BE = 8
    REL32 = 16
    REL26 = 74
    HI16 = 82
    LO16 = 84
    REL26_BE = 92
    HI16_BE = 96
    LO16_BE = 98
    GPREL16 = 100
    

class PsyqExprOpcode(Enum):
    VALUE = 0
    SYMBOL = 2
    SECTION_BASE = 4
    SECTION_START = 12
    SECTION_END = 22
    ADD = 44
    SUB = 46
    DIV = 50


class PsyqSection:
    def __init__(self, index, group, alignment, name):
        self.index = index
        self.group = group
        self.alignment = alignment
        self.name = name
        self.offset = 0
        self.size = 0


class PsyqRelocation:
    def __init__(self):
        self.reloc_type = 0
        self.offset = 0
        self.expression = ""


class PsyqImportedSymbol:
    def __init__(self, index, name):
        self.index = index
        self.name = name


class PsyqExportedSymbol:
    def __init__(self, index, section_index, offset, name):
        self.index = index
        self.section_index = section_index
        self.offset = offset
        self.name = name


class PsyqObjFile:
    def __init__(self):
        self.sections = {}
        self.imports = []
        self.exports = []
        self.relocations = []
        #expression
        self.current_section = 0

    def get_current_section(self):
        return self.sections[self.current_section]


class OBJView(BinaryView):
    name = "OBJ"
    long_name = "PSYQ-OBJ"

    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.platform = Architecture['mipsel32'].standalone_platform
        self.data = data
        self.objFile = PsyqObjFile()
        self.index = 0

    @classmethod
    def is_valid_for_data(self, data):
        if data[0:4] != b"LNK\x02":
            return False
        return True

    def perform_is_executable(self):
        return False

    def _get_address_size(self, ctxt):
        return self.arch.address_size

    def init(self):
        self.add_auto_segment(0, self.data.length, 0, self.data.length, SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)
        #self.add_auto_section(".text", 0x200, 0x9C4)
        self.parse()
        return True

    def parse(self):
        self.index += 4 # skip past header
        while (self.index < self.data.length):
            self.resolve_opcode()

    def resolve_opcode(self):
        opcode = int.from_bytes(self.read_byte())
        if opcode == PsyqOpcode.PROGRAMTYPE.value:
            self.objFile.program_type = self.parse_program_type()
        elif opcode == PsyqOpcode.SECTION.value:
            section = self.parse_section()
            self.objFile.sections[section.index] = section
        elif opcode == PsyqOpcode.IMPORTED_SYMBOL.value:
            symbol = self.parse_imported_symbol()
            self.objFile.imports.append(symbol)
        elif opcode == PsyqOpcode.EXPORTED_SYMBOL.value:
            symbol = self.parse_exported_symbol()
            self.objFile.exports.append(symbol)
        elif opcode == PsyqOpcode.SWITCH.value:
            self.objFile.current_section = self.parse_switch()
        elif opcode == PsyqOpcode.BYTES.value:
            self.parse_bytes()
        elif opcode == PsyqOpcode.RELOCATION.value:
            self.parse_relocation()

    def parse_program_type(self):
        value = int.from_bytes(self.read_byte())
        if value != 7 and value != 9:
            log_warn("Unknown program type: {}".format(program_type))
        return value

    def parse_section(self):
        index = struct.unpack("<H", self.read_word())[0]
        group = struct.unpack("<H", self.read_word())[0]
        alignment = int.from_bytes(self.read_byte())
        name_len = int.from_bytes(self.read_byte())
        name = self.read_bytes(name_len)
        return PsyqSection(index, group, alignment, name)

    def parse_imported_symbol(self):
        index = self.read_word()
        name_len = int.from_bytes(self.read_byte())
        name = self.read_bytes(name_len)
        return PsyqImportedSymbol(index, name)

    def parse_exported_symbol(self):
        index = self.read_word()
        section_index = self.read_word()
        offset = struct.unpack("<I", self.read_dword())[0]
        name_len = int.from_bytes(self.read_byte())
        name = self.read_bytes(name_len)
        return PsyqExportedSymbol(index, section_index, offset, name)

    def parse_bytes(self):
        section = self.objFile.get_current_section()
        size = struct.unpack("<H", self.read_word())[0]
        section.size = size
        section.offset = self.index
        self.read_bytes(size) # skipping the buffer and advancing the offset to the end of the section since we don't need to copy the bytes

    def parse_switch(self):
        return struct.unpack("<H", self.read_word())[0]

    def parse_relocation(self):
        foo1 = self.objFile.imports
        foo2 = self.objFile.exports
        foo3 = self.objFile.sections
        foo4 = self.objFile.relocations
        reloc = PsyqRelocation()
        section = self.objFile.get_current_section()
        reloc.reloc_type = int.from_bytes(self.read_byte())
        reloc.offset = struct.unpack("<H", self.read_word())[0] + section.offset

    def read_word(self):
        return self.read_bytes(2)

    def read_dword(self):
        return self.read_bytes(4)

    def read_byte(self):
        return self.read_bytes(1)

    def read_bytes(self, length):
        val = self.data[self.index:self.index+length]
        self.index += length
        return val