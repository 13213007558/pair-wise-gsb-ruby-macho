#!/usr/bin/env ruby
# frozen_string_literal: true

# Generates a Mach-O object file containing concatenated DWARF 2-5
# `.debug_line` line number programs, used by test/test_debug_line.rb.
#
# The file is generated entirely in Ruby; no compiler, yaml2obj, or dwarfdump
# is needed at generation or test time. Regenerate with:
#
#   ruby test/src/debug_line/make_debug_line_fixture.rb
#
# The DWARF 5 program exercises the version 5 directory/file name tables
# (including DW_FORM_line_strp references into .debug_line_str) and emits two
# sequences over non-contiguous address ranges. The DWARF 2-4 programs
# exercise the legacy directory/file tables, DW_LNE_define_file and
# DW_LNE_set_discriminator.

require "fileutils"

# A little-endian binary accumulator with DWARF-aware encoders.
class Buffer
  def initialize
    @bytes = +""
  end

  def u8(value)
    @bytes << [value].pack("C")
    self
  end

  def u16(value)
    @bytes << [value].pack("v")
    self
  end

  def u32(value)
    @bytes << [value].pack("V")
    self
  end

  def u64(value)
    @bytes << [value].pack("Q<")
    self
  end

  def uleb(value)
    raise ArgumentError, "negative uleb" if value.negative?

    while value >= 0x80
      @bytes << [(value & 0x7f) | 0x80].pack("C")
      value >>= 7
    end
    @bytes << [value].pack("C")
    self
  end

  def sleb(value)
    loop do
      byte = value & 0x7f
      sign = byte & 0x40
      value >>= 7
      done = (value.zero? && sign.zero?) || (value == -1 && sign != 0)
      @bytes << [byte | (done ? 0 : 0x80)].pack("C")
      break if done
    end
    self
  end

  def string(value)
    @bytes << value.to_s.b << "\x00"
    self
  end

  def raw(data)
    @bytes << data.to_s.b
    self
  end

  def to_s
    @bytes
  end

  def size
    @bytes.bytesize
  end
end

# Builds one `.debug_line` line number program body (header + opcodes).
class LineProgram
  DW_LNS_COPY = 0x01
  DW_LNS_ADVANCE_PC = 0x02
  DW_LNS_ADVANCE_LINE = 0x03
  DW_LNS_SET_FILE = 0x04
  DW_LNS_SET_COLUMN = 0x05
  DW_LNS_NEGATE_STMT = 0x06
  DW_LNS_CONST_ADD_PC = 0x08
  DW_LNS_FIXED_ADVANCE_PC = 0x09
  DW_LNS_SET_PROLOGUE_END = 0x0a
  DW_LNS_SET_ISA = 0x0c

  DW_LNE_END_SEQUENCE = 0x01
  DW_LNE_SET_ADDRESS = 0x02
  DW_LNE_DEFINE_FILE = 0x03
  DW_LNE_SET_DISCRIMINATOR = 0x04

  DW_LNCT_PATH = 0x01
  DW_LNCT_DIRECTORY_INDEX = 0x02

  DW_FORM_STRING = 0x08
  DW_FORM_DATA1 = 0x0b
  DW_FORM_LINE_STRP = 0x1e

  # Parameters common to every program emitted by the fixture.
  MIN_INST_LEN = 1
  MAX_OPS_PER_INST = 2
  LINE_BASE = -5
  LINE_RANGE = 14
  OPCODE_BASE = 13

  # The standard opcode length table (opcode_base - 1 = 12 entries).
  STANDARD_LENGTHS = [
    0, # DW_LNS_copy
    1, # DW_LNS_advance_pc
    1, # DW_LNS_advance_line
    1, # DW_LNS_set_file
    1, # DW_LNS_set_column
    0, # DW_LNS_negate_stmt
    0, # DW_LNS_set_basic_block
    0, # DW_LNS_const_add_pc
    1, # DW_LNS_fixed_advance_pc
    0, # DW_LNS_set_prologue_end
    0, # DW_LNS_set_epilogue_begin
    1, # DW_LNS_set_isa
  ].freeze

  def initialize(version)
    @version = version
    @ops = Buffer.new
  end

  def copy
    @ops.u8(DW_LNS_COPY)
  end

  def set_file(index)
    @ops.u8(DW_LNS_SET_FILE).uleb(index)
  end

  def set_column(column)
    @ops.u8(DW_LNS_SET_COLUMN).uleb(column)
  end

  def advance_pc(operation_advance)
    @ops.u8(DW_LNS_ADVANCE_PC).uleb(operation_advance)
  end

  def advance_line(delta)
    @ops.u8(DW_LNS_ADVANCE_LINE).sleb(delta)
  end

  def negate_stmt
    @ops.u8(DW_LNS_NEGATE_STMT)
  end

  def const_add_pc
    @ops.u8(DW_LNS_CONST_ADD_PC)
  end

  def fixed_advance_pc(halfword)
    @ops.u8(DW_LNS_FIXED_ADVANCE_PC).u16(halfword)
  end

  def prologue_end
    @ops.u8(DW_LNS_SET_PROLOGUE_END)
  end

  def set_isa(isa)
    @ops.u8(DW_LNS_SET_ISA).uleb(isa)
  end

  def special(adjusted)
    @ops.u8(OPCODE_BASE + adjusted)
  end

  def end_sequence
    extended(DW_LNE_END_SEQUENCE) {}
  end

  def set_address(address)
    extended(DW_LNE_SET_ADDRESS) { |body| body.u64(address) }
  end

  def define_file(name, directory_index)
    extended(DW_LNE_DEFINE_FILE) do |body|
      body.string(name).uleb(directory_index).uleb(0).uleb(0)
    end
  end

  def set_discriminator(value)
    extended(DW_LNE_SET_DISCRIMINATOR) { |body| body.uleb(value) }
  end

  # Emits the complete unit (length-prefixed) for concatenation into
  # `.debug_line`.
  def unit(line_str_offsets)
    @line_str_offsets = line_str_offsets
    header = header_buffer

    body = Buffer.new
    body.raw(header.to_s)
    body.raw(@ops.to_s)

    unit = Buffer.new
    unit.u32(body.size).raw(body.to_s)
    unit.to_s
  end

  private

  def extended(number)
    body = Buffer.new
    body.u8(number)
    yield body
    @ops.u8(0).uleb(body.size).raw(body.to_s)
  end

  # Assembles the program header, with v5 and v2-4 table formats.
  def header_buffer
    tables = Buffer.new
    fixed = Buffer.new
    if @version >= 5
      emit_v5_tables(tables)
      fixed.u8(8) # address_size
      fixed.u8(0) # segment_selector_size
      fixed.u32(fixed_after_length_size + tables.size) # header_length
    else
      emit_legacy_tables(tables)
      fixed.u32(0) # compilation unit header length (unused for .debug_line)
    end
    fixed.u8(MIN_INST_LEN)
    fixed.u8(MAX_OPS_PER_INST) if @version >= 5
    fixed.u8(1) # default_is_stmt
    fixed.u8(LINE_BASE & 0xff)
    fixed.u8(LINE_RANGE)
    fixed.u8(OPCODE_BASE)
    STANDARD_LENGTHS.each { |length| fixed.uleb(length) }

    header = Buffer.new
    header.u16(@version)
    header.raw(fixed.to_s)
    header.raw(tables.to_s)
    header
  end

  # The number of bytes in the fixed header following the header_length
  # field itself, used to compute header_length.
  def fixed_after_length_size
    buffer = Buffer.new
    buffer.u8(MIN_INST_LEN)
    buffer.u8(MAX_OPS_PER_INST)
    buffer.u8(1)
    buffer.u8(LINE_BASE & 0xff)
    buffer.u8(LINE_RANGE)
    buffer.u8(OPCODE_BASE)
    STANDARD_LENGTHS.each { |length| buffer.uleb(length) }
    buffer.size
  end

  # DWARF 2-4: NUL-terminated include directories followed by the
  # NUL-terminated file-name table.
  def emit_legacy_tables(buffer)
    buffer.string("src")
    buffer.string("") # end of include directories

    # file 1: legacy.c in directory 1
    buffer.string("legacy.c").uleb(1).uleb(0).uleb(0)
    buffer.string("") # end of file-name table
  end

  # DWARF 5: explicit file and directory counts with (content, form) pairs.
  def emit_v5_tables(buffer)
    buffer.uleb(2) # directories count
    buffer.uleb(1) # directory_entry_format_count
    buffer.uleb(DW_LNCT_PATH).uleb(DW_FORM_LINE_STRP)
    path_entry(buffer, @line_str_offsets.fetch("src"))
    path_entry(buffer, @line_str_offsets.fetch("include"))

    buffer.uleb(3) # file names count
    buffer.uleb(2) # file_name_entry_format_count
    buffer.uleb(DW_LNCT_PATH).uleb(DW_FORM_LINE_STRP)
    buffer.uleb(DW_LNCT_DIRECTORY_INDEX).uleb(DW_FORM_DATA1)
    file_entry(buffer, @line_str_offsets.fetch("main.c"), 0)
    file_entry(buffer, @line_str_offsets.fetch("util.c"), 1)
    file_entry(buffer, @line_str_offsets.fetch("extra.c"), 0)
  end

  def path_entry(buffer, offset)
    buffer.u32(offset)
  end

  def file_entry(buffer, offset, directory_index)
    buffer.u32(offset) # DW_LNCT_PATH / DW_FORM_line_strp
    buffer.u8(directory_index) # DW_LNCT_directory_index / DW_FORM_data1
  end
end

module MachOFixture
  MH_MAGIC_64 = 0xfeedfacf
  CPU_TYPE_X86_64 = 0x01000007
  CPU_SUBTYPE_X86_64_ALL = 3
  MH_OBJECT = 1
  LC_SEGMENT_64 = 0x19
  S_REGULAR = 0
  S_ATTR_DEBUG = 0x02000000

  # A 64-bit Mach-O section record (80 bytes).
  def self.section(sectname, segname, size, offset)
    Buffer.new.tap do |b|
      b.raw(sectname.to_s.b.ljust(16, "\x00"))
      b.raw(segname.to_s.b.ljust(16, "\x00"))
      b.u64(0)          # addr
      b.u64(size)       # size
      b.u32(offset)     # offset
      b.u32(0)          # align
      b.u32(0)          # reloff
      b.u32(0)          # nreloc
      b.u32(S_REGULAR | S_ATTR_DEBUG)
      b.u32(0)          # reserved1
      b.u32(0)          # reserved2
      b.u32(0)          # reserved3
    end.to_s
  end

  def self.build(debug_line, debug_line_str)
    sections = [
      section("__debug_line", "__DWARF", debug_line.bytesize, 0),
      section("__debug_line_str", "__DWARF", debug_line_str.bytesize, 0),
    ]

    cmdsize = 72 + sections.sum(&:bytesize)
    segment = Buffer.new
    segment.u32(LC_SEGMENT_64)
    segment.u32(cmdsize)
    segment.raw("__DWARF".b.ljust(16, "\x00"))
    segment.u64(0) # vmaddr
    segment.u64(0) # vmsize
    segment.u64(0) # fileoff
    segment.u64(0) # filesize
    segment.u32(7) # maxprot rwx
    segment.u32(7) # initprot
    segment.u32(sections.size)
    segment.u32(0) # flags
    segment.raw(sections.join)

    header = Buffer.new
    header.u32(MH_MAGIC_64)
    header.u32(CPU_TYPE_X86_64)
    header.u32(CPU_SUBTYPE_X86_64_ALL)
    header.u32(MH_OBJECT)
    header.u32(1) # ncmds
    header.u32(cmdsize)
    header.u32(0) # flags
    header.u32(0) # reserved

    data_offset = header.size + cmdsize
    line_offset = data_offset
    str_offset = line_offset + debug_line.bytesize

    # Patch section offsets/sizes now that they are known.
    patched = segment.to_s
    # section_64 layout: sectname(16) segname(16) addr(8) size(8) offset(4)
    patched[72 + 40, 8] = [debug_line.bytesize].pack("Q<")
    patched[72 + 48, 4] = [line_offset].pack("V")
    patched[152 + 40, 8] = [debug_line_str.bytesize].pack("Q<")
    patched[152 + 48, 4] = [str_offset].pack("V")

    Buffer.new.tap do |b|
      b.raw(header.to_s)
      b.raw(patched)
      b.raw(debug_line)
      b.raw(debug_line_str)
    end.to_s
  end
end

# Builds the .debug_line_str section and returns the offsets needed by the v5
# file/directory table references.
def build_line_strings
  line_str = Buffer.new
  offsets = {}
  %w[src include main.c util.c extra.c].each do |value|
    offsets[value] = line_str.size
    line_str.string(value)
  end
  [line_str.to_s, offsets]
end

# Populates the opcodes of the DWARF 5 program.
def build_v5_ops(program)
  # First sequence begins at 0x1000. min_inst_length=1, max_ops_per_inst=2
  # means an operation advance of 2 folds into one instruction byte while
  # tracking op_index through the VLIW boundary.
  #
  # Special opcodes encode (op_advance, line_delta) with line_range 14 and
  # line_base -5:
  #   special(0)  => +0 ops, line -5 (first encodable delta)
  #   special(5)  => +0 ops, line +0
  #   special(19) => +1 op,  line +0
  #   special(33) => +2 ops, line +0 (one instruction byte; op_index wraps)
  program.set_address(0x1000)
  program.set_file(0) # main.c (0-based v5)
  program.set_column(5)
  program.prologue_end
  program.special(5)  # row @0x1000 op0: main.c line 1, column 5

  program.set_column(8)
  program.copy        # duplicate address: a second raw row at 0x1000

  program.set_discriminator(42)
  program.special(19) # @0x1000 op1: main.c line 1, discriminator 42
  program.special(33) # folds to @0x1001 op0: main.c line 1, discriminator reset
  program.advance_line(9)
  program.advance_pc(1)
  program.copy        # @0x1001 op1: main.c line 10
  program.fixed_advance_pc(0x0004) # byte advance; op_index resets
  program.special(5)  # @0x1005 op0: main.c line 10
  program.end_sequence

  # Second, non-contiguous sequence begins at 0x4000.
  program.set_address(0x4000)
  program.set_file(1) # util.c
  program.set_column(11)
  program.special(5)  # @0x4000: util.c line 1, column 11
  program.set_file(2) # extra.c
  program.advance_line(-1) # line back to 0 ("no source line" sentinel)
  program.copy        # @0x4000: extra.c line 0
  program.advance_pc(2) # advance one full instruction (0x4000 -> 0x4001)
  program.copy         # @0x4001 op0: extra.c line 0
  program.advance_pc(2) # another instruction (0x4001 -> 0x4002)
  program.copy         # @0x4002 op0: extra.c line 0
  program.end_sequence
end

# Populates the opcodes of a DWARF 2-4 program.
def build_legacy_ops(program, version)
  program.set_address(0x2000)
  program.set_file(1) # legacy.c
  program.set_column(4)
  program.special(5) # @0x2000 op0: legacy.c line 1, column 4

  if version == 4
    program.set_discriminator(2)
    program.advance_pc(1) # @0x2000 op1, discriminator 2
  else
    program.advance_pc(1) # @0x2000 op1
  end
  program.special(5)  # line stays 1

  if version <= 3
    # Defined at runtime: file index 2, "generated.c", directory 0.
    program.define_file("generated.c", 0)
    program.set_file(2)
  else
    program.set_file(1)
  end
  program.negate_stmt
  program.const_add_pc # (255 - 13) / 14 = 17 ops => @0x2009 op0
  program.copy
  program.fixed_advance_pc(0x0002) # byte advance to 0x200b, op_index resets
  program.copy
  program.set_isa(1)
  program.special(5) # @0x200b: line 1, isa 1
  program.advance_pc(2)
  program.special(5) # @0x200d: line 1, isa 1
  program.end_sequence

  # Second, non-contiguous sequence.
  program.set_address(0x6000)
  program.set_file(1)
  program.special(5) # @0x6000: legacy.c line 1
  program.advance_pc(1)
  program.special(5) # @0x6001: legacy.c line 1
  program.advance_pc(1)
  program.special(5) # @0x6002: legacy.c line 1
  program.end_sequence
end

def main
  line_str, line_str_offsets = build_line_strings

  debug_line = Buffer.new
  (2..5).each do |version|
    program = LineProgram.new(version)
    if version >= 5
      build_v5_ops(program)
    else
      build_legacy_ops(program, version)
    end
    debug_line.raw(program.unit(line_str_offsets))
  end

  macho = MachOFixture.build(debug_line.to_s, line_str)
  destination = File.expand_path(
    "../../bin/dwarf/debug-line.macho",
    __dir__,
  )
  FileUtils.mkdir_p(File.dirname(destination))
  File.binwrite(destination, macho)
  warn "wrote #{destination} (#{macho.bytesize} bytes)"
end

main if __FILE__ == $PROGRAM_NAME
