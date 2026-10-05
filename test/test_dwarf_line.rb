# frozen_string_literal: true

require_relative "helpers"

class DwarfLineTest < Minitest::Test
  # Encodes +value+ as unsigned LEB128.
  def uleb(value)
    bytes = []
    loop do
      byte = value & 0x7f
      value >>= 7
      byte |= 0x80 unless value.zero?
      bytes << byte
      break if value.zero?
    end
    bytes.pack("C*")
  end

  # Encodes +value+ as signed LEB128.
  def sleb(value)
    bytes = []
    loop do
      byte = value & 0x7f
      value >>= 7
      done = (value.zero? && (byte & 0x40).zero?) || (value == -1 && (byte & 0x40) != 0)
      byte |= 0x80 unless done
      bytes << byte
      break if done
    end
    bytes.pack("C*")
  end

  # Wraps a line program body in a unit with the given version-appropriate
  # header fields.
  def wrap_unit(version:, header_fields:, program:)
    body = [version].pack("S<")
    if version >= 5
      body << [8, 0].pack("C*") # address_size, segment_selector_size
    end
    body << [header_fields.bytesize].pack("L<")
    body << header_fields
    body << program
    [body.bytesize].pack("L<") + body
  end

  # Standard opcode lengths shared by every fixture (opcode_base is 13).
  STANDARD_OPCODE_LENGTHS = [0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1].pack("C*").freeze

  # Builds a version 2-4 style header (NUL-terminated directory and file
  # lists). +max_ops+ is only emitted for version 4.
  def legacy_header(max_ops: nil)
    header = +"".b
    header << [1].pack("C")                 # min_instruction_length
    header << [max_ops].pack("C") unless max_ops.nil?
    header << [1].pack("C")                 # default_is_stmt
    header << [-5].pack("c")                # line_base
    header << [14, 13].pack("C*")           # line_range, opcode_base
    header << STANDARD_OPCODE_LENGTHS
    header << "/proj\0\0"                 # one include directory
    header << "foo.c\0" << uleb(1) << uleb(0) << uleb(0)
    header << "bar.c\0" << uleb(0) << uleb(0) << uleb(0)
    header << "\0"
    header
  end

  def extended(sub_opcode, operand)
    "\x00".b + uleb(1 + operand.bytesize) + [sub_opcode].pack("C") + operand
  end

  def set_address(address, size)
    extended(2, [address].pack(size == 8 ? "Q<" : "L<"))
  end

  def end_sequence
    extended(1, "")
  end

  # A version 5 program with a directory/file table and two sequences over
  # the non-contiguous ranges 0x1001...0x1002 and 0x5000...0x5015.
  def build_v5_section
    header = +"".b
    header << [1, 3, 1].pack("C*") # min_instruction_length, max_ops, default_is_stmt
    header << [-5].pack("c")       # line_base
    header << [14, 13].pack("C*")  # line_range, opcode_base
    header << STANDARD_OPCODE_LENGTHS
    header << [1].pack("C")        # directory entry format count
    header << uleb(1) << uleb(0x08) # DW_LNCT_path, DW_FORM_string
    header << uleb(2)              # directories count
    header << "/src\0" << "/src/lib\0"
    header << [3].pack("C")        # file name entry format count
    header << uleb(1) << uleb(0x08) # DW_LNCT_path, DW_FORM_string
    header << uleb(2) << uleb(0x0f) # DW_LNCT_directory_index, DW_FORM_udata
    header << uleb(4) << uleb(0x0f) # DW_LNCT_size, DW_FORM_udata
    header << uleb(2)              # file names count
    header << "main.c\0" << uleb(0) << uleb(100)
    header << "util.c\0" << uleb(1) << uleb(200)

    program = +"".b
    # Sequence 1: starts at 0x1000.
    program << set_address(0x1000, 8)
    program << [4].pack("C") << uleb(0)      # set_file 0 (main.c)
    program << [5].pack("C") << uleb(4)      # set_column 4
    program << [2].pack("C") << uleb(5)      # advance_pc 5: addr 0x1001, op_index 2
    program << [1].pack("C")                 # copy -> row A
    program << [13 + 20].pack("C")           # special: addr 0x1002, line 2 -> row B
    program << [1].pack("C")                 # copy -> row C (same address)
    program << extended(4, uleb(7))          # set_discriminator 7
    program << [3].pack("C") << sleb(3)      # advance_line 3 -> line 5
    program << [1].pack("C")                 # copy -> row D (discriminator 7)
    program << [2].pack("C") << uleb(1)      # advance_pc 1: addr stays, op_index 1
    program << [1].pack("C")                 # copy -> row E
    program << [2].pack("C") << uleb(4)      # advance_pc 4: addr 0x1003
    program << end_sequence                  # closes sequence 1 only
    # Sequence 2: disjoint range starting at 0x5000.
    program << set_address(0x5000, 8)
    program << [4].pack("C") << uleb(1)      # set_file 1 (util.c)
    program << [3].pack("C") << sleb(10)     # advance_line 10 -> line 11
    program << [1].pack("C")                 # copy -> row G
    program << [8].pack("C")                 # const_add_pc: addr 0x5005, op_index 2
    program << [1].pack("C")                 # copy -> row H
    program << [9].pack("C") << [0x10].pack("S<") # fixed_advance_pc 0x10 -> 0x5015
    program << [6].pack("C")                 # negate_stmt
    program << [7].pack("C")                 # set_basic_block
    program << [1].pack("C")                 # copy -> row I
    program << [2].pack("C") << uleb(3)      # advance_pc 3: addr 0x5016
    program << end_sequence

    wrap_unit(:version => 5, :header_fields => header, :program => program)
  end

  # A version 2 program exercising the legacy header, DW_LNE_define_file,
  # and a 4-byte address size passed by the caller.
  def build_v2_section
    program = +"".b
    program << set_address(0x800, 4)
    program << [1].pack("C")                          # copy -> row at 0x800 (foo.c)
    program << extended(3, "baz.h\0" + uleb(1) + uleb(0) + uleb(0)) # define_file
    program << [4].pack("C") << uleb(3)               # set_file 3 (baz.h)
    program << [3].pack("C") << sleb(40)              # advance_line 40
    program << [1].pack("C")                          # copy -> row at 0x800 (baz.h)
    program << [13 + 35].pack("C")                    # special: addr 0x802, line 43
    program << [2].pack("C") << uleb(0x100)           # advance_pc -> 0x902
    program << [5].pack("C") << uleb(9)               # set_column 9
    program << [1].pack("C")                          # copy -> row at 0x902
    program << end_sequence

    wrap_unit(:version => 2, :header_fields => legacy_header, :program => program)
  end

  # A minimal version 4 program, mainly to cover the
  # max_ops_per_instruction header field introduced in version 4.
  def build_v4_section
    program = +"".b
    program << set_address(0x100, 8)
    program << [2].pack("C") << uleb(3) # advance_pc 3 with max_ops 2: addr 0x101, op_index 1
    program << [1].pack("C")
    program << end_sequence

    wrap_unit(:version => 4, :header_fields => legacy_header(:max_ops => 2), :program => program)
  end

  def test_v5_header_tables
    program = MachO::DWARF::LineProgram.parse(build_v5_section)
    header = program.header

    assert_equal 5, header.version
    assert_equal 8, header.address_size
    assert_equal 3, header.max_ops_per_instruction
    assert_equal(-5, header.line_base)
    assert_equal 14, header.line_range
    assert_equal ["/src", "/src/lib"], header.directories
    assert_equal 2, header.files.size

    main = header.files[0]
    assert_equal "main.c", main.name
    assert_equal 0, main.directory_index
    assert_equal "/src", main.directory
    assert_equal "/src/main.c", main.path
    assert_equal 100, main.size

    util = header.files[1]
    assert_equal "/src/lib/util.c", util.path
    assert_equal 200, util.size
  end

  def test_v5_sequences_and_rows
    program = MachO::DWARF::LineProgram.parse(build_v5_section)
    rows = program.rows

    assert_equal 10, rows.size
    assert_equal 2, program.sequences.size

    first, second = program.sequences
    assert_equal 0x1001, first.start_address
    assert_equal 0x1003, first.end_address
    assert_equal 0x5000, second.start_address
    assert_equal 0x5016, second.end_address

    row_a = rows[0]
    assert_equal 0x1001, row_a.address
    assert_equal 2, row_a.op_index
    assert_equal 1, row_a.line
    assert_equal 4, row_a.column
    assert_equal "/src/main.c", row_a.file.path
    assert_predicate row_a, :statement?

    # The special opcode advanced the line and folded op_index into the
    # address computation.
    row_b = rows[1]
    assert_equal 0x1002, row_b.address
    assert_equal 0, row_b.op_index
    assert_equal 2, row_b.line

    # Rows C, D and E share row B's address.
    assert_equal [0x1002, 0x1002, 0x1002], rows[2..4].map(&:address)
    assert_equal 7, rows[3].discriminator
    assert_equal 5, rows[3].line
    assert_equal 0, rows[4].discriminator
    assert_equal 1, rows[4].op_index

    # end_sequence closed only the first sequence: registers reset, and the
    # second sequence decoded from a disjoint address range.
    row_g = rows[6]
    assert_equal 0x5000, row_g.address
    assert_equal 11, row_g.line
    assert_equal 0, row_g.column
    assert_equal "/src/lib/util.c", row_g.file.path

    row_h = rows[7]
    assert_equal 0x5005, row_h.address
    assert_equal 2, row_h.op_index

    row_i = rows[8]
    assert_equal 0x5015, row_i.address
    refute_predicate row_i, :statement?
    assert_predicate row_i, :basic_block?

    assert_predicate rows[5], :sequence_end?
    assert_predicate rows[9], :sequence_end?
  end

  def test_v5_table_queries
    table = MachO::DWARF::LineProgram.parse(build_v5_section).to_table

    # All raw rows at a shared address are visible.
    assert_equal 4, table.rows_at(0x1002).size
    assert_equal 1, table.rows_at(0x5000).size

    # lookup follows the documented selection rule: last row emitted at the
    # greatest covered address not exceeding the query.
    assert_equal 1, table.lookup(0x1001).line
    assert_equal 5, table.lookup(0x1002).line
    assert_equal 11, table.lookup(0x5000).line
    assert_equal 11, table.lookup(0x5004).line
    assert_equal 0x5005, table.lookup(0x5014).address
    assert_equal 0x5015, table.lookup(0x5015).address

    # Sequence boundaries and gaps between sequences match nothing.
    assert_nil table.lookup(0x1003)
    assert_nil table.lookup(0x3000)
    assert_nil table.lookup(0x5016)
    refute table.cover?(0x3000)
    assert table.cover?(0x5000)

    # Range queries return every raw row in the range, in emission order.
    assert_equal [0x1002, 0x1002, 0x1002, 0x1002, 0x5000], table.rows_in(0x1002..0x5000).map(&:address)
  end

  def test_v2_program
    program = MachO::DWARF::LineProgram.parse(build_v2_section, :address_size => 4)
    header = program.header

    assert_equal 2, header.version
    assert_equal 1, header.max_ops_per_instruction
    assert_equal ["/proj"], header.directories
    assert_equal 3, header.files.size
    assert_equal "/proj/foo.c", header.files[0].path
    assert_nil header.files[1].directory
    assert_equal "bar.c", header.files[1].name
    # DW_LNE_define_file appended a third entry mid-program.
    assert_equal "/proj/baz.h", header.files[2].path

    rows = program.rows
    assert_equal 5, rows.size
    assert_equal 1, program.sequences.size

    assert_equal 0x800, rows[0].address
    assert_equal "foo.c", rows[0].file.name
    assert_equal 1, rows[0].line

    assert_equal 0x800, rows[1].address
    assert_equal "baz.h", rows[1].file.name
    assert_equal 41, rows[1].line

    # Special opcode: address and line advanced together.
    assert_equal 0x802, rows[2].address
    assert_equal 43, rows[2].line

    assert_equal 0x902, rows[3].address
    assert_equal 9, rows[3].column
    assert_predicate rows[4], :sequence_end?

    table = program.to_table
    assert_equal 2, table.rows_at(0x800).size
    assert_equal 41, table.lookup(0x801).line
    assert_equal 43, table.lookup(0x900).line
    assert_nil table.lookup(0x902)
  end

  def test_v4_max_ops_per_instruction
    program = MachO::DWARF::LineProgram.parse(build_v4_section)

    assert_equal 4, program.header.version
    assert_equal 2, program.header.max_ops_per_instruction

    row = program.rows.first
    assert_equal 0x101, row.address
    assert_equal 1, row.op_index
  end

  def test_v5_line_strp_form
    line_str = "/strp_dir\0strp_file.c\0"

    header = +"".b
    header << [1, 1, 1].pack("C*")
    header << [-5].pack("c")
    header << [14, 13].pack("C*")
    header << STANDARD_OPCODE_LENGTHS
    header << [1].pack("C")         # directory entry format count
    header << uleb(1) << uleb(0x1f) # DW_LNCT_path, DW_FORM_line_strp
    header << uleb(1)               # directories count
    header << [0].pack("L<")        # offset of "/strp_dir" in line_str
    header << [1].pack("C")         # file name entry format count
    header << uleb(1) << uleb(0x1f) # DW_LNCT_path, DW_FORM_line_strp
    header << uleb(1)               # file names count
    header << [10].pack("L<")       # offset of "strp_file.c" in line_str

    program = set_address(0x7000, 8) + [1].pack("C") + end_sequence
    section = wrap_unit(:version => 5, :header_fields => header, :program => program)

    parsed = MachO::DWARF::LineProgram.parse(section, :line_str => line_str)
    assert_equal ["/strp_dir"], parsed.header.directories
    assert_equal "strp_file.c", parsed.header.files[0].name

    assert_raises(MachO::DWARF::Error) do
      MachO::DWARF::LineProgram.parse(section)
    end
  end

  def test_unsupported_version
    section = wrap_unit(:version => 6, :header_fields => "", :program => "")

    error = assert_raises(MachO::DWARF::Error) do
      MachO::DWARF::LineProgram.parse(section)
    end
    assert_match(/version/, error.message)
  end

  def test_truncated_unit
    assert_raises(MachO::DWARF::Error) do
      MachO::DWARF::LineProgram.parse([0x40].pack("L<") + "short")
    end
  end
end
