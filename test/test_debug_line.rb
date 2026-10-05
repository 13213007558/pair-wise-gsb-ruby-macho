# frozen_string_literal: true

require_relative "helpers"

class DebugLineTest < Minitest::Test
  include Helpers

  FIXTURE = File.expand_path("bin/dwarf/debug-line.macho", __dir__)
  GENERATOR = File.expand_path("src/debug_line/make_debug_line_fixture.rb", __dir__)

  def setup
    @file = MachO::MachOFile.new(FIXTURE)
    @programs = @file.debug_line.programs
  end

  def test_fixture_is_present_and_generated_by_ruby_script
    assert File.file?(FIXTURE), "run `ruby #{GENERATOR}` to create the fixture"
    assert File.file?(GENERATOR)
  end

  def test_section_is_parsed_from_dwarf_segment
    assert_kind_of MachO::DWARF::DebugLine, @file.debug_line
    assert_equal [2, 3, 4, 5], @programs.map(&:version)
  end

  def test_header_parameters
    v5 = @programs.last
    assert_equal 1, v5.minimum_instruction_length
    assert_equal 2, v5.maximum_operations_per_instruction
    assert_equal 1, v5.default_is_stmt
    assert_equal(-5, v5.line_base)
    assert_equal 14, v5.line_range
    assert_equal 13, v5.opcode_base
    assert_equal 8, v5.address_size
  end

  def test_v5_directory_and_file_tables
    v5 = @programs.last
    assert_equal %w[src include], v5.directories
    names = v5.files.map(&:name)
    assert_equal %w[main.c util.c extra.c], names
    assert_equal [0, 1, 0], v5.files.map(&:directory_index)
  end

  def test_legacy_directory_and_file_tables
    v2, v3, v4 = @programs

    [v2, v3, v4].each do |program|
      assert_equal %w[src], program.directories
      assert_equal %w[legacy.c], program.files.first(1).map(&:name)
      assert_equal 1, program.maximum_operations_per_instruction
    end

    assert_equal %w[legacy.c generated.c], v2.files.map(&:name)
    assert_equal %w[legacy.c generated.c], v3.files.map(&:name)
    assert_equal %w[legacy.c], v4.files.map(&:name)
  end

  def test_two_non_contiguous_sequences
    v5 = @programs.last
    assert_equal 2, v5.sequences.size
    assert v5.sequences.all? { |sequence| sequence.last.end_sequence }
    assert_equal 0x1000, v5.sequences.first.first.address
    assert_equal 0x1006, v5.sequences.first.last.address
    assert_equal 0x4000, v5.sequences.last.first.address
    assert_equal 0x4002, v5.sequences.last.last.address
  end

  def test_end_sequence_closes_only_its_own_sequence
    v5 = @programs.last
    end_rows = v5.rows.select(&:end_sequence)
    assert_equal 2, end_rows.size
    assert_equal [0x1006, 0x4002], end_rows.map(&:address)
    # Rows following an end_sequence begin a fresh sequence at the new address.
    assert_equal 0x4000, v5.sequences.last.first.address
  end

  def test_multiple_rows_at_same_address
    v5 = @programs.last
    rows = v5.rows_at(0x1000)
    assert_equal 3, rows.size
    assert_equal [5, 8, 8], rows.map(&:column)
    assert_equal [0, 0, 1], rows.map(&:op_index)
    assert_equal 42, rows[2].discriminator
    assert rows.none?(&:end_sequence)

    rows = v5.rows_at(0x4000)
    assert_equal %w[util.c extra.c], rows.map(&:file)
  end

  def test_at_prefers_first_row_at_exact_address
    v5 = @programs.last
    row = v5.at(0x1000)
    assert_equal "main.c", row.file
    assert_equal 5, row.column
  end

  def test_at_within_range_uses_last_row_not_exceeding_address
    v5 = @programs.last
    # 0x1002 is the first address of the next line; 0x1005 resolves to it.
    row = v5.at(0x1005)
    assert_equal 10, row.line
    assert_equal 0x1002, row.address

    # Second, non-contiguous sequence starts at 0x4000.
    row = v5.at(0x4001)
    assert_equal "extra.c", row.file
    assert_equal 0, row.line
  end

  def test_at_returns_nil_outside_any_sequence
    v5 = @programs.last
    assert_nil v5.at(0x0fff)
    assert_nil v5.at(0x3000) # gap between the two sequences
    assert_nil v5.at(0x1006) # the end_sequence address itself is excluded
    assert_nil v5.at(0x5000)
  end

  def test_rows_for_returns_the_full_covering_sequence
    v5 = @programs.last
    rows = v5.rows_for(0x1003)
    assert_equal 6, rows.size
    assert_equal 0x1000, rows.first.address
    assert_equal 0x1006, rows.last.address
    assert rows.none?(&:end_sequence)
    assert_nil v5.rows_for(0x3000)
  end

  def test_op_index_enters_address_advancement
    v5 = @programs.last
    rows = v5.rows_at(0x1000)
    # The third row advances one operation within the two-operation
    # instruction at 0x1000; op_index becomes 1 without changing address.
    assert_equal 1, rows.last.op_index

    # A second operation advance wraps across the VLIW boundary at 0x1001,
    # and the following advance_pc/copy lands at 0x1002 with op_index 0.
    assert_equal 0x1002, v5.at(0x1002).address
    assert_equal 0, v5.at(0x1002).op_index
    # The in-between row records op_index 1 at 0x1001.
    between = v5.rows.find { |row| row.address == 0x1001 }
    assert_equal 1, between.op_index
  end

  def test_special_opcodes_advance_line_and_address
    v5 = @programs.last
    first = v5.rows_at(0x1000).first
    assert_equal 1, first.line

    # advance_line(+9), advance_pc(1), copy -> line 10 at 0x1001/0x1002.
    assert_equal 10, v5.at(0x1002).line
  end

  def test_discriminator_is_recorded_and_reset
    v5 = @programs.last
    assert_equal 42, v5.rows_at(0x1000).last.discriminator
    # Discriminator resets after the row is appended.
    assert_equal 0, v5.at(0x1002).discriminator
  end

  def test_prologue_end_flag
    v5 = @programs.last
    assert v5.rows_at(0x1000).first.prologue_end
    refute v5.rows_at(0x1000).last.prologue_end
  end

  def test_define_file_extended_opcode_in_v2_and_v3
    v2, v3 = @programs
    [v2, v3].each do |program|
      row = program.at(0x2012)
      assert_equal "generated.c", row.file
      refute row.statement? # negate_stmt precedes this row
    end
  end

  def test_fixed_advance_pc_and_set_isa
    v2 = @programs.first
    # const_add_pc advances 17 ops to 0x2012; fixed_advance_pc(2) moves to
    # 0x2014 and resets op_index.
    row = v2.at(0x2014)
    assert_equal 0, row.op_index

    # Two rows are emitted at 0x2014; the second sets isa = 1.
    assert_equal [0, 1], v2.rows_at(0x2014).map(&:isa)
  end

  def test_set_discriminator_only_in_v4
    v4 = @programs[2]
    assert_equal 2, v4.at(0x2001).discriminator
    assert_equal 0, v4.at(0x2012).discriminator
  end

  def test_legacy_sequences
    @programs[0...3].each do |program|
      assert_equal 2, program.sequences.size
      assert_equal [0x2000, 0x6000], program.sequences.map { |sequence| sequence.first.address }
    end
  end

  def test_querying_legacy_programs
    v2 = @programs.first
    assert_equal "legacy.c", v2.at(0x2000).file
    assert_equal "legacy.c", v2.at(0x6001).file
    assert_nil v2.at(0x3000)
    assert_nil v2.at(0x2016) # end_sequence address is excluded
  end

  def test_row_to_h
    v5 = @programs.last
    hash = v5.rows.first.to_h
    assert_equal 0x1000, hash["address"]
    assert_equal "main.c", hash["file"]
    assert_equal 1, hash["line"]
    assert_equal 5, hash["column"]
    assert_equal 0, hash["discriminator"]
    assert_equal false, hash["end_sequence"]
  end

  def test_debug_line_programs_on_file_without_section
    file = MachO::MachOFile.new(fixture(:x86_64, "hello.o"))
    assert_nil file.debug_line
    assert_equal [], file.debug_line_programs
  end

  def test_standalone_reader_parses_concatenated_programs
    data = @file.send(:dwarf_section_data, "__debug_line")
    line_strings = @file.send(:dwarf_section_data, "__debug_line_str")
    reader = MachO::DWARF::DebugLine.new(
      data,
      :endianness => :little,
      :address_size => 8,
      :line_strings => line_strings,
    )
    assert_equal [2, 3, 4, 5], reader.programs.map(&:version)
  end

  def test_standalone_reader_is_endianness_aware
    # A tiny big-endian v3 program with one set-address/end-sequence pair.
    program = [
      0,                    # extended opcode marker
      9,                    # operand length (1 + 8)
      2,                    # DW_LNE_set_address
    ].pack("CCC")
    program += [0x0000000000008000].pack("Q>") # big-endian address
    program += [0, 1, 1].pack("CCC") # end_sequence (length 1)

    tables = "\x00\x00"
    fixed = [0].pack("N")
    fixed += [1, 1, -5 & 0xff, 14, 13].pack("C*")
    fixed += ([0] * 12).map { |n| uleb(n) }.join
    fixed += tables
    body = [3].pack("n") + fixed + program
    unit = [body.bytesize].pack("N") + body

    reader = MachO::DWARF::DebugLine.new(unit, :endianness => :big, :address_size => 8)
    assert_equal :big, reader.endianness
    assert_equal 0x8000, reader.programs.first.rows.first.address
  end

  def test_zero_padded_section_tail_is_tolerated
    data = @file.send(:dwarf_section_data, "__debug_line")
    padded = data + "\x00" * 16
    reader = MachO::DWARF::DebugLine.new(
      padded,
      :line_strings => @file.send(:dwarf_section_data, "__debug_line_str"),
    )
    assert_equal 4, reader.programs.size
  end

  def test_dwarf64_unit_length_is_supported
    opcodes = 1.chr # DW_LNS_copy (one row at address 0)
    tables = uleb(0) + uleb(0) + uleb(0) + uleb(0)
    std_lengths = [0] * 12
    after_length = [1, 2, 1, -5 & 0xff, 14, 13].pack("C*") +
                   std_lengths.map { |n| uleb(n) }.join
    fixed = [8, 0].pack("CC")
    fixed << [after_length.bytesize + tables.bytesize].pack("Q<")
    fixed << after_length
    fixed << tables
    body = [5].pack("v") + fixed + opcodes

    unit = [0xffffffff].pack("V") + [body.bytesize].pack("Q<") + body
    reader = MachO::DWARF::DebugLine.new(unit)
    assert_equal 8, reader.programs.first.offset_size
    assert_equal 1, reader.programs.first.rows.size
  end

  def test_unsupported_version_raises
    header = build_unit_header(1)
    assert_raises MachO::DWARF::DebugLineError do
      MachO::DWARF::DebugLine.new(header)
    end
  end

  def test_truncated_unit_raises
    header = build_unit_header(5)
    assert_raises MachO::DWARF::DebugLineError do
      MachO::DWARF::DebugLine.new(header.byteslice(0, 4))
    end
  end

  def test_unknown_standard_opcode_operands_are_skipped
    # Emit a v5 program whose opcode_base is 14 (one extra unknown standard
    # opcode with two operands) followed by those operands and a copy.
    program = build_custom_standard_program
    reader = MachO::DWARF::DebugLine.new(program)
    assert_equal 1, reader.programs.size
    assert_equal 1, reader.programs.first.rows.size
  end

  private

  # Builds a minimal, truncated-to-header unit for the given version.
  def build_unit_header(version)
    header = build_header(version, 13, [0] * 12, "")
    [header.bytesize].pack("V") + header
  end

  # Builds a v5 unit declaring one unknown 13th standard opcode (two operands),
  # then exercising it before a normal copy row.
  def build_custom_standard_program
    opcodes = uleb(13) + uleb(7) + uleb(9) + 1.chr
    header = build_header(5, 14, [0] * 12 + [2], opcodes)
    [header.bytesize].pack("V") + header
  end

  # Assembles one version-2-5 line program unit body (after unit_length).
  def build_header(version, opcode_base, standard_lengths, opcodes)
    tables = if version >= 5
      # empty v5 path tables: zero entries of each kind
      uleb(0) + uleb(0) + uleb(0) + uleb(0)
    else
      "\x00\x00"
    end

    fixed = +""
    if version >= 5
      fixed << [8, 0].pack("CC")
      after_length = +""
      after_length << [1, 2, 1, -5 & 0xff, 14, opcode_base].pack("C*")
      after_length << standard_lengths.map { |n| uleb(n) }.join
      fixed << [after_length.bytesize + tables.bytesize].pack("V")
      fixed << after_length
    else
      fixed << [0].pack("V")
      fixed << [1, 1, -5 & 0xff, 14, opcode_base].pack("C*")
      fixed << standard_lengths.map { |n| uleb(n) }.join
    end
    fixed << tables

    [version].pack("v") + fixed + opcodes
  end

  def uleb(value)
    out = +""
    while value >= 0x80
      out << [(value & 0x7f) | 0x80].pack("C")
      value >>= 7
    end
    out << [value].pack("C")
    out
  end
end
