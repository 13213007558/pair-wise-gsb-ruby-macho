# frozen_string_literal: true

require_relative "helpers"

class DyldInfoTest < Minitest::Test
  include Helpers

  DI = MachO::DyldInfo

  def uleb(value)
    bytes = []
    loop do
      byte = value & 0x7F
      value >>= 7
      byte |= 0x80 unless value.zero?
      bytes << byte
      break if value.zero?
    end
    bytes.pack("C*")
  end

  def sleb(value)
    bytes = []
    loop do
      byte = value & 0x7F
      value >>= 7
      done = (value.zero? && (byte & 0x40).zero?) || (value == -1 && (byte & 0x40) != 0)
      byte |= 0x80 unless done
      bytes << byte
      break if done
    end
    bytes.pack("C*")
  end

  def segment(vmaddr, vmsize)
    DI::Segment.new(vmaddr, vmsize)
  end

  def stream(*parts)
    parts.flatten.map { |part| part.is_a?(Integer) ? part.chr : part }.join.b
  end

  def test_read_uleb128
    assert_equal [0, 1], DI.read_uleb128("\x00")
    assert_equal [127, 1], DI.read_uleb128("\x7F")
    assert_equal [128, 2], DI.read_uleb128("\x80\x01")
    assert_equal [624_485, 3], DI.read_uleb128("\xE5\x8E\x26")
    assert_equal [42, 2], DI.read_uleb128("\xFF\x2A\x00", 1)
  end

  def test_read_uleb128_truncated
    assert_raises(MachO::DyldInfoError) { DI.read_uleb128("\x80") }
    assert_raises(MachO::DyldInfoError) { DI.read_uleb128("") }
  end

  def test_read_uleb128_too_large
    assert_raises(MachO::DyldInfoError) { DI.read_uleb128("\xFF" * 10) }
  end

  def test_read_sleb128
    assert_equal [0, 1], DI.read_sleb128("\x00")
    assert_equal [-1, 1], DI.read_sleb128("\x7F")
    assert_equal [-128, 2], DI.read_sleb128("\x80\x7F")
    assert_equal [127, 2], DI.read_sleb128("\xFF\x00")
    assert_equal [-123_456, 3], DI.read_sleb128("\xC0\xBB\x78")
  end

  def test_read_sleb128_truncated
    assert_raises(MachO::DyldInfoError) { DI.read_sleb128("\x80") }
  end

  def test_rebase_single_action
    bytes = stream(
      DI::REBASE_OPCODE_SET_TYPE_IMM | DI::REBASE_TYPE_POINTER,
      DI::REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB,
      uleb(0x20),
      DI::REBASE_OPCODE_DO_REBASE_IMM_TIMES | 1,
      DI::REBASE_OPCODE_DONE
    )

    actions = DI.rebase_actions(bytes, :segments => [segment(0x1000, 0x100)])

    assert_equal 1, actions.size
    action = actions.first
    assert_equal 0, action.source_offset
    assert_equal 0, action.segment_index
    assert_equal 0x20, action.segment_offset
    assert_equal 0x1020, action.address
    assert_equal DI::REBASE_TYPE_POINTER, action.type
  end

  def test_rebase_without_segments_has_no_address
    bytes = stream(
      DI::REBASE_OPCODE_SET_TYPE_IMM | DI::REBASE_TYPE_POINTER,
      DI::REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB,
      uleb(0x20),
      DI::REBASE_OPCODE_DO_REBASE_IMM_TIMES | 1,
      DI::REBASE_OPCODE_DONE
    )

    action = DI.rebase_actions(bytes).first
    assert_nil action.address
    assert_equal 0x20, action.segment_offset
  end

  def test_rebase_repeated_skips
    bytes = stream(
      DI::REBASE_OPCODE_SET_TYPE_IMM | DI::REBASE_TYPE_POINTER,
      DI::REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB,
      uleb(0x10),
      DI::REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB,
      uleb(3),
      uleb(8),
      DI::REBASE_OPCODE_ADD_ADDR_IMM_SCALED | 2,
      DI::REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB,
      uleb(0x30),
      DI::REBASE_OPCODE_DONE
    )

    actions = DI.rebase_actions(bytes, :segments => [segment(0x1000, 0x1000)])

    # 3 fixups skipping 8 + 8 bytes each, then ADD_ADDR_IMM_SCALED (2 * 8),
    # then one fixup that adds 0x30 afterwards (which must not affect it).
    assert_equal [0x10, 0x20, 0x30, 0x50], actions.map(&:segment_offset)
    assert_equal [0x1010, 0x1020, 0x1030, 0x1050], actions.map(&:address)
  end

  def test_rebase_source_offsets_advance_per_record
    bytes = stream(
      DI::REBASE_OPCODE_SET_TYPE_IMM | DI::REBASE_TYPE_POINTER,
      DI::REBASE_OPCODE_DO_REBASE_IMM_TIMES | 2,
      DI::REBASE_OPCODE_DO_REBASE_IMM_TIMES | 1,
      DI::REBASE_OPCODE_DONE
    )

    actions = DI.rebase_actions(bytes, :segments => [segment(0, 0x100)])

    assert_equal [0, 0, 2], actions.map(&:source_offset)
  end

  def test_rebase_segment_overflow
    bytes = stream(
      DI::REBASE_OPCODE_SET_TYPE_IMM | DI::REBASE_TYPE_POINTER,
      DI::REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB,
      uleb(0),
      DI::REBASE_OPCODE_DO_REBASE_IMM_TIMES | 3,
      DI::REBASE_OPCODE_DONE
    )

    # vmsize 0x10 fits exactly two 8-byte fixups; the third overflows.
    assert_raises(MachO::DyldInfoError) do
      DI.rebase_actions(bytes, :segments => [segment(0x1000, 0x10)])
    end
  end

  def test_rebase_segment_index_out_of_range
    bytes = stream(
      DI::REBASE_OPCODE_SET_TYPE_IMM | DI::REBASE_TYPE_POINTER,
      DI::REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | 1,
      uleb(0),
      DI::REBASE_OPCODE_DONE
    )

    assert_raises(MachO::DyldInfoError) do
      DI.rebase_actions(bytes, :segments => [segment(0x1000, 0x100)])
    end
  end

  def test_rebase_requires_type
    bytes = stream(
      DI::REBASE_OPCODE_DO_REBASE_IMM_TIMES | 1,
      DI::REBASE_OPCODE_DONE
    )

    assert_raises(MachO::DyldInfoError) { DI.rebase_actions(bytes) }
  end

  def test_rebase_done_terminates_stream
    bytes = stream(
      DI::REBASE_OPCODE_SET_TYPE_IMM | DI::REBASE_TYPE_POINTER,
      DI::REBASE_OPCODE_DO_REBASE_IMM_TIMES | 1,
      DI::REBASE_OPCODE_DONE,
      DI::REBASE_OPCODE_DO_REBASE_IMM_TIMES | 5
    )

    assert_equal 1, DI.rebase_actions(bytes).size
  end

  def test_rebase_unknown_opcode
    assert_raises(MachO::DyldInfoError) { DI.rebase_actions("\xF0") }
  end

  def test_rebase_truncated_uleb
    bytes = stream(
      DI::REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB,
      "\x80"
    )

    assert_raises(MachO::DyldInfoError) { DI.rebase_actions(bytes) }
  end

  def bind_stream(ordinal_opcode, name)
    stream(
      ordinal_opcode,
      DI::BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | DI::BIND_SYMBOL_FLAGS_WEAK_IMPORT,
      name, "\x00",
      DI::BIND_OPCODE_SET_TYPE_IMM | DI::BIND_TYPE_POINTER,
      DI::BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB,
      uleb(0x18),
      DI::BIND_OPCODE_DO_BIND,
      DI::BIND_OPCODE_DONE
    )
  end

  def test_bind_basic
    stream = bind_stream(DI::BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | 2, "_foo")

    actions = DI.bind_actions(stream, :segments => [segment(0x2000, 0x100)])

    assert_equal 1, actions.size
    action = actions.first
    assert_equal 0, action.source_offset
    assert_equal 0x18, action.segment_offset
    assert_equal 0x2018, action.address
    assert_equal DI::BIND_TYPE_POINTER, action.type
    assert_equal 2, action.library_ordinal
    assert_kind_of Integer, action.library_ordinal
    refute action.special_ordinal?
    assert_equal "_foo", action.symbol_name
    assert_equal DI::BIND_SYMBOL_FLAGS_WEAK_IMPORT, action.symbol_flags
    assert_equal 0, action.addend
  end

  def test_bind_special_ordinals_are_not_table_indices
    {
      0x0 => :self,
      0xF => :main_executable,
      0xE => :flat_lookup,
    }.each do |immediate, expected|
      stream = bind_stream(DI::BIND_OPCODE_SET_DYLIB_SPECIAL_IMM | immediate, "_foo")
      action = DI.bind_actions(stream).first

      assert_equal expected, action.library_ordinal
      assert_kind_of Symbol, action.library_ordinal
      assert action.special_ordinal?
    end
  end

  def test_bind_unknown_special_ordinal
    stream = bind_stream(DI::BIND_OPCODE_SET_DYLIB_SPECIAL_IMM | 0xD, "_foo")

    assert_raises(MachO::DyldInfoError) { DI.bind_actions(stream) }
  end

  def test_bind_addend_sleb
    bytes = stream(
      DI::BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM,
      "_foo", "\x00",
      DI::BIND_OPCODE_SET_TYPE_IMM | DI::BIND_TYPE_POINTER,
      DI::BIND_OPCODE_SET_ADDEND_SLEB,
      sleb(-5),
      DI::BIND_OPCODE_DO_BIND,
      DI::BIND_OPCODE_DONE
    )

    assert_equal(-5, DI.bind_actions(bytes).first.addend)
  end

  def test_bind_requires_symbol_name
    bytes = stream(
      DI::BIND_OPCODE_SET_TYPE_IMM | DI::BIND_TYPE_POINTER,
      DI::BIND_OPCODE_DO_BIND,
      DI::BIND_OPCODE_DONE
    )

    assert_raises(MachO::DyldInfoError) { DI.bind_actions(bytes) }
  end

  def test_bind_done_terminates_non_lazy_stream
    record = bind_stream(DI::BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | 1, "_foo")
    bytes = record + record

    assert_equal 1, DI.bind_actions(bytes, :kind => :bind).size
    assert_equal 1, DI.bind_actions(bytes, :kind => :weak_bind).size
  end

  def test_lazy_bind_done_does_not_end_stream
    record_one = stream(
      DI::BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM,
      "_a", "\x00",
      DI::BIND_OPCODE_DO_BIND,
      DI::BIND_OPCODE_DONE
    )
    record_two = stream(
      DI::BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM,
      "_b", "\x00",
      DI::BIND_OPCODE_DO_BIND,
      DI::BIND_OPCODE_DONE
    )

    actions = DI.bind_actions(record_one + record_two, :kind => :lazy_bind)

    assert_equal %w[_a _b], actions.map(&:symbol_name)
    assert_equal 0, actions[0].source_offset
    assert_equal record_one.bytesize, actions[1].source_offset
    # state is reset between records: both bind as pointers for dylib :self
    assert_equal [DI::BIND_TYPE_POINTER, DI::BIND_TYPE_POINTER], actions.map(&:type)
    assert_equal %i[self self], actions.map(&:library_ordinal)
  end

  def test_bind_times_skipping
    bytes = stream(
      DI::BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM,
      "_foo", "\x00",
      DI::BIND_OPCODE_SET_TYPE_IMM | DI::BIND_TYPE_POINTER,
      DI::BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB,
      uleb(0x8),
      DI::BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB,
      uleb(2),
      uleb(2),
      DI::BIND_OPCODE_DONE
    )

    actions = DI.bind_actions(bytes, :segments => [segment(0, 0x100)])

    assert_equal [0x8, 0x8 + 2 + 8], actions.map(&:segment_offset)
  end

  def test_bind_invalid_kind
    assert_raises(ArgumentError) { DI.bind_actions("", :kind => :bogus) }
  end

  def test_actions_for_macho_file
    macho = MachO::MachOFile.new(fixture(:i386, "hello.bin"))
    actions = DI.actions_for(macho)

    assert_equal %i[rebase bind weak_bind lazy_bind], actions.keys
    actions.each_value { |list| assert_kind_of Array, list }

    segments = macho.segments
    actions[:rebase].each do |action|
      segment = segments[action.segment_index]
      assert_operator action.address, :>=, segment.vmaddr
      assert_operator action.address, :<, segment.vmaddr + segment.vmsize
    end

    lazy = actions[:lazy_bind]
    refute_empty lazy
    assert lazy.all? { |action| action.symbol_name.start_with?("_") }
    assert lazy.none?(&:special_ordinal?)
  end

  def test_actions_for_returns_nil_without_dyld_info
    macho = MachO::MachOFile.new(fixture(:i386, "hello.o"))

    assert_nil DI.actions_for(macho)
  end
end
