# frozen_string_literal: true

require_relative "helpers"

class DyldInfoTest < Minitest::Test
  include MachO::DyldInfo

  SEGMENTS = [
    { :vmaddr => 0x100000000, :vmsize => 0x100000 },
    { :vmaddr => 0x100100000, :vmsize => 0x2000 },
  ].freeze

  def interpreter(pointer_size: 8, segments: SEGMENTS)
    MachO::DyldInfo::Interpreter.new(segments, :pointer_size => pointer_size)
  end

  def stream(*bytes)
    bytes.pack("C*")
  end

  def test_rebase_pointer_actions_preserve_source_offsets
    # set type pointer; set seg 0 offset 0x20; rebase 2 times; done
    bytes = stream(0x11, 0x20, 0x20, 0x52, 0x00)
    actions = interpreter.rebase_actions(bytes)

    assert_equal 2, actions.size
    assert_equal [REBASE_TYPE_POINTER, REBASE_TYPE_POINTER], actions.map(&:type)
    assert_equal [0x20, 0x28], actions.map(&:seg_offset)
    assert_equal [0x100000020, 0x100000028], actions.map(&:vmaddr)
    # both actions originate from the DO_REBASE_IMM_TIMES opcode at offset 3
    assert_equal [3, 3], actions.map(&:offset)
  end

  def test_rebase_uleb128_multibyte
    # set type pointer; set seg 0 offset 0; add 624485 (0xE5 0x8E 0x26);
    # rebase 1 time; done
    bytes = stream(0x11, 0x20, 0x00, 0x30, 0xE5, 0x8E, 0x26, 0x51, 0x00)
    actions = interpreter.rebase_actions(bytes)

    assert_equal 1, actions.size
    assert_equal 624_485, actions.first.seg_offset
    assert_equal 0x100000000 + 624_485, actions.first.vmaddr
    assert_equal 7, actions.first.offset
  end

  def test_rebase_uleb_times_skipping_uleb
    # set type pointer; set seg 1 offset 0x10; rebase 3 times skipping 4; done
    bytes = stream(0x11, 0x21, 0x10, 0x80, 0x03, 0x04, 0x00)
    actions = interpreter.rebase_actions(bytes)

    assert_equal 3, actions.size
    assert_equal [1, 1, 1], actions.map(&:seg_index)
    assert_equal [0x10, 0x1C, 0x28], actions.map(&:seg_offset)
    assert_equal [0x100100010, 0x10010001C, 0x100100028], actions.map(&:vmaddr)
    assert_equal [3, 3, 3], actions.map(&:offset)
  end

  def test_rebase_add_addr_imm_scaled_uses_pointer_size
    # set type pointer; set seg 0 offset 0; add 3 * pointer_size; rebase once
    bytes = stream(0x11, 0x20, 0x00, 0x43, 0x51, 0x00)

    assert_equal 0x18, interpreter(:pointer_size => 8).rebase_actions(bytes).first.seg_offset
    assert_equal 0x0C, interpreter(:pointer_size => 4).rebase_actions(bytes).first.seg_offset
  end

  def test_rebase_segment_index_out_of_range
    # set type pointer; set seg 5 offset 0 (only 2 segments known)
    bytes = stream(0x11, 0x25, 0x00, 0x51, 0x00)

    error = assert_raises(MachO::DyldInfoError) { interpreter.rebase_actions(bytes) }
    assert_match(/segment index 5/, error.message)
  end

  def test_rebase_segment_offset_overflow
    segments = [{ :vmaddr => 0x1000, :vmsize => 0x20 }]
    # set type pointer; set seg 0 offset 0x20 (== vmsize); rebase once
    bytes = stream(0x11, 0x20, 0x20, 0x51, 0x00)

    error = assert_raises(MachO::DyldInfoError) do
      interpreter(:segments => segments).rebase_actions(bytes)
    end
    assert_match(/exceeds size 32 of segment 0/, error.message)
  end

  def test_rebase_unknown_opcode_raises
    assert_raises(MachO::DyldInfoError) { interpreter.rebase_actions(stream(0x90)) }
  end

  def test_rebase_without_type_raises
    # set seg 0 offset 0; rebase once (no type was ever set)
    assert_raises(MachO::DyldInfoError) { interpreter.rebase_actions(stream(0x20, 0x00, 0x51)) }
  end

  def test_bind_basic_action
    # ordinal imm 1; symbol weak-import "_puts"; type pointer; addend -2;
    # set seg 1 offset 0x40; bind; done
    bytes = stream(0x11, 0x41) + "_puts\0" + stream(0x51, 0x60, 0x7E, 0x71, 0x40, 0x90, 0x00)
    actions = interpreter.bind_actions(bytes)

    assert_equal 1, actions.size
    action = actions.first
    assert_equal BIND_TYPE_POINTER, action.type
    assert_equal 1, action.dylib_ordinal
    assert_equal "_puts", action.symbol
    assert_equal(-2, action.addend)
    assert_equal BIND_SYMBOL_FLAGS_WEAK_IMPORT, action.flags
    assert_equal 1, action.seg_index
    assert_equal 0x40, action.seg_offset
    assert_equal 0x100100040, action.vmaddr
    assert_equal 13, action.offset
  end

  def test_bind_sleb128_positive_addend
    # symbol "_x"; addend 64 (0xC0 0x00); set seg 0 offset 0; bind; done
    bytes = stream(0x40) + "_x\0" + stream(0x60, 0xC0, 0x00, 0x70, 0x00, 0x90, 0x00)
    actions = interpreter.bind_actions(bytes)

    assert_equal 64, actions.first.addend
  end

  def test_bind_special_dylib_ordinals_are_not_plain_indices
    ordinals = [0x30, 0x3E, 0x3F].map do |special_op|
      # special ordinal op; symbol "_x"; set seg 0 offset 0; bind; done
      bytes = stream(special_op, 0x40) + "_x\0" + stream(0x70, 0x00, 0x90, 0x00)
      interpreter.bind_actions(bytes).first.dylib_ordinal
    end

    assert_equal [
      BIND_SPECIAL_DYLIB_SELF,
      BIND_SPECIAL_DYLIB_FLAT_LOOKUP,
      BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE,
    ], ordinals
    refute_equal 15, ordinals.last
  end

  def test_bind_plain_dylib_ordinals
    # ordinal imm 3; symbol "_x"; set seg 0 offset 0; bind; done
    imm_bytes = stream(0x13, 0x40) + "_x\0" + stream(0x70, 0x00, 0x90, 0x00)
    # ordinal uleb 150 (0x96 0x01); symbol "_x"; set seg 0 offset 0; bind; done
    uleb_bytes = stream(0x20, 0x96, 0x01, 0x40) + "_x\0" + stream(0x70, 0x00, 0x90, 0x00)

    assert_equal 3, interpreter.bind_actions(imm_bytes).first.dylib_ordinal
    assert_equal 150, interpreter.bind_actions(uleb_bytes).first.dylib_ordinal
  end

  def test_lazy_bind_done_ends_record_not_region
    # record 1: symbol "_a"; set seg 0 offset 0; bind; done
    # record 2: symbol "_b"; add 8; bind; done
    bytes = stream(0x40) + "_a\0" + stream(0x70, 0x00, 0x90, 0x00) +
            stream(0x40) + "_b\0" + stream(0x80, 0x08, 0x90, 0x00)

    lazy_actions = interpreter.bind_actions(bytes, :lazy => true)
    assert_equal 2, lazy_actions.size
    assert_equal %w[_a _b], lazy_actions.map(&:symbol)
    assert_equal [0x00, 0x10], lazy_actions.map(&:seg_offset)

    # a non-lazy interpretation stops at the first DONE
    bind_actions = interpreter.bind_actions(bytes)
    assert_equal 1, bind_actions.size
    assert_equal "_a", bind_actions.first.symbol
  end

  def test_bind_uleb_times_skipping_uleb
    # symbol "_x"; set seg 0 offset 0x100 (0x80 0x02); bind 3 times skipping 4; done
    bytes = stream(0x40) + "_x\0" + stream(0x70, 0x80, 0x02, 0xC0, 0x03, 0x04, 0x00)
    actions = interpreter.bind_actions(bytes)

    assert_equal 3, actions.size
    assert_equal [0x100, 0x10C, 0x118], actions.map(&:seg_offset)
    assert_equal [7, 7, 7], actions.map(&:offset)
  end

  def test_bind_add_addr_variants
    # symbol "_x"; set seg 0 offset 0; bind add uleb 0x20; bind add imm 2
    # scaled; done
    bytes = stream(0x40) + "_x\0" + stream(0x70, 0x00, 0xA0, 0x20, 0xB2, 0x00)
    actions = interpreter.bind_actions(bytes)

    assert_equal 2, actions.size
    # first bind at 0, then += 8 (pointer) + 0x20
    # second bind at 0x28, then += 8 + 2 * 8
    assert_equal [0x00, 0x28], actions.map(&:seg_offset)
  end

  def test_bind_threaded_is_unimplemented
    assert_raises(MachO::UnimplementedError) { interpreter.bind_actions(stream(0xD0, 0x00)) }
  end

  def test_bind_unknown_opcode_raises
    assert_raises(MachO::DyldInfoError) { interpreter.bind_actions(stream(0xE0)) }
  end

  def test_bind_without_symbol_raises
    # set seg 0 offset 0; bind (no symbol was ever set)
    assert_raises(MachO::DyldInfoError) { interpreter.bind_actions(stream(0x70, 0x00, 0x90)) }
  end

  def test_bind_segment_index_out_of_range
    # symbol "_x"; set seg 7 offset 0; bind
    bytes = stream(0x40) + "_x\0" + stream(0x77, 0x00, 0x90)

    error = assert_raises(MachO::DyldInfoError) { interpreter.bind_actions(bytes) }
    assert_match(/segment index 7/, error.message)
  end

  def test_bind_segment_offset_overflow
    segments = [{ :vmaddr => 0x1000, :vmsize => 0x08 }]
    # symbol "_x"; set seg 0 offset 0; bind 3 times (third lands past vmsize)
    bytes = stream(0x40) + "_x\0" + stream(0x70, 0x00, 0xC0, 0x03, 0x00, 0x00)

    error = assert_raises(MachO::DyldInfoError) do
      interpreter(:segments => segments).bind_actions(bytes)
    end
    assert_match(/exceeds size 8 of segment 0/, error.message)
  end

  def test_truncated_uleb128_raises
    # set seg 0 offset with an unterminated ULEB128
    assert_raises(MachO::DyldInfoError) { interpreter.rebase_actions(stream(0x11, 0x20, 0x80)) }
  end

  def test_oversized_uleb128_raises
    # 11 continuation bytes exceed a 64-bit value
    bytes = stream(0x11, 0x20) + stream(*([0x80] * 11))
    assert_raises(MachO::DyldInfoError) { interpreter.rebase_actions(bytes) }
  end

  def test_truncated_sleb128_raises
    # symbol "_x"; addend with an unterminated SLEB128
    bytes = stream(0x40) + "_x\0" + stream(0x60, 0x80)
    assert_raises(MachO::DyldInfoError) { interpreter.bind_actions(bytes) }
  end

  def test_unterminated_symbol_raises
    bytes = stream(0x40) + "_x"
    assert_raises(MachO::DyldInfoError) { interpreter.bind_actions(bytes) }
  end

  def test_empty_stream_produces_no_actions
    assert_empty interpreter.rebase_actions("")
    assert_empty interpreter.bind_actions("")
  end

  def test_action_hashes
    bytes = stream(0x11, 0x20, 0x20, 0x51, 0x00)
    rebase_hash = interpreter.rebase_actions(bytes).first.to_h
    assert_equal REBASE_TYPE_POINTER, rebase_hash["type"]
    assert_equal 0x20, rebase_hash["seg_offset"]
    assert_equal 3, rebase_hash["offset"]

    bind_bytes = stream(0x40) + "_x\0" + stream(0x70, 0x00, 0x90, 0x00)
    bind_hash = interpreter.bind_actions(bind_bytes).first.to_h
    assert_equal "_x", bind_hash["symbol"]
    assert_equal BIND_SPECIAL_DYLIB_SELF, bind_hash["dylib_ordinal"]
  end
end
