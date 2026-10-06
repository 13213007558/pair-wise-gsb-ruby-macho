# frozen_string_literal: true

require_relative "helpers"

class RelocationsTest < Minitest::Test
  include Helpers

  # Fixtures used by the integration tests (MH_OBJECT files) are:
  # - test/bin/x86_64/hello.o (existing) and test/bin/x86_64/relocs.o
  # - test/bin/arm64/relocs.o
  # They were produced with clang -c --target=<triple>; the evaluator only
  # reads them, never executes their code or invokes a linker.

  # Assembles the two raw relocation_info words for an entry.
  def reloc_word(address:, type:, length:, pcrel:, extern:, symbol:, addend_raw: false)
    if addend_raw
      info = (0xf << 28) | (symbol & 0x00ffffff)
    else
      info = (type << 28) | (length << 25) | (pcrel ? 1 << 24 : 0) |
             (extern ? 1 << 27 : 0) | (symbol & 0x00ffffff)
    end
    [address, info]
  end

  def x86_entry(**kwargs)
    MachO::Relocations::RelocationEntry.coerce(
      reloc_word(**kwargs)
    )
  end

  def arm64_entry(addend: false, **kwargs)
    MachO::Relocations::RelocationEntry.coerce(
      reloc_word(:addend_raw => addend, **kwargs), :arch => :arm64
    )
  end

  # ---------- raw entry decoding ----------

  def test_from_words_decodes_fields
    entry = x86_entry(:address => 0x10, :type => 2, :length => 2,
                      :pcrel => true, :extern => true, :symbol => 7)

    assert_equal 0x10, entry.address
    assert_equal 2, entry.type
    assert_equal 2, entry.length
    assert entry.pcrel?
    assert entry.external?
    assert_equal 7, entry.symbol
    assert_equal 4, entry.field_size
  end

  def test_from_words_decodes_local_section_ordinal
    entry = x86_entry(:address => 0, :type => 1, :length => 2,
                      :pcrel => true, :extern => false, :symbol => 2)

    refute entry.external?
    assert_equal 2, entry.symbol
  end

  def test_from_words_decodes_arm64_addend_as_signed_24bit
    positive = arm64_entry(:addend => true, :address => 4, :type => 0xf,
                           :length => 0, :pcrel => false, :extern => false, :symbol => 0x28)
    negative = arm64_entry(:addend => true, :address => 4, :type => 0xf,
                           :length => 0, :pcrel => false, :extern => false,
                           :symbol => 0x1000000 - 8)

    assert_equal 10, positive.type
    assert_equal 0x28, positive.symbol
    assert_equal(-8, negative.symbol)
    refute positive.pcrel?
    refute positive.external?
  end

  def test_addend_nibble_is_architecture_specific
    # raw r_type 0xf is ARM64_RELOC_ADDEND only on arm64; on x86_64 it is an
    # unknown reloc number and must not be silently treated as an ADDEND
    arm = MachO::Relocations::RelocationEntry.from_words(0, (0xf << 28), nil, :arch => :arm64)
    x86 = MachO::Relocations::RelocationEntry.from_words(0, (0xf << 28), nil, :arch => :x86_64)

    assert_equal 10, arm.type
    assert_equal 15, x86.type
  end

  def test_from_words_rejects_scattered_entries
    error = assert_raises(MachO::RelocationError) do
      MachO::Relocations::RelocationEntry.from_words(0x80000000, 0)
    end

    assert_match(/scattered/, error.message)
  end

  def test_from_hash_accepts_symbolic_types
    entry = MachO::Relocations::RelocationEntry.from_hash(
      "address" => 0,
      "type" => :ARM64_RELOC_PAGE21,
      "length" => 2,
      "pcrel" => true,
      "external" => true,
      "symbol" => 3,
    )

    assert_equal 3, entry.type
    assert entry.pcrel?
    assert entry.external?
  end

  # ---------- x86_64: UNSIGNED ----------

  def test_x86_64_unsigned_external
    bytes = "\x08" + "\x00" * 15
    entry = x86_entry(:address => 0, :type => 0, :length => 3,
                      :pcrel => false, :extern => true, :symbol => 4)

    out, results = MachO::Relocations::RelocationEvaluator.new(
      :x86_64, bytes, [entry], :symbol_addresses => { 4 => 0x1000 }
    ).evaluate

    assert_equal 0x1008, out.byteslice(0, 8).unpack1("Q<")
    result = results.first
    assert_equal :X86_64_RELOC_UNSIGNED, result.type
    assert_equal 8, result.addend
    assert_equal 0x1000, result.target
    assert_equal 8, result.size
  end

  def test_x86_64_unsigned_local_uses_section_base
    bytes = "\x04" + "\x00" * 7
    entry = x86_entry(:address => 0, :type => 0, :length => 3,
                      :pcrel => false, :extern => false, :symbol => 2)

    out, = MachO::Relocations::RelocationEvaluator.new(
      :x86_64, bytes, [entry], :section_addresses => { 2 => 0x5000 },
      :section_ordinal => 1
    ).evaluate

    assert_equal 0x5004, out.byteslice(0, 8).unpack1("Q<")
  end

  def test_x86_64_unsigned_16bit_field
    bytes = "\x02\x00\x00\x00"
    entry = x86_entry(:address => 0, :type => 0, :length => 1,
                      :pcrel => false, :extern => true, :symbol => 4)

    out, results = MachO::Relocations::RelocationEvaluator.new(
      :x86_64, bytes, [entry], :symbol_addresses => { 4 => 0x100 }
    ).evaluate

    assert_equal 0x102, out.byteslice(0, 2).unpack1("S<")
    assert_equal 2, results.first.size
  end

  # ---------- x86_64: SIGNED / BRANCH ----------

  def test_x86_64_signed_is_pc_relative
    bytes = "\x90" * 11 + "\x14\x00\x00\x00"
    entry = x86_entry(:address => 11, :type => 1, :length => 2,
                      :pcrel => true, :extern => false, :symbol => 2)

    out, results = MachO::Relocations::RelocationEvaluator.new(
      :x86_64, bytes, [entry],
      :section_addresses => { 1 => 0x1000, 2 => 0x1023 },
      :section_origins => { 1 => 0, 2 => 0x23 },
      :section_ordinal => 1
    ).evaluate

    # local: A + (S - S_origin) - (own_final - own_origin) - size
    assert_equal 0x14 + (0x1023 - 0x23) - (0x1000 - 0) - 4,
                 out.byteslice(11, 4).unpack1("l<")
    assert_equal 0x1023, results.first.target
  end

  def test_x86_64_branch_external
    bytes = "\xe8" + "\x00" * 4 + "\xcc"
    entry = x86_entry(:address => 1, :type => 2, :length => 2,
                      :pcrel => true, :extern => true, :symbol => 0)

    out, results = MachO::Relocations::RelocationEvaluator.new(
      :x86_64, bytes, [entry],
      :symbol_addresses => { 0 => 0x100f20 },
      :section_addresses => { 1 => 0x100000 },
      :section_ordinal => 1
    ).evaluate

    assert_equal 0x100f20 - (0x100000 + 1 + 4), out.byteslice(1, 4).unpack1("l<")
    assert_equal :X86_64_RELOC_BRANCH, results.first.type
  end

  def test_x86_64_signed_local_cross_section
    # e8 + field holding the object displacement from the field start (-13)
    bytes = "\xe8".b + [-13].pack("l<")
    entry = x86_entry(:address => 1, :type => 2, :length => 2,
                      :pcrel => true, :extern => false, :symbol => 2)

    out, = MachO::Relocations::RelocationEvaluator.new(
      :x86_64, bytes, [entry],
      :section_addresses => { 2 => 0x2000, 3 => 0x3000 },
      :section_origins => { 2 => 0x0, 3 => 0x8 },
      :section_ordinal => 3
    ).evaluate

    # A + (S_final - S_origin) - (own_final - own_origin) - size
    expected = -13 + (0x2000 - 0x0) - (0x3000 - 0x8) - 4
    assert_equal expected, out.byteslice(1, 4).unpack1("l<")
  end

  def test_x86_64_signed_requires_pcrel_and_long
    bad_flags = x86_entry(:address => 0, :type => 1, :length => 2,
                          :pcrel => false, :extern => true, :symbol => 0)

    assert_raises(MachO::RelocationError) do
      MachO::Relocations::RelocationEvaluator.new(
        :x86_64, "\x00" * 8, [bad_flags], :symbol_addresses => { 0 => 0 }
      ).evaluate
    end
  end

  # ---------- x86_64: SUBTRACTOR pairs ----------

  def test_x86_64_subtractor_pair_external
    bytes = [7].pack("q<") + "\x00" * 8
    sub = x86_entry(:address => 0, :type => 5, :length => 3,
                    :pcrel => false, :extern => true, :symbol => 6)
    uns = x86_entry(:address => 0, :type => 0, :length => 3,
                    :pcrel => false, :extern => true, :symbol => 5)

    out, results = MachO::Relocations::RelocationEvaluator.new(
      :x86_64, bytes, [sub, uns],
      :symbol_addresses => { 5 => 0x2000, 6 => 0x1000 }
    ).evaluate

    # field 7 + (0x2000 - 0) - (0x1000 - 0) = 4103
    assert_equal 4103, out.byteslice(0, 8).unpack1("q<")
    assert_equal :X86_64_RELOC_SUBTRACTOR, results[0].type
    assert_equal :X86_64_RELOC_UNSIGNED, results[1].type
    assert_equal 1, results[0].paired_with
    assert_equal 0, results[1].paired_with
    assert_equal 4103, results[0].new_value
  end

  def test_x86_64_subtractor_pair_validated_before_writes
    bytes = [7].pack("q<") + "\x00" * 8
    original = bytes.dup
    sub = x86_entry(:address => 0, :type => 5, :length => 3,
                    :pcrel => false, :extern => true, :symbol => 6)
    uns = x86_entry(:address => 4, :type => 0, :length => 3,
                    :pcrel => false, :extern => true, :symbol => 5)

    assert_raises(MachO::RelocationError) do
      MachO::Relocations::RelocationEvaluator.new(
        :x86_64, bytes, [sub, uns],
        :symbol_addresses => { 5 => 0x2000, 6 => 0x1000 }
      ).evaluate
    end

    assert_equal original, bytes
  end

  def test_x86_64_unsupported_types_are_rejected
    got = x86_entry(:address => 0, :type => 4, :length => 2,
                    :pcrel => true, :extern => true, :symbol => 0)

    error = assert_raises(MachO::UnsupportedRelocationTypeError) do
      MachO::Relocations::RelocationEvaluator.new(
        :x86_64, "\x00" * 8, [got], :symbol_addresses => { 0 => 0 }
      ).evaluate
    end

    assert_match(/X86_64_RELOC_GOT/, error.message)
  end

  # ---------- arm64: BRANCH26 ----------

  def arm64_evaluator(entries, bytes = nil, symbols = { 1 => 0 }, sections = {}, ordinal = nil)
    bytes ||= "\x00" * 64
    MachO::Relocations::RelocationEvaluator.new(
      :arm64, bytes, entries,
      :symbol_addresses => symbols,
      :section_addresses => sections,
      :section_ordinal => ordinal
    )
  end

  def test_arm64_branch26_external
    # b #0 -> 0x14000000
    bytes = [0x14000000].pack("L<") + "\x00" * 60
    entry = arm64_entry(:address => 0, :type => 2, :length => 2,
                        :pcrel => true, :extern => true, :symbol => 1)

    out, results = arm64_evaluator(
      [entry], bytes, { 1 => 40 }, { 1 => 0 }, 1
    ).evaluate

    # (40 - 0) / 4 = 10
    assert_equal 0x1400000a, out.byteslice(0, 4).unpack1("L<")
    assert_equal 40, results.first.detail["displacement"]
    assert_equal 10, results.first.detail["imm26"]
  end

  def test_arm64_branch26_negative_with_addend_pair
    # bl #0 -> 0x94000000
    bytes = [0x94000000].pack("L<") + "\x00" * 60
    addend = arm64_entry(:addend => true, :address => 0, :type => 0xf,
                         :length => 0, :pcrel => false, :extern => false,
                         :symbol => 0x1000000 - 8)
    branch = arm64_entry(:address => 0, :type => 2, :length => 2,
                         :pcrel => true, :extern => true, :symbol => 1)

    out, results = arm64_evaluator(
      [addend, branch], bytes, { 1 => 0x20 }, { 1 => 0 }, 1
    ).evaluate

    # (0x20 - 8 - 0) / 4 = 24 / 4 = 6, link bit preserved
    assert_equal 0x94000006, out.byteslice(0, 4).unpack1("L<")
    assert_equal :ARM64_RELOC_ADDEND, results[0].type
    assert_equal(-8, results[0].addend)
    assert_equal 1, results[0].paired_with
    assert_equal 0, results[1].paired_with
  end

  def test_arm64_branch26_overflow
    bytes = [0x14000000].pack("L<") + "\x00" * 60
    entry = arm64_entry(:address => 0, :type => 2, :length => 2,
                        :pcrel => true, :extern => true, :symbol => 1)

    assert_raises(MachO::RelocationOverflowError) do
      arm64_evaluator([entry], bytes, { 1 => 0x10000000 }, { 1 => 0 }, 1).evaluate
    end
  end

  def test_arm64_branch26_unaligned_displacement
    bytes = [0x14000000].pack("L<") + "\x00" * 60
    entry = arm64_entry(:address => 0, :type => 2, :length => 2,
                        :pcrel => true, :extern => true, :symbol => 1)

    assert_raises(MachO::RelocationOverflowError) do
      arm64_evaluator([entry], bytes, { 1 => 1 }, { 1 => 0 }, 1).evaluate
    end
  end

  def test_arm64_branch26_rejects_non_branch_instruction
    bytes = [0xd503201f].pack("L<") + "\x00" * 60 # nop
    entry = arm64_entry(:address => 0, :type => 2, :length => 2,
                        :pcrel => true, :extern => true, :symbol => 1)

    assert_raises(MachO::RelocationError) do
      arm64_evaluator([entry], bytes, { 1 => 0 }, { 1 => 0 }, 1).evaluate
    end
  end

  # ---------- arm64: PAGE21 / PAGEOFF12 ----------

  def test_arm64_page21_and_pageoff12_add
    # adrp x0, 0 ; add x0, x0, #0
    bytes = [0x90000000, 0x91000000].pack("L<L<") + "\x00" * 56
    page = arm64_entry(:address => 0, :type => 3, :length => 2,
                       :pcrel => true, :extern => true, :symbol => 1)
    off = arm64_entry(:address => 4, :type => 4, :length => 2,
                      :pcrel => false, :extern => true, :symbol => 1)

    target = 0x1234567
    out, = arm64_evaluator([page, off], bytes, { 1 => target }, { 1 => 0 }, 1).evaluate

    adrp = out.byteslice(0, 4).unpack1("L<")
    add = out.byteslice(4, 4).unpack1("L<")
    immlo = (adrp >> 29) & 3
    immhi = (adrp >> 5) & 0x7ffff
    imm21 = (immhi << 2) | immlo
    imm21 -= (1 << 21) if imm21 >= (1 << 20)

    assert_equal((target & ~0xfff) >> 12, imm21)
    assert_equal target & 0xfff, (add >> 10) & 0xfff
  end

  def test_arm64_pageoff12_load_store_scaling
    # ldr x2, [x1, #0] -> 0xf9400022 (scale 8); ldrb w2 -> 0x39400022 (scale 1)
    bytes = [0xf9400022, 0x39400022].pack("L<L<") + "\x00" * 56
    ldr_x = arm64_entry(:address => 0, :type => 4, :length => 2,
                        :pcrel => false, :extern => true, :symbol => 1)
    ldr_b = arm64_entry(:address => 4, :type => 4, :length => 2,
                        :pcrel => false, :extern => true, :symbol => 2)

    out, = arm64_evaluator(
      [ldr_x, ldr_b], bytes, { 1 => 0x1040, 2 => 0x2001 }, { 1 => 0 }, 1
    ).evaluate

    # 0x1040 / 8 = 8 for the 64-bit load; 0x2001 is unscaled for the byte load
    ldr_imm = (out.byteslice(0, 4).unpack1("L<") >> 10) & 0xfff
    ldrb_imm = (out.byteslice(4, 4).unpack1("L<") >> 10) & 0xfff
    assert_equal 8, ldr_imm
    assert_equal 1, ldrb_imm
  end

  def test_arm64_page21_overflow
    bytes = [0x90000000].pack("L<") + "\x00" * 60
    page = arm64_entry(:address => 0, :type => 3, :length => 2,
                       :pcrel => true, :extern => true, :symbol => 1)

    assert_raises(MachO::RelocationOverflowError) do
      arm64_evaluator([page], bytes, { 1 => 0x1000000000 }, { 1 => 0 }, 1).evaluate
    end
  end

  def test_arm64_pageoff12_addend_pair_is_invalid
    bytes = [0x91000000].pack("L<") + "\x00" * 60
    addend = arm64_entry(:addend => true, :address => 0, :type => 0xf,
                         :length => 0, :pcrel => false, :extern => false, :symbol => 4)
    off = arm64_entry(:address => 0, :type => 4, :length => 2,
                      :pcrel => false, :extern => true, :symbol => 1)

    assert_raises(MachO::RelocationError) do
      arm64_evaluator([addend, off], bytes, { 1 => 0 }, { 1 => 0 }, 1).evaluate
    end
  end

  # ---------- arm64: UNSIGNED ----------

  def test_arm64_unsigned_external
    bytes = "\x00" * 8
    entry = arm64_entry(:address => 0, :type => 0, :length => 3,
                        :pcrel => false, :extern => true, :symbol => 1)

    out, = arm64_evaluator([entry], bytes, { 1 => 0xdeadbeef }, {}, nil).evaluate

    assert_equal 0xdeadbeef, out.byteslice(0, 8).unpack1("Q<")
  end

  def test_arm64_unsigned_with_addend_pair
    bytes = "\x00" * 8
    addend = arm64_entry(:addend => true, :address => 0, :type => 0xf,
                         :length => 0, :pcrel => false, :extern => false, :symbol => 12)
    unsigned = arm64_entry(:address => 0, :type => 0, :length => 3,
                           :pcrel => false, :extern => true, :symbol => 1)

    out, = arm64_evaluator([addend, unsigned], bytes, { 1 => 0x1000 }, {}, nil).evaluate

    assert_equal 0x100c, out.byteslice(0, 8).unpack1("Q<")
  end

  def test_arm64_unsigned_32bit_overflow
    bytes = "\x00" * 8
    entry = arm64_entry(:address => 0, :type => 0, :length => 2,
                        :pcrel => false, :extern => true, :symbol => 1)

    assert_raises(MachO::RelocationOverflowError) do
      arm64_evaluator([entry], bytes, { 1 => 0x1_0000_0000 }, {}, nil).evaluate
    end
  end

  def test_arm64_unsupported_types_are_rejected
    tlv = arm64_entry(:address => 0, :type => 8, :length => 2,
                      :pcrel => true, :extern => true, :symbol => 1)

    error = assert_raises(MachO::UnsupportedRelocationTypeError) do
      arm64_evaluator([tlv], "\x00" * 8, { 1 => 0 }, {}, 1).evaluate
    end

    assert_match(/ARM64_RELOC_TLVP_LOAD_PAGE21/, error.message)
  end

  def test_arm64_subtractor_is_unsupported
    sub = arm64_entry(:address => 0, :type => 1, :length => 3,
                      :pcrel => false, :extern => true, :symbol => 1)

    assert_raises(MachO::UnsupportedRelocationTypeError) do
      arm64_evaluator([sub], "\x00" * 8, { 1 => 0 }, {}, nil).evaluate
    end
  end

  def test_dangling_addend_is_rejected
    addend = arm64_entry(:addend => true, :address => 0, :type => 0xf,
                         :length => 0, :pcrel => false, :extern => false, :symbol => 4)

    assert_raises(MachO::RelocationError) do
      arm64_evaluator([addend], "\x00" * 8, { 1 => 0 }, {}, 1).evaluate
    end
  end

  # ---------- validation and error handling ----------

  def test_missing_external_symbol
    entry = x86_entry(:address => 0, :type => 0, :length => 3,
                      :pcrel => false, :extern => true, :symbol => 99)

    assert_raises(MachO::RelocationSymbolError) do
      MachO::Relocations::RelocationEvaluator.new(:x86_64, "\x00" * 8, [entry]).evaluate
    end
  end

  def test_missing_section_base
    entry = x86_entry(:address => 0, :type => 0, :length => 3,
                      :pcrel => false, :extern => false, :symbol => 4)

    assert_raises(MachO::RelocationSectionError) do
      MachO::Relocations::RelocationEvaluator.new(:x86_64, "\x00" * 8, [entry]).evaluate
    end
  end

  def test_field_outside_section_bounds
    entry = x86_entry(:address => 6, :type => 0, :length => 3,
                      :pcrel => false, :extern => true, :symbol => 0)

    error = assert_raises(MachO::RelocationError) do
      MachO::Relocations::RelocationEvaluator.new(
        :x86_64, "\x00" * 8, [entry], :symbol_addresses => { 0 => 0 }
      ).evaluate
    end

    assert_match(/outside the section/, error.message)
  end

  def test_invalid_architecture
    entry = x86_entry(:address => 0, :type => 0, :length => 3,
                      :pcrel => false, :extern => true, :symbol => 0)

    assert_raises(MachO::RelocationError) do
      MachO::Relocations::RelocationEvaluator.new(:ppc, "\x00" * 8, [entry])
    end
  end

  def test_all_entries_validated_before_any_write
    bytes = "\x00" * 16
    good = x86_entry(:address => 0, :type => 0, :length => 3,
                     :pcrel => false, :extern => true, :symbol => 0)
    bad = x86_entry(:address => 8, :type => 0, :length => 2,
                    :pcrel => false, :extern => true, :symbol => 1)
    snapshot = bytes.dup

    assert_raises(MachO::RelocationOverflowError) do
      MachO::Relocations::RelocationEvaluator.new(
        :x86_64, bytes, [good, bad],
        :symbol_addresses => { 0 => 0x100, 1 => 0x1_0000_0000 }
      ).evaluate
    end

    assert_equal snapshot, bytes
  end

  def test_input_bytes_are_not_mutated_on_success
    bytes = "\x00" * 8
    entry = x86_entry(:address => 0, :type => 0, :length => 3,
                      :pcrel => false, :extern => true, :symbol => 0)

    out, = MachO::Relocations::RelocationEvaluator.new(
      :x86_64, bytes, [entry], :symbol_addresses => { 0 => 0x42 }
    ).evaluate

    refute_equal out, bytes
    assert_equal "\x00" * 8, bytes
  end

  def test_parse_relocation_words_rejects_truncated_tables
    error = assert_raises(MachO::RelocationError) do
      MachO::Relocations.parse_relocation_words("\x00" * 9, 0, 2)
    end

    assert_match(/relocation table/, error.message)
  end

  def test_result_to_h
    entry = x86_entry(:address => 0, :type => 0, :length => 3,
                      :pcrel => false, :extern => true, :symbol => 0)

    _, results = MachO::Relocations::RelocationEvaluator.new(
      :x86_64, "\x00" * 8, [entry], :symbol_addresses => { 0 => 0x42 }
    ).evaluate

    hash = results.first.to_h
    assert_equal :X86_64_RELOC_UNSIGNED, hash["type"]
    assert_equal 0x42, hash["new_value"]
  end

  # ---------- integration with real MH_OBJECT fixtures ----------

  def test_evaluate_section_arm64_fixture
    file = MachO::MachOFile.new_from_bin(File.binread(fixture(:arm64, "relocs.o")))
    section = file.segments.flat_map(&:sections).find do |sect|
      sect.sectname.strip == "__text"
    end

    bytes, results = MachO::Relocations.evaluate_section(
      file, section,
      :symbol_addresses => { 1 => 0x40, 3 => 0x40 },
      :section_addresses => { 1 => 0x0, 2 => 0x40 },
    )

    assert_equal 10, results.length
    types = results.map(&:type)
    assert_includes types, :ARM64_RELOC_BRANCH26
    assert_includes types, :ARM64_RELOC_PAGE21
    assert_includes types, :ARM64_RELOC_PAGEOFF12
    assert_includes types, :ARM64_RELOC_ADDEND

    # b at 0x0 targeting 0x40: imm26 = 0x40 / 4 = 16
    assert_equal 0x14000010, bytes.byteslice(0, 4).unpack1("L<")
    # bl _ext+8 at 0x4: (0x40 + 8 - 4) / 4 = 17
    assert_equal 0x94000011, bytes.byteslice(4, 4).unpack1("L<")
    # add x0, x0, #0x40 (PAGEOFF12 add immediate)
    assert_equal 0x91010000, bytes.byteslice(0xc, 4).unpack1("L<")
    # ldr x2, [x1, #0x40] -> imm12 = 0x40 / 8 = 8
    assert_equal 0xf9402022, bytes.byteslice(0x14, 4).unpack1("L<")
    # local b Ll at 0x18 (external relocation to Ll at 0x40): (0x40 - 0x18)/4
    assert_equal 10, (bytes.byteslice(0x18, 4).unpack1("L<") & 0x03ffffff)
    # local b Ll-8 at 0x1c: (0x40 - 8 - 0x1c) / 4
    assert_equal 7, (bytes.byteslice(0x1c, 4).unpack1("L<") & 0x03ffffff)
  end

  def test_evaluate_section_x86_64_signed_and_branch_fixture
    file = MachO::MachOFile.new_from_bin(File.binread(fixture(:x86_64, "hello.o")))
    section = file.segments.flat_map(&:sections).find do |sect|
      sect.sectname.strip == "__text"
    end

    bytes, results = MachO::Relocations.evaluate_section(
      file, section,
      :symbol_addresses => { 1 => 0x1f20 },
      :section_addresses => { 1 => 0x1000, 2 => 0x1023, 3 => 0x1038, 4 => 0x1058 },
    )

    assert_equal %i[X86_64_RELOC_BRANCH X86_64_RELOC_SIGNED], results.map(&:type)

    # leaq: the local field is measured from the field start, so subtract
    # the 4-byte field width to reach the post-instruction PC
    assert_equal 16, bytes.byteslice(0xb, 4).unpack1("l<")
    # call _printf: S - P with P at the end of the call instruction
    assert_equal 0x1f20 - (0x1000 + 0x12 + 4),
                 bytes.byteslice(0x12, 4).unpack1("l<")
  end

  def test_evaluate_section_x86_64_subtractor_fixture
    file = MachO::MachOFile.new_from_bin(File.binread(fixture(:x86_64, "relocs.o")))
    section = file.segments.flat_map(&:sections).find do |sect|
      sect.sectname.strip == "__data"
    end

    bytes, results = MachO::Relocations.evaluate_section(
      file, section,
      :symbol_addresses => { 0 => 0x1000 },
      :section_addresses => { 1 => 0x0, 2 => 0xd },
    )

    # local unsigned at 0x8: section 2 final base (0xd) + field (0x1d)
    assert_equal 0x2a, bytes.byteslice(8, 8).unpack1("Q<")
    # subtractor pair at 0x0: field + (minuend 0x1000 - origin 0) -
    # (subtrahend final 0xd - origin 0xd)
    assert_equal(-0x1d + 0x1000 - (0xd - 0xd), bytes.byteslice(0, 8).unpack1("q<"))
    pair = results.select(&:paired_with)
    assert_equal 2, pair.length
  end

  def test_evaluate_section_rejects_non_objects
    file = MachO.open(fixture(:x86_64, "hello.bin"))
    section = file.segments.flat_map(&:sections).find do |sect|
      sect.sectname.strip == "__text"
    end

    assert_raises(MachO::RelocationError) do
      MachO::Relocations.evaluate_section(file, section)
    end
  end

  def test_scattered_entry_is_rejected_by_the_evaluator
    scattered = [0x80000000, 0x00000000]

    assert_raises(MachO::RelocationError) do
      MachO::Relocations::RelocationEvaluator.new(
        :x86_64, "\x00" * 8, [scattered]
      ).evaluate
    end
  end
end
