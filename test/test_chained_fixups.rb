# frozen_string_literal: true

require_relative "helpers"
require_relative "chained_fixups_fixtures"

class ChainedFixupsTest < Minitest::Test
  Builder = ChainedFixupsFixtures::MachOBuilder

  # ---------------------------------------------------------------- real file

  REFERENCE_DYLIB = ".tmp/ref/libref.dylib"

  def test_real_clang_arm64_dylib
    unless File.file?(REFERENCE_DYLIB)
      skip "build .tmp/ref/libref.dylib to run the end-to-end reference check"
    end

    file = MachO::MachOFile.new(REFERENCE_DYLIB)
    refute_nil file.chained_fixups
    fixups = file.chained_fixups.fixups

    assert_equal 4, fixups.size
    assert_equal [:bind, :rebase, :bind, :bind], fixups.map(&:type)

    bind_foo = fixups[0]
    assert_equal 0x4000, bind_foo.file_offset
    assert_equal 0x4000, bind_foo.runtime_offset
    assert_equal :DYLD_CHAINED_PTR_64_OFFSET, bind_foo.pointer_format
    assert_equal "_external_foo", bind_foo.symbol_name
    assert_equal 1, bind_foo.import.lib_ordinal
    assert_equal "@rpath/libext.dylib", bind_foo.import.dylib

    rebase = fixups[1]
    assert_equal 0x8000, rebase.file_offset
    assert_equal 0x55C, rebase.target_offset
    assert_nil rebase.ordinal

    puts_bind = fixups[2]
    assert_equal "_puts", puts_bind.symbol_name
    assert_equal "/usr/lib/libSystem.B.dylib", puts_bind.import.dylib

    counter = fixups[3]
    assert_equal "_shared_counter", counter.symbol_name
  end

  def test_nil_without_load_command
    file = MachO::MachOFile.new("test/bin/x86_64/libhello.dylib")
    assert_nil file.chained_fixups
  end

  def test_fat_file_exposes_per_slice_fixups
    arm64 = File.binread(".tmp/ref/libref.dylib")
    x86 = File.binread("test/bin/x86_64/libhello.dylib")
    fat = MachO::FatFile.new_from_machos(
      MachO::MachOFile.new_from_bin(x86),
      MachO::MachOFile.new_from_bin(arm64),
    )

    assert_equal 2, fat.chained_fixups.size
    assert_nil fat.chained_fixups[0]
    refute_nil fat.chained_fixups[1]
    assert_equal 4, fat.chained_fixups[1].fixups.size
  end

  # ------------------------------------------------------------- PTR_64(_OFFSET)

  def test_ptr_64_offset_bind_and_rebase
    builder = Builder.new(:pointer_format => 6)
    builder.import("_sym")
    builder.pointer(0, builder.rebase64(:target => 0x1234, :next_step => 1))
    builder.pointer(8, builder.bind64(:ordinal => 0, :addend => 200, :next_step => 0))
    file = builder.build!

    rebase, bind = file.chained_fixups.fixups
    assert_equal :rebase, rebase.type
    assert_equal 0x1234, rebase.target_offset
    assert_equal 0x1234, rebase.target_vmaddr
    assert_equal 0x4000, rebase.file_offset

    assert_equal :bind, bind.type
    assert_equal "_sym", bind.symbol_name
    assert_equal 200, bind.bind_addend
    assert_equal 0x4008, bind.file_offset
  end

  def test_ptr_64_target_is_vmaddr
    builder = Builder.new(:pointer_format => 2)
    # The 44-bit vmaddr target is target36 | (high8 << 36).
    builder.pointer(0, builder.rebase64(:target => 0x4000, :high8 => 0x10))
    file = builder.build!

    fixup = file.chained_fixups.fixups.first
    assert_equal :DYLD_CHAINED_PTR_64, fixup.pointer_format
    assert_equal 0x10000004000, fixup.target_vmaddr
    assert_equal 0x10000004000, fixup.target_offset
  end

  def test_ptr_64_high8_preserved
    builder = Builder.new(:pointer_format => 6)
    raw = builder.rebase64(:target => 0x10, :high8 => 0xAB, :next_step => 0)
    builder.pointer(0, raw)
    file = builder.build!

    fixup = file.chained_fixups.fixups.first
    assert_equal 0xAB, fixup.high8
    assert_equal 0xAB000000010, fixup.target_offset
  end

  # ------------------------------------------------------- ARM64E_USERLAND (9)

  def test_arm64e_userland_non_auth
    builder = Builder.new(:pointer_format => 9)
    builder.import("_fn")
    builder.pointer(0, builder.userland_rebase(:target => 0x4242, :next_step => 1))
    addend = -4
    builder.pointer(8, builder.userland_bind(:ordinal => 0, :addend => addend, :next_step => 0))
    file = builder.build!

    rebase, bind = file.chained_fixups.fixups
    assert_equal :DYLD_CHAINED_PTR_ARM64E_USERLAND, rebase.pointer_format
    refute rebase.authenticated
    assert_equal 0x4242, rebase.target_offset

    refute bind.authenticated
    assert_equal(-4, bind.bind_addend)
    assert_equal "_fn", bind.symbol_name
  end

  def test_arm64e_userland_auth_bind_keeps_pac_fields
    builder = Builder.new(:pointer_format => 9)
    builder.import("_auth_fn")
    raw = builder.userland_auth_bind(
      :ordinal => 0, :diversity => 0x1234, :key => 2, :addr_div => true, :next_step => 0,
    )
    builder.pointer(0, raw)
    file = builder.build!

    fixup = file.chained_fixups.fixups.first
    assert fixup.authenticated
    assert_equal :bind, fixup.type
    assert_equal :DA, fixup.key
    assert_equal 0x1234, fixup.diversity
    assert_equal true, fixup.address_diversified
    assert_equal "_auth_fn", fixup.symbol_name
  end

  def test_arm64e_userland_auth_rebase_keeps_pac_fields
    builder = Builder.new(:pointer_format => 9)
    raw = builder.userland_auth_rebase(
      :target => 0x7000, :diversity => 0x42, :key => 1, :addr_div => false, :next_step => 0,
    )
    builder.pointer(0, raw)
    file = builder.build!

    fixup = file.chained_fixups.fixups.first
    assert fixup.authenticated
    assert_equal :rebase, fixup.type
    assert_equal :IB, fixup.key
    assert_equal 0x42, fixup.diversity
    assert_equal false, fixup.address_diversified
    assert_equal 0x7000, fixup.target_offset
  end

  def test_arm64e_userland_all_pac_keys
    { 0 => :IA, 1 => :IB, 2 => :DA, 3 => :DB }.each do |key_id, key_name|
      builder = Builder.new(:pointer_format => 9)
      raw = builder.userland_auth_rebase(
        :target => 8, :diversity => 0, :key => key_id, :addr_div => false,
      )
      builder.pointer(0, raw)
      fixup = builder.build!.chained_fixups.fixups.first
      assert_equal key_name, fixup.key
    end
  end

  # ------------------------------------------------------------- import formats

  def test_import_format_addend
    builder = Builder.new(:pointer_format => 6, :imports_format => 2)
    builder.import("_sym", :addend => -1234)
    builder.pointer(0, builder.bind64(:ordinal => 0, :next_step => 0))
    file = builder.build!

    imp = file.chained_fixups.imports.first
    assert_equal :DYLD_CHAINED_IMPORT_ADDEND, file.chained_fixups.imports_format
    assert_equal(-1234, imp.addend)
  end

  def test_import_format_addend64
    builder = Builder.new(:pointer_format => 6, :imports_format => 3)
    builder.import("_sym64", :ordinal => 5, :addend => 0x100000001)
    builder.pointer(0, builder.bind64(:ordinal => 0, :next_step => 0))
    file = builder.build!

    imp = file.chained_fixups.imports.first
    assert_equal :DYLD_CHAINED_IMPORT_ADDEND64, file.chained_fixups.imports_format
    assert_equal 5, imp.lib_ordinal
    assert_equal 0x100000001, imp.addend
  end

  def test_weak_import
    builder = Builder.new(:pointer_format => 6)
    builder.import("_weak", :weak => true)
    builder.pointer(0, builder.bind64(:ordinal => 0))
    file = builder.build!

    assert file.chained_fixups.imports.first.weak_import
  end

  def test_zlib_compressed_symbol_pool
    builder = Builder.new(:pointer_format => 6, :compressed_symbols => true)
    builder.import("_compressed_symbol")
    builder.pointer(0, builder.bind64(:ordinal => 0))
    file = builder.build!

    assert_equal "_compressed_symbol", file.chained_fixups.fixups.first.symbol_name
  end

  def test_multiple_imports_share_pool
    builder = Builder.new(:pointer_format => 6)
    builder.import("_a").import("_b")
    builder.pointer(0, builder.bind64(:ordinal => 0, :next_step => 1))
    builder.pointer(8, builder.bind64(:ordinal => 1))
    file = builder.build!

    assert_equal %w[_a _b], file.chained_fixups.fixups.map(&:symbol_name)
  end

  def test_special_negative_ordinal
    builder = Builder.new(:pointer_format => 6)
    builder.import("_flat", :ordinal => 0xFE) # -2 sign-extended
    builder.pointer(0, builder.bind64(:ordinal => 0))
    file = builder.build!

    imp = file.chained_fixups.imports.first
    assert_equal(-2, imp.lib_ordinal)
    assert_equal :BIND_SPECIAL_DYLIB_FLAT_LOOKUP, imp.special_ordinal
    assert_nil imp.dylib
  end

  def test_addend64_negative_ordinal_16bit
    builder = Builder.new(:pointer_format => 6, :imports_format => 3)
    builder.import("_weak", :ordinal => 0xFFFE, :addend => 0) # -2 in 16 bits
    builder.pointer(0, builder.bind64(:ordinal => 0))
    file = builder.build!

    assert_equal(-2, file.chained_fixups.imports.first.lib_ordinal)
  end

  def test_multi_start_page_two_independent_chains
    builder = Builder.new(:pointer_format => 6)
    builder.import("_x").import("_y")
    builder.pointer(16, builder.bind64(:ordinal => 0, :next_step => 1))
    builder.pointer(24, builder.bind64(:ordinal => 1))
    builder.pointer(64, builder.rebase64(:target => 1))
    builder.multi_start(0, [16, 64])
    file = builder.build!

    types = file.chained_fixups.fixups.map { |f| [f.runtime_offset - 0x4000, f.type] }
    assert_equal [[16, :bind], [24, :bind], [64, :rebase]], types
  end

  def test_pointer_formats_and_segment_metadata
    builder = Builder.new(:pointer_format => 9)
    builder.pointer(0, builder.userland_rebase(:target => 8))
    file = builder.build!

    assert_equal({ 1 => :DYLD_CHAINED_PTR_ARM64E_USERLAND }, file.chained_fixups.pointer_formats)
    seg = file.chained_fixups.segment_starts.first
    assert_equal 0x4000, seg.segment_offset
    assert_equal 0x4000, seg.page_size
  end

  def test_rebases_and_binds_helpers
    builder = Builder.new(:pointer_format => 6)
    builder.import("_s")
    builder.pointer(0, builder.rebase64(:target => 8, :next_step => 1))
    builder.pointer(8, builder.bind64(:ordinal => 0))
    cf = builder.build!.chained_fixups

    assert_equal [:rebase], cf.rebases.map(&:type)
    assert_equal [:bind], cf.binds.map(&:type)
  end

  def test_to_h_serialization
    builder = Builder.new(:pointer_format => 6)
    builder.import("_s")
    builder.pointer(0, builder.bind64(:ordinal => 0))
    hash = builder.build!.chained_fixups.to_h

    assert_equal :DYLD_CHAINED_IMPORT, hash["imports_format"]
    assert_equal :bind, hash["fixups"].first["type"]
    assert_equal "_s", hash["fixups"].first["import"]["name"]
  end

  # --------------------------------------------------------------- multi-start

  def test_multi_start_page
    builder = Builder.new(:pointer_format => 6)
    builder.import("_x")
    # Two independent chains on one page, encoded via the overflow list.
    builder.pointer(16, builder.bind64(:ordinal => 0))
    builder.pointer(48, builder.rebase64(:target => 0x99))
    builder.multi_start(0, [16, 48])
    file = builder.build!

    offsets = file.chained_fixups.fixups.map(&:runtime_offset).sort
    assert_equal [0x4010, 0x4030], offsets
  end

  def test_empty_page_via_start_none
    builder = Builder.new(:pointer_format => 6)
    builder.pointer(0, builder.rebase64(:target => 1))
    # Two pages: first has a chain, second is empty.
    builder.page_starts([0, 0xFFFF])
    file = builder.build!

    assert_equal 1, file.chained_fixups.fixups.size
  end

  # ------------------------------------------------------------------- errors

  def test_chain_out_of_page_bounds
    builder = Builder.new(:pointer_format => 6)
    # start at 0x3FFC, the 8-byte pointer overruns a 0x4000 page
    builder.page_starts([0x3FFC])
    file = builder.build!

    error = assert_raises(MachO::ChainedFixupsChainOutOfBoundsError) do
      file.chained_fixups.fixups
    end
    assert_match(/0x7ffc/i, error.message)
  end

  def test_chain_step_leaves_page
    builder = Builder.new(:pointer_format => 6)
    # Step 0x7FF (stride 8) lands at 0x3FF8; the pointer there is followed by
    # another step that pushes the chain past the page end.
    builder.pointer(0, builder.rebase64(:target => 1, :next_step => 0x7FF))
    builder.pointer(0x3FF8, builder.rebase64(:target => 1, :next_step => 1))
    file = builder.build!

    assert_raises(MachO::ChainedFixupsChainOutOfBoundsError) do
      file.chained_fixups.fixups
    end
  end

  def test_duplicate_location
    builder = Builder.new(:pointer_format => 6)
    builder.import("_a").import("_b")
    builder.pointer(0, builder.bind64(:ordinal => 0, :next_step => 0))
    # Two chain starts on the same page both point at offset 0.
    builder.multi_start(0, [0, 0])
    file = builder.build!

    assert_raises(MachO::ChainedFixupsDuplicateLocationError) do
      file.chained_fixups.fixups
    end
  end

  def test_bad_ordinal
    builder = Builder.new(:pointer_format => 6)
    builder.import("_only_one")
    builder.pointer(0, builder.bind64(:ordinal => 99))
    file = builder.build!

    error = assert_raises(MachO::ChainedFixupsBadOrdinalError) do
      file.chained_fixups.fixups
    end
    assert_match(/99/, error.message)
    assert_match(/0x4000/, error.message)
  end

  def test_unsupported_pointer_format
    builder = Builder.new(:pointer_format => 1) # DYLD_CHAINED_PTR_ARM64E
    builder.pointer(0, 0)
    file = builder.build!

    error = assert_raises(MachO::ChainedFixupsError) { file.chained_fixups.fixups }
    assert_match(/Unsupported chained pointer format 1/, error.message)
  end

  def test_truncated_payload
    builder = Builder.new(:pointer_format => 6)
    builder.pointer(0, builder.rebase64(:target => 1))
    file = builder.build!
    cmd = file.command(:LC_DYLD_CHAINED_FIXUPS).first
    truncated = file.serialize.byteslice(0, cmd.dataoff + 4)
    truncated_file = MachO::MachOFile.new_from_bin(truncated)
    assert_raises(MachO::ChainedFixupsError) { truncated_file.chained_fixups }
  end

  def test_linkedit_command_rejects_other_types
    # A LinkeditDataCommand that isn't LC_DYLD_CHAINED_FIXUPS must refuse.
    file = MachO::MachOFile.new("test/bin/x86_64/hello.bin")
    cmd = file.load_commands.find { |c| c.is_a?(MachO::LoadCommands::LinkeditDataCommand) }
    skip("no LinkeditDataCommand in fixture") if cmd.nil?
    assert_raises(MachO::ChainedFixupsError) { cmd.chained_fixups }
  end

  def test_read_only_enumeration
    fixup = MachO::ChainedFixups::Fixup.new(
      :file_offset => 0, :vmaddr => 0, :runtime_offset => 0, :type => :bind,
      :pointer_format => :DYLD_CHAINED_PTR_64_OFFSET, :segment_index => 1, :raw => 0,
    )
    assert_raises(NoMethodError) { fixup.type = :rebase }
  end
end
