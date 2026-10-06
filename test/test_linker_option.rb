# frozen_string_literal: true

require_relative "helpers"

class LinkerOptionTest < Minitest::Test
  include Helpers

  LONG_OPTION = "-lthis_is_a_fairly_long_library_name_for_header_growth"

  def fixture_bin(archs, name)
    File.binread(fixture(archs, name))
  end

  # Returns, for each section of the file's first segment, the raw section
  # contents and relocation entries at the offsets recorded in its load
  # commands.
  def section_payloads(file)
    file.segments.first.sections.map do |section|
      {
        :name => section.sectname,
        :addr => section.addr,
        :align => section.align,
        :data => file.serialize.byteslice(section.offset, section.size),
        :relocs => section.reloff.zero? ? "" : file.serialize.byteslice(section.reloff, section.nreloc * 8),
      }
    end
  end

  # Returns the symbol table's nlist entries as [n_strx, n_type, n_sect,
  # n_desc, n_value] tuples, plus the raw string table.
  def symbols_and_strings(file)
    symtab = file.command(:LC_SYMTAB).first
    entries = symtab.nsyms.times.map do |index|
      file.serialize.byteslice(symtab.symoff + (index * 16), 16).unpack("LCcSQ>")
    end

    [entries, file.serialize.byteslice(symtab.stroff, symtab.strsize)]
  end

  def test_create_and_serialize_linker_option
    command = MachO::LoadCommands::LoadCommand.create(:LC_LINKER_OPTION, "-lfoo")
    context = MachO::LoadCommands::LoadCommand::SerializationContext.new(:little, 8)
    raw = command.serialize(context)

    cmd, cmdsize, count = raw.unpack("L<3")
    assert_equal MachO::LoadCommands::LOAD_COMMAND_CONSTANTS[:LC_LINKER_OPTION], cmd
    assert_equal count, 1
    assert_equal 0, cmdsize % 8
    assert_equal raw.bytesize, cmdsize
    assert_equal "-lfoo" + ("\x00" * 7), raw.byteslice(12, raw.bytesize - 12)
  end

  def test_create_linker_option_with_multiple_strings_is_padded
    command = MachO::LoadCommands::LoadCommand.create(:LC_LINKER_OPTION, "-labc", "-x")
    context = MachO::LoadCommands::LoadCommand::SerializationContext.new(:little, 8)
    raw = command.serialize(context)

    _cmd, cmdsize, count = raw.unpack("L<3")
    assert_equal 2, count
    assert_equal 0, cmdsize % 8
    assert_equal "-labc\x00-x\x00\x00\x00\x00", raw.byteslice(12, raw.bytesize - 12)

    assert_raises ArgumentError do
      MachO::LoadCommands::LoadCommand.create(:LC_LINKER_OPTION)
    end
  end

  def test_add_linker_option_accepts_a_single_array_argument
    file = MachO::MachOFile.new_from_bin(fixture_bin(:x86_64, "reloc-object.o"))
    file.add_linker_option(["-lfoo", "-lbar" + ("y" * 64)])

    command = file.command(:LC_LINKER_OPTION).first
    assert_equal ["-lfoo", "-lbar" + ("y" * 64)], command.options
    assert_equal 2, command.count
  end

  def test_growing_object_header_preserves_payload_and_references
    file = MachO::MachOFile.new_from_bin(fixture_bin(:x86_64, "reloc-object.o"))
    original = file.serialize.dup

    before_sections = section_payloads(file)
    before_symbols, before_strings = symbols_and_strings(file)
    before_first_offset = file.segments.first.sections.reject(&:empty?).map(&:offset).min
    before_payload = original.byteslice(before_first_offset, original.bytesize - before_first_offset)

    file.add_linker_option(LONG_OPTION)
    grown = file.serialize

    # The file grew by exactly one load command plus alignment padding.
    command = file.command(:LC_LINKER_OPTION).first
    assert_operator grown.bytesize, :>, original.bytesize
    assert_equal [LONG_OPTION], command.options
    assert_equal 0, command.cmdsize % 8

    segment = file.segments.first
    shift = segment.fileoff - before_first_offset
    assert_equal grown.bytesize - original.bytesize, shift
    assert_equal 0, segment.fileoff % 16

    # Every byte from the first section onward moved as one contiguous block.
    assert_equal before_payload, grown.byteslice(segment.fileoff, grown.bytesize - segment.fileoff)

    # Section contents, relocation entries and their logical addresses are
    # unchanged; only the file offsets moved.
    section_payloads(file).each_with_index do |after, index|
      before = before_sections[index]
      actual_section = file.segments.first.sections[index]
      assert_equal before[:name], after[:name]
      assert_equal before[:addr], after[:addr]
      assert_equal before[:align], after[:align]
      assert_equal before[:data], after[:data]
      assert_equal before[:relocs], after[:relocs]
      assert_equal 0, actual_section.offset % (2**actual_section.align) unless actual_section.empty?
    end

    # Symbol values (logical addresses) and the string table are preserved.
    after_symbols, after_strings = symbols_and_strings(file)
    assert_equal before_symbols.map { |entry| entry[4] }, after_symbols.map { |entry| entry[4] }
    assert_equal before_symbols.map { |entry| entry[0..3] }, after_symbols.map { |entry| entry[0..3] }
    assert_equal before_strings, after_strings
  end

  def test_grown_object_can_be_read_independently_after_write
    file = MachO::MachOFile.new(fixture(:x86_64, "reloc-object.o"))
    file.add_linker_option(LONG_OPTION)

    Tempfile.open(["grown", ".o"]) do |tempfile|
      file.write(tempfile.path)

      reread = MachO::MachOFile.new(tempfile.path)
      assert reread.object?
      assert_equal :x86_64, reread.cputype
      assert_equal [LONG_OPTION], reread.command(:LC_LINKER_OPTION).first.options
      assert_equal 2, reread.segments.first.sections.size
      assert_equal [1, 1], reread.segments.first.sections.map(&:nreloc)
    end
  end

  def test_fat_container_grows_one_slice_and_leaves_the_other_untouched
    fat = MachO::FatFile.new(fixture([:x86_64, :arm64], "reloc-object.o"))
    x86_64 = fat.extract(:x86_64)
    arm64 = fat.extract(:arm64)

    original_x86_64 = x86_64.serialize.dup
    original_arm64 = arm64.serialize.dup
    first_offset = x86_64.segments.first.sections.reject(&:empty?).map(&:offset).min
    original_payload = original_x86_64.byteslice(first_offset, original_x86_64.bytesize - first_offset)

    x86_64.add_linker_option(LONG_OPTION)
    grown_fat = MachO::FatFile.new_from_machos(x86_64, arm64)

    Tempfile.open(["grown", ".o"]) do |tempfile|
      grown_fat.write(tempfile.path)
      reread = MachO::FatFile.new(tempfile.path)

      # Each fat_arch records the exact bytes present at its aligned offset.
      reread.fat_archs.each do |arch|
        blob = reread.serialize.byteslice(arch.offset, arch.size)
        assert_equal reread.extract(arch.cputype == MachO::Headers::CPU_TYPE_X86_64 ? :x86_64 : :arm64).serialize, blob
        assert_equal 0, arch.offset % (2**arch.align)
      end

      grown_x86_64 = reread.extract(:x86_64)
      untouched_arm64 = reread.extract(:arm64)

      assert_equal [LONG_OPTION], grown_x86_64.command(:LC_LINKER_OPTION).first.options
      new_payload_offset = grown_x86_64.segments.first.fileoff
      moved_payload = grown_x86_64.serialize.byteslice(new_payload_offset,
                                                      grown_x86_64.serialize.bytesize - new_payload_offset)
      assert_equal original_payload, moved_payload

      # The other architecture slice is byte-for-byte identical, including
      # its fat_arch alignment requirements.
      assert_equal original_arm64, untouched_arm64.serialize
    end
  end

  def test_add_linker_option_to_every_fat_slice_rebuilds_aligned_layout
    fat = MachO::FatFile.new(fixture([:x86_64, :arm64], "reloc-object.o"))
    fat.add_linker_option(LONG_OPTION)

    Tempfile.open(["grown", ".o"]) do |tempfile|
      fat.write(tempfile.path)
      reread = MachO::FatFile.new(tempfile.path)

      assert_equal [:x86_64, :arm64], reread.machos.map(&:cputype)
      reread.machos.each do |slice|
        assert slice.object?
        assert_equal [LONG_OPTION], slice.command(:LC_LINKER_OPTION).first.options
        assert_equal [1, 1], slice.segments.first.sections.map(&:nreloc)
      end

      reread.fat_archs.each do |arch|
        assert_equal 0, arch.offset % (2**arch.align)
        assert_equal arch.size, reread.serialize.byteslice(arch.offset, arch.size).bytesize
      end
    end
  end

  def test_unknown_offset_bearing_load_command_fails_before_any_write
    raw = fixture_bin(:x86_64, "reloc-object.o").dup
    # Replace LC_BUILD_VERSION (cmdsize 24, immediately after LC_SEGMENT_64)
    # with an unrecognized command id. A permissive parse keeps it as a
    # generic LoadCommand whose file offsets (if any) can't be rewritten.
    load_command_offset = MachO::Headers::MachHeader64.bytesize + 232
    raw[load_command_offset, 4] = [0x77777777].pack("L<")

    file = MachO::MachOFile.new_from_bin(raw, :permissive => true)
    snapshot = file.serialize.dup

    assert_raises MachO::HeaderGrowError do
      file.add_linker_option(LONG_OPTION)
    end

    assert_equal snapshot, file.serialize
  end

  def test_non_growable_filetypes_keep_header_pad_behavior
    executable = MachO::MachOFile.new(fixture(:x86_64, "hello.bin"))
    assert_raises MachO::HeaderPadError do
      executable.add_linker_option("-l" + ("x" * 4096))
    end

    dylib = MachO::MachOFile.new(fixture(:x86_64, "libhello.dylib"))
    assert_raises MachO::HeaderPadError do
      dylib.add_linker_option("-l" + ("x" * 4096))
    end

    object32 = MachO::MachOFile.new(fixture(:i386, "hello.o"))
    assert_raises MachO::HeaderPadError do
      object32.add_linker_option("-l" + ("x" * 4096))
    end
  end
end
