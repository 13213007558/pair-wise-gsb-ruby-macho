# frozen_string_literal: true

require_relative "helpers"

class FilesetTest < Minitest::Test
  include Helpers

  MH_MAGIC_64 = 0xfeedfacf
  CPU_TYPE_X86_64 = 0x01000007
  CPU_SUBTYPE_X86_64_ALL = 3
  MH_FILESET = 0xc
  MH_KEXT_BUNDLE = 0xb
  LC_SEGMENT_64 = 0x19
  LC_FILESET_ENTRY = 0x80000035

  MACH_HEADER_64_SIZE = 32
  SEGMENT_64_SIZE = 72
  SECTION_64_SIZE = 80
  FILESET_ENTRY_FIXED_SIZE = 32

  ENTRY_ONE_FILEOFF = 0x100
  ENTRY_TWO_FILEOFF = 0x200
  ENTRY_ONE_VMADDR = 0x100000000
  ENTRY_TWO_VMADDR = 0x200000000

  def mach_header_64(filetype, cmds)
    [MH_MAGIC_64, CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, filetype,
     cmds.size, cmds.sum(&:bytesize), 0, 0].pack("L<8") + cmds.join
  end

  # Builds an LC_SEGMENT_64 command. `sections` is an array of
  # [sectname, addr, size, offset] tuples.
  def segment_command_64(segname, vmaddr, vmsize, fileoff, filesize, sections = [])
    cmdsize = SEGMENT_64_SIZE + (sections.size * SECTION_64_SIZE)
    cmd = [LC_SEGMENT_64, cmdsize, segname, vmaddr, vmsize, fileoff, filesize,
           7, 5, sections.size, 0].pack("L<2a16Q<4L<4")
    sections.each do |sectname, addr, size, offset|
      cmd << [sectname, segname, addr, size, offset, 0, 0, 0, 0, 0, 0, 0].pack("a16a16Q<2L<8")
    end
    cmd
  end

  def fileset_entry_command(entry_id, vmaddr, fileoff)
    string = entry_id + "\x00"
    cmdsize = FILESET_ENTRY_FIXED_SIZE + string.bytesize
    cmdsize += 4 - (cmdsize % 4) if (cmdsize % 4) != 0
    [LC_FILESET_ENTRY, cmdsize, vmaddr, fileoff, FILESET_ENTRY_FIXED_SIZE, 0].pack("L<2Q<2L<2") +
      string.ljust(cmdsize - FILESET_ENTRY_FIXED_SIZE, "\x00")
  end

  # Builds a standalone 64-bit Mach-O with a single __TEXT segment containing
  # one section. Section file offsets are relative to the Mach-O's own header.
  def sub_macho(sectname, contents)
    data_off = MACH_HEADER_64_SIZE + SEGMENT_64_SIZE + SECTION_64_SIZE
    segment = segment_command_64("__TEXT", 0x1000, 0x1000, 0, data_off + contents.bytesize,
                                 [[sectname, 0x1000 + data_off, contents.bytesize, data_off]])
    bin = mach_header_64(MH_KEXT_BUNDLE, [segment])
    bin << "\x00" * (data_off - bin.bytesize)
    bin << contents
    bin
  end

  # Builds an MH_FILESET container with a __TEXT segment and the given
  # [[entry_id, vmaddr, fileoff], ...] entries; `bodies` maps file offsets
  # to the data placed there.
  def fileset_container(entries, bodies = {})
    cmds = [segment_command_64("__TEXT", 0, 0, 0, 0)]
    entries.each do |entry_id, vmaddr, fileoff|
      cmds << fileset_entry_command(entry_id, vmaddr, fileoff)
    end
    bin = mach_header_64(MH_FILESET, cmds)
    bodies.each do |offset, data|
      bin << "\x00" * (offset - bin.bytesize) if bin.bytesize < offset
      bin << data
    end
    bin
  end

  def two_entry_container
    fileset_container(
      [["com.example.one", ENTRY_ONE_VMADDR, ENTRY_ONE_FILEOFF],
       ["com.example.two", ENTRY_TWO_VMADDR, ENTRY_TWO_FILEOFF]],
      ENTRY_ONE_FILEOFF => sub_macho("__text", "AAAA"),
      ENTRY_TWO_FILEOFF => sub_macho("__const", "BBBB")
    )
  end

  def test_open_fileset
    tempfile_with_data("fileset", two_entry_container) do |file|
      macho = MachO.open(file.path)

      assert_kind_of MachO::MachOFile, macho
      assert_predicate macho, :fileset?
      assert_equal ENTRY_ONE_FILEOFF, macho.fileset_entry("com.example.one").view_offset
    end
  end

  def test_fileset_entry_lookup
    macho = MachO::MachOFile.new_from_bin(two_entry_container)

    assert_predicate macho, :fileset?
    assert_equal %w[com.example.one com.example.two], macho.fileset_entries.keys

    entry_cmd = macho.fileset_entries["com.example.one"]
    assert_kind_of MachO::LoadCommands::FilesetEntryCommand, entry_cmd
    assert_equal ENTRY_ONE_VMADDR, entry_cmd.vmaddr
    assert_equal ENTRY_ONE_FILEOFF, entry_cmd.fileoff

    one = macho.fileset_entry("com.example.one")
    two = macho.fileset_entry("com.example.two")

    assert_kind_of MachO::MachOFile, one
    assert_predicate one, :view?
    assert_equal ENTRY_ONE_FILEOFF, one.view_offset
    assert_equal ENTRY_TWO_FILEOFF, two.view_offset
    assert_equal :kext_bundle, one.filetype
    assert_equal :kext_bundle, two.filetype
  end

  def test_fileset_entry_load_commands_and_sections
    macho = MachO::MachOFile.new_from_bin(two_entry_container)

    one = macho.fileset_entry("com.example.one")
    two = macho.fileset_entry("com.example.two")

    assert_equal 1, one.load_commands.size

    segment = one.segments.first
    assert_equal "__TEXT", segment.segname

    section = segment.sections.first
    assert_equal "__text", section.section_name
    assert_equal 4, section.size
    # section file offsets are relative to the entry's own header
    assert_equal MACH_HEADER_64_SIZE + SEGMENT_64_SIZE + SECTION_64_SIZE, section.offset

    assert_equal "__const", two.segments.first.sections.first.section_name
  end

  def test_entries_share_container_backing_data
    macho = MachO::MachOFile.new_from_bin(two_entry_container)
    container_data = macho.load_commands.first.view.raw_data

    one = macho.fileset_entry("com.example.one")
    two = macho.fileset_entry("com.example.two")

    # the container's buffer is shared, never copied
    assert_same container_data, one.load_commands.first.view.raw_data
    assert_same container_data, two.load_commands.first.view.raw_data

    # load command views use container-absolute offsets into the shared buffer
    assert_equal ENTRY_ONE_FILEOFF + MACH_HEADER_64_SIZE, one.load_commands.first.view.offset
    assert_equal ENTRY_TWO_FILEOFF + MACH_HEADER_64_SIZE, two.load_commands.first.view.offset
  end

  def test_entry_view_is_read_only
    macho = MachO::MachOFile.new_from_bin(two_entry_container)
    one = macho.fileset_entry("com.example.one")

    assert_raises(MachO::MachOError) { one.serialize }
    assert_raises(MachO::MachOError) { one.write("should_not_be_written.bin") }
    assert_raises(MachO::MachOError) { one.write! }
    assert_raises(MachO::MachOError) { one.insert_command(0, nil) }
    assert_raises(MachO::MachOError) { one.delete_command(one.load_commands.first) }
    assert_raises(MachO::MachOError) { one.add_rpath("/foo") }

    # the container itself remains fully usable
    assert_equal two_entry_container, macho.serialize
  end

  def test_unknown_entry_id
    macho = MachO::MachOFile.new_from_bin(two_entry_container)

    error = assert_raises(MachO::FilesetEntryUnknownError) do
      macho.fileset_entry("com.example.missing")
    end
    assert_match "com.example.missing", error.message
  end

  def test_duplicate_entry_id
    bin = fileset_container(
      [["com.example.dupe", ENTRY_ONE_VMADDR, ENTRY_ONE_FILEOFF],
       ["com.example.dupe", ENTRY_TWO_VMADDR, ENTRY_TWO_FILEOFF]],
      ENTRY_ONE_FILEOFF => sub_macho("__text", "AAAA"),
      ENTRY_TWO_FILEOFF => sub_macho("__const", "BBBB")
    )
    macho = MachO::MachOFile.new_from_bin(bin)

    error = assert_raises(MachO::DuplicateFilesetEntryError) { macho.fileset_entries }
    assert_match "com.example.dupe", error.message
  end

  def test_entry_out_of_bounds
    bin = fileset_container([["com.example.oob", ENTRY_ONE_VMADDR, 0x1000]])
    macho = MachO::MachOFile.new_from_bin(bin)

    error = assert_raises(MachO::FilesetEntryBoundsError) do
      macho.fileset_entry("com.example.oob")
    end
    assert_match "out of bounds", error.message
  end

  def test_entry_overlapping_container_header
    bin = fileset_container([["com.example.bad", ENTRY_ONE_VMADDR, 0x20]])
    macho = MachO::MachOFile.new_from_bin(bin)

    error = assert_raises(MachO::FilesetEntryOverlapError) { macho.fileset_entries }
    assert_match "overlaps", error.message
  end

  def test_entry_overlapping_another_entry_header
    bin = fileset_container(
      [["com.example.one", ENTRY_ONE_VMADDR, ENTRY_ONE_FILEOFF],
       ["com.example.two", ENTRY_TWO_VMADDR, ENTRY_ONE_FILEOFF + 8]],
      ENTRY_ONE_FILEOFF => sub_macho("__text", "AAAA")
    )
    macho = MachO::MachOFile.new_from_bin(bin)

    error = assert_raises(MachO::FilesetEntryOverlapError) { macho.fileset_entries }
    assert_match "com.example.two", error.message
  end

  def test_compressed_macho_still_requires_decompress_option
    compressed = [MachO::Headers::COMPRESSED_MAGIC].pack("N") + ("\x00" * 64)

    assert_raises(MachO::CompressedMachOError) do
      MachO::MachOFile.new_from_bin(compressed)
    end
  end
end
