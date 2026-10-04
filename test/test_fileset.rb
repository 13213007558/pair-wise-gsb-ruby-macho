# frozen_string_literal: true

require_relative "helpers"

# Tests for MH_FILESET containers and their LC_FILESET_ENTRY sub-images.
# The fixtures are synthesized in-memory: a container Mach-O with two
# LC_FILESET_ENTRY commands pointing at two sub-images at non-zero offsets,
# plus a shared read-only data region that both sub-images reference.
class MachOFilesetTest < Minitest::Test
  include Helpers

  MH_MAGIC_64 = MachO::Headers::MH_MAGIC_64
  CPU_TYPE_X86_64 = MachO::Headers::CPU_TYPE_X86_64
  CPU_SUBTYPE_X86_64_ALL = MachO::Headers::CPU_SUBTYPE_X86_64_ALL
  MH_FILESET = MachO::Headers::MH_FILESET
  MH_KEXT_BUNDLE = MachO::Headers::MH_KEXT_BUNDLE
  LC_SEGMENT_64 = MachO::LoadCommands::LOAD_COMMAND_CONSTANTS[:LC_SEGMENT_64]
  LC_FILESET_ENTRY = MachO::LoadCommands::LOAD_COMMAND_CONSTANTS[:LC_FILESET_ENTRY]

  ENTRY_A_OFFSET = 0x1000
  ENTRY_B_OFFSET = 0x2000
  ENTRY_A_VMADDR = 0x100000000
  ENTRY_B_VMADDR = 0x100010000
  SHARED_DATA_OFFSET = 0x3000
  SHARED_DATA = "shared read-only backing data".b
  CONTAINER_SIZE = 0x4000

  def test_open_fileset
    tempfile_with_data("fileset", build_container(default_entries)) do |file|
      macho = MachO.open(file.path)

      assert_kind_of MachO::MachOFile, macho
      assert macho.fileset?
      assert_equal 2, macho.command(:LC_FILESET_ENTRY).size
    end
  end

  def test_access_entries_by_id
    macho = MachO::MachOFile.new_from_bin(build_container(default_entries))
    entries = macho.fileset_entries

    assert_equal %w[com.example.alpha com.example.beta], entries.keys.sort

    alpha = macho.fileset_entry("com.example.alpha")
    beta = macho.fileset_entry("com.example.beta")

    assert_kind_of MachO::MachOFile, alpha
    assert_kind_of MachO::MachOFile, beta
    assert_equal ENTRY_A_OFFSET, alpha.header_offset
    assert_equal ENTRY_B_OFFSET, beta.header_offset
    assert alpha.fileset_entry?
    assert beta.fileset_entry?
    refute macho.fileset_entry?
    assert_equal 0, macho.header_offset
    assert_equal :kext_bundle, alpha.filetype
    assert_nil macho.fileset_entry("com.example.unknown")
  end

  def test_entries_share_container_data
    macho = MachO::MachOFile.new_from_bin(build_container(default_entries))
    alpha = macho.fileset_entry("com.example.alpha")
    beta = macho.fileset_entry("com.example.beta")

    # sub-images must not copy the container's data
    assert_same macho.serialize, alpha.serialize
    assert_same macho.serialize, beta.serialize
  end

  def test_entry_load_commands_and_sections
    macho = MachO::MachOFile.new_from_bin(build_container(default_entries))
    alpha = macho.fileset_entry("com.example.alpha")

    assert_equal 1, alpha.load_commands.size

    segment = alpha.segments.first

    assert_equal "__TEXT", segment.segname
    assert_equal ENTRY_A_VMADDR, segment.vmaddr
    assert_equal ENTRY_A_OFFSET, segment.fileoff

    section = segment.sections.first

    assert_equal "__text", section.sectname
    # file offsets are relative to the container, indexing the shared data
    assert_equal SHARED_DATA_OFFSET, section.offset
    assert_equal SHARED_DATA, macho.serialize[section.offset, section.size]
    # VM addresses map to container-relative file offsets as usual
    assert_equal SHARED_DATA_OFFSET, section.addr - segment.vmaddr + segment.fileoff

    beta = macho.fileset_entry("com.example.beta")

    assert_equal "__const", beta.segments.first.sections.first.sectname
    assert_equal SHARED_DATA_OFFSET, beta.segments.first.sections.first.offset
  end

  def test_entry_is_read_only
    macho = MachO::MachOFile.new_from_bin(build_container(default_entries))
    alpha = macho.fileset_entry("com.example.alpha")

    assert_raises(MachO::ModificationError) { alpha.add_rpath("/foo") }
    assert_raises(MachO::ModificationError) { alpha.delete_command(alpha.load_commands.first) }
  end

  def test_entry_out_of_bounds
    entries = default_entries
    entries[1][:offset] = 0x9000
    entries[1][:image] = false

    error = assert_raises(MachO::FilesetEntryError) do
      MachO::MachOFile.new_from_bin(build_container(entries)).fileset_entries
    end

    assert_match(/com\.example\.beta/, error.message)
    assert_match(/out of bounds/, error.message)
  end

  def test_entry_within_container_header
    entries = default_entries
    entries[0][:offset] = 0x20
    entries[0][:image] = false

    error = assert_raises(MachO::FilesetEntryError) do
      MachO::MachOFile.new_from_bin(build_container(entries)).fileset_entries
    end

    assert_match(/com\.example\.alpha/, error.message)
    assert_match(/header region/, error.message)
  end

  def test_entry_within_another_entry_header
    entries = default_entries
    entries[1][:offset] = ENTRY_A_OFFSET + 0x10
    entries[1][:image] = false

    error = assert_raises(MachO::FilesetEntryError) do
      MachO::MachOFile.new_from_bin(build_container(entries)).fileset_entries
    end

    assert_match(/com\.example\.beta/, error.message)
    assert_match(/header region/, error.message)
  end

  def test_duplicate_entry_id
    entries = default_entries
    entries[1][:id] = entries[0][:id]

    error = assert_raises(MachO::FilesetEntryError) do
      MachO::MachOFile.new_from_bin(build_container(entries)).fileset_entries
    end

    assert_match(/duplicate fileset entry ID: com\.example\.alpha/, error.message)
  end

  def test_entry_without_mach_header
    entries = default_entries
    entries[1][:offset] = SHARED_DATA_OFFSET
    entries[1][:image] = false

    error = assert_raises(MachO::FilesetEntryError) do
      MachO::MachOFile.new_from_bin(build_container(entries)).fileset_entries
    end

    assert_match(/invalid fileset entry com\.example\.beta/, error.message)
  end

  def test_no_fileset_entries
    macho = MachO::MachOFile.new_from_bin(build_mach_header(MachO::Headers::MH_EXECUTE, []))

    refute macho.fileset?
    assert_empty macho.fileset_entries
    assert_nil macho.fileset_entry("com.example.alpha")
  end

  def test_compressed_macho_still_requires_decompress_option
    assert_raises(MachO::CompressedMachOError) do
      MachO::MachOFile.new_from_bin("comp" + ("\x00" * 1024))
    end
  end

  private

  def default_entries
    [
      {
        :id => "com.example.alpha",
        :offset => ENTRY_A_OFFSET,
        :vmaddr => ENTRY_A_VMADDR,
        :sectname => "__text",
      },
      {
        :id => "com.example.beta",
        :offset => ENTRY_B_OFFSET,
        :vmaddr => ENTRY_B_VMADDR,
        :sectname => "__const",
      },
    ]
  end

  def build_mach_header(filetype, commands)
    sizeofcmds = commands.sum(&:bytesize)
    header = [MH_MAGIC_64, CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, filetype,
              commands.size, sizeofcmds, 0, 0,].pack("L<8")

    header + commands.join
  end

  def build_segment_command(vmaddr, fileoff, sections)
    cmdsize = 72 + (sections.size * 80)
    segment = [LC_SEGMENT_64, cmdsize, "__TEXT", vmaddr, 0x1000, fileoff, 0x1000,
               7, 5, sections.size, 0,].pack("L<2a16Q<4l<2L<2")

    segment + sections.join
  end

  def build_section(sectname, addr)
    [sectname, "__TEXT", addr, SHARED_DATA.bytesize, SHARED_DATA_OFFSET,
     0, 0, 0, 0, 0, 0, 0,].pack("a16a16Q<2L<8")
  end

  def build_fileset_entry_command(vmaddr, fileoff, entry_id)
    cmdsize = 32 + MachO::Utils.round(entry_id.bytesize + 1, 8)
    command = [LC_FILESET_ENTRY, cmdsize, vmaddr, fileoff, 32, 0].pack("L<2Q<2L<2")

    command + entry_id + ("\x00" * (cmdsize - 32 - entry_id.bytesize))
  end

  def build_entry_image(offset, vmaddr, sectname)
    section_addr = vmaddr + (SHARED_DATA_OFFSET - offset)
    section = build_section(sectname, section_addr)
    segment = build_segment_command(vmaddr, offset, [section])

    build_mach_header(MH_KEXT_BUNDLE, [segment])
  end

  def build_container(entries)
    commands = entries.map do |entry|
      build_fileset_entry_command(entry[:vmaddr], entry[:offset], entry[:id])
    end
    data = build_mach_header(MH_FILESET, commands)

    entries.each do |entry|
      next unless entry.fetch(:image, true)

      data << ("\x00" * (entry[:offset] - data.bytesize)) if entry[:offset] > data.bytesize
      data << build_entry_image(entry[:offset], entry[:vmaddr], entry[:sectname])
    end

    data << ("\x00" * (SHARED_DATA_OFFSET - data.bytesize)) << SHARED_DATA
    data << ("\x00" * (CONTAINER_SIZE - data.bytesize)) if data.bytesize < CONTAINER_SIZE
    data
  end
end

