# frozen_string_literal: true

require_relative "helpers"

class MachOObjectHeaderGrowthTest < Minitest::Test
  include Helpers

  LINKER_OPTION = "-lthis_is_a_long_library_name_that_cannot_use_header_padding"

  def test_grows_object_header_in_a_fat_container
    Dir.mktmpdir("ruby-macho-object-growth") do |dir|
      source = File.join(dir, "object.c")
      x86_64_path = File.join(dir, "x86_64.o")
      arm64_path = File.join(dir, "arm64.o")

      File.write(source, <<~C)
        #include <stdint.h>
        __attribute__((used, section("__DATA,__first"))) uint64_t first_value = 0x1122334455667788ULL;
        __attribute__((used, section("__DATA,__second"))) uint64_t second_value = 0x8877665544332211ULL;
        extern int external_symbol(void);
        int get_external(void) { return external_symbol(); }
      C

      x86_64_built = system("clang", "-arch", "x86_64", "-c", source, "-o", x86_64_path,
                           :out => File::NULL, :err => File::NULL)
      arm64_built = system("clang", "-arch", "arm64", "-c", source, "-o", arm64_path,
                         :out => File::NULL, :err => File::NULL)
      skip("clang is not available") unless x86_64_built && arm64_built

      x86_64 = MachO::MachOFile.new(x86_64_path)
      arm64 = MachO::MachOFile.new(arm64_path)
      fat = MachO::FatFile.new_from_machos(x86_64, arm64)
      original_x86_64 = fat.machos.first.serialize.dup
      original_arm64 = fat.machos.last.serialize.dup
      original_x86_64_file = MachO::MachOFile.new_from_bin(original_x86_64)
      original_section_info = section_info(original_x86_64_file)
      original_symbol_info = symbol_info(original_x86_64_file)
      original_relocations = relocations(original_x86_64_file)

      fat.add_linker_option(LINKER_OPTION, :arch => :x86_64)

      modified = MachO::FatFile.new_from_bin(fat.serialize)
      modified_x86_64 = modified.extract(:x86_64)
      modified_arm64 = modified.extract(:arm64)
      command = modified_x86_64.command(:LC_LINKER_OPTION).first

      refute_nil command
      assert_operator modified_x86_64.serialize.bytesize, :>, original_x86_64.bytesize
      assert_equal original_arm64, modified_arm64.serialize

      delta = modified_x86_64.serialize.bytesize - original_x86_64.bytesize
      assert_equal command.cmdsize, delta
      assert_equal original_x86_64_file.sizeofcmds + delta, modified_x86_64.sizeofcmds
      assert_equal 0, command.cmdsize % 16
      suffix_start = modified_x86_64.header.class.bytesize + modified_x86_64.sizeofcmds
      old_header_size = modified_x86_64.header.class.bytesize + original_x86_64_file.sizeofcmds
      expected_suffix = original_x86_64.byteslice(old_header_size..)
      assert_equal expected_suffix, modified_x86_64.serialize.byteslice(suffix_start..)

      modified_section_info = section_info(modified_x86_64)
      assert_equal modified_section_info.map { |info| info[:addr] }, original_section_info.map { |info| info[:addr] }
      assert_equal modified_section_info.map { |info| info[:offset] }, original_section_info.map { |info| info[:offset] + delta }
      assert_equal modified_section_info.map { |info| info[:reloff] },
                   original_section_info.map { |info| info[:reloff] + (info[:reloff].zero? ? 0 : delta) }
      assert_equal modified_section_info.map { |info| info[:nreloc] }, original_section_info.map { |info| info[:nreloc] }

      assert_equal original_symbol_info[:symoff] + delta, symbol_info(modified_x86_64)[:symoff]
      assert_equal original_symbol_info[:stroff] + delta, symbol_info(modified_x86_64)[:stroff]
      assert_equal original_symbol_info[:nsyms], symbol_info(modified_x86_64)[:nsyms]
      assert_equal original_symbol_info[:strsize], symbol_info(modified_x86_64)[:strsize]
      assert_equal original_relocations, relocations(modified_x86_64)
    end
  end

  def test_rejects_unknown_file_offset_command_before_writing
    Tempfile.create(["unknown-command", ".o"]) do |path|
      bin = File.binread(fixture(:x86_64, "hello.o")).b
      bin[32, 4] = [0x7fffffff].pack("L<")
      File.binwrite(path, bin)
      file = MachO::MachOFile.new(path, :permissive => true)

      assert_raises MachO::HeaderGrowError do
        file.add_linker_option(LINKER_OPTION)
      end

      assert_equal bin, File.binread(path)
    end
  end

  def test_rejects_non_object_files
    file = MachO::MachOFile.new(fixture(:x86_64, "hello.bin"))

    assert_raises MachO::HeaderGrowError do
      file.add_linker_option(LINKER_OPTION)
    end

    assert_equal File.binread(fixture(:x86_64, "hello.bin")), file.serialize
  end

  private

  def section_info(macho)
    macho.segments.flat_map do |segment|
      segment.sections.map do |section|
        {
          :name => section.sectname,
          :addr => section.addr,
          :offset => section.offset,
          :reloff => section.reloff,
          :nreloc => section.nreloc,
        }
      end
    end
  end

  def symbol_info(macho)
    command = macho.command(:LC_SYMTAB).first
    {
      :symoff => command.symoff,
      :nsyms => command.nsyms,
      :stroff => command.stroff,
      :strsize => command.strsize,
    }
  end

  def relocations(macho)
    macho.segments.flat_map do |segment|
      segment.sections.flat_map do |section|
        next [] if section.nreloc.zero?

        Array.new(section.nreloc) do |index|
          offset = section.reloff + (index * 8)
          address = macho.serialize.unpack1("L<", :offset => offset) & 0x00ffffff
          info = macho.serialize.unpack1("L<", :offset => offset + 4)
          symbol = info & 0x00ffffff
          { :section => section.sectname, :address => address, :symbol => symbol }
        end
      end
    end
  end
end
