# frozen_string_literal: true

require_relative "helpers"

class RelocationsTest < Minitest::Test
  include Helpers

  LC_SEGMENT_64 = 0x19
  LC_SYMTAB = 0x02
  CPU_X86_64 = 0x01000007
  CPU_ARM64 = 0x0100000c

  class ObjectWriter
    HEADER_SIZE = 32
    SEGMENT_SIZE = 72
    SECTION_SIZE = 80
    SYMTAB_SIZE = 24
    ENTRY_SIZE = 16

    Section = Struct.new(:name, :segment, :data, :relocations, keyword_init: true)
    SymbolRecord = Struct.new(:name, :section, :value, :external, :string_offset, keyword_init: true) do
      def n_sect(writer)
        section.nil? ? 0 : writer.section_index(section) + 1
      end
    end

    Relocation = Struct.new(:section, :address, :symbol, :ordinal, :external, :pcrel, :length, :type,
                           :addend, :scattered_value, keyword_init: true)

    attr_reader :sections, :symbols

    def initialize(cputype)
      @cputype = cputype
      @sections = []
      @symbols = []
    end

    def section(name, segment, data, relocations: [])
      @sections << Section.new(:name => name, :segment => segment,
                               :data => data.b, :relocations => relocations)
    end

    def symbol(name, section: nil, value: 0, external: false)
      @symbols << SymbolRecord.new(:name => name, :section => section,
                                  :value => value, :external => external)
    end

    def reloc(section, address, symbol: nil, ordinal: nil, external: false, pcrel: false,
              length: 2, type: 0, addend: nil, scattered_value: nil)
      section.relocations << Relocation.new(:section => section, :address => address,
                                            :symbol => symbol, :ordinal => ordinal,
                                            :external => external, :pcrel => pcrel,
                                            :length => length, :type => type, :addend => addend,
                                            :scattered_value => scattered_value)
    end

    def section_index(section)
      @sections.index(section)
    end

    def symbol_index(symbol)
      @symbols.index(symbol)
    end

    def build
      sizeofcmds = SEGMENT_SIZE + SECTION_SIZE * sections.length + SYMTAB_SIZE
      header_end = HEADER_SIZE + sizeofcmds
      section_offset = align(header_end, 8)
      section_layout = layout_sections(section_offset)
      reloc_offset = align(section_layout.values.first[:offset] +
                           section_layout.values.sum { |layout| layout[:size] }, 8)
      @reloc_offset = reloc_offset
      reloc_layout = layout_relocations(reloc_offset)
      sym_offset = align(reloc_offset + reloc_layout.values.sum { |layout| layout[:size] }, 8)
      str_offset = sym_offset + ENTRY_SIZE * symbols.length
      strings = build_strings

      bin = "\0" * str_offset + strings
      bin[0, 32] = header
      segment_command_size = SEGMENT_SIZE + SECTION_SIZE * sections.length
      bin[HEADER_SIZE, segment_command_size] = segment_command(section_layout)
      write_sections(bin, section_layout)
      write_relocations(bin, reloc_layout)
      write_symbols(bin, sym_offset, strings)
      bin
    end

    private

    def align(value, boundary)
      (value + boundary - 1) & ~(boundary - 1)
    end

    def layout_sections(offset)
      layout = {}
      cursor = offset
      sections.each do |section|
        layout[section] = { :offset => cursor, :size => section.data.bytesize }
        cursor += section.data.bytesize
      end
      layout
    end

    def layout_relocations(offset)
      layout = {}
      cursor = offset
      sections.each do |section|
        layout[section] = { :offset => cursor, :size => section.relocations.length * 8 }
        cursor += layout[section][:size]
      end
      layout
    end

    def build_strings
      strings = +"\0"
      symbols.each do |symbol|
        symbol_name = "#{symbol.name}\0"
        symbol.string_offset = strings.bytesize
        strings << symbol_name
      end
      strings
    end

    def header
      sizeofcmds = SEGMENT_SIZE + SECTION_SIZE * sections.length + SYMTAB_SIZE
      cpusubtype = @cputype == CPU_X86_64 ? 3 : 0
      [0xfeedfacf, @cputype, cpusubtype, 1, 2, sizeofcmds, 0, 0].pack("L<7L")
    end

    def segment_command(section_layout)
      section_end = section_layout.values.first[:offset] + section_layout.values.sum { |layout| layout[:size] }
      end_offset = align(section_end + sections.sum { |section| section.relocations.length * 8 }, 8)
      segment = [LC_SEGMENT_64, SEGMENT_SIZE + SECTION_SIZE * sections.length].pack("L<2")
      segment << ("\0" * 16)
      segment << [0, end_offset, section_layout.values.first[:offset], end_offset,
                  7, 5, sections.length, 0].pack("Q<4l<4")
      addr = 0
      reloc_cursor = @reloc_offset
      sections.each do |section|
        layout = section_layout[section]
        segment << section.name.ljust(16, "\0")
        segment << section.segment.ljust(16, "\0")
        segment << [addr, section.data.bytesize].pack("Q<Q<")
        segment << [layout[:offset]].pack("L<")
        segment << [2, reloc_cursor, section.relocations.length,
                    0x80000400, 0, 0, 0].pack("L<7")
        addr += section.data.bytesize
        reloc_cursor += section.relocations.length * 8
      end
      segment
    end

    def write_sections(bin, layout)
      sections.each { |section| bin[layout[section][:offset], section.data.bytesize] = section.data }
    end

    def write_relocations(bin, layout)
      sections.each do |section|
        section.relocations.each_with_index do |relocation, index|
          number = if relocation.type == 10
            relocation.addend || 0
          elsif !relocation.scattered_value.nil?
            0
          elsif relocation.external
            symbol_index(relocation.symbol)
          else
            relocation.ordinal
          end
          number = 0xffffff & number.to_i if relocation.type == 10
          info = ((relocation.type & 0x0f) << 28) |
                 (((relocation.pcrel ? 1 : 0) & 1) << 24) |
                 ((relocation.length & 3) << 25) |
                 (((relocation.external ? 1 : 0) & 1) << 27) |
                 (number & 0x00ffffff)
          info &= 0xffffffff
          address = relocation.address
          address |= 0x80000000 unless relocation.scattered_value.nil?
          value = relocation.scattered_value || info
          bin[layout[section][:offset] + index * 8, 8] = [address, value].pack("L<2")
        end
      end
    end

    def write_symbols(bin, sym_offset, strings)
      symbols.each_with_index do |symbol, index|
        external = symbol.external || symbol.section.nil?
        n_type = (external ? 1 : 0) | (symbol.section.nil? ? 0 : 0x0e)
        offset = sym_offset + index * ENTRY_SIZE
        bin[offset, 4] = [symbol.string_offset].pack("L<")
        bin[offset + 4] = [n_type].pack("C")
        bin[offset + 5] = [symbol.n_sect(self)].pack("C")
        bin[offset + 6, 2] = [0].pack("v")
        bin[offset + 8, 8] = [symbol.value].pack("Q<")
      end
      symtab_offset = HEADER_SIZE + SEGMENT_SIZE + SECTION_SIZE * sections.length
      bin[symtab_offset, 8] = [LC_SYMTAB, SYMTAB_SIZE].pack("L<2")
      bin[symtab_offset + 8, 16] = [sym_offset, symbols.length, sym_offset + ENTRY_SIZE * symbols.length,
                                    strings.bytesize].pack("L<4")
    end
  end

  def test_x86_64_external_branch_and_positive_addend
    writer = ObjectWriter.new(CPU_X86_64)
    writer.section("__text", "__TEXT", "\xe8\x2a\x00\x00\x00")
    writer.symbol("_foo")
    text = writer.sections.first
    writer.reloc(text, 1, :symbol => writer.symbols.first, :external => true,
                 :pcrel => true, :length => 2, :type => 2)

    file = MachO::MachOFile.new_from_bin(writer.build)
    relocation = file.relocations.operations.first

    assert file.object?
    section_table = file.relocations_for_section(file.sections.first)
    assert_equal "__TEXT,__text", section_table.operations.first.section_name
    assert_equal :BRANCH, relocation.type
    assert_equal "__TEXT,__text", relocation.section_name
    assert_predicate relocation, :pc_relative?
    assert_predicate relocation, :external?
    assert_equal "_foo", relocation.symbol_name
    assert_equal 0, relocation.symbol_index
    assert_nil relocation.section_ordinal
    assert_equal 42, relocation.instruction_addend
    assert_equal 42, relocation.addend
  end

  def test_x86_64_subtractor_unsigned_are_one_operation
    writer = ObjectWriter.new(CPU_X86_64)
    writer.section("__text", "__TEXT", "\x90" * 16)
    writer.section("__data", "__DATA", "\x00" * 16)
    writer.symbol("_start", :section => writer.sections.first, :value => 0)
    writer.symbol("_end", :section => writer.sections.last, :value => 16)
    text = writer.sections.first
    text.data[0, 8] = [37].pack("Q<")
    writer.reloc(text, 0, :ordinal => 2, :length => 3, :type => 5)
    writer.reloc(text, 0, :ordinal => 1, :length => 3, :type => 0)

    file = MachO::MachOFile.new_from_bin(writer.build)
    relocation = file.relocations.operations.first

    assert_equal 2, file.relocations.entries.length
    assert_equal 1, file.relocations.operations.length
    assert_equal :subtractor, relocation.pair_type
    assert_equal :subtractor_followed_by_unsigned, relocation.relation
    assert_predicate relocation, :local?
    assert_equal 1, relocation.section_ordinal
    assert_equal 2, relocation.subtrahend_target.ordinal
    assert_equal 37, relocation.instruction_addend
    assert_equal 37, relocation.addend
  end

  def test_arm64_negative_addend_precedes_branch
    writer = ObjectWriter.new(CPU_ARM64)
    writer.section("__text", "__TEXT", "\x00\x00\x00\x94")
    writer.symbol("_foo")
    text = writer.sections.first
    writer.reloc(text, 0, :symbol => writer.symbols.first, :external => true,
                 :pcrel => true, :length => 2, :type => 10, :addend => -5)
    writer.reloc(text, 0, :symbol => writer.symbols.first, :external => true,
                 :pcrel => true, :length => 2, :type => 2)
    file = MachO::MachOFile.new_from_bin(writer.build)
    relocation = file.relocations.operations.first

    assert_equal 2, file.relocations.entries.length
    assert_equal 1, file.relocations.operations.length
    assert_equal :addend, relocation.pair_type
    assert_equal :addend_followed_by_operation, relocation.relation
    assert_equal :BRANCH26, relocation.type
    assert_equal "_foo", relocation.symbol_name
    assert_predicate relocation, :pc_relative?
    assert_equal(-5, relocation.explicit_addend)
    assert_equal(-5, relocation.addend)
    assert_equal 0, relocation.instruction_addend
  end

  def test_x86_64_signed_scattered_addend_is_one_operation
    writer = ObjectWriter.new(CPU_X86_64)
    writer.section("__text", "__TEXT", "\x90" * 8)
    writer.section("__data", "__DATA", "\x00" * 8)
    text = writer.sections.first
    writer.reloc(text, 0, :ordinal => 2, :pcrel => true, :length => 2, :type => 1)
    writer.reloc(text, 0, :length => 2, :type => 0, :scattered_value => -7)

    table = MachO::MachOFile.new_from_bin(writer.build).relocations
    relocation = table.operations.first

    assert_equal 2, table.entries.length
    assert_equal 1, table.operations.length
    assert_equal :signed, relocation.pair_type
    assert_equal :signed_followed_by_scattered_addend, relocation.relation
    assert_equal 2, relocation.section_ordinal
    assert_equal(-7, relocation.explicit_addend)
    assert_equal(-7, relocation.addend)
    assert_equal 0, relocation.instruction_addend
  end

  def test_arm64_addend_subtractor_unsigned_are_one_operation
    writer = ObjectWriter.new(CPU_ARM64)
    writer.section("__text", "__TEXT", "\x90" * 8)
    writer.section("__data", "__DATA", "\x00" * 8)
    text = writer.sections.first
    text.data[0, 8] = [12].pack("Q<")
    writer.reloc(text, 0, :ordinal => 1, :length => 3, :type => 10, :addend => 12)
    writer.reloc(text, 0, :ordinal => 2, :length => 3, :type => 1)
    writer.reloc(text, 0, :ordinal => 1, :length => 3, :type => 0)
    table = MachO::MachOFile.new_from_bin(writer.build).relocations
    relocation = table.operations.first

    assert_equal 3, table.entries.length
    assert_equal 1, table.operations.length
    assert_equal [0, 1, 2], relocation.entry_indices
    assert_equal :addend_subtractor, relocation.pair_type
    assert_equal 12, relocation.explicit_addend
    assert_equal 1, relocation.section_ordinal
    assert_equal 2, relocation.subtrahend_target.section_ordinal
    assert_equal 12, relocation.instruction_addend
  end

  def test_structured_diagnostics
    writer = ObjectWriter.new(CPU_ARM64)
    writer.section("__text", "__TEXT", "\x00" * 8)
    writer.section("__data", "__DATA", "\x00" * 8)
    text = writer.sections.first
    writer.reloc(text, 0, :symbol => nil, :ordinal => 9, :length => 2, :type => 15)
    writer.reloc(text, 0, :symbol => nil, :ordinal => 9, :length => 2, :type => 2)
    writer.reloc(text, 4, :symbol => nil, :ordinal => 1, :length => 2, :type => 10)

    table = MachO::MachOFile.new_from_bin(writer.build).relocations
    ids = table.diagnostics.map(&:id)

    refute_predicate table, :valid?
    assert_includes ids, :section_ordinal_out_of_bounds
    assert_includes ids, :missing_relocation_pair
    assert_includes ids, :unsupported_relocation_type
    error = assert_raises(MachO::RelocationError) do
      MachO::MachOFile.new_from_bin(writer.build).relocations(:strict => true)
    end
    assert_kind_of Array, error.diagnostics
  end
end
