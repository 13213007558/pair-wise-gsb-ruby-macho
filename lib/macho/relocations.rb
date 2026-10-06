# frozen_string_literal: true

require "forwardable"

module MachO
  # Classes and constants for parsing section relocation tables in relocatable
  # Mach-O files. Relocation entries are interpreted as paired linker operations;
  # this code does not link or execute their contents.
  module Relocations
    R_SCATTERED = 0x80000000
    R_PCREL = 0x01000000
    R_LENGTH_MASK = 0x06000000
    R_EXTERNAL = 0x08000000
    R_TYPE_MASK = 0xf0000000
    R_SYMBOLNUM_MASK = 0x00ffffff
    R_LENGTH_SHIFT = 25
    R_TYPE_SHIFT = 28
    SIGNED24_MASK = 0x800000
    SIGNED24_MOD = 0x1000000

    X86_64_RELOC_TYPES = {
      0 => :UNSIGNED,
      1 => :SIGNED,
      2 => :BRANCH,
      3 => :GOT_LOAD,
      4 => :GOT,
      5 => :SUBTRACTOR,
      7 => :SIGNED_1,
      8 => :SIGNED_2,
      9 => :SIGNED_4,
      10 => :TLV,
    }.freeze

    ARM64_RELOC_TYPES = {
      0 => :UNSIGNED,
      1 => :SUBTRACTOR,
      2 => :BRANCH26,
      3 => :PAGE21,
      4 => :PAGEOFF12,
      5 => :GOT_LOAD_PAGE21,
      6 => :GOT_LOAD_PAGEOFF12,
      7 => :POINTER_TO_GOT,
      8 => :TLVP_LOAD_PAGE21,
      9 => :TLVP_LOAD_PAGEOFF12,
      10 => :ADDEND,
      11 => :AUTHENTICATED_POINTER,
    }.freeze

    RELOCATION_TYPES = {
      Headers::CPU_TYPE_X86_64 => X86_64_RELOC_TYPES,
      Headers::CPU_TYPE_ARM64 => ARM64_RELOC_TYPES,
    }.freeze

    N_STAB = 0xe0
    N_TYPE = 0x0e
    N_EXT = 0x01
    N_SECT = 0x0e

    def self.signed24(value)
      value -= SIGNED24_MOD if value & SIGNED24_MASK != 0
      value
    end

    def self.signed32(value)
      value >= 0x80000000 ? value - 0x100000000 : value
    end

    RawEntry = Struct.new(:section_index, :entry_index, :address, :value, :info, :scattered, keyword_init: true) do
      def r_address
        scattered ? address & 0x7fffffff : address
      end

      def r_symbolnum
        return nil if scattered

        info & R_SYMBOLNUM_MASK
      end

      def r_pcrel
        !(info & R_PCREL).zero?
      end

      def r_length
        (info & R_LENGTH_MASK) >> R_LENGTH_SHIFT
      end

      def r_extern
        !(info & R_EXTERNAL).zero?
      end

      alias external? r_extern

      alias pc_relative? r_pcrel

      def symbol_index
        r_extern ? r_symbolnum : nil
      end

      def section_ordinal
        r_extern ? nil : r_symbolnum
      end

      def r_type
        return ((address >> 24) & 0x0f) if scattered

        (info & R_TYPE_MASK) >> R_TYPE_SHIFT
      end

      def addend
        return nil unless scattered || r_type == 10

        scattered ? Relocations.signed32(value) : Relocations.signed24(r_symbolnum.to_i)
      end

      def type_name(relocation_types)
        relocation_types[r_type]
      end
    end

    RelocationTarget = Struct.new(:kind, :symbol, :ordinal, :section, :address, keyword_init: true) do
      def external?
        kind == :external
      end

      def local?
        kind == :local
      end

      def section_ordinal
        ordinal
      end

      def to_h
        {
          "kind" => kind,
          "symbol" => symbol && symbol.name,
          "symbol_index" => symbol && symbol.index,
          "section_ordinal" => ordinal,
          "section" => section && "#{section.segname},#{section.sectname}",
          "address" => address,
        }
      end
    end

    class RelocationSymbol
      attr_reader :index, :n_strx, :n_type, :n_sect, :n_desc, :value

      def initialize(index, n_strx, n_type, n_sect, n_desc, value)
        @index = index
        @n_strx = n_strx
        @n_type = n_type
        @n_sect = n_sect
        @n_desc = n_desc
        @value = value
      end

      def external?
        !(n_type & N_EXT).zero?
      end

      def stab?
        (n_type & N_STAB) != 0
      end

      def section_symbol?
        !stab? && (n_type & N_TYPE) == N_SECT
      end

      def name
        @name
      end

      def resolve_name(string_table)
        return if n_strx.negative? || n_strx >= string_table.bytesize

        stop = string_table.index("\0", n_strx) || string_table.bytesize
        @name = string_table[n_strx...stop]
      end

      def to_h
        {
          "index" => index,
          "name" => name,
          "n_strx" => n_strx,
          "n_type" => n_type,
          "n_sect" => n_sect,
          "n_desc" => n_desc,
          "value" => value,
          "external" => external?,
        }
      end
    end

    class RelocationDiagnostic
      attr_reader :id, :message, :section_index, :entry_index, :details

      def initialize(id, message, section_index: nil, entry_index: nil, **details)
        @id = id
        @message = message
        @section_index = section_index
        @entry_index = entry_index
        @details = details
      end

      def to_h
        {
          "id" => id,
          "message" => message,
          "section_index" => section_index,
          "entry_index" => entry_index,
          "details" => details,
        }
      end
    end

    class RelocationOperation
      attr_reader :type, :section, :section_index, :address, :file_offset, :pc_relative,
                  :length, :target, :subtrahend_target, :addend, :instruction_addend,
                  :explicit_addend, :entries, :pair_type, :relation

      def initialize(entry, section, section_index, target, relocation_types, entries:, pair_type:, relation:)
        @entries = entries
        @pair_type = pair_type
        @relation = relation
        @section = section
        @section_index = section_index
        @address = entry.address
        @file_offset = section.offset + entry.address
        @pc_relative = entry.r_pcrel
        @length = entry.r_length
        @type = entry.type_name(relocation_types)
        @target = target
        @subtrahend_target = nil
        @addend = nil
        @instruction_addend = nil
        @explicit_addend = nil
      end

      def paired?
        entries.length > 1
      end

      def entry_indices
        entries.map(&:entry_index)
      end

      def external?
        !target.nil? && target.external?
      end

      def local?
        !target.nil? && target.local?
      end

      alias pc_relative? pc_relative

      def symbol
        target&.symbol
      end

      def symbol_name
        symbol&.name
      end

      def symbol_index
        symbol&.index
      end

      def section_ordinal
        local? ? target.ordinal : nil
      end

      def target_section
        target&.section
      end

      def target_address
        target&.address
      end

      def location
        {
          "section" => "#{section.segname},#{section.sectname}",
          "address" => address,
          "offset" => file_offset,
        }
      end

      def section_name
        "#{section.segname},#{section.sectname}"
      end

      def apply_parts(subtrahend_target:, addend:, instruction_addend:, explicit_addend:)
        @subtrahend_target = subtrahend_target
        @addend = addend
        @instruction_addend = instruction_addend
        @explicit_addend = explicit_addend
      end

      def to_h
        {
          "type" => type,
          "relation" => relation,
          "pair_type" => pair_type,
          "paired" => paired?,
          "section_index" => section_index,
          "section" => "#{section.segname},#{section.sectname}",
          "address" => address,
          "offset" => file_offset,
          "pc_relative" => pc_relative,
          "length" => length,
          "target" => target && target.to_h,
          "subtrahend_target" => subtrahend_target && subtrahend_target.to_h,
          "addend" => addend,
          "instruction_addend" => instruction_addend,
          "explicit_addend" => explicit_addend,
          "entry_indices" => entries.map(&:entry_index),
        }
      end
    end

    class RelocationTable
      include Enumerable
      extend Forwardable

      def_delegators :operations, :each, :size, :length, :[], :first, :last
      attr_reader :operations, :entries, :diagnostics

      def initialize(operations, entries, diagnostics, cputypes_by_section_index)
        @operations = operations
        @entries = entries
        @diagnostics = diagnostics
        @cputypes_by_section_index = cputypes_by_section_index
      end

      def valid?
        diagnostics.empty?
      end

      def strict!
        raise RelocationError, diagnostics.map(&:to_h) unless valid?

        self
      end

      def to_h
        {
          "valid" => valid?,
          "operations" => operations.map(&:to_h),
          "entries" => entries.map(&method(:raw_entry_to_h)),
          "diagnostics" => diagnostics.map(&:to_h),
        }
      end

      private

      def raw_entry_to_h(entry)
        cputype = @cputypes_by_section_index.fetch(entry.section_index)
        relocation_types = RELOCATION_TYPES.fetch(cputype)
        {
          "section_index" => entry.section_index,
          "entry_index" => entry.entry_index,
          "address" => entry.address,
          "value" => entry.value,
          "scattered" => entry.scattered,
          "symbol_or_section" => entry.r_symbolnum,
          "pc_relative" => entry.r_pcrel,
          "length" => entry.r_length,
          "external" => entry.r_extern,
          "type" => entry.type_name(relocation_types),
          "raw_type" => entry.r_type,
        }
      end
    end

    SectionContext = Struct.new(:section, :ordinal, :cputype, keyword_init: true) do
      def offset
        section.offset
      end

      def addr
        section.addr
      end

      def size
        section.size
      end

      def sectname
        section.sectname
      end

      def segname
        section.segname
      end
    end

    class RelocationParser
      EntrySize = 8
      LengthFormats = { 0 => "C", 1 => "S", 2 => "L", 3 => "Q" }.freeze

      def initialize(file)
        @file = file
        @data = file.serialize
        @endianness = file.endianness
        @cputype = file.header.cputype
        @relocation_types = RELOCATION_TYPES[@cputype]
        @diagnostics = []
        @sections = build_sections
        @symbols = parse_symbols
        @raw_entries = []
      end

      def parse
        return empty_table unless @relocation_types

        parse_sections
        operations = build_operations
        cputypes = @sections.transform_values(&:cputype)
        RelocationTable.new(operations, @raw_entries, @diagnostics, cputypes)
      end

      private

      def empty_table
        diagnostics = if @relocation_types
          @diagnostics
        else
          [RelocationDiagnostic.new(:unsupported_architecture,
                                    "relocation parsing is not supported for #{@file.cputype}")]
        end
        RelocationTable.new([], [], diagnostics, {})
      end

      def build_sections
        sections = {}
        ordinal = 0
        @file.segments.each do |segment|
          segment.sections.each do |section|
            ordinal += 1
            sections[ordinal] = SectionContext.new(:section => section, :ordinal => ordinal,
                                                  :cputype => @cputype)
          end
        end
        sections
      end

      def parse_symbols
        symtab = @file.command(:LC_SYMTAB).first
        return {} if symtab.nil?

        symbols = {}
        string_table = read_string_table(symtab)
        size = @file.magic64? ? 16 : 12

        symtab.nsyms.times do |index|
          offset = symtab.symoff + index * size
          bytes = bytes_at(offset, size)
          if bytes.nil?
            diagnostic(:truncated_symbol_table, "symbol table entry #{index} is truncated",
                         :entry_index => index, :offset => offset, :needed => size)
            next
          end

          n_strx, n_type, n_sect, n_desc, value = unpack_nlist(bytes)
          symbol = RelocationSymbol.new(index, n_strx, n_type, n_sect, n_desc, value)
          symbol.resolve_name(string_table) if string_table && n_strx < string_table.bytesize
          symbols[index] = symbol
        end

        symbols
      end

      def read_string_table(symtab)
        return "" if symtab.strsize.zero?

        string_table = bytes_at(symtab.stroff, symtab.strsize)
        if string_table.nil?
          diagnostic(:truncated_string_table, "string table is truncated",
                       :offset => symtab.stroff, :needed => symtab.strsize)
          return ""
        end
        string_table
      end

      def parse_sections
        @sections.each_value do |context|
          parse_section(context)
        end
      end

      def parse_section(context)
        needed = context.section.nreloc * EntrySize
        return if needed.zero?

        bytes = bytes_at(context.section.reloff, needed)
        if bytes.nil?
          diagnostic(:truncated_relocation_table, "relocation table is truncated",
                       :section_index => context.ordinal, :offset => context.section.reloff,
                       :needed => needed)
          return
        end

        context.section.nreloc.times do |entry_index|
          address, info = unpack_many(bytes.byteslice(entry_index * EntrySize, EntrySize), "LL")
          @raw_entries << RawEntry.new(:section_index => context.ordinal,
                                       :entry_index => entry_index,
                                       :address => address & 0x7fffffff,
                                       :value => info,
                                       :info => info,
                                       :scattered => (address & R_SCATTERED) != 0)
        end
      end

      def build_operations
        operations = []
        grouped = {}
        @raw_entries.each do |entry|
          next if grouped[entry_key(entry)]

          if entry.scattered
            diagnostic(:missing_relocation_pair, "scattered relocation has no preceding entry",
                         :section => entry.section_index, :entry => entry.entry_index)
            next
          end

          type = entry.type_name(@relocation_types)
          if type.nil?
            diagnostic(:unsupported_relocation_type, "unsupported relocation type #{entry.r_type}",
                         :section => entry.section_index, :entry => entry.entry_index,
                         :raw_type => entry.r_type)
            next
          end

          entries = [entry]
          pair_type = :single
          relation = :primary
          next_index = entry.entry_index + 1

          if type == :ADDEND
            follower = raw_entry(entry.section_index, next_index)
            if follower.nil? || follower.scattered
              diagnostic(:missing_relocation_pair, "ARM64 ADDEND relocation has no following relocation",
                           :section => entry.section_index, :entry => entry.entry_index)
              next
            end
            unless supported_entry?(follower)
              diagnostic(:unsupported_relocation_type,
                           "ARM64 ADDEND relocation is followed by unsupported relocation type #{follower.r_type}",
                           :section => follower.section_index, :entry => follower.entry_index,
                           :raw_type => follower.r_type)
              next
            end
            if follower.type_name(@relocation_types) == :SUBTRACTOR
              unsigned = raw_entry(entry.section_index, next_index + 1)
              if unsigned.nil? || unsigned.scattered || unsigned.type_name(@relocation_types) != :UNSIGNED
                diagnostic(:missing_relocation_pair,
                             "ARM64 ADDEND/SUBTRACTOR relocation must be followed by UNSIGNED",
                             :section => entry.section_index, :entry => entry.entry_index)
                next
              end
              entries.concat([follower, unsigned])
              pair_type = :addend_subtractor
              relation = :addend_subtractor_followed_by_unsigned
              grouped[entry_key(follower)] = true
              grouped[entry_key(unsigned)] = true
            else
              entries << follower
              pair_type = :addend
              relation = :addend_followed_by_operation
              grouped[entry_key(follower)] = true
            end
          elsif type == :SUBTRACTOR
            follower = raw_entry(entry.section_index, next_index)
            if follower.nil? || follower.scattered || follower.type_name(@relocation_types) != :UNSIGNED
              diagnostic(:missing_relocation_pair, "SUBTRACTOR relocation must be followed by UNSIGNED",
                           :section => entry.section_index, :entry => entry.entry_index)
              next
            end
            entries << follower
            pair_type = :subtractor
            relation = :subtractor_followed_by_unsigned
            grouped[entry_key(follower)] = true
          elsif @cputype == Headers::CPU_TYPE_X86_64 && [:SIGNED, :SIGNED_1, :SIGNED_2, :SIGNED_4].include?(type)
            follower = raw_entry(entry.section_index, next_index)
            if follower&.scattered
              entries << follower
              pair_type = :signed
              relation = :signed_followed_by_scattered_addend
              grouped[entry_key(follower)] = true
            end
          end

          operation = create_operation(entries, pair_type, relation)
          operations << operation if operation
        end
        operations
      end

      def entry_key(entry)
        [entry.section_index, entry.entry_index]
      end

      def raw_entry(section_index, entry_index)
        @raw_entries.find { |entry| entry.section_index == section_index && entry.entry_index == entry_index }
      end

      def supported_entry?(entry)
        !entry.type_name(@relocation_types).nil?
      end

      def create_operation(entries, pair_type, relation)
        explicit_entry, subtrahend_entry, primary_entry = paired_entries(entries, pair_type)
        context = @sections.fetch(primary_entry.section_index)
        target = resolve_target(primary_entry, context)
        return nil if target.nil?

        operation = RelocationOperation.new(primary_entry, context, context.ordinal, target,
                                            @relocation_types, :entries => entries,
                                            :pair_type => pair_type, :relation => relation)
        subtrahend_target = subtrahend_entry.nil? ? nil : resolve_target(subtrahend_entry, context)
        explicit = explicit_entry&.addend
        instruction = instruction_addend(primary_entry, context, :paired => pair_type == :signed)
        semantic = explicit || semantic_addend(primary_entry, context, target, instruction)
        operation.apply_parts(:subtrahend_target => subtrahend_target,
                              :addend => semantic,
                              :instruction_addend => instruction,
                              :explicit_addend => explicit)
        operation
      end

      def paired_entries(entries, pair_type)
        case pair_type
        when :single
          [nil, nil, entries.first]
        when :addend
          [entries.first, nil, entries.last]
        when :subtractor
          [nil, entries.first, entries.last]
        when :addend_subtractor
          [entries[0], entries[1], entries[2]]
        when :signed
          [entries.last, nil, entries.first]
        end
      end

      def resolve_target(entry, context)
        if entry.r_extern
          symbol = @symbols[entry.r_symbolnum]
          if symbol.nil?
            diagnostic(:symbol_index_out_of_bounds,
                         "external symbol index #{entry.r_symbolnum} is out of bounds",
                         :section => context.ordinal, :entry => entry.entry_index,
                         :symbol_index => entry.r_symbolnum)
            return nil
          end
          RelocationTarget.new(:kind => :external, :symbol => symbol,
                               :ordinal => nil, :section => nil, :address => symbol.value)
        else
          ordinal = entry.r_symbolnum
          section = @sections[ordinal]
          if section.nil?
            diagnostic(:section_ordinal_out_of_bounds,
                         "local section ordinal #{ordinal} is out of bounds",
                         :section => context.ordinal, :entry => entry.entry_index,
                         :section_ordinal => ordinal)
            return nil
          end
          RelocationTarget.new(:kind => :local, :symbol => nil, :ordinal => ordinal,
                               :section => section.section, :address => section.addr)
        end
      end

      def instruction_addend(entry, context, paired: false)
        return nil unless supported_length?(entry, context)

        bytes = relocatable_bytes(entry, context, :paired => paired)
        return nil if bytes.nil?

        case entry.type_name(@relocation_types)
        when :UNSIGNED, :SUBTRACTOR
          unpack_integer(bytes, entry.r_length, false)
        when :POINTER_TO_GOT
          unpack_integer(bytes, entry.r_length, true)
        when :SIGNED, :SIGNED_1, :SIGNED_2, :SIGNED_4, :BRANCH, :GOT_LOAD, :GOT, :TLV
          x86_instruction_addend(entry, bytes, paired)
        when :BRANCH26, :GOT_LOAD_PAGE21, :GOT_LOAD_PAGEOFF12, :TLVP_LOAD_PAGE21,
             :TLVP_LOAD_PAGEOFF12, :PAGE21, :PAGEOFF12
          arm64_instruction_addend(entry, bytes)
        when :ADDEND
          nil
        end
      end

      def x86_instruction_addend(entry, bytes, paired = false)
        return 0 if paired

        value = unpack_integer(bytes, entry.r_length, true)
        return value if !entry.r_pcrel || entry.type_name(@relocation_types) == :BRANCH

        signed_types = [:SIGNED, :SIGNED_1, :SIGNED_2, :SIGNED_4]
        return value if signed_types.include?(entry.type_name(@relocation_types))

        value - entry.address - byte_count(entry.r_length)
      end

      def arm64_instruction_addend(entry, bytes)
        instruction = unpack_integer(bytes, 2, false)
        case entry.type_name(@relocation_types)
        when :BRANCH26
          sign_extend((instruction & 0x03ffffff) << 2, 28)
        when :PAGE21, :GOT_LOAD_PAGE21, :TLVP_LOAD_PAGE21
          low = (instruction >> 29) & 3
          high = (instruction >> 5) & 0x7ffff
          sign_extend((high << 2) | low, 21)
        when :PAGEOFF12, :GOT_LOAD_PAGEOFF12, :TLVP_LOAD_PAGEOFF12
          arm64_pageoff12(instruction)
        end
      end

      def arm64_pageoff12(instruction)
        imm12 = (instruction >> 10) & 0xfff
        if instruction & 0x00800000 != 0
          size = (instruction >> 30) & 3
          imm12 << [1, 2, 4, 8].fetch(size, 0)
        else
          imm12
        end
      end

      def semantic_addend(entry, context, target, instruction)
        return nil if instruction.nil?

        case entry.type_name(@relocation_types)
        when :UNSIGNED, :SUBTRACTOR
          entry.r_extern ? instruction : target.address + instruction
        when :SIGNED
          instruction
        when :SIGNED_1, :SIGNED_2, :SIGNED_4, :GOT_LOAD, :GOT, :TLV
          entry.r_extern ? instruction : target.address + instruction
        when :BRANCH
          instruction
        when :BRANCH26, :PAGE21, :PAGEOFF12, :GOT_LOAD_PAGE21, :GOT_LOAD_PAGEOFF12,
             :TLVP_LOAD_PAGE21, :TLVP_LOAD_PAGEOFF12
          instruction
        else
          instruction
        end
      end

      def relocatable_bytes(entry, context, paired: false)
        count = byte_count(entry.r_length)
        offset = relocatable_offset(entry, context, :paired => paired)
        bytes = bytes_at(offset, count)
        return bytes if bytes

        diagnostic(:relocation_out_of_bounds, "relocation location is outside its section",
                     :section => context.ordinal, :entry => entry.entry_index,
                     :address => entry.address, :needed => count)
        nil
      end

      def relocatable_offset(entry, context, paired: false)
        address = entry.address
        x86_pcrel = @cputype == Headers::CPU_TYPE_X86_64 && entry.r_pcrel
        type_name = entry.type_name(@relocation_types)
        no_adjust_types = [:BRANCH, :SIGNED, :SIGNED_1, :SIGNED_2, :SIGNED_4]
        address += 1 if x86_pcrel && !paired && !no_adjust_types.include?(type_name)
        context.offset + address
      end

      def byte_count(length)
        1 << length
      end

      def unpack_integer(bytes, length, signed)
        base = LengthFormats.fetch(length)
        format = if !signed || base == "C"
          base
        else
          { "S" => "s", "L" => "l", "Q" => "q" }.fetch(base)
        end
        format += endian_format
        bytes.unpack1(format)
      end

      def supported_length?(entry, context)
        return true if LengthFormats.key?(entry.r_length)

        diagnostic(:unsupported_relocation_length, "unsupported relocation length #{entry.r_length}",
                     :section => context.ordinal, :entry => entry.entry_index,
                     :length => entry.r_length)
        false
      end

      def sign_extend(value, bits)
        modulo = 1 << bits
        value >= (1 << (bits - 1)) ? value - modulo : value
      end

      def bytes_at(offset, size)
        return nil if offset.negative? || size.negative? || offset + size > @data.bytesize

        @data.byteslice(offset, size)
      end

      def unpack_many(bytes, abstract_format)
        endian = @endianness == :big ? ">" : "<"
        bytes.unpack(abstract_format + endian)
      end

      def unpack_nlist(bytes)
        n_strx = bytes.unpack1("L#{endian_format}")
        n_type = bytes.getbyte(4)
        n_sect = bytes.getbyte(5)
        n_desc = bytes.byteslice(6, 2).unpack1("v")
        value_size = @file.magic64? ? 8 : 4
        value_format = (@file.magic64? ? "Q" : "l") + endian_format
        value = bytes.byteslice(8, value_size).unpack1(value_format)
        [n_strx, n_type, n_sect, n_desc, value]
      end

      def endian_format
        @endianness == :big ? ">" : "<"
      end

      def diagnostic(id, message, section: nil, entry: nil, **details)
        @diagnostics << RelocationDiagnostic.new(id, message, :section_index => section,
                                                  :entry_index => entry, **details)
      end
    end
  end
end
