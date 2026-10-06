# frozen_string_literal: true

require "forwardable"

module MachO
  # Read-only parsing of `LC_DYLD_CHAINED_FIXUPS` payloads, including the
  # chains of {Fixup}s that dyld applies at load time. This module never
  # modifies the image and does not compute pointer authentication (PAC):
  # authenticated pointers expose their key and diversity information.
  #
  # Supported pointer formats:
  # - `DYLD_CHAINED_PTR_64` (2)
  # - `DYLD_CHAINED_PTR_64_OFFSET` (6)
  # - `DYLD_CHAINED_PTR_ARM64E_USERLAND` (9)
  # - `DYLD_CHAINED_PTR_ARM64E_USERLAND24` (12, decoded identically except
  #   for its 24-bit bind ordinal)
  #
  # All three import encodings are supported:
  # - `DYLD_CHAINED_IMPORT` (1)
  # - `DYLD_CHAINED_IMPORT_ADDEND` (2)
  # - `DYLD_CHAINED_IMPORT_ADDEND64` (3)
  module ChainedFixups
    # pointer formats, see `mach-o/fixup-chains.h`
    POINTER_FORMATS = {
      1 => :DYLD_CHAINED_PTR_ARM64E,
      2 => :DYLD_CHAINED_PTR_64,
      3 => :DYLD_CHAINED_PTR_32,
      4 => :DYLD_CHAINED_PTR_32_CACHE,
      5 => :DYLD_CHAINED_PTR_32_FIRMWARE,
      6 => :DYLD_CHAINED_PTR_64_OFFSET,
      7 => :DYLD_CHAINED_PTR_ARM64E_KERNEL,
      8 => :DYLD_CHAINED_PTR_64_KERNEL_CACHE,
      9 => :DYLD_CHAINED_PTR_ARM64E_USERLAND,
      10 => :DYLD_CHAINED_PTR_ARM64E_FIRMWARE,
      11 => :DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE,
      12 => :DYLD_CHAINED_PTR_ARM64E_USERLAND24,
      13 => :DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE,
      14 => :DYLD_CHAINED_PTR_ARM64E_SEGMENTED,
    }.freeze

    # pointer formats understood by this parser
    SUPPORTED_POINTER_FORMATS = {
      2 => :DYLD_CHAINED_PTR_64,
      6 => :DYLD_CHAINED_PTR_64_OFFSET,
      9 => :DYLD_CHAINED_PTR_ARM64E_USERLAND,
      12 => :DYLD_CHAINED_PTR_ARM64E_USERLAND24,
    }.freeze

    # imports format, see `dyld_chained_fixups_header.imports_format`
    IMPORT_FORMATS = {
      1 => :DYLD_CHAINED_IMPORT,
      2 => :DYLD_CHAINED_IMPORT_ADDEND,
      3 => :DYLD_CHAINED_IMPORT_ADDEND64,
    }.freeze

    IMPORT_RECORD_SIZES = {
      1 => 4,
      2 => 8,
      3 => 16,
    }.freeze

    # special values in `page_start[]`
    START_NONE = 0xFFFF
    START_MULTI = 0x8000
    START_LAST = 0x8000

    # `dyld_chained_fixups_header.symbols_format` values
    SYMBOLS_UNCOMPRESSED = 0
    SYMBOLS_COMPRESSED = 1

    # size of the leading fields of `dyld_chained_starts_in_segment`
    STARTS_IN_SEGMENT_HEADER_SIZE = 22

    # well-known negative `dylib ordinal` values and their names
    SPECIAL_LIB_ORDINALS = {
      -1 => :EXECUTABLE_ORDINAL,
      -2 => :DYLIB_ORDINAL_MAIN,
      -3 => :DYLIB_ORDINAL_LOADED_LAZY,
      -7 => :DYLIB_ORDINAL_ITSHELF,
      -8 => :DYLIB_ORDINAL_PRIV,
      -9 => :DYLIB_ORDINAL_EXEC_GROUP,
      -15 => :DYLIB_ORDINAL_CREATOR,
    }.freeze

    # PAC key discriminator values
    KEYS = {
      0 => :IA,
      1 => :IB,
      2 => :DA,
      3 => :DB,
    }.freeze

    # A single imported symbol as referenced by an `ordinal` in a bind pointer.
    class Import
      # @return [Integer] ordinal of this import within the imports table
      attr_reader :ordinal

      # @return [Integer] raw signed dylib ordinal (see `dylib_special_ordinal`)
      attr_reader :lib_ordinal

      # @return [Boolean] whether the symbol is a weak import
      attr_reader :weak_import

      # @return [Integer] offset of the name within the symbol strings pool
      attr_reader :name_offset

      # @return [String] the symbol name
      attr_reader :name

      # @return [Integer] addend encoded in the import table (0 for
      #  `DYLD_CHAINED_IMPORT`)
      attr_reader :table_addend

      # @api private
      def initialize(ordinal, lib_ordinal, weak_import, name_offset, name,
                     table_addend)
        @ordinal = ordinal
        @lib_ordinal = lib_ordinal
        @weak_import = weak_import
        @name_offset = name_offset
        @name = name
        @table_addend = table_addend
      end

      # @return [Symbol, Integer] the resolved dylib ordinal: a positive
      #  index into the image's dylib load commands, or a special symbol
      #  such as `:EXECUTABLE_ORDINAL`
      def dylib_special_ordinal
        SPECIAL_LIB_ORDINALS.fetch(@lib_ordinal, @lib_ordinal)
      end

      # @return [Hash] a hash representation of this {Import}
      def to_h
        {
          "ordinal" => ordinal,
          "lib_ordinal" => lib_ordinal,
          "dylib_ordinal" => dylib_special_ordinal,
          "weak_import" => weak_import,
          "name_offset" => name_offset,
          "name" => name,
          "table_addend" => table_addend,
        }
      end
    end

    # A single entry in a fixup chain, i.e. one pointer slot that dyld fills
    # in when the image is loaded.
    class Fixup
      # @return [Integer] file offset of the 64-bit pointer slot
      attr_reader :file_offset

      # @return [Integer] runtime address of the pointer slot relative to the
      #  image base (`vmaddr - slide_base`)
      attr_reader :runtime_offset

      # @return [Integer] runtime address of the pointer slot as a vmaddr
      attr_reader :vmaddr

      # @return [Symbol] `:rebase` or `:bind`
      attr_reader :kind

      # @return [Symbol] the pointer format (`DYLD_CHAINED_PTR_*`)
      attr_reader :pointer_format

      # @return [Integer] total signed addend applied to the target
      attr_reader :addend

      # @return [Integer, nil] for rebases, the target's vmaddr
      #  (`DYLD_CHAINED_PTR_64`) or nil for image-relative targets
      attr_reader :target_vmaddr

      # @return [Integer, nil] for rebases, the target's runtime offset
      #  (`DYLD_CHAINED_PTR_64_OFFSET`, ARM64E) or the encoded image-relative
      #  component of `DYLD_CHAINED_PTR_64`
      attr_reader :target_runtime_offset

      # @return [Integer, nil] top 8 bits of the target vmaddr (ARM64E
      #  unauthenticated pointers)
      attr_reader :high8

      # @return [Import, nil] the imported symbol for binds
      attr_reader :import

      # @return [Integer, nil] raw ordinal into the imports table for binds
      attr_reader :ordinal

      # @return [Boolean] whether this is an authenticated pointer
      attr_reader :authenticated

      # @return [Symbol, nil] PAC key (`:IA`, `:IB`, `:DA`, `:DB`)
      attr_reader :key

      # @return [Integer, nil] raw PAC key discriminator (0..3)
      attr_reader :key_discriminator

      # @return [Integer, nil] PAC diversity
      attr_reader :diversity

      # @return [Boolean, nil] whether address diversity is requested
      attr_reader :address_diversity

      # @api private
      def initialize(file_offset:, runtime_offset:, vmaddr:, kind:,
                     pointer_format:, addend:, target_vmaddr: nil,
                     target_runtime_offset: nil, high8: nil, import: nil,
                     ordinal: nil, authenticated: false, key: nil,
                     key_discriminator: nil, diversity: nil,
                     address_diversity: nil)
        @file_offset = file_offset
        @runtime_offset = runtime_offset
        @vmaddr = vmaddr
        @kind = kind
        @pointer_format = pointer_format
        @addend = addend
        @target_vmaddr = target_vmaddr
        @target_runtime_offset = target_runtime_offset
        @high8 = high8
        @import = import
        @ordinal = ordinal
        @authenticated = authenticated
        @key = key
        @key_discriminator = key_discriminator
        @diversity = diversity
        @address_diversity = address_diversity
      end

      # @return [Boolean] whether this fixup is a bind
      def bind?
        kind == :bind
      end

      # @return [Boolean] whether this fixup is a rebase
      def rebase?
        kind == :rebase
      end

      # @return [String, nil] the bound symbol name
      def symbol
        import&.name
      end

      # @return [Hash] a hash representation of this {Fixup}
      def to_h
        {
          "file_offset" => file_offset,
          "runtime_offset" => runtime_offset,
          "vmaddr" => vmaddr,
          "kind" => kind,
          "pointer_format" => pointer_format,
          "addend" => addend,
          "target_vmaddr" => target_vmaddr,
          "target_runtime_offset" => target_runtime_offset,
          "high8" => high8,
          "ordinal" => ordinal,
          "symbol" => symbol,
          "authenticated" => authenticated,
          "key" => key,
          "key_discriminator" => key_discriminator,
          "diversity" => diversity,
          "address_diversity" => address_diversity,
        }
      end
    end

    # Enumerates every fixup in an `LC_DYLD_CHAINED_FIXUPS` payload of a
    # {MachOFile}. The enumeration is read-only and eager: all fixups and
    # imports are decoded when the instance is created so that structural
    # errors surface immediately.
    class ChainedFixupSet
      include Enumerable
      extend Forwardable

      # @return [Integer] fixups header version
      attr_reader :fixups_version

      # @return [Integer] raw imports format constant
      attr_reader :imports_format

      # @return [Symbol] `:DYLD_CHAINED_IMPORT`, etc.
      attr_reader :imports_format_name

      # @return [Integer] raw symbols format constant
      attr_reader :symbols_format

      # @return [Array<Import>] the decoded imports table
      attr_reader :imports

      # @return [Array<Fixup>] every fixup, in file order
      attr_reader :fixups

      # Parses the chained fixups payload of `macho` starting at the given
      # {LoadCommands::LinkeditDataCommand}.
      # @param macho [MachOFile] the image containing the payload
      # @param command [LoadCommands::LinkeditDataCommand] the
      #  `LC_DYLD_CHAINED_FIXUPS` load command
      # @return [ChainedFixupSet]
      def self.parse(macho, command)
        new(macho, command).parse!
      end

      # @!method each
      #  Iterates over every {Fixup}.
      #  @return [Enumerator]
      def_delegator :fixups, :each
      def_delegators :fixups, :length, :size, :empty?

      # @return [Fixup, nil] the fixup whose pointer slot is at the given
      #  file offset
      def fixup_at_file_offset(offset)
        @fixups_by_file_offset[offset]
      end

      # @return [Array<Fixup>] all bind fixups
      def binds
        fixups.select(&:bind?)
      end

      # @return [Array<Fixup>] all rebase fixups
      def rebases
        fixups.select(&:rebase?)
      end

      # @return [Hash] a hash representation of this {ChainedFixupSet}
      def to_h
        {
          "fixups_version" => fixups_version,
          "imports_format" => imports_format,
          "imports_format_name" => imports_format_name,
          "symbols_format" => symbols_format,
          "imports" => imports.map(&:to_h),
          "fixups" => fixups.map(&:to_h),
        }
      end

      protected

      def initialize(macho, command)
        @macho = macho
        @command = command
        @raw = macho.serialize
        @base = command.dataoff
        @size = command.datasize
        @fixups = []
        @fixups_by_file_offset = {}
      end

      private

      # Reads bytes within the fixups payload.
      # @param rel [Integer] offset relative to the payload base
      # @param length [Integer] number of bytes
      # @param what [String] description used in errors
      def read_payload(rel, length, what)
        abs = @base + rel
        if rel < 0 || length < 0 || abs + length > @raw.bytesize ||
           rel + length > @size || abs < 0
          raise ChainedFixupError,
                "#{what} (payload offset 0x#{rel.to_s(16)}, #{length} bytes) " \
                "extends beyond the LC_DYLD_CHAINED_FIXUPS payload " \
                "(file offset 0x#{@base.to_s(16)}, size #{@size})"
        end

        @raw.byteslice(abs, length)
      end

      def read_u16_payload(rel, what)
        read_payload(rel, 2, what).unpack1("v")
      end

      def read_u32_payload(rel, what)
        read_payload(rel, 4, what).unpack1("V")
      end

      def read_i32_payload(rel, what)
        read_payload(rel, 4, what).unpack1("l<")
      end

      def read_u64_payload(rel, what)
        read_payload(rel, 8, what).unpack1("Q<")
      end

      def read_i64_payload(rel, what)
        read_payload(rel, 8, what).unpack1("q<")
      end

      # Reads the raw 64-bit chained pointer at a file offset.
      def read_slot(file_offset, location)
        if file_offset < 0 || file_offset + 8 > @raw.bytesize
          raise ChainedFixupError,
                "#{location}: pointer slot at file offset " \
                "0x#{file_offset.to_s(16)} is outside the image"
        end

        @raw.byteslice(file_offset, 8).unpack1("Q<")
      end

      public def parse!
        unless @macho.magic64?
          raise ChainedFixupError,
                "LC_DYLD_CHAINED_FIXUPS is only supported in 64-bit images"
        end

        if @macho.endianness != :little
          raise ChainedFixupError,
                "LC_DYLD_CHAINED_FIXUPS payloads are little-endian"
        end

        if @base < 0 || @size < 28 || @base + @size > @raw.bytesize
          raise ChainedFixupError,
                "LC_DYLD_CHAINED_FIXUPS dataoff=0x#{@base.to_s(16)}, " \
                "datasize=#{@size} points outside the image " \
                "(#{@raw.bytesize} bytes)"
        end

        parse_header
        parse_symbols
        parse_imports
        parse_starts

        self
      end

      def parse_header
        header = read_payload(0, 28, "fixups header").unpack("V7")
        @fixups_version = header[0]
        @starts_offset = header[1]
        @imports_offset = header[2]
        @symbols_offset = header[3]
        @imports_count = header[4]
        @imports_format = header[5]
        @symbols_format = header[6]

        @imports_format_name = IMPORT_FORMATS[@imports_format]
        if @imports_format_name.nil?
          raise ChainedFixupError,
                "unknown chained imports format #{@imports_format} in " \
                "LC_DYLD_CHAINED_FIXUPS header at file offset " \
                "0x#{@base.to_s(16)}"
        end

        unless [SYMBOLS_UNCOMPRESSED, SYMBOLS_COMPRESSED].include?(@symbols_format)
          raise ChainedFixupError,
                "unknown chained symbols format #{@symbols_format} in " \
                "LC_DYLD_CHAINED_FIXUPS header at file offset " \
                "0x#{@base.to_s(16)}"
        end

        check_payload_offset(:starts_offset, @starts_offset, allow_zero: true)
        check_payload_offset(:imports_offset, @imports_offset, allow_zero: @imports_count.zero?)
        check_payload_offset(:symbols_offset, @symbols_offset, allow_zero: true)

        return if @starts_offset.zero? && @imports_count.zero?

        if @starts_offset.zero?
          raise ChainedFixupError,
                "LC_DYLD_CHAINED_FIXUPS header declares #{@imports_count} " \
                "imports but starts_offset is 0"
        end

        unless @imports_offset.zero? || @imports_count.zero?
          table_size = @imports_count * IMPORT_RECORD_SIZES.fetch(@imports_format)
          check_payload_range(@imports_offset, table_size, "imports table")
        end

        unless @symbols_offset.zero?
          check_payload_range(@symbols_offset, @size - @symbols_offset,
                               "symbol strings pool")
        end
      end

      def check_payload_offset(field, offset, allow_zero:)
        return if offset.zero? && allow_zero
        if offset > @size
          raise ChainedFixupError,
                "LC_DYLD_CHAINED_FIXUPS #{field} 0x#{offset.to_s(16)} is " \
                "outside the payload (size #{@size})"
        end
      end

      def check_payload_range(offset, length, what)
        if length < 0 || offset + length > @size
          raise ChainedFixupError,
                "#{what} (payload offset 0x#{offset.to_s(16)}, #{length} bytes) " \
                "extends beyond the LC_DYLD_CHAINED_FIXUPS payload (size #{@size})"
        end
      end

      def parse_symbols
        @symbols_data = if @symbols_offset.zero? || @symbols_offset >= @size
          ""
        else
          read_payload(@symbols_offset, @size - @symbols_offset,
                        "symbol strings pool")
        end
        @symbol_names_by_offset = {}

        case @symbols_format
        when SYMBOLS_UNCOMPRESSED
          parse_uncompressed_symbols
        when SYMBOLS_COMPRESSED
          parse_compressed_symbols
        end
      end

      def parse_uncompressed_symbols
        pos = 0
        while pos < @symbols_data.bytesize
          name = uncompressed_symbol_at(pos)
          @symbol_names_by_offset[pos] = name
          pos += name.bytesize + 1
        end
      end

      def uncompressed_symbol_at(pos)
        null = @symbols_data.index("\0", pos)
        raise_unterminated_symbol(pos) if null.nil?

        @symbols_data.byteslice(pos, null - pos)
      end

      def parse_compressed_symbols
        pos = 0
        while pos < @symbols_data.bytesize
          start = pos
          length, advanced = read_uleb128(pos, "compressed symbol length")
          pos += advanced
          if pos + length > @symbols_data.bytesize
            raise ChainedFixupError,
                  "compressed symbol (payload offset " \
                  "0x#{(@symbols_offset + start).to_s(16)}, length #{length}) " \
                  "extends beyond the symbol strings pool"
          end

          name = @symbols_data.byteslice(pos, length)
          @symbol_names_by_offset[start] = name
          # Import records may reference either the ULEB128 prefix or the
          # first symbol byte directly.
          @symbol_names_by_offset[pos] = name
          pos += length
        end
      end

      def read_uleb128(pos, what)
        result = 0
        shift = 0
        start = pos
        loop do
          if pos >= @symbols_data.bytesize
            raise ChainedFixupError,
                  "#{what} (payload offset " \
                  "0x#{(@symbols_offset + start).to_s(16)}) is truncated"
          end

          byte = @symbols_data.getbyte(pos)
          pos += 1
          result |= (byte & 0x7f) << shift
          return [result, pos - start] if byte.nobits?(0x80)

          shift += 7
          if shift > 63
            raise ChainedFixupError,
                  "#{what} (payload offset " \
                  "0x#{(@symbols_offset + start).to_s(16)}) is too large"
          end
        end
      end

      def raise_unterminated_symbol(pos)
        raise ChainedFixupError,
              "symbol name at payload offset " \
              "0x#{(@symbols_offset + pos).to_s(16)} is not NUL-terminated"
      end

      def symbol_name_for(name_offset, ordinal)
        if name_offset > @symbols_data.bytesize
          raise ChainedFixupError,
                "import ordinal #{ordinal} references symbol pool offset " \
                "0x#{name_offset.to_s(16)} outside of the pool " \
                "(#{@symbols_data.bytesize} bytes)"
        end

        if @symbols_format == SYMBOLS_COMPRESSED
          return @symbol_names_by_offset.fetch(name_offset) do
            raise ChainedFixupError,
                  "import ordinal #{ordinal} references compressed symbol at " \
                  "payload offset 0x#{(@symbols_offset + name_offset).to_s(16)} " \
                  "which is not the start of a symbol"
          end
        else
          return @symbol_names_by_offset.fetch(name_offset) do
            uncompressed_symbol_at(name_offset)
          end
        end
      end

      def parse_imports
        record_size = IMPORT_RECORD_SIZES.fetch(@imports_format)
        @imports = Array.new(@imports_count) do |ordinal|
          rel = @imports_offset + ordinal * record_size
          case @imports_format
          when 1
            raw = read_u32_payload(rel, "import ordinal #{ordinal}")
            lib_ordinal, weak, name_offset = decode_import_word(raw, 8, 32, 23, ordinal)
            table_addend = 0
          when 2
            raw = read_u32_payload(rel, "import ordinal #{ordinal}")
            lib_ordinal, weak, name_offset = decode_import_word(raw, 8, 32, 23, ordinal)
            table_addend = read_i32_payload(rel + 4, "import ordinal #{ordinal} addend")
          when 3
            raw = read_u64_payload(rel, "import ordinal #{ordinal}")
            lib_ordinal, weak, name_offset = decode_import_word(raw, 16, 64, 32, ordinal)
            table_addend = read_i64_payload(rel + 8, "import ordinal #{ordinal} addend")
          end

          name = symbol_name_for(name_offset, ordinal)
          Import.new(ordinal, lib_ordinal, weak, name_offset, name, table_addend)
        end
      end

      def sign8(value)
        value >= 0x80 ? value - 0x100 : value
      end

      def sign16(value)
        value >= 0x8000 ? value - 0x10000 : value
      end

      # Decodes one import word. The classic `dyld_chained_import` layout
      # packs the signed dylib ordinal in the top `ord_bits`, the weak flag
      # below it and the symbol-pool byte offset in the low bits. Modern
      # linkers emit a compact layout: `(byte_offset << 9) |
      # 0x200 | (lib_ordinal << 1) | (weak << 8)`. The two are disambiguated
      # by which decoded name offset lands on a symbol-pool string boundary.
      def decode_import_word(raw, ord_bits, total_bits, name_bits, ordinal)
        ord_shift = total_bits - ord_bits
        compact = [
          sign_n((raw >> 1) & 0x7f, 7),
          (raw & 0x100) != 0,
          raw >> 9,
        ]
        classic = [
          sign_n((raw >> ord_shift) & ((1 << ord_bits) - 1), ord_bits),
          ((raw >> (ord_shift - 1)) & 1) == 1,
          raw & ((1 << name_bits) - 1),
        ]
        candidates = [compact, classic]
        chosen = candidates.find { |candidate| valid_symbol_offset?(candidate[2]) }
        unless chosen
          raise ChainedFixupError,
                "import ordinal #{ordinal} does not reference a valid " \
                "symbol pool offset (raw 0x#{raw.to_s(16)})"
        end
        chosen
      end

      def valid_symbol_offset?(offset)
        return true if @symbol_names_by_offset.key?(offset)
        return false if offset >= @symbols_data.bytesize

        if @symbols_format == SYMBOLS_COMPRESSED
          begin
            length, advanced = read_uleb128(offset, "compressed symbol length")
            offset + advanced + length <= @symbols_data.bytesize
          rescue ChainedFixupError
            false
          end
        else
          !@symbols_data.index("\0", offset).nil?
        end
      end

      def sign_n(value, bits)
        value >= (1 << (bits - 1)) ? value - (1 << bits) : value
      end

      def parse_starts
        starts_in_image = @starts_offset
        seg_count = read_u32_payload(starts_in_image, "seg_count")
        seg_info_table = starts_in_image + 4

        # Validate the whole seg_info_offset[] table up front so that 64-bit
        # segment indexes can be trusted.
        read_payload(seg_info_table, seg_count * 4, "seg_info_offset table")

        @seg_info_offsets = Array.new(seg_count) do |seg_index|
          read_u32_payload(seg_info_table + seg_index * 4,
                           "seg_info_offset[#{seg_index}]")
        end

        @seg_info_offsets.each_with_index do |offset, seg_index|
          next if offset.zero?

          parse_segment_starts(seg_index, offset)
        end
      end

      def parse_segment_starts(seg_index, seg_info_offset)
        rel = @starts_offset + seg_info_offset
        location = "segment #{seg_index}"

        fields = read_payload(rel, STARTS_IN_SEGMENT_HEADER_SIZE,
                              "dyld_chained_starts_in_segment for #{location}")
        size = fields[0, 4].unpack1("V")
        page_size = fields[4, 2].unpack1("v")
        pointer_format = fields[6, 2].unpack1("v")
        page_count = fields[20, 2].unpack1("v")

        format_name = POINTER_FORMATS[pointer_format]
        if format_name.nil?
          raise ChainedFixupError,
                "#{location}: unknown chained pointer format " \
                "#{pointer_format} (at payload offset 0x#{rel.to_s(16)})"
        end

        unless SUPPORTED_POINTER_FORMATS.key?(pointer_format)
          raise ChainedFixupError,
                "#{location}: unsupported chained pointer format " \
                "#{format_name} (#{pointer_format}); only " \
                "DYLD_CHAINED_PTR_64, DYLD_CHAINED_PTR_64_OFFSET and " \
                "DYLD_CHAINED_PTR_ARM64E_USERLAND (and USERLAND24) are supported"
        end

        if page_size.zero? || (page_size & (page_size - 1)) != 0
          raise ChainedFixupError,
                "#{location}: invalid chained fixups page size 0x#{page_size.to_s(16)}"
        end

        if size < STARTS_IN_SEGMENT_HEADER_SIZE + page_count * 2
          raise ChainedFixupError,
                "#{location}: starts_in_segment size #{size} is too small for " \
                "#{page_count} page entries (needs at least " \
                "#{STARTS_IN_SEGMENT_HEADER_SIZE + page_count * 2} bytes)"
        end

        segment = segment_for(seg_index, location)
        stride = [9, 12].include?(pointer_format) ? 8 : 4

        page_starts_rel = rel + STARTS_IN_SEGMENT_HEADER_SIZE
        multi_start_rel = page_starts_rel + page_count * 2
        chain_starts_limit = rel + size

        page_count.times do |page_index|
          entry = read_u16_payload(page_starts_rel + page_index * 2,
                                   "#{location} page_start[#{page_index}]")
          next if entry == START_NONE

          starts = starts_for_page(rel, entry, multi_start_rel, chain_starts_limit,
                                   size, location, page_index)
          starts.each do |page_start|
            walk_chain(segment, seg_index, page_index, page_start, page_size,
                       stride, pointer_format, format_name, location)
          end
        end
      end

      def segment_for(seg_index, location)
        segments = @macho.segments
        if seg_index >= segments.length
          raise ChainedFixupError,
                "#{location}: segment index #{seg_index} is out of range " \
                "(image has #{segments.length} segments)"
        end

        segment = segments[seg_index]
        segment
      end

      # Expands a `page_start[]` entry into one or more in-page offsets.
      def starts_for_page(seg_rel, entry, multi_start_rel,
                          chain_starts_limit, size, location, page_index)
        return [entry] if entry.nobits?(START_MULTI)

        chain_index = entry & 0x7fff
        starts = []
        loop do
          chain_rel = multi_start_rel + chain_index * 2
          if chain_rel + 2 > chain_starts_limit
            raise ChainedFixupError,
                  "#{location} page #{page_index}: multi-start index " \
                  "#{chain_index} (payload offset 0x#{chain_rel.to_s(16)}) " \
                  "extends beyond the starts_in_segment record at payload " \
                  "offset 0x#{seg_rel.to_s(16)} (size #{size})"
          end

          start_entry = read_u16_payload(chain_rel,
                                         "#{location} page #{page_index} chain_starts[#{chain_index}]")
          last = (start_entry & START_LAST) != 0
          starts << (start_entry & 0x7fff)
          chain_rel += 2
          chain_index += 1
          break if last
        end
        starts
      end

      def image_base
        @image_base ||= begin
          first = @macho.segments.find { |seg| seg.vmaddr != 0 }
          first&.vmaddr || 0
        end
      end

      # Walks one chain starting at `page_start` bytes into a page.
      def walk_chain(segment, seg_index, page_index, page_start, page_size,
                     stride, pointer_format, format_name, location)
        page_base_vm = segment.vmaddr + page_index * page_size
        page_base_file = segment.fileoff + page_index * page_size
        page_location = "#{location}, page #{page_index}"

        if page_start >= page_size
          raise ChainedFixupError,
                "#{page_location}: chain start offset #{page_start} is beyond " \
                "the page size (0x#{page_size.to_s(16)})"
        end

        if (page_start % stride) != 0
          raise ChainedFixupError,
                "#{page_location}: chain start offset #{page_start} is not " \
                "aligned to the #{stride}-byte chain stride"
        end

        offset_in_page = page_start
        loop do
          if offset_in_page + 8 > page_size
            raise ChainedFixupError,
                  "#{page_location}: chain walks to offset #{offset_in_page}, " \
                  "beyond the end of the 0x#{page_size.to_s(16)}-byte page"
          end

          if (offset_in_page % stride) != 0
            raise ChainedFixupError,
                  "#{page_location}: chain offset #{offset_in_page} is not " \
                  "aligned to the #{stride}-byte chain stride"
          end

          file_offset = page_base_file + offset_in_page
          vmaddr = page_base_vm + offset_in_page
          slot_location = "#{page_location}, page offset #{offset_in_page} " \
                           "(file offset 0x#{file_offset.to_s(16)})"
          unless within_segment_file?(segment, file_offset)
            raise ChainedFixupError,
                  "#{slot_location}: pointer slot is outside the file-backed " \
                  "range of segment #{seg_index} (#{segment.segname.inspect})"
          end

          if @fixups_by_file_offset.key?(file_offset)
            raise ChainedFixupError,
                  "#{slot_location}: pointer slot is visited more than once by " \
                  "the fixup chains"
          end

          raw = read_slot(file_offset, slot_location)
          fixup, next_encoded = decode_pointer(raw, file_offset, vmaddr,
                                               pointer_format, format_name,
                                               slot_location)
          @fixups_by_file_offset[file_offset] = fixup
          @fixups << fixup

          # 64-bit formats store 12 next bits at 52..63 for rebases; for binds
          # bit 63 is the bind flag, so only 11 bits are available. ARM64E
          # uses 11 dedicated bits at 51..61 in either case.
          next_encoded &= 0x7ff if pointer_format == 2 || pointer_format == 6
          next_offset = next_encoded * stride
          break if next_offset.zero?

          if (next_offset % stride) != 0
            raise ChainedFixupError,
                  "#{page_location}: chain's next pointer (#{next_offset}) is " \
                  "not aligned to the #{stride}-byte chain stride"
          end
          if next_offset + 8 > page_size
            raise ChainedFixupError,
                  "#{page_location}: chain's next pointer (#{next_offset}) walks " \
                  "beyond the end of the 0x#{page_size.to_s(16)}-byte page"
          end

          offset_in_page = next_offset
        end
      end

      def within_segment_file?(segment, file_offset)
        file_offset >= segment.fileoff &&
          file_offset + 8 <= segment.fileoff + segment.filesize
      end

      def decode_pointer(raw, file_offset, vmaddr, pointer_format,
                         format_name, location)
        bind = (raw >> 63) == 1
        runtime_offset = vmaddr - image_base

        if pointer_format == 9
          decode_arm64e_userland(raw, file_offset, vmaddr, runtime_offset,
                                 bind, format_name, location)
        elsif pointer_format == 12
          decode_arm64e_userland24(raw, file_offset, vmaddr, runtime_offset,
                                   bind, format_name, location)
        else
          decode_ptr64(raw, file_offset, vmaddr, runtime_offset, bind,
                       pointer_format, format_name, location)
        end
      end

      def decode_ptr64(raw, file_offset, vmaddr, runtime_offset, bind,
                       pointer_format, format_name, location)
        next_encoded = (raw >> 52) & 0xfff
        if bind
          ordinal = (raw >> 12) & 0xffffff
          inline_addend = (raw >> 36) & 0xff
          addend = bind_addend(ordinal, inline_addend, location)
          import = import_for_ordinal(ordinal, location)

          fixup = Fixup.new(:file_offset => file_offset,
                            :runtime_offset => runtime_offset,
                            :vmaddr => vmaddr, :kind => :bind,
                            :pointer_format => format_name, :addend => addend,
                            :import => import, :ordinal => ordinal)
        else
          target_offset = (raw >> 12) & 0xfffffffff
          high8 = (raw >> 44) & 0xff
          if pointer_format == 2
            target_runtime = target_offset | (high8 << 36)
            target_vmaddr = image_base + target_runtime
          else
            target_vmaddr = nil
            target_runtime = target_offset
          end

          fixup = Fixup.new(:file_offset => file_offset,
                            :runtime_offset => runtime_offset,
                            :vmaddr => vmaddr, :kind => :rebase,
                            :pointer_format => format_name, :addend => 0,
                            :target_vmaddr => target_vmaddr,
                            :target_runtime_offset => target_runtime,
                            :high8 => high8)
        end

        [fixup, next_encoded]
      end

      def decode_arm64e_userland(raw, file_offset, vmaddr, runtime_offset,
                                 bind, format_name, location)
        authenticated = ((raw >> 62) & 1) == 1
        next_encoded = (raw >> 51) & 0x7ff

        if bind
          ordinal = raw & 0xffff
          if authenticated
            diversity = (raw >> 32) & 0xffff
            addr_div = (raw >> 48) & 1
            key_discriminator = (raw >> 49) & 3
            inline_addend = 0
          else
            diversity = nil
            addr_div = nil
            key_discriminator = nil
            inline_addend = sign19((raw >> 32) & 0x7ffff)
          end
          addend = bind_addend(ordinal, inline_addend, location)
          import = import_for_ordinal(ordinal, location)

          fixup = Fixup.new(:file_offset => file_offset,
                            :runtime_offset => runtime_offset,
                            :vmaddr => vmaddr, :kind => :bind,
                            :pointer_format => format_name, :addend => addend,
                            :import => import, :ordinal => ordinal,
                            :authenticated => authenticated,
                            :key => KEYS[key_discriminator],
                            :key_discriminator => key_discriminator,
                            :diversity => diversity,
                            :address_diversity => authenticated ? addr_div == 1 : nil)
        elsif authenticated
          target_runtime = raw & 0xffffffff
          diversity = (raw >> 32) & 0xffff
          addr_div = (raw >> 48) & 1
          key_discriminator = (raw >> 49) & 3

          fixup = Fixup.new(:file_offset => file_offset,
                            :runtime_offset => runtime_offset,
                            :vmaddr => vmaddr, :kind => :rebase,
                            :pointer_format => format_name, :addend => 0,
                            :target_runtime_offset => target_runtime,
                            :authenticated => true,
                            :key => KEYS[key_discriminator],
                            :key_discriminator => key_discriminator,
                            :diversity => diversity,
                            :address_diversity => addr_div == 1)
        else
          target_runtime = raw & 0x7ffffffffff
          high8 = (raw >> 43) & 0xff
          target_vmaddr = image_base + target_runtime

          fixup = Fixup.new(:file_offset => file_offset,
                            :runtime_offset => runtime_offset,
                            :vmaddr => vmaddr, :kind => :rebase,
                            :pointer_format => format_name, :addend => 0,
                            :target_vmaddr => target_vmaddr,
                            :target_runtime_offset => target_runtime,
                            :high8 => high8)
        end

        [fixup, next_encoded]
      end

      def sign19(value)
        value >= 0x40000 ? value - 0x80000 : value
      end

      # DYLD_CHAINED_PTR_ARM64E_USERLAND24: same rebase layout as USERLAND, but
      # binds carry a 24-bit ordinal and no inline addend.
      def decode_arm64e_userland24(raw, file_offset, vmaddr, runtime_offset,
                                   bind, format_name, location)
        authenticated = ((raw >> 62) & 1) == 1
        if bind
          ordinal = raw & 0xffffff
          addend = bind_addend(ordinal, 0, location)
          import = import_for_ordinal(ordinal, location)
          if authenticated
            diversity = (raw >> 32) & 0xffff
            addr_div = (raw >> 48) & 1
            key_discriminator = (raw >> 49) & 3
          else
            diversity = nil
            addr_div = nil
            key_discriminator = nil
          end

          fixup = Fixup.new(:file_offset => file_offset,
                            :runtime_offset => runtime_offset,
                            :vmaddr => vmaddr, :kind => :bind,
                            :pointer_format => format_name, :addend => addend,
                            :import => import, :ordinal => ordinal,
                            :authenticated => authenticated,
                            :key => KEYS[key_discriminator],
                            :key_discriminator => key_discriminator,
                            :diversity => diversity,
                            :address_diversity => authenticated ? addr_div == 1 : nil)
        else
          target_runtime = raw & 0x7ffffffffff
          high8 = (raw >> 43) & 0xff
          target_vmaddr = image_base + target_runtime

          fixup = Fixup.new(:file_offset => file_offset,
                            :runtime_offset => runtime_offset,
                            :vmaddr => vmaddr, :kind => :rebase,
                            :pointer_format => format_name, :addend => 0,
                            :target_vmaddr => target_vmaddr,
                            :target_runtime_offset => target_runtime,
                            :high8 => high8)
        end

        [fixup, (raw >> 51) & 0x7ff]
      end

      def bind_addend(ordinal, inline_addend, location)
        import = import_for_ordinal(ordinal, location)
        import.table_addend + inline_addend
      end

      def import_for_ordinal(ordinal, location)
        if ordinal >= @imports_count
          raise ChainedFixupError,
                "#{location}: bind pointer references imports table ordinal " \
                "#{ordinal} but the table contains only #{@imports_count} " \
                "entr#{@imports_count == 1 ? "y" : "ies"}"
        end

        @imports[ordinal]
      end
    end
  end
end
