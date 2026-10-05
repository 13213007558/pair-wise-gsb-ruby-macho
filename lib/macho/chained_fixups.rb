# frozen_string_literal: true

module MachO
  # Offline inspection support for `LC_DYLD_CHAINED_FIXUPS`.
  module ChainedFixups
    DYLD_CHAINED_PTR_64 = 2
    DYLD_CHAINED_PTR_64_OFFSET = 6
    DYLD_CHAINED_PTR_ARM64E_USERLAND = 9

    DYLD_CHAINED_IMPORT = 1
    DYLD_CHAINED_IMPORT_ADDEND = 2
    DYLD_CHAINED_IMPORT_ADDEND64 = 3

    SUPPORTED_POINTER_FORMATS = {
      DYLD_CHAINED_PTR_64 => :DYLD_CHAINED_PTR_64,
      DYLD_CHAINED_PTR_64_OFFSET => :DYLD_CHAINED_PTR_64_OFFSET,
      DYLD_CHAINED_PTR_ARM64E_USERLAND => :DYLD_CHAINED_PTR_ARM64E_USERLAND,
    }.freeze

    IMPORT_FORMATS = {
      DYLD_CHAINED_IMPORT => :DYLD_CHAINED_IMPORT,
      DYLD_CHAINED_IMPORT_ADDEND => :DYLD_CHAINED_IMPORT_ADDEND,
      DYLD_CHAINED_IMPORT_ADDEND64 => :DYLD_CHAINED_IMPORT_ADDEND64,
    }.freeze

    SPECIAL_LIBRARIES = {
      0 => "self",
      -1 => "main executable",
      -2 => "flat lookup",
      -3 => "weak lookup",
    }.freeze

    # A symbol imported by a chained bind.
    class Import
      # @return [Integer] the ordinal used by chain entries
      attr_reader :ordinal

      # @return [Integer] the originating library ordinal
      attr_reader :library_ordinal

      # @return [String, nil] the originating library path when known
      attr_reader :library

      # @return [String] the imported symbol name
      attr_reader :name

      # @return [Boolean] whether the import is marked weak
      attr_reader :weak_import

      # @return [Integer] the addend attached to the import table entry
      attr_reader :addend

      # @api private
      def initialize(ordinal, library_ordinal, library, name, weak_import, addend)
        @ordinal = ordinal
        @library_ordinal = library_ordinal
        @library = library
        @name = name
        @weak_import = weak_import
        @addend = addend
      end

      # @return [Hash] a hash representation of this import
      def to_h
        {
          "ordinal" => ordinal,
          "library_ordinal" => library_ordinal,
          "library" => library,
          "name" => name,
          "weak_import" => weak_import,
          "addend" => addend,
        }
      end
    end

    # One chained rebase or bind location.
    class Fixup
      # @return [:rebase, :bind] the fixup kind
      attr_reader :kind

      # @return [Integer] the fixup's file offset
      attr_reader :file_offset

      # @return [Integer] the fixup's virtual address
      attr_reader :address

      # @return [Integer] the segment index containing the fixup
      attr_reader :segment_index

      # @return [Integer] the page index within the containing segment
      attr_reader :page_index

      # @return [Integer] the offset of the fixup within its page
      attr_reader :page_offset

      # @return [Integer] the raw encoded fixup
      attr_reader :raw_value

      # @return [Symbol] the chain pointer format
      attr_reader :pointer_format

      # @return [Integer] the encoded next-chain stride, in fixup entries
      attr_reader :chain_next

      # @return [Integer, nil] the encoded rebase target
      attr_reader :target

      # @return [Integer, nil] the encoded high target bits
      attr_reader :high8

      # @return [Integer, nil] the resolved target virtual address for a rebase
      attr_reader :target_address

      # @return [Import, nil] the imported symbol for a bind
      attr_reader :import

      # @return [Integer] the addend
      attr_reader :addend

      # @return [Boolean] whether an arm64e fixup uses authentication
      attr_reader :authenticated

      # @return [Integer, nil] the arm64e authentication key
      attr_reader :key

      # @return [Integer, nil] the arm64e diversity value
      attr_reader :diversity

      # @return [Boolean, nil] whether arm64e uses address diversification
      attr_reader :addr_div

      # @api private
      def initialize(**attributes)
        attributes.each do |name, value|
          instance_variable_set("@#{name}", value)
        end
      end

      # @return [Hash] a hash representation of this fixup
      def to_h
        {
          "pointer_format" => pointer_format,
          "kind" => kind,
          "file_offset" => file_offset,
          "address" => address,
          "segment_index" => segment_index,
          "page_index" => page_index,
          "page_offset" => page_offset,
          "raw_value" => raw_value,
          "chain_next" => chain_next,
          "target" => target,
          "high8" => high8,
          "target_address" => target_address,
          "import" => import&.to_h,
          "addend" => addend,
          "authenticated" => authenticated,
          "key" => key,
          "diversity" => diversity,
          "addr_div" => addr_div,
        }
      end

      # @return [Boolean] whether this fixup is a rebase
      def rebase?
        kind == :rebase
      end

      # @return [Boolean] whether this fixup is a bind
      def bind?
        kind == :bind
      end
    end

    # The complete contents of an `LC_DYLD_CHAINED_FIXUPS` payload.
    class Fixups
      # @return [Integer] the fixups format version
      attr_reader :version

      # @return [Integer] the starts table offset within the payload
      attr_reader :starts_offset

      # @return [Integer] the imports table offset within the payload
      attr_reader :imports_offset

      # @return [Integer] the symbols table offset within the payload
      attr_reader :symbols_offset

      # @return [Symbol] the imports table format
      attr_reader :imports_format

      # @return [Integer] the symbols table format
      attr_reader :symbols_format

      # @return [Array<Symbol>] pointer formats present in the starts table
      attr_reader :pointer_formats

      # @return [Array<Import>] all imported symbols
      attr_reader :imports

      # @return [Array<Fixup>] all rebase and bind locations
      attr_reader :fixups

      # @api private
      def initialize(header, imports, fixups)
        @version = header.fetch(:fixups_version)
        @starts_offset = header.fetch(:starts_offset)
        @imports_offset = header.fetch(:imports_offset)
        @symbols_offset = header.fetch(:symbols_offset)
        @imports_format = header.fetch(:imports_format)
        @symbols_format = header.fetch(:symbols_format)
        @imports = imports
        @fixups = fixups
        @pointer_formats = fixups.map(&:pointer_format).uniq
      end

      # @return [Hash] a hash representation of the chained fixups
      def to_h
        {
          "version" => version,
          "starts_offset" => starts_offset,
          "imports_offset" => imports_offset,
          "symbols_offset" => symbols_offset,
          "imports_format" => imports_format,
          "symbols_format" => symbols_format,
          "pointer_formats" => pointer_formats,
          "imports" => imports.map(&:to_h),
          "fixups" => fixups.map(&:to_h),
        }
      end
    end

    # Parses chained fixups from a {MachOFile} without applying or signing them.
    class Parser
      # @api private
      def initialize(macho_file, command)
        @macho_file = macho_file
        @command = command
        @raw_data = macho_file.serialize
      end

      # @return [Fixups] the parsed chained fixups
      # @raise [ChainedFixupsError] if the payload is malformed
      # @api private
      def parse
        raise ChainedFixupsError, "chained fixups require a 64-bit Mach-O" unless @macho_file.magic64?
        raise ChainedFixupsError, "big-endian chained fixups are not supported" unless @macho_file.endianness == :little

        @payload = read_exact(@command.dataoff, @command.datasize, "chained fixups payload")
        header = parse_header
        @imports = parse_imports(header)
        @fixups = parse_fixups(header)

        Fixups.new(header, @imports, @fixups)
      end

      private

      def parse_header
        header = read_payload_fields(0, "L<7", "chained fixups header")
        fixups_version, starts_offset, imports_offset, symbols_offset,
          imports_count, imports_format, symbols_format = header

        raise ChainedFixupsError, "unsupported chained fixups version #{fixups_version}" unless fixups_version.zero?
        raise ChainedFixupsError, "compressed chained fixup symbols are not supported" unless symbols_format.zero?
        unless IMPORT_FORMATS.key?(imports_format)
          raise ChainedFixupsError, "unknown chained imports format #{imports_format}"
        end

        offsets = [starts_offset, imports_offset, symbols_offset]
        ordered = offsets.each_cons(2).all? { |first, second| first <= second }
        raise ChainedFixupsError, "chained fixups table offsets are out of order" unless ordered
        raise ChainedFixupsError, "chained fixups starts table is out of bounds" if starts_offset >= @payload.bytesize
        raise ChainedFixupsError, "chained fixups imports table is out of bounds" unless fits?(imports_offset, 0)
        raise ChainedFixupsError, "chained fixups symbols table is out of bounds" if symbols_offset >= @payload.bytesize
        raise ChainedFixupsError, "too many chained fixup imports" if imports_count > (@payload.bytesize / 4)
        if starts_offset == imports_offset
          raise ChainedFixupsError, "chained fixups imports table overlaps another table"
        end
        if symbols_offset == imports_offset
          raise ChainedFixupsError, "chained fixups symbols table overlaps another table"
        end

        {
          :fixups_version => fixups_version,
          :starts_offset => starts_offset,
          :imports_offset => imports_offset,
          :symbols_offset => symbols_offset,
          :imports_count => imports_count,
          :imports_format => IMPORT_FORMATS.fetch(imports_format),
          :symbols_format => symbols_format,
        }
      end

      def parse_imports(header)
        format = header.fetch(:imports_format)
        count = header.fetch(:imports_count)
        offset = header.fetch(:imports_offset)
        symbols_offset = header.fetch(:symbols_offset)
        entry_size = import_entry_size(format)

        require_fit(offset, entry_size * count, "chained fixups imports table")

        count.times.map do |index|
          entry_offset = offset + index * entry_size
          addend = 0

          if format == :DYLD_CHAINED_IMPORT_ADDEND64
            raw_import = read_payload_field(entry_offset, "Q<", "chained fixup import")
            library_ordinal = sign_extend(raw_import & 0xffff, 16)
            weak_import = ((raw_import >> 16) & 1) == 1
            name_offset = raw_import >> 32
            addend = read_signed(entry_offset + 8, 8)
          else
            raw_import = read_payload_field(entry_offset, "L<", "chained fixup import")
            library_ordinal = sign_extend(raw_import & 0xff, 8)
            weak_import = ((raw_import >> 8) & 1) == 1
            name_offset = raw_import >> 9
            if format == :DYLD_CHAINED_IMPORT_ADDEND
              require_fit(entry_offset + 4, 4, "chained fixup import addend")
              addend = read_signed(entry_offset + 4, 4)
            end
          end

          name = read_symbol(symbols_offset + name_offset)
          library = library_name(library_ordinal)
          Import.new(index, library_ordinal, library, name, weak_import, addend)
        end
      end

      def parse_fixups(header)
        segments = @macho_file.segments
        starts_offset = header.fetch(:starts_offset)
        seg_count = read_payload_field(starts_offset, "L<", "chained segment count")
        unless seg_count == segments.size
          raise ChainedFixupsError,
                "chained segment count #{seg_count} does not match #{segments.size} segments"
        end

        @visited_locations = {}
        fixups = []

        seg_count.times do |segment_index|
          segment_relative_offset = read_payload_field(starts_offset + 4 + segment_index * 4,
                                                       "L<", "chained segment offset")
          next if segment_relative_offset.zero?

          segment_start = starts_offset + segment_relative_offset
          fixups.concat(parse_segment_fixups(segment_index, segment_start, header.fetch(:imports_offset)))
        end

        fixups
      end

      def parse_segment_fixups(segment_index, segment_start, imports_offset)
        require_fit(segment_start, 22, "chained segment starts")

        size = read_payload_field(segment_start, "L<", "chained segment starts size")
        page_size = read_payload_field(segment_start + 4, "S<", "chained fixups page size")
        pointer_format_value = read_payload_field(segment_start + 6, "S<", "chained pointer format")
        segment_vmaddr = read_payload_field(segment_start + 8, "Q<", "chained segment address")
        page_count = read_payload_field(segment_start + 20, "S<", "chained page count")
        pointer_format = SUPPORTED_POINTER_FORMATS[pointer_format_value]
        raise ChainedFixupsError, "unsupported chained pointer format #{pointer_format_value}" unless pointer_format
        unless [0x1000, 0x4000].include?(page_size)
          raise ChainedFixupsError, "invalid chained fixups page size #{page_size}"
        end
        raise ChainedFixupsError, "chained segment starts size is too small" if size < 22
        require_fit(segment_start, size, "chained segment starts table")
        unless segment_start + size <= imports_offset
          raise ChainedFixupsError, "chained segment starts table overlaps the imports table"
        end

        segment = @macho_file.segments[segment_index]
        expected_vmaddr = image_base + segment_vmaddr
        unless segment.vmaddr == expected_vmaddr
          raise ChainedFixupsError,
                "chained segment offset 0x#{segment_vmaddr.to_s(16)} does not match segment #{segment_index} " \
                "address 0x#{segment.vmaddr.to_s(16)} (image base 0x#{image_base.to_s(16)})"
        end

        page_array_start = segment_start + 22
        require_fit(page_array_start, page_count * 2, "chained page starts")
        require_segment_range(segment, page_count * page_size)
        page_count.times.flat_map do |page_index|
          first_start = read_payload_field(page_array_start + page_index * 2, "S<", "chained page start")
          starts = chain_starts(segment_start, size, first_start)
          starts.flat_map do |page_offset|
            walk_chain(segment, segment_index, page_index, page_size, page_offset, pointer_format)
          end
        end
      end

      def chain_starts(segment_start, size, first_start)
        return [] if first_start == 0xffff
        return [first_start] unless (first_start & 0x8000) != 0

        chain_start_index = first_start & 0x7fff
        starts = []
        chain_start_offset = segment_start + chain_start_index
        if chain_start_index < 22 || chain_start_offset + 2 > segment_start + size
          raise ChainedFixupsError, "invalid chained multi-start offset #{chain_start_index}"
        end

        loop do
          require_fit(chain_start_offset, 2, "chained multi-start entry")
          entry = read_payload_field(chain_start_offset, "S<", "chained multi-start entry")
          starts << (entry & 0x7fff)
          break if (entry & 0x8000) != 0

          chain_start_offset += 2
          if chain_start_offset + 2 > segment_start + size
            raise ChainedFixupsError, "chained multi-start list exceeds segment starts size #{size}"
          end
        end

        starts
      end

      def walk_chain(segment, segment_index, page_index, page_size, page_offset,
                    pointer_format)
        if page_offset % 8 != 0 || page_offset >= page_size
          raise ChainedFixupsError, "chained fixup page offset #{page_offset} is invalid"
        end

        page_file_offset = segment.fileoff + page_index * page_size
        page_address = segment.vmaddr + page_index * page_size
        fixups = []
        offset_in_page = page_offset

        loop do
          location = page_file_offset + offset_in_page
          if location + 8 > @raw_data.bytesize || location + 8 > segment.fileoff + segment.filesize
            raise ChainedFixupsError, "chained fixup at file offset 0x#{location.to_s(16)} is out of bounds"
          end
          if @visited_locations.key?(location)
            raise ChainedFixupsError, "chained fixup location 0x#{location.to_s(16)} is visited more than once"
          end

          @visited_locations[location] = true
          raw_value = @raw_data.byteslice(location, 8).unpack1("Q<")
          fixup = decode_fixup(raw_value, location, page_address + offset_in_page,
                               segment_index, page_index, offset_in_page, pointer_format)
          fixups << fixup

          chain_next = fixup.chain_next
          break if chain_next.zero?

          next_offset = offset_in_page + chain_next * fixup_stride(pointer_format)
          if next_offset >= page_size
            raise ChainedFixupsError, "chained fixup crosses a page boundary at 0x#{location.to_s(16)}"
          end
          raise ChainedFixupsError, "chained fixup next offset is unaligned" if next_offset % 8 != 0
          offset_in_page = next_offset
        end

        fixups
      end

      def decode_fixup(raw_value, file_offset, address, segment_index, page_index, page_offset,
                       pointer_format)
        attributes = {
          :pointer_format => pointer_format,
          :file_offset => file_offset,
          :address => address,
          :segment_index => segment_index,
          :page_index => page_index,
          :page_offset => page_offset,
          :raw_value => raw_value,
        }

        if pointer_format == :DYLD_CHAINED_PTR_ARM64E_USERLAND
          decode_arm64e_userland(raw_value, attributes)
        else
          decode_ptr_64(raw_value, attributes, pointer_format)
        end
      end

      def decode_ptr_64(raw_value, attributes, pointer_format)
        bind = (raw_value >> 63) == 1
        chain_next = (raw_value >> 51) & 0xfff
        attributes[:chain_next] = chain_next
        attributes[:authenticated] = false

        if bind
          ordinal = raw_value & 0xffffff
          inline_addend = (raw_value >> 24) & 0xff
          import = import_at(ordinal)
          attributes.merge!(
            :kind => :bind,
            :import => import,
            :addend => import.addend + inline_addend,
          )
        else
          low_target = raw_value & 0xfffffffff
          target = low_target
          high8 = nil
          if pointer_format == :DYLD_CHAINED_PTR_64_OFFSET
            high8 = (raw_value >> 36) & 0xff
            target = low_target | (high8 << 36)
          end
          target_address =
            if pointer_format == :DYLD_CHAINED_PTR_64_OFFSET
              image_base + target
            else
              target
            end
          attributes.merge!(
            :kind => :rebase,
            :target => target,
            :target_address => target_address,
            :high8 => high8,
            :addend => 0,
          )
        end

        Fixup.new(**attributes)
      end

      def decode_arm64e_userland(raw_value, attributes)
        authenticated = (raw_value >> 63) == 1
        bind = ((raw_value >> 62) & 1) == 1
        chain_next = (raw_value >> 51) & 0x7ff
        attributes[:chain_next] = chain_next
        attributes[:authenticated] = authenticated

        if bind
          ordinal = raw_value & 0xffff
          import = import_at(ordinal)
          attributes[:import] = import
          attributes[:kind] = :bind

          if authenticated
            attributes[:diversity] = (raw_value >> 32) & 0xffff
            attributes[:addr_div] = ((raw_value >> 48) & 1) == 1
            attributes[:key] = (raw_value >> 49) & 3
            attributes[:addend] = import.addend
        else
            attributes[:diversity] = nil
            attributes[:addr_div] = nil
            attributes[:key] = nil
            attributes[:addend] = sign_extend((raw_value >> 32) & 0x7ffff, 19)
          end
        elsif authenticated
          target = raw_value & 0xffffffff
          attributes[:diversity] = (raw_value >> 32) & 0xffff
          attributes[:addr_div] = ((raw_value >> 48) & 1) == 1
          attributes[:key] = (raw_value >> 49) & 3
          attributes[:kind] = :rebase
          attributes[:target] = target
          attributes[:target_address] = image_base + target
          attributes[:addend] = 0
        else
          low_target = raw_value & 0x7ffffffffff
          high8 = (raw_value >> 43) & 0xff
          target = low_target | (high8 << 43)
          attributes[:kind] = :rebase
          attributes[:target] = target
          attributes[:target_address] = image_base + target
          attributes[:high8] = high8
          attributes[:addend] = 0
        end

        Fixup.new(**attributes)
      end

      def import_at(ordinal)
        unless ordinal >= 0 && ordinal < @imports.size
          raise ChainedFixupsError, "chained fixup import ordinal #{ordinal} is out of bounds"
        end

        @imports[ordinal]
      end

      def fixup_stride(pointer_format)
        pointer_format == :DYLD_CHAINED_PTR_ARM64E_USERLAND ? 8 : 4
      end

      def require_segment_range(segment, size)
        end_offset = segment.fileoff + size
        if end_offset < segment.fileoff || end_offset > segment.fileoff + segment.filesize
          raise ChainedFixupsError, "chained fixup pages exceed segment bounds"
        end
      end

      def import_entry_size(format)
        case format
        when :DYLD_CHAINED_IMPORT
          4
        when :DYLD_CHAINED_IMPORT_ADDEND
          8
        when :DYLD_CHAINED_IMPORT_ADDEND64
          16
        end
      end

      def read_symbol(offset)
        if offset >= @payload.bytesize
          raise ChainedFixupsError, "chained fixup symbol offset #{offset} is out of bounds"
        end

        end_offset = @payload.index("\0", offset)
        raise ChainedFixupsError, "chained fixup symbol at offset #{offset} is not null terminated" unless end_offset

        @payload.byteslice(offset, end_offset - offset).force_encoding(Encoding::UTF_8)
      end

      def library_name(library_ordinal)
        return SPECIAL_LIBRARIES[library_ordinal] if SPECIAL_LIBRARIES.key?(library_ordinal)
        return unless library_ordinal.positive?

        dylib_commands = @macho_file.dylib_load_commands
        return unless library_ordinal <= dylib_commands.size

        dylib_commands[library_ordinal - 1].name.to_s
      end

      def image_base
        @image_base ||= begin
          mapped_segments = @macho_file.segments.select { |segment| segment.filesize.positive? }
          first_segment = mapped_segments.min_by(&:vmaddr)
          first_segment&.vmaddr || 0
        end
      end

      def read_exact(offset, size, description)
        data = @raw_data.byteslice(offset, size)
        if size.negative? || data.nil? || data.bytesize != size
          raise ChainedFixupsError, "#{description} is out of bounds"
        end

        data
      end

      def require_fit(offset, size, description)
        raise ChainedFixupsError, "#{description} is out of bounds" unless fits?(offset, size)
      end

      def fits?(offset, size)
        return false if offset.negative? || size.negative? || offset > @payload.bytesize

        size <= @payload.bytesize - offset
      end

      def read_payload_fields(offset, format, description)
        type, count = format.split("<")
        type_size = { "C" => 1, "S" => 2, "L" => 4, "Q" => 8 }.fetch(type)
        size = type_size * (count || 1).to_i
        require_fit(offset, size, description)
        @payload.byteslice(offset, size).unpack(format)
      end

      def read_payload_field(offset, format, description)
        read_payload_fields(offset, format, description).first
      end

      def read_signed(offset, size)
        format = size == 8 ? "Q<" : "L<"
        value = read_payload_field(offset, format, "signed value")
        sign_extend(value, size * 8)
      end

      def sign_extend(value, bits)
        mask = 1 << (bits - 1)
        (value ^ mask) - mask
      end
    end
  end
end
