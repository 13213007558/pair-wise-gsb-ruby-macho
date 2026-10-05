# frozen_string_literal: true

module MachO
  # An offline inspector for LC_DYLD_CHAINED_FIXUPS payloads.
  #
  # The parser walks the chain starts described by the payload and decodes
  # every fixup location it visits, classifying each one as a {Rebase} or a
  # {Bind}. It performs all reads through explicit offsets, checks chain
  # bounds, duplicate visits, and imports table indices, and never
  # authenticates or signs pointers, so it is safe to run on untrusted
  # binaries.
  #
  # Supported pointer formats:
  # * DYLD_CHAINED_PTR_64 (2)
  # * DYLD_CHAINED_PTR_64_OFFSET (6)
  # * DYLD_CHAINED_PTR_ARM64E_USERLAND (9)
  #
  # @example
  #  file = MachO.open("mybinary")
  #  MachO::ChainedFixups.parse(file).each do |fixup|
  #    puts "%#x: %s" % [fixup.offset, fixup.type]
  #  end
  module ChainedFixups
    # DYLD_CHAINED_PTR_64: 64-bit unauthenticated pointers, rebase targets
    #  are vmaddrs. Chain stride is 4 bytes.
    DYLD_CHAINED_PTR_64 = 2

    # DYLD_CHAINED_PTR_64_OFFSET: like {DYLD_CHAINED_PTR_64}, but rebase
    #  targets are vm offsets from the image's preferred load address.
    DYLD_CHAINED_PTR_64_OFFSET = 6

    # DYLD_CHAINED_PTR_ARM64E_USERLAND: arm64e userland pointers, possibly
    #  authenticated. Chain stride is 8 bytes.
    DYLD_CHAINED_PTR_ARM64E_USERLAND = 9

    # Maps a supported dyld_chained_starts_in_segment.pointer_format value
    # to the chain stride (in bytes) its +next+ field is expressed in.
    POINTER_STRIDES = {
      DYLD_CHAINED_PTR_64 => 4,
      DYLD_CHAINED_PTR_64_OFFSET => 4,
      DYLD_CHAINED_PTR_ARM64E_USERLAND => 8,
    }.freeze

    # DYLD_CHAINED_IMPORT: imports are 4-byte dyld_chained_import entries.
    DYLD_CHAINED_IMPORT = 1

    # DYLD_CHAINED_IMPORT_ADDEND: imports are 8-byte
    #  dyld_chained_import_addend entries.
    DYLD_CHAINED_IMPORT_ADDEND = 2

    # DYLD_CHAINED_IMPORT_ADDEND64: imports are 16-byte
    #  dyld_chained_import_addend64 entries.
    DYLD_CHAINED_IMPORT_ADDEND64 = 3

    # Maps a supported dyld_chained_fixups_header.imports_format value to
    # the size (in bytes) of one imports table entry.
    IMPORT_FORMAT_SIZES = {
      DYLD_CHAINED_IMPORT => 4,
      DYLD_CHAINED_IMPORT_ADDEND => 8,
      DYLD_CHAINED_IMPORT_ADDEND64 => 16,
    }.freeze

    # page_start[] value marking a page without any fixups.
    START_NONE = 0xFFFF

    # High bit of a page_start[] entry, marking an index into chain_starts[].
    START_MULTI = 0x8000

    # High bit of a chain_starts[] entry, marking the last start of a page.
    START_LAST = 0x8000

    # Size of dyld_chained_fixups_header.
    HEADER_SIZE = 28

    # Size of dyld_chained_starts_in_segment without its page_start array.
    SEGMENT_STARTS_HEADER_SIZE = 22

    # A symbol imported by the inspected image, as described by one entry of
    # the payload's imports table.
    Import = Struct.new(:name, :library_ordinal, :weak_import, :addend, :keyword_init => true) do
      # @return [Boolean] true if the import is weak
      def weak_import?
        weak_import
      end
    end

    # A rebase fixup: the location holds a pointer to a target inside (or,
    # for malformed chains, outside) the image.
    Rebase = Struct.new(:offset, :target, :authenticated, :key, :diversity, :addr_div, :keyword_init => true) do
      # @return [Symbol] always +:rebase+
      def type
        :rebase
      end

      # @return [Boolean] true if this is an authenticated (arm64e) pointer
      def authenticated?
        authenticated
      end

      # @return [Hash] a hash representation of this fixup
      def to_h
        {
          "type" => type,
          "offset" => offset,
          "target" => target,
          "authenticated" => authenticated,
          "key" => key,
          "diversity" => diversity,
          "addr_div" => addr_div,
        }.compact
      end
    end

    # A bind fixup: the location holds a pointer to an imported symbol.
    Bind = Struct.new(:offset, :ordinal, :addend, :symbol, :library_ordinal, :weak_import,
                      :import_addend, :authenticated, :key, :diversity, :addr_div, :keyword_init => true) do
      # @return [Symbol] always +:bind+
      def type
        :bind
      end

      # @return [Boolean] true if this is an authenticated (arm64e) pointer
      def authenticated?
        authenticated
      end

      # @return [Boolean] true if the imported symbol is weak
      def weak_import?
        weak_import
      end

      # The addend stored in the chain entry plus the addend stored in the
      # imports table (if the imports format carries one).
      # @return [Integer] the combined addend
      def total_addend
        addend + (import_addend || 0)
      end

      # @return [Hash] a hash representation of this fixup
      def to_h
        {
          "type" => type,
          "offset" => offset,
          "ordinal" => ordinal,
          "symbol" => symbol,
          "addend" => addend,
          "import_addend" => import_addend,
          "library_ordinal" => library_ordinal,
          "weak_import" => weak_import,
          "authenticated" => authenticated,
          "key" => key,
          "diversity" => diversity,
          "addr_div" => addr_div,
        }.compact
      end
    end

    class << self
      # Parses the LC_DYLD_CHAINED_FIXUPS payload of a Mach-O and returns
      # every fixup location in walk order.
      # @param macho [MachOFile] the Mach-O to inspect
      # @return [Array<Rebase, Bind>] the decoded fixups, empty if the
      #  Mach-O has no LC_DYLD_CHAINED_FIXUPS command
      # @raise [ChainedFixupsError] if the payload is malformed or unsupported
      def parse(macho)
        commands = macho.command(:LC_DYLD_CHAINED_FIXUPS)
        return [] if commands.empty?
        raise ChainedFixupsError, "multiple LC_DYLD_CHAINED_FIXUPS commands" if commands.size > 1

        command = commands.first
        payload = macho.serialize.byteslice(command.dataoff, command.datasize)
        if payload.nil? || payload.bytesize < command.datasize
          raise ChainedFixupsError, "LC_DYLD_CHAINED_FIXUPS payload is out of bounds"
        end

        parse_payload(payload, &image_reader(macho))
      end

      # Parses a raw LC_DYLD_CHAINED_FIXUPS payload.
      # @param payload [String] the payload bytes
      # @yieldparam vm_offset [Integer] a vm offset within the inspected image
      # @yieldparam length [Integer] how many bytes to read there
      # @yieldreturn [String, nil] the bytes at +vm_offset+, or nil if that
      #  location is not mapped
      # @return [Array<Rebase, Bind>] the decoded fixups
      # @raise [ChainedFixupsError] if the payload is malformed or unsupported
      def parse_payload(payload, &reader)
        Parser.new(payload, reader).entries
      end

      private

      # Builds a vm-offset reader over the file-backed contents of a Mach-O.
      # @param macho [MachOFile] the Mach-O to read from
      # @return [Proc] maps (vm_offset, length) to bytes, or nil if unmapped
      def image_reader(macho)
        segments = macho.segments.reject { |segment| segment.filesize.zero? }
        base_segment = segments.find { |segment| segment.fileoff.zero? } || segments.min_by(&:vmaddr)
        raw_data = macho.serialize

        lambda do |vm_offset, length|
          next nil if base_segment.nil?

          vmaddr = base_segment.vmaddr + vm_offset
          segment = segments.find do |candidate|
            vmaddr >= candidate.vmaddr && vmaddr + length <= candidate.vmaddr + candidate.filesize
          end
          next nil if segment.nil?

          raw_data.byteslice(segment.fileoff + (vmaddr - segment.vmaddr), length)
        end
      end
    end

    # Walks a single LC_DYLD_CHAINED_FIXUPS payload. Not reusable; create a
    # new instance per payload.
    # @api private
    class Parser
      # The starts of one segment: page geometry plus, for each page, the
      # list of chain start offsets within that page.
      SegmentStarts = Struct.new(:page_size, :pointer_format, :segment_offset, :pages)

      # @param payload [String] the LC_DYLD_CHAINED_FIXUPS payload
      # @param reader [#call] maps (vm_offset, length) to bytes, or nil
      def initialize(payload, reader)
        @payload = payload
        @reader = reader
        @visited = {}
      end

      # Decodes every fixup location reachable from the chain starts.
      # @return [Array<Rebase, Bind>] the decoded fixups, in walk order
      # @raise [ChainedFixupsError] if the payload is malformed or unsupported
      def entries
        starts_offset, imports_offset, symbols_offset, imports_count, imports_format = parse_header
        imports = parse_imports(imports_offset, imports_count, imports_format, symbols_offset)

        fixups = []
        each_segment_starts(starts_offset) do |segment|
          walk_segment(segment, imports, fixups)
        end
        fixups
      end

      private

      # @return [Array<Integer>] the payload header fields needed for parsing
      def parse_header
        if @payload.bytesize < HEADER_SIZE
          raise ChainedFixupsError, "chained fixups payload too small for header"
        end

        version, starts_offset, imports_offset, symbols_offset, imports_count, imports_format, symbols_format =
          @payload.unpack("V7")

        unless version.zero?
          raise ChainedFixupsError, "unsupported chained fixups version: #{version}"
        end
        unless symbols_format.zero?
          raise ChainedFixupsError, "unsupported chained fixups symbols format: #{symbols_format}"
        end
        if imports_count.positive? && !IMPORT_FORMAT_SIZES.key?(imports_format)
          raise ChainedFixupsError, "unsupported chained fixups imports format: #{imports_format}"
        end

        [starts_offset, imports_offset, symbols_offset, imports_count, imports_format]
      end

      # @return [Array<Import>] the decoded imports table
      def parse_imports(offset, count, format, symbols_offset)
        return [] if count.zero?

        entry_size = IMPORT_FORMAT_SIZES.fetch(format)
        if offset + (count * entry_size) > @payload.bytesize
          raise ChainedFixupsError, "imports table extends past end of payload"
        end

        Array.new(count) do |index|
          entry_offset = offset + (index * entry_size)
          case format
          when DYLD_CHAINED_IMPORT
            word = read_uint32(entry_offset)
            lib_ordinal = word & 0xFF
            weak_import = (word >> 8).allbits?(1)
            name_offset = word >> 9
            addend = nil
          when DYLD_CHAINED_IMPORT_ADDEND
            word = read_uint32(entry_offset)
            lib_ordinal = word & 0xFF
            weak_import = (word >> 8).allbits?(1)
            name_offset = word >> 9
            addend = read_int32(entry_offset + 4)
          when DYLD_CHAINED_IMPORT_ADDEND64
            word = read_uint64(entry_offset)
            lib_ordinal = word & 0xFFFF
            weak_import = (word >> 16).allbits?(1)
            name_offset = (word >> 32) & 0xFFFFFFFF
            addend = read_int64(entry_offset + 8)
          end

          Import.new(
            :name => read_symbol(symbols_offset + name_offset),
            :library_ordinal => lib_ordinal,
            :weak_import => weak_import,
            :addend => addend
          )
        end
      end

      # Yields the {SegmentStarts} of each segment that has chained fixups.
      def each_segment_starts(starts_offset)
        segment_count = read_uint32(starts_offset)
        segment_count.times do |index|
          info_offset = read_uint32(starts_offset + 4 + (index * 4))
          next if info_offset.zero? # segment has no chained fixups

          yield parse_segment_starts(starts_offset + info_offset)
        end
      end

      # @return [SegmentStarts] the decoded starts of one segment
      def parse_segment_starts(offset)
        size, page_size, pointer_format, segment_offset, _max_valid_pointer, page_count =
          checked_slice(offset, SEGMENT_STARTS_HEADER_SIZE).unpack("V v v Q< V v")

        unless POINTER_STRIDES.key?(pointer_format)
          raise ChainedFixupsError, "unsupported chained fixups pointer format: #{pointer_format}"
        end

        starts_end = SEGMENT_STARTS_HEADER_SIZE + (page_count * 2)
        if size < starts_end
          raise ChainedFixupsError, "dyld_chained_starts_in_segment size #{size} is too small"
        end
        checked_slice(offset, size) # bounds-check the whole struct, incl. chain_starts

        page_starts = checked_slice(offset + SEGMENT_STARTS_HEADER_SIZE, page_count * 2).unpack("v*")
        chain_starts_count = (size - starts_end) / 2

        pages = page_starts.map do |page_start|
          if page_start == START_NONE
            []
          elsif page_start.allbits?(START_MULTI)
            multi_starts(offset + starts_end, chain_starts_count, page_start & ~START_MULTI, page_size)
          else
            [check_page_offset(page_start, page_size)]
          end
        end

        SegmentStarts.new(page_size, pointer_format, segment_offset, pages)
      end

      # Resolves a START_MULTI page_start entry to its list of chain starts.
      # @return [Array<Integer>] the chain start offsets within the page
      def multi_starts(chain_starts_offset, chain_starts_count, index, page_size)
        starts = []
        loop do
          if index >= chain_starts_count
            raise ChainedFixupsError, "chain_starts index #{index} is out of bounds"
          end

          value = read_uint16(chain_starts_offset + (index * 2))
          starts << check_page_offset(value & ~START_LAST, page_size)
          break if value.allbits?(START_LAST)

          index += 1
        end
        starts
      end

      def check_page_offset(page_offset, page_size)
        if page_offset >= page_size
          raise ChainedFixupsError,
                "chain start offset #{page_offset} is beyond page size #{page_size}"
        end
        page_offset
      end

      def walk_segment(segment, imports, fixups)
        stride = POINTER_STRIDES.fetch(segment.pointer_format)
        segment.pages.each_with_index do |starts, page_index|
          page_base = segment.segment_offset + (page_index * segment.page_size)
          starts.each do |start|
            walk_chain(page_base, start, segment.page_size, stride, segment.pointer_format, imports, fixups)
          end
        end
      end

      def walk_chain(page_base, start, page_size, stride, pointer_format, imports, fixups)
        page_offset = start
        loop do
          location = page_base + page_offset
          if @visited.key?(location)
            raise ChainedFixupsError, "fixup chain revisits location %#x" % location
          end
          @visited[location] = true

          if page_offset + 8 > page_size
            raise ChainedFixupsError, "fixup at page offset %#x extends past end of page" % page_offset
          end

          raw = @reader.call(location, 8)
          if raw.nil? || raw.bytesize < 8
            raise ChainedFixupsError, "cannot read fixup at vm offset %#x" % location
          end

          fixup, next_units = decode(raw.unpack1("Q<"), pointer_format, location, imports)
          fixups << fixup
          break if next_units.zero?

          page_offset += next_units * stride
          if page_offset >= page_size
            raise ChainedFixupsError, "fixup chain continues past end of page at page offset %#x" % page_offset
          end
        end
      end

      # @return [Array(Rebase, Bind), Integer] the decoded fixup and the
      #  +next+ field of the chain entry
      def decode(value, pointer_format, location, imports)
        case pointer_format
        when DYLD_CHAINED_PTR_64, DYLD_CHAINED_PTR_64_OFFSET
          decode_ptr64(value, location, imports)
        when DYLD_CHAINED_PTR_ARM64E_USERLAND
          decode_arm64e(value, location, imports)
        end
      end

      # Decodes a dyld_chained_ptr_64_rebase/dyld_chained_ptr_64_bind entry.
      def decode_ptr64(value, location, imports)
        next_units = (value >> 51) & 0xFFF
        if (value >> 63).allbits?(1)
          ordinal = value & 0xFFFFFF
          addend = (value >> 24) & 0xFF
          [make_bind(location, ordinal, addend, imports, :authenticated => false), next_units]
        else
          target = (value & 0xFFFFFFFFF) | (((value >> 36) & 0xFF) << 56)
          [Rebase.new(:offset => location, :target => target, :authenticated => false), next_units]
        end
      end

      # Decodes an arm64e chain entry. Authenticated entries are reported
      # with their key/diversity/addrDiv bits as stored; no pointer signing
      # or authentication is attempted.
      def decode_arm64e(value, location, imports)
        bind = (value >> 62).allbits?(1)
        authenticated = (value >> 63).allbits?(1)
        next_units = (value >> 51) & 0x7FF

        if authenticated
          diversity = (value >> 32) & 0xFFFF
          addr_div = (value >> 48).allbits?(1)
          key = (value >> 49) & 0x3
          fixup = if bind
            make_bind(location, value & 0xFFFF, 0, imports,
                      :authenticated => true, :key => key,
                      :diversity => diversity, :addr_div => addr_div)
          else
            Rebase.new(:offset => location, :target => value & 0xFFFFFFFF,
                       :authenticated => true, :key => key,
                       :diversity => diversity, :addr_div => addr_div)
          end
        elsif bind
          addend = sign_extend((value >> 32) & 0x7FFFF, 19)
          fixup = make_bind(location, value & 0xFFFF, addend, imports, :authenticated => false)
        else
          target = (value & 0x7FFFFFFFFFF) | (((value >> 43) & 0xFF) << 56)
          fixup = Rebase.new(:offset => location, :target => target, :authenticated => false)
        end

        [fixup, next_units]
      end

      def make_bind(location, ordinal, addend, imports, attributes = {})
        import = imports[ordinal]
        if import.nil?
          raise ChainedFixupsError,
                "bind ordinal #{ordinal} is out of range (#{imports.size} imports)"
        end

        Bind.new(**{
          :offset => location,
          :ordinal => ordinal,
          :addend => addend,
          :symbol => import.name,
          :library_ordinal => import.library_ordinal,
          :weak_import => import.weak_import,
          :import_addend => import.addend,
        }.merge(attributes))
      end

      def sign_extend(value, bits)
        value -= (1 << bits) if value.allbits?(1 << (bits - 1))
        value
      end

      def read_symbol(offset)
        if offset >= @payload.bytesize
          raise ChainedFixupsError, "symbol name offset #{offset} is out of bounds"
        end

        terminator = @payload.index("\0".b, offset)
        if terminator.nil?
          raise ChainedFixupsError, "symbol name at payload offset #{offset} is not NUL-terminated"
        end

        @payload.byteslice(offset...terminator)
      end

      def read_uint16(offset)
        checked_slice(offset, 2).unpack1("v")
      end

      def read_uint32(offset)
        checked_slice(offset, 4).unpack1("V")
      end

      def read_uint64(offset)
        checked_slice(offset, 8).unpack1("Q<")
      end

      def read_int32(offset)
        checked_slice(offset, 4).unpack1("l<")
      end

      def read_int64(offset)
        checked_slice(offset, 8).unpack1("q<")
      end

      def checked_slice(offset, length)
        if offset.negative? || offset + length > @payload.bytesize
          raise ChainedFixupsError,
                "read of #{length} bytes at payload offset #{offset} is out of bounds"
        end
        @payload.byteslice(offset, length)
      end
    end
  end
end
