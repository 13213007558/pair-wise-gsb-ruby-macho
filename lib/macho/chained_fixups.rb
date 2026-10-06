# frozen_string_literal: true

require "zlib"

module MachO
  # A read-only parser for the payload of LC_DYLD_CHAINED_FIXUPS. Chained fixups
  # are the modern replacement for the bind/rebase opcodes embedded in
  # LC_DYLD_INFO. The payload describes where pointers live, how to walk the
  # chains of pointers within each page, and a compressed pool of imported
  # symbols that binds resolve against.
  #
  # The parser is purely descriptive: it enumerates what the on-disk image
  # contains without applying any fixups or performing pointer authentication
  # (PAC). See {Fixup} for the information returned for each pointer.
  #
  # @see https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h
  class ChainedFixups < MachOView
    # pointer formats currently understood by the parser.
    # @see Header#pointer_format
    POINTER_FORMATS = {
      2 => :DYLD_CHAINED_PTR_64,
      6 => :DYLD_CHAINED_PTR_64_OFFSET,
      9 => :DYLD_CHAINED_PTR_ARM64E_USERLAND,
    }.freeze

    # The stride (in bytes) applied to the `next` field to reach the following
    # pointer. fixup-chains.h comments mention a 4-byte stride for PTR_64*, but
    # chained 64-bit pointers are always 8 bytes apart in shipped images (a
    # `next` of 1 advances one pointer), which is also what the system linker
    # and dyld produce and consume.
    # @api private
    STRIDES = {
      2 => 8,
      6 => 8,
      9 => 8,
    }.freeze

    # encodings of the imports table.
    # @see Header#imports_format
    IMPORT_FORMATS = {
      1 => :DYLD_CHAINED_IMPORT,
      2 => :DYLD_CHAINED_IMPORT_ADDEND,
      3 => :DYLD_CHAINED_IMPORT_ADDEND64,
    }.freeze

    # on-disk sizes of each imports table entry, in bytes.
    # @api private
    IMPORT_SIZES = {
      1 => 4,
      2 => 8,
      3 => 16,
    }.freeze

    # raw (uncompressed) symbol pool.
    SYMBOLS_UNCOMPRESSED = 0

    # zlib-compressed symbol pool.
    SYMBOLS_ZLIB_COMPRESSED = 1

    # a page without any fixups.
    # @api private
    START_NONE = 0xFFFF

    # the high bit of a page start marks an index into the overflow list of
    # chain starts for a page with multiple independent chains.
    # @api private
    START_MULTI = 0x8000

    # the high bit of an overflow entry marks the final start for that page.
    # @api private
    START_LAST = 0x8000

    # size of the fixed prefix of a dyld_chained_starts_in_segment record
    # (everything up to but not including page_start[]).
    # @api private
    SEGMENT_STARTS_PREFIX = 22

    # PAC key discriminators used by authenticated pointers.
    AUTH_KEYS = {
      0 => :IA,
      1 => :IB,
      2 => :DA,
      3 => :DB,
    }.freeze

    # special dylib ordinals encoded in imports (negative values when
    # sign-extended).
    SPECIAL_ORDINALS = {
      0 => :BIND_SPECIAL_DYLIB_SELF,
      -1 => :BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE,
      -2 => :BIND_SPECIAL_DYLIB_FLAT_LOOKUP,
      -3 => :BIND_SPECIAL_DYLIB_WEAK_LOOKUP,
    }.freeze

    # The dyld_chained_fixups_header at the start of the load command payload.
    class Header < MachOStructure
      # @return [Integer] format version (currently 0)
      field :fixups_version, :uint32

      # @return [Integer] offset of the dyld_chained_starts_in_image
      field :starts_offset, :uint32

      # @return [Integer] offset of the imports table
      field :imports_offset, :uint32

      # @return [Integer] offset of the symbol string pool
      field :symbols_offset, :uint32

      # @return [Integer] number of imported symbols
      field :imports_count, :uint32

      # @return [Integer] encoding of the imports table
      field :imports_format, :uint32

      # @return [Integer] encoding of the symbol string pool
      field :symbols_format, :uint32
    end
    # @return [MachOFile] the Mach-O this payload belongs to
    attr_reader :macho_file

    # @return [Integer] the file offset at which the payload starts
    attr_reader :payload_offset

    # @return [Header] the payload header
    attr_reader :header

    # @param macho_file [MachOFile] the Mach-O containing the load command
    # @param command [LoadCommands::LinkeditDataCommand] the LC_DYLD_CHAINED_FIXUPS
    #  load command locating the payload
    # @return [ChainedFixups] a parser for the load command's payload
    # @raise [ChainedFixupsError] if the payload is truncated or malformed
    def initialize(macho_file, command)
      @macho_file = macho_file
      @command = command
      @payload_offset = command.dataoff
      payload = macho_file.serialize.byteslice(command.dataoff, command.datasize)
      super(macho_file, payload, macho_file.endianness, command.dataoff)
      @header = parse_header
      @symbols = parse_symbol_pool
      @imports = parse_imports
      @fixups = nil
    end

    # @return [Symbol] the symbol form of {Header#imports_format}
    def imports_format
      IMPORT_FORMATS.fetch(header.imports_format) do
        raise ChainedFixupsError,
              "Unknown chained fixups import format #{header.imports_format}"
      end
    end

    # @return [Symbol] the symbol form of the segment pointer formats, keyed
    #  by segment index (segments without starts are omitted)
    def pointer_formats
      segment_starts.to_h { |seg| [seg.segment_index, seg.pointer_format] }
    end

    # @return [Array<Import>] the resolved imports table, in ordinal order
    def imports
      @imports.dup
    end

    # Information about one segment's chain-start metadata.
    SegmentStarts = Struct.new(:segment_index, :size, :page_size, :pointer_format,
                              :pointer_format_id, :segment_offset, :max_valid_pointer,
                              :page_count, :page_starts, :record_offset, :record,
                              keyword_init: true)

    # @return [Array<SegmentStarts>] chain-start metadata for every segment that
    #  participates in fixups
    def segment_starts
      @segment_starts ||= parse_all_segment_starts
    end

    # Walks every chain in every segment and returns the fixups it contains.
    # @return [Array<Fixup>] the fixups, ordered by segment, page, and chain
    # @raise [ChainedFixupsChainOutOfBoundsError] if a chain leaves its page
    # @raise [ChainedFixupsDuplicateLocationError] if a location is visited twice
    # @raise [ChainedFixupsBadOrdinalError] if a bind names a missing import
    # @raise [ChainedFixupsError] for any other malformed payload
    def fixups
      @fixups ||= enumerate_fixups
    end

    alias to_a fixups

    # @return [Enumerable<Fixup>] the rebases
    def rebases
      fixups.select(&:rebase?)
    end

    # @return [Enumerable<Fixup>] the binds
    def binds
      fixups.select(&:bind?)
    end

    # @return [Hash] a hash representation of the parsed payload
    def to_h
      {
        "fixups_version" => header.fixups_version,
        "imports_format" => imports_format,
        "symbols_format" => header.symbols_format,
        "pointer_formats" => pointer_formats.transform_values(&:to_s),
        "imports" => @imports.map { |i| { "name" => i.name, "lib_ordinal" => i.lib_ordinal } },
        "fixups" => fixups.map(&:to_h),
      }
    end

    private

    # @api private
    def parse_header
      raise ChainedFixupsError, "LC_DYLD_CHAINED_FIXUPS payload is empty" if raw_data.empty?
      unless raw_data.bytesize >= Header.bytesize
        raise ChainedFixupsError, "Chained fixups payload is truncated: " \
                                "need #{Header.bytesize} bytes, have #{raw_data.bytesize}"
      end

      hdr = Header.new_from_bin(endianness, raw_data.byteslice(0, Header.bytesize))
      unless hdr.fixups_version.zero?
        raise ChainedFixupsError, "Unsupported chained fixups version #{hdr.fixups_version}"
      end
      unless IMPORT_FORMATS.key?(hdr.imports_format)
        raise ChainedFixupsError, "Unknown chained fixups import format #{hdr.imports_format}"
      end
      unless [SYMBOLS_UNCOMPRESSED, SYMBOLS_ZLIB_COMPRESSED].include?(hdr.symbols_format)
        raise ChainedFixupsError, "Unknown chained fixups symbols format #{hdr.symbols_format}"
      end

      hdr
    end

    # @api private
    def parse_symbol_pool
      raw = bytes_from(header.symbols_offset, "symbols pool")

      if header.symbols_format == SYMBOLS_ZLIB_COMPRESSED
        begin
          raw = Zlib::Inflate.inflate(raw)
        rescue Zlib::Error => e
          raise ChainedFixupsError, "Failed to inflate compressed symbol pool: #{e.message}"
        end
      end

      raw
    end

    # @api private
    def parse_imports
      entry_size = IMPORT_SIZES.fetch(header.imports_format)
      imports_table_size = header.imports_count * entry_size
      table = bytes_from(header.imports_offset, "imports table", imports_table_size)

      Array.new(header.imports_count) do |ordinal|
        entry = table.byteslice(ordinal * entry_size, entry_size)
        parse_import(ordinal, entry)
      end
    end

    # @api private
    def parse_import(ordinal, entry)
      case header.imports_format
      when 1
        packed = read_uint32(entry, 0, "import #{ordinal}")
        lib_byte = packed & 0xFF
        weak = ((packed >> 8) & 1) == 1
        name_offset = packed >> 9
        addend = nil
      when 2
        packed = read_uint32(entry, 0, "import #{ordinal}")
        lib_byte = packed & 0xFF
        weak = ((packed >> 8) & 1) == 1
        name_offset = packed >> 9
        addend = read_int32(entry, 4, "import #{ordinal} addend")
      when 3
        first = read_uint64(entry, 0, "import #{ordinal}")
        lib_byte = first & 0xFFFF
        weak = ((first >> 16) & 1) == 1
        name_offset = first >> 32
        addend = read_int64(entry, 8, "import #{ordinal} addend")
      end

      ordinal_bits = header.imports_format == 3 ? 16 : 8
      lib_ordinal = interpret_lib_ordinal(lib_byte, :bits => ordinal_bits)
      name = symbol_at(name_offset, ordinal)
      special = SPECIAL_ORDINALS[lib_ordinal]
      dylib = dylib_path_for(lib_ordinal)

      Import.new(lib_ordinal, weak, name_offset, addend, name, special, dylib)
    end

    # The 8-bit and 16-bit ordinal fields are sign-extended when their high bit
    # is set (the special ordinals are negative).
    # @api private
    def interpret_lib_ordinal(value, bits:)
      sign_bit = 1 << (bits - 1)
      mask = (1 << bits) - 1
      value &= mask
      (value & sign_bit).zero? ? value : value - (1 << bits)
    end

    # @api private
    def symbol_at(name_offset, ordinal)
      if name_offset >= @symbols.bytesize
        raise ChainedFixupsError, "Import ordinal #{ordinal} names symbol at offset " \
                                  "#{name_offset}, beyond symbol pool (#{@symbols.bytesize} bytes)"
      end

      terminator = @symbols.index("\0", name_offset)
      if terminator.nil?
        raise ChainedFixupsError, "Import ordinal #{ordinal} has an unterminated symbol name"
      end

      @symbols.byteslice(name_offset, terminator - name_offset).force_encoding(Encoding::UTF_8)
    end

    # @api private
    def dylib_path_for(lib_ordinal)
      return nil unless lib_ordinal.positive?

      dylib_commands[lib_ordinal - 1]&.name&.to_s
    end

    # @api private
    def dylib_commands
      @dylib_commands ||= macho_file.dylib_load_commands
    end

    # @api private
    def bytes_from(offset, what, length = nil)
      raise ChainedFixupsError, "#{what.capitalize} offset #{offset} is out of bounds " \
                                "(payload is #{raw_data.bytesize} bytes)" if offset > raw_data.bytesize

      if length.nil?
        raw_data.byteslice(offset, raw_data.bytesize - offset)
      else
        if offset + length > raw_data.bytesize
          raise ChainedFixupsError, "#{what.capitalize} overruns the payload: offset #{offset} " \
                                    "+ #{length} bytes > #{raw_data.bytesize}"
        end
        raw_data.byteslice(offset, length)
      end
    end

    # @api private
    def read_uint32(bin, offset, what)
      slice = bin.byteslice(offset, 4)
      if slice.nil? || slice.bytesize < 4
        raise ChainedFixupsError, "Truncated #{what}"
      end
      slice.unpack1(Utils.specialize_format("L=", endianness))
    end

    # @api private
    def read_int32(bin, offset, what)
      slice = bin.byteslice(offset, 4)
      raise ChainedFixupsError, "Truncated #{what}" if slice.nil? || slice.bytesize < 4
      slice.unpack1(Utils.specialize_format("l=", endianness))
    end

    # @api private
    def read_uint64(bin, offset, what)
      slice = bin.byteslice(offset, 8)
      if slice.nil? || slice.bytesize < 8
        raise ChainedFixupsError, "Truncated #{what}"
      end
      slice.unpack1(Utils.specialize_format("Q=", endianness))
    end

    # @api private
    def read_int64(bin, offset, what)
      slice = bin.byteslice(offset, 8)
      raise ChainedFixupsError, "Truncated #{what}" if slice.nil? || slice.bytesize < 8
      slice.unpack1(Utils.specialize_format("q=", endianness))
    end

    # @api private
    def parse_all_segment_starts
      image = bytes_from(header.starts_offset, "starts_in_image")
      raise ChainedFixupsError, "Truncated dyld_chained_starts_in_image" if image.bytesize < 4

      seg_count = read_uint32(image, 0, "starts_in_image seg_count")
      offsets_size = 4 + (4 * seg_count)
      if offsets_size > image.bytesize
        raise ChainedFixupsError, "dyld_chained_starts_in_image declares #{seg_count} segments " \
                                  "but only #{(image.bytesize - 4) / 4} segment info offsets fit"
      end
      if seg_count > macho_file.segments.size
        raise ChainedFixupsError, "dyld_chained_starts_in_image seg_count (#{seg_count}) exceeds " \
                                  "the number of segments (#{macho_file.segments.size})"
      end

      seg_info_offsets = (0...seg_count).map do |i|
        read_uint32(image, 4 + (4 * i), "seg_info_offset #{i}")
      end

      seg_info_offsets.each_with_index.filter_map do |seg_info_offset, seg_index|
        next nil if seg_info_offset.zero?
        parse_segment_starts(image, header.starts_offset, seg_info_offset, seg_index)
      end
    end

    # @api private
    def parse_segment_starts(image, image_offset, seg_info_offset, seg_index)
      record = image.byteslice(seg_info_offset, image.bytesize - seg_info_offset)
      if record.nil? || record.bytesize < SEGMENT_STARTS_PREFIX
        raise ChainedFixupsError, "Segment #{seg_index} starts record at payload offset " \
                                  "#{image_offset + seg_info_offset} is truncated"
      end

      size = read_uint32(record, 0, "segment #{seg_index} starts size")
      page_size = record.byteslice(4, 2).unpack1(Utils.specialize_format("S=", endianness))
      format_id = record.byteslice(6, 2).unpack1(Utils.specialize_format("S=", endianness))
      segment_offset = read_uint64(record, 8, "segment #{seg_index} segment_offset")
      max_valid_pointer = read_uint32(record, 16, "segment #{seg_index} max_valid_pointer")
      page_count = record.byteslice(20, 2).unpack1(Utils.specialize_format("S=", endianness))

      unless POINTER_FORMATS.key?(format_id)
        name = format_name_hint(format_id)
        raise ChainedFixupsError, "Unsupported chained pointer format #{format_id} (#{name}) " \
                                  "in segment #{seg_index}"
      end

      unless [0x1000, 0x4000].include?(page_size)
        raise ChainedFixupsError, "Segment #{seg_index} has invalid chain page size 0x#{page_size.to_s(16)}"
      end

      page_starts_size = 2 * page_count
      if SEGMENT_STARTS_PREFIX + page_starts_size > record.bytesize
        raise ChainedFixupsError, "Segment #{seg_index} page_start array overruns its starts record"
      end

      page_starts = (0...page_count).map do |i|
        record.byteslice(SEGMENT_STARTS_PREFIX + (2 * i), 2)
              .unpack1(Utils.specialize_format("S=", endianness))
      end

      SegmentStarts.new(
        :segment_index => seg_index,
        :size => size,
        :page_size => page_size,
        :pointer_format_id => format_id,
        :pointer_format => POINTER_FORMATS[format_id],
        :segment_offset => segment_offset,
        :max_valid_pointer => max_valid_pointer,
        :page_count => page_count,
        :page_starts => page_starts,
        :record_offset => image_offset + seg_info_offset,
        :record => record,
      )
    end

    # @api private
    def format_name_hint(format_id)
      case format_id
      when 1 then "DYLD_CHAINED_PTR_ARM64E"
      when 7 then "DYLD_CHAINED_PTR_ARM64_KERNEL"
      when 12 then "DYLD_CHAINED_PTR_ARM64E_USERLAND24"
      when 13 then "DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE"
      else "unknown"
      end
    end

    # @api private
    def image_base
      @image_base ||= begin
        mapped = macho_file.segments.select { |seg| seg.filesize.positive? }
        if mapped.empty?
          raise ChainedFixupsError, "Mach-O has no file-backed segments to locate fixups"
        end

        mapped.map(&:vmaddr).min
      end
    end

    # Resolve an in-page offset to a file offset and a runtime offset,
    # validating that it stays inside the page and the segment's file data.
    # @api private
    def location_for(segment_starts, in_page_offset)
      runtime_offset = segment_starts.segment_offset + in_page_offset
      segment = macho_file.segments[segment_starts.segment_index]

      if in_page_offset >= segment_starts.page_size
        raise ChainedFixupsChainOutOfBoundsError.new(
          runtime_offset,
          "page offset #{in_page_offset} >= page size #{segment_starts.page_size} " \
          "in segment #{segment_starts.segment_index}",
        )
      end

      if segment.nil?
        raise ChainedFixupsError, "Fixup at runtime offset 0x#{runtime_offset.to_s(16)} references " \
                                  "missing segment #{segment_starts.segment_index}"
      end

      segment_base = segment.vmaddr - image_base
      within_segment = runtime_offset - segment_base
      if within_segment.negative?
        raise ChainedFixupsChainOutOfBoundsError.new(
          runtime_offset,
          "before start of #{segment.segname.inspect} at runtime offset 0x#{segment_base.to_s(16)}",
        )
      end
      unless within_segment < segment.filesize
        range_end = segment_base + segment.filesize
        raise ChainedFixupsChainOutOfBoundsError.new(
          runtime_offset,
          "outside file-backed range of #{segment.segname.inspect} " \
          "[0x#{segment_base.to_s(16)}, 0x#{range_end.to_s(16)})",
        )
      end

      file_offset = segment.fileoff + within_segment
      vm_relative = runtime_offset
      [file_offset, image_base + vm_relative, vm_relative]
    end

    # The list of in-page chain starts for a page, handling the multi-start
    # (overflow) encoding for pages containing multiple independent chains.
    # @api private
    def chain_starts_for_page(segment_starts, page_index, raw_start)
      return [raw_start] unless (raw_start & START_MULTI).positive?

      record = segment_starts.record
      index = raw_start & 0x7FFF
      starts = []
      loop do
        if index + 2 > segment_starts.size || index + 2 > record.bytesize
          raise ChainedFixupsError, "Multi-start chain list for segment " \
                                    "#{segment_starts.segment_index} page #{page_index} indexes " \
                                    "past the starts record (offset #{index})"
        end
        entry = record.byteslice(index, 2)
                     .unpack1(Utils.specialize_format("S=", endianness))
        starts << (entry & 0x7FFF)
        index += 2
        break if (entry & START_LAST).positive?
      end
      starts
    end

    # @api private
    def enumerate_fixups
      fixups = []
      visited = {}

      segment_starts.each do |segment_starts|
        segment_starts.page_starts.each_with_index do |raw_start, page_index|
          next if raw_start == START_NONE

          chain_starts_for_page(segment_starts, page_index, raw_start).each do |start|
            walk_chain(segment_starts, page_index, start, fixups, visited)
          end
        end
      end

      fixups
    end

    # @api private
    def walk_chain(segment_starts, page_index, start_offset, fixups, visited)
      stride = STRIDES.fetch(segment_starts.pointer_format_id)
      in_page_offset = start_offset
      chain_step = 0

      loop do
        pointer_end = in_page_offset + 8
        if pointer_end > segment_starts.page_size || in_page_offset.negative?
          runtime_offset = segment_starts.segment_offset + in_page_offset
          raise ChainedFixupsChainOutOfBoundsError.new(
            runtime_offset,
            "chain pointer overruns #{segment_starts.page_size}-byte page in segment " \
            "#{segment_starts.segment_index} page #{page_index}",
          )
        end

        runtime_offset = segment_starts.segment_offset + in_page_offset
        if visited.key?(runtime_offset)
          raise ChainedFixupsDuplicateLocationError, runtime_offset
        end
        visited[runtime_offset] = [segment_starts.segment_index, page_index, chain_step]

        file_offset, vmaddr, offset = location_for(segment_starts, in_page_offset)
        image_data = macho_file.serialize
        if file_offset + 8 > image_data.bytesize
          raise ChainedFixupsError, "Fixup at file offset #{file_offset} is beyond the end of the file"
        end
        raw = image_data.byteslice(file_offset, 8)
                      .unpack1(Utils.specialize_format("Q=", endianness))

        fixups << decode_pointer(segment_starts, raw, file_offset, vmaddr, offset)

        next_step = chain_next_step(raw)
        break if next_step.zero?

        in_page_offset += next_step * stride
        chain_step += 1
      end
    end

    # Extract the `next` chain step: the 11-bit field at bits[62:52], shared by
    # every supported pointer encoding. It is multiplied by the format's stride
    # (8 for all formats supported here) to reach the next pointer in the chain.
    # @api private
    def chain_next_step(raw)
      (raw >> 52) & 0x7FF
    end

    # @api private
    def decode_pointer(segment_starts, raw, file_offset, vmaddr, runtime_offset)
      common = {
        :file_offset => file_offset,
        :vmaddr => vmaddr,
        :runtime_offset => runtime_offset,
        :pointer_format => segment_starts.pointer_format,
        :segment_index => segment_starts.segment_index,
        :raw => raw,
      }

      case segment_starts.pointer_format_id
      when 2, 6 then decode_ptr_64(segment_starts.pointer_format_id, raw, common)
      when 9 then decode_ptr_arm64e_userland(raw, common)
      end
    end

    # DYLD_CHAINED_PTR_64 / DYLD_CHAINED_PTR_64_OFFSET
    # @api private
    def decode_ptr_64(format_id, raw, common)
      if (raw >> 63) == 1
        ordinal = raw & 0xFFFFFF
        addend = (raw >> 24) & 0xFF
        import = import_for(ordinal, common[:runtime_offset])
        Fixup.new(**common, :type => :bind, :ordinal => ordinal, :bind_addend => addend,
                  :import => import, :authenticated => false)
      else
        target_low = raw & 0xFFFFFFFFF # 36 bits
        high8 = (raw >> 36) & 0xFF
        if format_id == 2
          target = target_low | (high8 << 36)
          Fixup.new(**common, :type => :rebase, :target_vmaddr => target,
                    :target_offset => target - image_base, :high8 => high8,
                    :authenticated => false)
        else
          target = target_low | (high8 << 36)
          Fixup.new(**common, :type => :rebase, :target_offset => target,
                    :target_vmaddr => image_base + target, :high8 => high8,
                    :authenticated => false)
        end
      end
    end

    # DYLD_CHAINED_PTR_ARM64E_USERLAND: stride 8, targets are runtime offsets.
    # @api private
    def decode_ptr_arm64e_userland(raw, common)
      bind = ((raw >> 63) & 1) == 1
      auth = ((raw >> 62) & 1) == 1

      if bind && auth
        ordinal = raw & 0xFFFF
        diversity = (raw >> 32) & 0xFFFF
        addr_div = ((raw >> 48) & 1) == 1
        key = AUTH_KEYS[(raw >> 49) & 3]
        import = import_for(ordinal, common[:runtime_offset])
        Fixup.new(**common, :type => :bind, :ordinal => ordinal,
                  :bind_addend => import.addend || 0, :import => import,
                  :authenticated => true, :key => key, :diversity => diversity,
                  :address_diversified => addr_div)
      elsif bind
        ordinal = raw & 0xFFFF
        addend = sign_extend((raw >> 32) & 0x7FFFF, 19)
        import = import_for(ordinal, common[:runtime_offset])
        Fixup.new(**common, :type => :bind, :ordinal => ordinal,
                  :bind_addend => addend, :import => import, :authenticated => false)
      elsif auth
        target = raw & 0xFFFFFFFF # 32-bit runtime offset
        diversity = (raw >> 32) & 0xFFFF
        addr_div = ((raw >> 48) & 1) == 1
        key = AUTH_KEYS[(raw >> 49) & 3]
        Fixup.new(**common, :type => :rebase, :target_offset => target,
                  :target_vmaddr => image_base + target,
                  :authenticated => true, :key => key, :diversity => diversity,
                  :address_diversified => addr_div)
      else
        target_low = raw & 0x7FFFFFFFFFF # 43-bit runtime offset
        high8 = (raw >> 43) & 0xFF
        target = target_low | (high8 << 43)
        Fixup.new(**common, :type => :rebase, :target_offset => target,
                  :target_vmaddr => image_base + target, :high8 => high8,
                  :authenticated => false)
      end
    end

    # @api private
    def import_for(ordinal, runtime_offset)
      if ordinal >= @imports.size
        raise ChainedFixupsBadOrdinalError.new(
          ordinal,
          "referenced by pointer at runtime offset 0x#{runtime_offset.to_s(16)}; " \
          "imports_count is #{@imports.size}",
        )
      end

      @imports[ordinal]
    end

    # @api private
    def sign_extend(value, bits)
      sign_bit = 1 << (bits - 1)
      mask = (1 << bits) - 1
      value &= mask
      (value ^ sign_bit) - sign_bit
    end

    # One entry in the imports table. For import formats that carry an addend
    # it is the addend baked into the import itself; per-pointer addends from
    # the chain encoding are reported separately on {Fixup}.
    class Import
      # @return [Integer] the raw library ordinal (1-based, or a negative
      #  special ordinal)
      attr_reader :lib_ordinal

      # @return [Boolean] whether the symbol is weakly imported
      attr_reader :weak_import

      # @return [Integer] offset of the symbol name in the symbol pool
      attr_reader :name_offset

      # @return [Integer, nil] the addend embedded in the import (formats 2 and 3)
      attr_reader :addend

      # @return [String] the imported symbol name
      attr_reader :name

      # @return [Symbol, nil] the special ordinal's name (e.g. :DYLIB_ORDINAL_FLAT_LOOKUP)
      attr_reader :special_ordinal

      # @return [String, nil] the path of the linked dylib, if resolvable
      attr_reader :dylib

      # @api private
      def initialize(lib_ordinal, weak_import, name_offset, addend, name, special_ordinal, dylib)
        @lib_ordinal = lib_ordinal
        @weak_import = weak_import
        @name_offset = name_offset
        @addend = addend
        @name = name
        @special_ordinal = special_ordinal
        @dylib = dylib
      end
    end

    # A single pointer described by a fixup chain. Instances are read-only and
    # never mutated: no rebase is applied and no PAC signing is performed.
    class Fixup
      # @return [Integer] the pointer's offset within the Mach-O file
      attr_reader :file_offset

      # @return [Integer] the pointer's runtime address (VM address in the image)
      attr_reader :vmaddr

      # @return [Integer] the pointer's runtime-relative offset (vmaddr minus
      #  the image base)
      attr_reader :runtime_offset

      # @return [Symbol] `:rebase` or `:bind`
      attr_reader :type

      # @return [Symbol] the on-disk pointer format (see {ChainedFixups::POINTER_FORMATS})
      attr_reader :pointer_format

      # @return [Integer] index of the segment containing the pointer
      attr_reader :segment_index

      # @return [Import, nil] the resolved import for a bind
      attr_reader :import

      # @return [Integer, nil] the raw import ordinal encoded in the pointer
      attr_reader :ordinal

      # @return [Integer] the addend to apply when binding (0 unless present)
      attr_reader :bind_addend

      # @return [Integer, nil] for a rebase, the runtime-relative offset of the
      #  pointer's target
      attr_reader :target_offset

      # @return [Integer, nil] for a `DYLD_CHAINED_PTR_64` rebase, the target's
      #  absolute VM address
      attr_reader :target_vmaddr

      # @return [Integer] the raw 64-bit on-disk pointer value
      attr_reader :raw

      # @return [Boolean] whether the pointer is authenticated (PAC)
      attr_reader :authenticated

      # @return [Symbol, nil] the PAC key (`:IA`, `:IB`, `:DA`, `:DB`)
      attr_reader :key

      # @return [Integer, nil] the PAC diversity value
      attr_reader :diversity

      # @return [Boolean, nil] whether the pointer address itself is folded
      #  into the PAC diversity (address diversity)
      attr_reader :address_diversified

      # @return [Integer, nil] the arm64e rebase `high8` field
      attr_reader :high8

      # @api private
      def initialize(**attrs)
        @file_offset = attrs.fetch(:file_offset)
        @vmaddr = attrs.fetch(:vmaddr)
        @runtime_offset = attrs.fetch(:runtime_offset)
        @type = attrs.fetch(:type)
        @pointer_format = attrs.fetch(:pointer_format)
        @segment_index = attrs.fetch(:segment_index)
        @import = attrs[:import]
        @ordinal = attrs[:ordinal]
        @bind_addend = attrs[:bind_addend] || 0
        @target_offset = attrs[:target_offset]
        @target_vmaddr = attrs[:target_vmaddr]
        @raw = attrs.fetch(:raw)
        @authenticated = attrs.fetch(:authenticated, false)
        @key = attrs[:key]
        @diversity = attrs[:diversity]
        @address_diversified = attrs[:address_diversified]
        @high8 = attrs[:high8]
      end

      # @return [Boolean] whether this fixup is a rebase
      def rebase?
        type == :rebase
      end

      # @return [Boolean] whether this fixup is a bind
      def bind?
        type == :bind
      end

      # @return [String, nil] the imported symbol name for a bind
      def symbol_name
        import&.name
      end

      # @return [Hash] a hash representation of this {Fixup}
      def to_h
        {
          "file_offset" => file_offset,
          "vmaddr" => vmaddr,
          "runtime_offset" => runtime_offset,
          "type" => type,
          "pointer_format" => pointer_format,
          "segment_index" => segment_index,
          "ordinal" => ordinal,
          "bind_addend" => bind_addend,
          "target_offset" => target_offset,
          "target_vmaddr" => target_vmaddr,
          "raw" => raw,
          "authenticated" => authenticated,
          "key" => key,
          "diversity" => diversity,
          "address_diversified" => address_diversified,
          "high8" => high8,
          "import" => import.nil? ? nil : {
            "name" => import.name,
            "lib_ordinal" => import.lib_ordinal,
            "weak_import" => import.weak_import,
          },
        }
      end
    end
  end
end
