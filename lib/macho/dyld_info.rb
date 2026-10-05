# frozen_string_literal: true

module MachO
  # An interpreter for the compressed dyld info opcode streams referenced by
  # the LC_DYLD_INFO and LC_DYLD_INFO_ONLY load commands found in older
  # Mach-O files. The interpreter walks a rebase, bind, weak bind, or lazy
  # bind byte stream and translates it into a list of address fixup actions.
  # It only produces descriptions of the fixups; it never modifies, loads,
  # or runs the binary the stream came from.
  module DyldInfo
    # mask isolating the opcode half of a rebase opcode byte
    REBASE_OPCODE_MASK = 0xF0

    # mask isolating the immediate half of a rebase opcode byte
    REBASE_IMMEDIATE_MASK = 0x0F

    # the rebase stream is finished
    REBASE_OPCODE_DONE = 0x00

    # set the rebase type to the immediate value
    REBASE_OPCODE_SET_TYPE_IMM = 0x10

    # set the segment index to the immediate value and the segment offset to
    # a following uleb128
    REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB = 0x20

    # add a following uleb128 to the segment offset
    REBASE_OPCODE_ADD_ADDR_ULEB = 0x30

    # add immediate * pointer size to the segment offset
    REBASE_OPCODE_ADD_ADDR_IMM_SCALED = 0x40

    # rebase immediate-times, advancing by the pointer size after each fixup
    REBASE_OPCODE_DO_REBASE_IMM_TIMES = 0x50

    # rebase uleb128-times, advancing by the pointer size after each fixup
    REBASE_OPCODE_DO_REBASE_ULEB_TIMES = 0x60

    # rebase once, then add a following uleb128 to the segment offset
    REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB = 0x70

    # rebase uleb128-times, skipping a uleb128-sized step plus the pointer
    # size after each fixup
    REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB = 0x80

    # the fixup is a pointer-sized value
    REBASE_TYPE_POINTER = 1

    # the fixup is a 32-bit absolute address in __TEXT
    REBASE_TYPE_TEXT_ABSOLUTE32 = 2

    # the fixup is a 32-bit PC-relative address in __TEXT
    REBASE_TYPE_TEXT_PCREL32 = 3

    # mask isolating the opcode half of a bind opcode byte
    BIND_OPCODE_MASK = 0xF0

    # mask isolating the immediate half of a bind opcode byte
    BIND_IMMEDIATE_MASK = 0x0F

    # the bind record (or the whole stream, for non-lazy binds) is finished
    BIND_OPCODE_DONE = 0x00

    # set the library ordinal to the immediate value
    BIND_OPCODE_SET_DYLIB_ORDINAL_IMM = 0x10

    # set the library ordinal to a following uleb128
    BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB = 0x20

    # set the library ordinal to a special value encoded in the immediate
    BIND_OPCODE_SET_DYLIB_SPECIAL_IMM = 0x30

    # set the symbol flags to the immediate value and the symbol name to a
    # following NUL-terminated string
    BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM = 0x40

    # set the bind type to the immediate value
    BIND_OPCODE_SET_TYPE_IMM = 0x50

    # set the addend to a following sleb128
    BIND_OPCODE_SET_ADDEND_SLEB = 0x60

    # set the segment index to the immediate value and the segment offset to
    # a following uleb128
    BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB = 0x70

    # add a following uleb128 to the segment offset
    BIND_OPCODE_ADD_ADDR_ULEB = 0x80

    # bind once, then advance the segment offset by the pointer size
    BIND_OPCODE_DO_BIND = 0x90

    # bind once, then add a following uleb128 plus the pointer size to the
    # segment offset
    BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB = 0xA0

    # bind once, then add immediate * pointer size plus the pointer size to
    # the segment offset
    BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED = 0xB0

    # bind uleb128-times, skipping a uleb128-sized step plus the pointer size
    # after each fixup
    BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB = 0xC0

    # the fixup is a pointer-sized value
    BIND_TYPE_POINTER = 1

    # the fixup is a 32-bit absolute address in __TEXT
    BIND_TYPE_TEXT_ABSOLUTE32 = 2

    # the fixup is a 32-bit PC-relative address in __TEXT
    BIND_TYPE_TEXT_PCREL32 = 3

    # the bound symbol is a weak import
    BIND_SYMBOL_FLAGS_WEAK_IMPORT = 0x1

    # the bound symbol is a non-weak definition
    BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION = 0x2

    # mapping of special (non-positive) library ordinals to symbolic names.
    # Special ordinals never index into the file's table of dependent
    # dylibs; only positive ordinals do.
    SPECIAL_ORDINALS = {
      0 => :self,
      -1 => :main_executable,
      -2 => :flat_lookup,
    }.freeze

    # A lightweight description of a Mach-O segment. The interpreter uses
    # segments to translate (segment index, segment offset) pairs into
    # virtual addresses and to detect fixups that would land outside the
    # segment.
    class Segment
      # @return [Integer] the segment's preferred virtual memory address
      attr_reader :vmaddr

      # @return [Integer] the segment's virtual memory size
      attr_reader :vmsize

      # @param vmaddr [Integer] the segment's preferred virtual memory address
      # @param vmsize [Integer] the segment's virtual memory size
      def initialize(vmaddr, vmsize)
        @vmaddr = vmaddr
        @vmsize = vmsize
      end
    end

    # A single rebase fixup decoded from a rebase opcode stream.
    class RebaseAction
      # @return [Integer] offset of the start of this action's record in the
      #   opcode stream
      attr_reader :source_offset

      # @return [Integer] index of the segment containing the fixup
      attr_reader :segment_index

      # @return [Integer] offset of the fixup within its segment
      attr_reader :segment_offset

      # @return [Integer, nil] virtual address of the fixup, or nil if no
      #   segment layout was supplied
      attr_reader :address

      # @return [Integer] one of the REBASE_TYPE_* constants
      attr_reader :type

      # @param source_offset [Integer] see {#source_offset}
      # @param segment_index [Integer] see {#segment_index}
      # @param segment_offset [Integer] see {#segment_offset}
      # @param address [Integer, nil] see {#address}
      # @param type [Integer] see {#type}
      def initialize(source_offset:, segment_index:, segment_offset:, address:, type:)
        @source_offset = source_offset
        @segment_index = segment_index
        @segment_offset = segment_offset
        @address = address
        @type = type
      end

      # @return [Hash] a hash representation of this {RebaseAction}
      def to_h
        {
          "source_offset" => source_offset,
          "segment_index" => segment_index,
          "segment_offset" => segment_offset,
          "address" => address,
          "type" => type,
        }
      end

      # @param other [Object] the object to compare with
      # @return [Boolean] true if +other+ is a {RebaseAction} with the same
      #   attributes
      def ==(other)
        other.is_a?(RebaseAction) && to_h == other.to_h
      end
    end

    # A single bind fixup decoded from a bind, weak bind, or lazy bind
    # opcode stream.
    class BindAction
      # @return [Integer] offset of the start of this action's record in the
      #   opcode stream
      attr_reader :source_offset

      # @return [Integer] index of the segment containing the fixup
      attr_reader :segment_index

      # @return [Integer] offset of the fixup within its segment
      attr_reader :segment_offset

      # @return [Integer, nil] virtual address of the fixup, or nil if no
      #   segment layout was supplied
      attr_reader :address

      # @return [Integer] one of the BIND_TYPE_* constants
      attr_reader :type

      # @return [Integer, Symbol] the 1-based index of the source dylib in
      #   the file's table of dependent dylibs, or a symbol from
      #   {SPECIAL_ORDINALS} (+:self+, +:main_executable+, or +:flat_lookup+)
      #   for special ordinals
      attr_reader :library_ordinal

      # @return [String] the name of the bound symbol
      attr_reader :symbol_name

      # @return [Integer] a bitwise-or of the BIND_SYMBOL_FLAGS_* constants
      attr_reader :symbol_flags

      # @return [Integer] the signed addend applied to the bound symbol
      attr_reader :addend

      # @param source_offset [Integer] see {#source_offset}
      # @param segment_index [Integer] see {#segment_index}
      # @param segment_offset [Integer] see {#segment_offset}
      # @param address [Integer, nil] see {#address}
      # @param type [Integer] see {#type}
      # @param library_ordinal [Integer, Symbol] see {#library_ordinal}
      # @param symbol_name [String] see {#symbol_name}
      # @param symbol_flags [Integer] see {#symbol_flags}
      # @param addend [Integer] see {#addend}
      def initialize(source_offset:, segment_index:, segment_offset:, address:, type:,
                     library_ordinal:, symbol_name:, symbol_flags:, addend:)
        @source_offset = source_offset
        @segment_index = segment_index
        @segment_offset = segment_offset
        @address = address
        @type = type
        @library_ordinal = library_ordinal
        @symbol_name = symbol_name
        @symbol_flags = symbol_flags
        @addend = addend
      end

      # @return [Boolean] true if the library ordinal is one of the special
      #   ordinals in {SPECIAL_ORDINALS} rather than an index into the file's
      #   table of dependent dylibs
      def special_ordinal?
        library_ordinal.is_a?(Symbol)
      end

      # @return [Hash] a hash representation of this {BindAction}
      def to_h
        {
          "source_offset" => source_offset,
          "segment_index" => segment_index,
          "segment_offset" => segment_offset,
          "address" => address,
          "type" => type,
          "library_ordinal" => library_ordinal,
          "symbol_name" => symbol_name,
          "symbol_flags" => symbol_flags,
          "addend" => addend,
        }
      end

      # @param other [Object] the object to compare with
      # @return [Boolean] true if +other+ is a {BindAction} with the same
      #   attributes
      def ==(other)
        other.is_a?(BindAction) && to_h == other.to_h
      end
    end

    class << self
      # Reads an unsigned LEB128 value from a byte string.
      # @param bytes [String] the byte string to read from
      # @param offset [Integer] the offset at which the value starts
      # @return [Array(Integer, Integer)] the decoded value and the offset of
      #   the first byte after it
      # @raise [DyldInfoError] if the value is truncated or exceeds 64 bits
      def read_uleb128(bytes, offset = 0)
        start = offset
        result = 0
        shift = 0

        loop do
          raise DyldInfoError, "truncated uleb128 value at offset #{start}" if offset >= bytes.bytesize

          byte = bytes.getbyte(offset)
          offset += 1
          result |= (byte & 0x7F) << shift
          break if (byte & 0x80).zero?

          shift += 7
          raise DyldInfoError, "uleb128 value at offset #{start} exceeds 64 bits" if shift > 63
        end

        [result, offset]
      end

      # Reads a signed LEB128 value from a byte string.
      # @param bytes [String] the byte string to read from
      # @param offset [Integer] the offset at which the value starts
      # @return [Array(Integer, Integer)] the decoded value and the offset of
      #   the first byte after it
      # @raise [DyldInfoError] if the value is truncated or exceeds 64 bits
      def read_sleb128(bytes, offset = 0)
        start = offset
        result = 0
        shift = 0

        loop do
          raise DyldInfoError, "truncated sleb128 value at offset #{start}" if offset >= bytes.bytesize

          byte = bytes.getbyte(offset)
          offset += 1
          result |= (byte & 0x7F) << shift
          shift += 7

          if (byte & 0x80).zero?
            result |= -(1 << shift) if shift < 64 && (byte & 0x40) != 0
            break
          end

          raise DyldInfoError, "sleb128 value at offset #{start} exceeds 64 bits" if shift > 63
        end

        [result, offset]
      end

      # Interprets a rebase opcode stream.
      # @param bytes [String] the raw rebase opcodes, e.g. the region of the
      #   file described by DyldInfoCommand#rebase_off/#rebase_size
      # @param segments [Array<Segment, Hash, #vmaddr>] the segment layout
      #   used to resolve addresses and check bounds; may be empty
      # @param pointer_size [Integer] the pointer size of the stream's
      #   architecture, in bytes
      # @return [Array<RebaseAction>] the decoded rebase fixups
      # @raise [DyldInfoError] if the stream is malformed
      def rebase_actions(bytes, segments: [], pointer_size: 8)
        Interpreter.new(bytes, :segments => segments, :pointer_size => pointer_size,
                               :kind => :rebase).actions
      end

      # Interprets a bind, weak bind, or lazy bind opcode stream.
      # @param bytes [String] the raw bind opcodes, e.g. the region of the
      #   file described by DyldInfoCommand#bind_off/#bind_size
      # @param segments [Array<Segment, Hash, #vmaddr>] the segment layout
      #   used to resolve addresses and check bounds; may be empty
      # @param pointer_size [Integer] the pointer size of the stream's
      #   architecture, in bytes
      # @param kind [Symbol] one of :bind, :weak_bind, or :lazy_bind. For
      #   :lazy_bind, a DONE opcode only ends the current record and the
      #   stream continues until its bytes are exhausted; for the other
      #   kinds, DONE ends the whole stream.
      # @return [Array<BindAction>] the decoded bind fixups
      # @raise [ArgumentError] if +kind+ is not a bind stream kind
      # @raise [DyldInfoError] if the stream is malformed
      def bind_actions(bytes, segments: [], pointer_size: 8, kind: :bind)
        unless %i[bind weak_bind lazy_bind].include?(kind)
          raise ArgumentError, "unknown bind stream kind: #{kind.inspect}"
        end

        Interpreter.new(bytes, :segments => segments, :pointer_size => pointer_size,
                               :kind => kind).actions
      end

      # Extracts and interprets every dyld info stream in a Mach-O file.
      # @param macho [MachO::MachOFile] the file to read
      # @return [Hash{Symbol => Array}, nil] the decoded fixups, keyed by
      #   stream kind (:rebase, :bind, :weak_bind, :lazy_bind), or nil if the
      #   file has no LC_DYLD_INFO or LC_DYLD_INFO_ONLY command
      # @raise [DyldInfoError] if a stream is malformed or lies outside the
      #   file
      def actions_for(macho)
        command = macho.command(:LC_DYLD_INFO_ONLY).first || macho.command(:LC_DYLD_INFO).first
        return nil if command.nil?

        raw = macho.serialize
        segments = macho.segments
        pointer_size = macho.magic64? ? 8 : 4

        {
          :rebase => rebase_actions(stream_slice(raw, command.rebase_off, command.rebase_size),
                                    :segments => segments, :pointer_size => pointer_size),
          :bind => bind_actions(stream_slice(raw, command.bind_off, command.bind_size),
                                :segments => segments, :pointer_size => pointer_size, :kind => :bind),
          :weak_bind => bind_actions(stream_slice(raw, command.weak_bind_off, command.weak_bind_size),
                                     :segments => segments, :pointer_size => pointer_size, :kind => :weak_bind),
          :lazy_bind => bind_actions(stream_slice(raw, command.lazy_bind_off, command.lazy_bind_size),
                                     :segments => segments, :pointer_size => pointer_size, :kind => :lazy_bind),
        }
      end

      # Converts a segment-like object into a {Segment}.
      # @param segment [Segment, Hash, #vmaddr] the object to convert
      # @return [Segment] the converted segment
      # @api private
      def normalize_segment(segment)
        return segment if segment.is_a?(Segment)

        if segment.respond_to?(:vmaddr) && segment.respond_to?(:vmsize)
          Segment.new(segment.vmaddr, segment.vmsize)
        else
          Segment.new(segment.fetch(:vmaddr), segment.fetch(:vmsize))
        end
      end

      private

      # @param raw [String] the file's raw data
      # @param offset [Integer] the stream's offset within the file
      # @param size [Integer] the stream's size
      # @return [String] the stream's bytes
      # @raise [DyldInfoError] if the region lies outside the file
      # @api private
      def stream_slice(raw, offset, size)
        return "" if size.zero?

        slice = raw[offset, size]
        if slice.nil? || slice.bytesize != size
          raise DyldInfoError, "dyld info stream at offset #{offset} (size #{size}) lies outside the file"
        end

        slice
      end
    end

    # Walks a single dyld info opcode stream and produces fixup actions.
    # Prefer {DyldInfo.rebase_actions} and {DyldInfo.bind_actions} over
    # instantiating this class directly.
    class Interpreter
      # @param bytes [String] the raw opcode stream
      # @param segments [Array<Segment, Hash, #vmaddr>] the segment layout
      #   used to resolve addresses and check bounds; may be empty
      # @param pointer_size [Integer] the pointer size of the stream's
      #   architecture, in bytes
      # @param kind [Symbol] one of :rebase, :bind, :weak_bind, or :lazy_bind
      def initialize(bytes, segments: [], pointer_size: 8, kind: :rebase)
        @bytes = bytes
        @segments = segments.map { |segment| DyldInfo.normalize_segment(segment) }
        @pointer_size = pointer_size
        @kind = kind
        @pos = 0
        @record_start = 0
        @type = @kind == :rebase ? 0 : BIND_TYPE_POINTER
        reset_record_state
      end

      # Interprets the whole stream.
      # @return [Array<RebaseAction, BindAction>] the decoded fixup actions
      # @raise [DyldInfoError] if the stream is malformed
      def actions
        found = []

        until @pos >= @bytes.bytesize
          byte = read_byte
          opcode = byte & REBASE_OPCODE_MASK
          immediate = byte & REBASE_IMMEDIATE_MASK

          done = if @kind == :rebase
            interpret_rebase(opcode, immediate, found)
          else
            interpret_bind(opcode, immediate, found)
          end
          break if done
        end

        found
      end

      private

      # Handles one rebase opcode.
      # @return [Boolean] true if the stream is finished
      # @api private
      def interpret_rebase(opcode, immediate, found)
        case opcode
        when REBASE_OPCODE_DONE
          true
        when REBASE_OPCODE_SET_TYPE_IMM
          @type = immediate
          validate_rebase_type!
          false
        when REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB
          @segment_index = immediate
          @segment_offset = read_uleb
          validate_segment_index!
          false
        when REBASE_OPCODE_ADD_ADDR_ULEB
          @segment_offset += read_uleb
          false
        when REBASE_OPCODE_ADD_ADDR_IMM_SCALED
          @segment_offset += immediate * @pointer_size
          false
        when REBASE_OPCODE_DO_REBASE_IMM_TIMES
          emit_rebases(found, immediate)
          false
        when REBASE_OPCODE_DO_REBASE_ULEB_TIMES
          emit_rebases(found, read_uleb)
          false
        when REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB
          emit_rebase(found)
          @segment_offset += read_uleb
          finish_record
          false
        when REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB
          count = read_uleb
          skip = read_uleb
          count.times do
            emit_rebase(found)
            @segment_offset += skip + @pointer_size
          end
          finish_record
          false
        else
          raise DyldInfoError, "unknown rebase opcode 0x%02<opcode>x at offset %<offset>d" % {
            :opcode => opcode, :offset => @pos - 1
          }
        end
      end

      # Handles one bind opcode.
      # @return [Boolean] true if the stream is finished
      # @api private
      def interpret_bind(opcode, immediate, found)
        case opcode
        when BIND_OPCODE_DONE
          # In a lazy bind stream, DONE only terminates the current record;
          # the stream itself continues until its bytes are exhausted, and
          # each record is interpreted with fresh state.
          if @kind == :lazy_bind
            finish_record
            reset_record_state
            false
          else
            true
          end
        when BIND_OPCODE_SET_DYLIB_ORDINAL_IMM
          self.library_ordinal = immediate
          false
        when BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB
          self.library_ordinal = read_uleb
          false
        when BIND_OPCODE_SET_DYLIB_SPECIAL_IMM
          raw = immediate.zero? ? 0 : immediate | 0xF0
          raw -= 0x100 if raw >= 0x80
          @library_ordinal = SPECIAL_ORDINALS.fetch(raw) do
            raise DyldInfoError, "unknown special dylib ordinal #{raw}"
          end
          false
        when BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM
          @symbol_flags = immediate
          @symbol_name = read_cstring
          false
        when BIND_OPCODE_SET_TYPE_IMM
          @type = immediate
          validate_bind_type!
          false
        when BIND_OPCODE_SET_ADDEND_SLEB
          @addend = read_sleb
          false
        when BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB
          @segment_index = immediate
          @segment_offset = read_uleb
          validate_segment_index!
          false
        when BIND_OPCODE_ADD_ADDR_ULEB
          @segment_offset += read_uleb
          false
        when BIND_OPCODE_DO_BIND
          emit_bind(found)
          @segment_offset += @pointer_size
          finish_record
          false
        when BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB
          emit_bind(found)
          @segment_offset += read_uleb + @pointer_size
          finish_record
          false
        when BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED
          emit_bind(found)
          @segment_offset += (immediate * @pointer_size) + @pointer_size
          finish_record
          false
        when BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB
          count = read_uleb
          skip = read_uleb
          count.times do
            emit_bind(found)
            @segment_offset += skip + @pointer_size
          end
          finish_record
          false
        else
          raise DyldInfoError, "unknown bind opcode 0x%02<opcode>x at offset %<offset>d" % {
            :opcode => opcode, :offset => @pos - 1
          }
        end
      end

      # @return [Integer] the next opcode byte
      # @raise [DyldInfoError] if the stream is exhausted
      # @api private
      def read_byte
        raise DyldInfoError, "unexpected end of dyld info stream" if @pos >= @bytes.bytesize

        byte = @bytes.getbyte(@pos)
        @pos += 1
        byte
      end

      # @return [Integer] the next uleb128 value
      # @api private
      def read_uleb
        value, @pos = DyldInfo.read_uleb128(@bytes, @pos)
        value
      end

      # @return [Integer] the next sleb128 value
      # @api private
      def read_sleb
        value, @pos = DyldInfo.read_sleb128(@bytes, @pos)
        value
      end

      # @return [String] the next NUL-terminated string
      # @raise [DyldInfoError] if no NUL terminator is found
      # @api private
      def read_cstring
        start = @pos
        terminator = @bytes.index(" ", start)
        raise DyldInfoError, "unterminated symbol name at offset #{start}" if terminator.nil?

        @pos = terminator + 1
        @bytes[start...terminator]
      end

      # Records a normal (table-index) library ordinal. Ordinal zero is the
      # special +:self+ ordinal, not a table index.
      # @param value [Integer] the ordinal read from the stream
      # @api private
      def library_ordinal=(value)
        @library_ordinal = value.zero? ? :self : value
      end

      # Marks the start of a new record in the opcode stream.
      # @return [void]
      # @api private
      def finish_record
        @record_start = @pos
      end

      # Resets the per-record bind state, as dyld does when it starts
      # interpreting a lazy bind record.
      # @return [void]
      # @api private
      def reset_record_state
        @type = BIND_TYPE_POINTER unless @kind == :rebase
        @segment_index = 0
        @segment_offset = 0
        @library_ordinal = :self
        @symbol_name = nil
        @symbol_flags = 0
        @addend = 0
      end

      # @raise [DyldInfoError] if the current rebase type is invalid
      # @api private
      def validate_rebase_type!
        return if (REBASE_TYPE_POINTER..REBASE_TYPE_TEXT_PCREL32).cover?(@type)

        raise DyldInfoError, "invalid rebase type #{@type}"
      end

      # @raise [DyldInfoError] if the current bind type is invalid
      # @api private
      def validate_bind_type!
        return if (BIND_TYPE_POINTER..BIND_TYPE_TEXT_PCREL32).cover?(@type)

        raise DyldInfoError, "invalid bind type #{@type}"
      end

      # @raise [DyldInfoError] if the current segment index is out of range
      # @api private
      def validate_segment_index!
        return if @segments.empty? || @segment_index < @segments.size

        raise DyldInfoError,
              "segment index #{@segment_index} out of range (#{@segments.size} segments)"
      end

      # @return [Integer, nil] the virtual address of the current fixup, or
      #   nil if no segment layout was supplied
      # @raise [DyldInfoError] if the fixup lies outside its segment
      # @api private
      def current_address
        return nil if @segments.empty?

        segment = @segments[@segment_index]
        if segment.nil?
          raise DyldInfoError,
                "segment index #{@segment_index} out of range (#{@segments.size} segments)"
        end
        if @segment_offset + @pointer_size > segment.vmsize
          raise DyldInfoError,
                "fixup at segment #{@segment_index} offset 0x#{@segment_offset.to_s(16)} " +                "lies outside the segment (vmsize 0x#{segment.vmsize.to_s(16)})"
        end

        segment.vmaddr + @segment_offset
      end

      # @raise [DyldInfoError] if the rebase type was never set
      # @api private
      def emit_rebase(found)
        raise DyldInfoError, "rebase opcode encountered before the rebase type was set" if @type.zero?

        found << RebaseAction.new(
          :source_offset => @record_start,
          :segment_index => @segment_index,
          :segment_offset => @segment_offset,
          :address => current_address,
          :type => @type
        )
      end

      # Emits +count+ rebase actions, advancing by the pointer size.
      # @return [void]
      # @api private
      def emit_rebases(found, count)
        count.times do
          emit_rebase(found)
          @segment_offset += @pointer_size
        end
        finish_record
      end

      # @raise [DyldInfoError] if the bind type or symbol name was never set
      # @api private
      def emit_bind(found)
        raise DyldInfoError, "bind opcode encountered before the bind type was set" if @type.zero?
        raise DyldInfoError, "bind opcode encountered before a symbol name was set" if @symbol_name.nil?

        found << BindAction.new(
          :source_offset => @record_start,
          :segment_index => @segment_index,
          :segment_offset => @segment_offset,
          :address => current_address,
          :type => @type,
          :library_ordinal => @library_ordinal,
          :symbol_name => @symbol_name,
          :symbol_flags => @symbol_flags,
          :addend => @addend
        )
      end
    end
  end
end
