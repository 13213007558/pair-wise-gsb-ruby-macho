# frozen_string_literal: true

module MachO
  # An interpreter for the compressed dyld information bytecode referenced
  # by the LC_DYLD_INFO and LC_DYLD_INFO_ONLY load commands. It decodes the
  # rebase, bind, weak bind, and lazy bind opcode streams into plain
  # address fix-up actions. The interpreter is pure: it never loads,
  # modifies, or runs the binary the streams were taken from.
  module DyldInfo
    # rebase type: a pointer-sized value
    REBASE_TYPE_POINTER = 1
    # rebase type: a 32-bit absolute address in a __text section
    REBASE_TYPE_TEXT_ABSOLUTE32 = 2
    # rebase type: a 32-bit PC-relative address in a __text section
    REBASE_TYPE_TEXT_PCREL32 = 3

    # mask for the opcode half of a rebase byte
    REBASE_OPCODE_MASK = 0xF0
    # mask for the immediate half of a rebase byte
    REBASE_IMMEDIATE_MASK = 0x0F
    # rebase opcode: the stream is finished
    REBASE_OPCODE_DONE = 0x00
    # rebase opcode: set the rebase type to the immediate value
    REBASE_OPCODE_SET_TYPE_IMM = 0x10
    # rebase opcode: set the segment and offset (ULEB128 follows)
    REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB = 0x20
    # rebase opcode: advance the segment offset (ULEB128 follows)
    REBASE_OPCODE_ADD_ADDR_ULEB = 0x30
    # rebase opcode: advance the segment offset by imm * pointer size
    REBASE_OPCODE_ADD_ADDR_IMM_SCALED = 0x40
    # rebase opcode: rebase imm times in a row
    REBASE_OPCODE_DO_REBASE_IMM_TIMES = 0x50
    # rebase opcode: rebase ULEB128 times in a row
    REBASE_OPCODE_DO_REBASE_ULEB_TIMES = 0x60
    # rebase opcode: rebase once, then advance the offset (ULEB128 follows)
    REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB = 0x70
    # rebase opcode: rebase ULEB128 times, skipping ULEB128 bytes each time
    REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB = 0x80

    # bind type: a pointer-sized value
    BIND_TYPE_POINTER = 1
    # bind type: a 32-bit absolute address in a __text section
    BIND_TYPE_TEXT_ABSOLUTE32 = 2
    # bind type: a 32-bit PC-relative address in a __text section
    BIND_TYPE_TEXT_PCREL32 = 3

    # bind flag: the symbol is a weak import
    BIND_SYMBOL_FLAGS_WEAK_IMPORT = 0x1
    # bind flag: the symbol is a weak definition
    BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION = 0x8

    # special dylib ordinal: this image
    BIND_SPECIAL_DYLIB_SELF = 0
    # special dylib ordinal: the main executable
    BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE = -1
    # special dylib ordinal: flat lookup
    BIND_SPECIAL_DYLIB_FLAT_LOOKUP = -2

    # mask for the opcode half of a bind byte
    BIND_OPCODE_MASK = 0xF0
    # mask for the immediate half of a bind byte
    BIND_IMMEDIATE_MASK = 0x0F
    # bind opcode: the stream (or, for lazy binding, the record) is finished
    BIND_OPCODE_DONE = 0x00
    # bind opcode: set the dylib ordinal to the immediate value
    BIND_OPCODE_SET_DYLIB_ORDINAL_IMM = 0x10
    # bind opcode: set the dylib ordinal (ULEB128 follows)
    BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB = 0x20
    # bind opcode: set a special dylib ordinal (sign-extended immediate)
    BIND_OPCODE_SET_DYLIB_SPECIAL_IMM = 0x30
    # bind opcode: set the symbol flags (immediate) and name (string follows)
    BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM = 0x40
    # bind opcode: set the bind type to the immediate value
    BIND_OPCODE_SET_TYPE_IMM = 0x50
    # bind opcode: set the addend (SLEB128 follows)
    BIND_OPCODE_SET_ADDEND_SLEB = 0x60
    # bind opcode: set the segment and offset (ULEB128 follows)
    BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB = 0x70
    # bind opcode: advance the segment offset (ULEB128 follows)
    BIND_OPCODE_ADD_ADDR_ULEB = 0x80
    # bind opcode: bind once, then advance by the pointer size
    BIND_OPCODE_DO_BIND = 0x90
    # bind opcode: bind once, then advance by pointer size + ULEB128
    BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB = 0xA0
    # bind opcode: bind once, then advance by (imm + 1) * pointer size
    BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED = 0xB0
    # bind opcode: bind ULEB128 times, skipping ULEB128 bytes each time
    BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB = 0xC0
    # bind opcode: threaded (chained) binds, not interpreted
    BIND_OPCODE_THREADED = 0xD0

    # A single address fix-up decoded from a rebase opcode stream.
    RebaseAction = Struct.new(:type, :seg_index, :seg_offset, :vmaddr, :offset, :keyword_init => true) do
      # @return [Hash] a hash representation of this {RebaseAction}
      def to_h
        {
          "type" => type,
          "seg_index" => seg_index,
          "seg_offset" => seg_offset,
          "vmaddr" => vmaddr,
          "offset" => offset,
        }
      end
    end

    # A single symbol binding decoded from a bind opcode stream.
    BindAction = Struct.new(
      :type, :seg_index, :seg_offset, :vmaddr,
      :dylib_ordinal, :symbol, :addend, :flags, :offset,
      :keyword_init => true
    ) do
      # @return [Hash] a hash representation of this {BindAction}
      def to_h
        {
          "type" => type,
          "seg_index" => seg_index,
          "seg_offset" => seg_offset,
          "vmaddr" => vmaddr,
          "dylib_ordinal" => dylib_ordinal,
          "symbol" => symbol,
          "addend" => addend,
          "flags" => flags,
          "offset" => offset,
        }
      end
    end

    # Decodes rebase and bind opcode streams into sequences of fix-up
    # actions. Each action records the offset of the opcode that produced
    # it, so results can be traced back into the original stream.
    #
    # @example
    #   segments = [{ :vmaddr => 0x100000000, :vmsize => 0x4000 }]
    #   interpreter = MachO::DyldInfo::Interpreter.new(segments)
    #   interpreter.rebase_actions(rebase_bytes)
    #   interpreter.bind_actions(bind_bytes)
    #   interpreter.bind_actions(lazy_bind_bytes, :lazy => true)
    class Interpreter
      # @param segments [Array<Hash>] segment descriptors in load command
      #   order, each with a +:vmaddr+ and a +:vmsize+ entry; objects
      #   responding to +#vmaddr+ and +#vmsize+ are also accepted
      # @param pointer_size [Integer] the pointer size of the image, in bytes
      def initialize(segments, pointer_size: 8)
        @segments = segments
        @pointer_size = pointer_size
      end

      # Interprets a rebase opcode stream.
      # @param bytes [String] the raw rebase opcodes
      # @return [Array<RebaseAction>] the decoded fix-up actions
      # @raise [DyldInfoError] if the stream is malformed or leaves the
      #   bounds of the known segments
      def rebase_actions(bytes)
        cursor = Cursor.new(bytes)
        state = { :type => nil, :seg_index => 0, :seg_offset => 0 }
        actions = []

        until cursor.eof?
          record_offset = cursor.offset
          byte = cursor.read_byte
          opcode = byte & REBASE_OPCODE_MASK
          imm = byte & REBASE_IMMEDIATE_MASK

          case opcode
          when REBASE_OPCODE_DONE
            break
          when REBASE_OPCODE_SET_TYPE_IMM
            state[:type] = checked_type(imm, REBASE_TYPE_POINTER..REBASE_TYPE_TEXT_PCREL32, record_offset)
          when REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB
            state[:seg_index] = checked_segment_index(imm, record_offset)
            state[:seg_offset] = cursor.read_uleb
          when REBASE_OPCODE_ADD_ADDR_ULEB
            state[:seg_offset] += cursor.read_uleb
          when REBASE_OPCODE_ADD_ADDR_IMM_SCALED
            state[:seg_offset] += imm * @pointer_size
          when REBASE_OPCODE_DO_REBASE_IMM_TIMES
            imm.times { emit_rebase(actions, state, record_offset) }
          when REBASE_OPCODE_DO_REBASE_ULEB_TIMES
            cursor.read_uleb.times { emit_rebase(actions, state, record_offset) }
          when REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB
            emit_rebase(actions, state, record_offset)
            state[:seg_offset] += cursor.read_uleb
          when REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB
            count = cursor.read_uleb
            skip = cursor.read_uleb
            count.times do
              emit_rebase(actions, state, record_offset)
              state[:seg_offset] += skip
            end
          else
            raise DyldInfoError, format("unknown rebase opcode 0x%02<byte>x at offset %<offset>d", :byte => byte, :offset => record_offset)
          end
        end

        actions
      end

      # Interprets a bind, weak bind, or lazy bind opcode stream.
      # @param bytes [String] the raw bind opcodes
      # @param lazy [Boolean] whether the stream is a lazy bind stream;
      #   in lazy streams a DONE opcode only ends the current record, not
      #   the whole region
      # @return [Array<BindAction>] the decoded binding actions
      # @raise [DyldInfoError] if the stream is malformed or leaves the
      #   bounds of the known segments
      def bind_actions(bytes, lazy: false)
        cursor = Cursor.new(bytes)
        state = {
          :type => BIND_TYPE_POINTER,
          :dylib_ordinal => BIND_SPECIAL_DYLIB_SELF,
          :symbol => nil,
          :addend => 0,
          :flags => 0,
          :seg_index => 0,
          :seg_offset => 0,
        }
        actions = []

        until cursor.eof?
          record_offset = cursor.offset
          byte = cursor.read_byte
          opcode = byte & BIND_OPCODE_MASK
          imm = byte & BIND_IMMEDIATE_MASK

          case opcode
          when BIND_OPCODE_DONE
            # In lazy bind streams DONE only terminates the current
            # record; interpretation continues with the next record.
            break unless lazy
          when BIND_OPCODE_SET_DYLIB_ORDINAL_IMM
            state[:dylib_ordinal] = imm
          when BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB
            state[:dylib_ordinal] = cursor.read_uleb
          when BIND_OPCODE_SET_DYLIB_SPECIAL_IMM
            # Special ordinals are stored as sign-extended 4-bit values:
            # 0x0 => self (0), 0xF => main executable (-1),
            # 0xE => flat lookup (-2). They must not be confused with
            # ordinary (positive) library ordinals.
            state[:dylib_ordinal] = imm >= 8 ? imm - 16 : imm
          when BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM
            state[:flags] = imm
            state[:symbol] = cursor.read_cstring
          when BIND_OPCODE_SET_TYPE_IMM
            state[:type] = checked_type(imm, BIND_TYPE_POINTER..BIND_TYPE_TEXT_PCREL32, record_offset)
          when BIND_OPCODE_SET_ADDEND_SLEB
            state[:addend] = cursor.read_sleb
          when BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB
            state[:seg_index] = checked_segment_index(imm, record_offset)
            state[:seg_offset] = cursor.read_uleb
          when BIND_OPCODE_ADD_ADDR_ULEB
            state[:seg_offset] += cursor.read_uleb
          when BIND_OPCODE_DO_BIND
            emit_bind(actions, state, record_offset)
          when BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB
            emit_bind(actions, state, record_offset)
            state[:seg_offset] += cursor.read_uleb
          when BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED
            emit_bind(actions, state, record_offset)
            state[:seg_offset] += imm * @pointer_size
          when BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB
            count = cursor.read_uleb
            skip = cursor.read_uleb
            count.times do
              emit_bind(actions, state, record_offset)
              state[:seg_offset] += skip
            end
          when BIND_OPCODE_THREADED
            raise UnimplementedError, "BIND_OPCODE_THREADED"
          else
            raise DyldInfoError, format("unknown bind opcode 0x%02<byte>x at offset %<offset>d", :byte => byte, :offset => record_offset)
          end
        end

        actions
      end

      private

      # Records a rebase action and advances to the next pointer.
      # @param actions [Array<RebaseAction>] the accumulator
      # @param state [Hash] the interpreter state
      # @param record_offset [Integer] the stream offset of the opcode
      # @return [void]
      def emit_rebase(actions, state, record_offset)
        raise DyldInfoError, "rebase action at offset #{record_offset} has no type" if state[:type].nil?

        check_segment_bounds!(state, record_offset)
        actions << RebaseAction.new(
          :type => state[:type],
          :seg_index => state[:seg_index],
          :seg_offset => state[:seg_offset],
          :vmaddr => segment_vmaddr(state[:seg_index]) + state[:seg_offset],
          :offset => record_offset
        )
        state[:seg_offset] += @pointer_size
      end

      # Records a bind action and advances to the next pointer.
      # @param actions [Array<BindAction>] the accumulator
      # @param state [Hash] the interpreter state
      # @param record_offset [Integer] the stream offset of the opcode
      # @return [void]
      def emit_bind(actions, state, record_offset)
        raise DyldInfoError, "bind action at offset #{record_offset} has no symbol" if state[:symbol].nil?

        check_segment_bounds!(state, record_offset)
        actions << BindAction.new(
          :type => state[:type],
          :seg_index => state[:seg_index],
          :seg_offset => state[:seg_offset],
          :vmaddr => segment_vmaddr(state[:seg_index]) + state[:seg_offset],
          :dylib_ordinal => state[:dylib_ordinal],
          :symbol => state[:symbol],
          :addend => state[:addend],
          :flags => state[:flags],
          :offset => record_offset
        )
        state[:seg_offset] += @pointer_size
      end

      # @param type [Integer] the type value from the stream
      # @param valid [Range] the valid type values
      # @param record_offset [Integer] the stream offset of the opcode
      # @return [Integer] the validated type
      # @raise [DyldInfoError] if the type is unknown
      def checked_type(type, valid, record_offset)
        return type if valid.cover?(type)

        raise DyldInfoError, "unknown fix-up type #{type} at offset #{record_offset}"
      end

      # @param index [Integer] the segment index from the stream
      # @param record_offset [Integer] the stream offset of the opcode
      # @return [Integer] the validated segment index
      # @raise [DyldInfoError] if the index is out of range
      def checked_segment_index(index, record_offset)
        return index if index < @segments.size

        raise DyldInfoError, "segment index #{index} at offset #{record_offset} " \
                             "exceeds known segment count #{@segments.size}"
      end

      # @param state [Hash] the interpreter state
      # @param record_offset [Integer] the stream offset of the opcode
      # @return [void]
      # @raise [DyldInfoError] if the current offset leaves the segment
      def check_segment_bounds!(state, record_offset)
        vmsize = segment_vmsize(state[:seg_index])
        return if vmsize.nil? || state[:seg_offset] < vmsize

        raise DyldInfoError, "offset #{state[:seg_offset]} at stream offset #{record_offset} " \
                             "exceeds size #{vmsize} of segment #{state[:seg_index]}"
      end

      # @param index [Integer] the segment index
      # @return [Integer] the segment's virtual memory address
      def segment_vmaddr(index)
        segment = @segments[index]
        segment.respond_to?(:vmaddr) ? segment.vmaddr : segment[:vmaddr]
      end

      # @param index [Integer] the segment index
      # @return [Integer, nil] the segment's virtual memory size
      def segment_vmsize(index)
        segment = @segments[index]
        segment.respond_to?(:vmsize) ? segment.vmsize : segment[:vmsize]
      end
    end

    # A low-level cursor over an opcode stream, with ULEB128/SLEB128 and
    # C string decoding.
    class Cursor
      # @return [Integer] the current offset within the stream
      attr_reader :offset

      # @param bytes [String] the opcode stream
      def initialize(bytes)
        @bytes = bytes
        @offset = 0
      end

      # @return [Boolean] whether the stream is exhausted
      def eof?
        @offset >= @bytes.bytesize
      end

      # @return [Integer] the next byte
      # @raise [DyldInfoError] if the stream is exhausted
      def read_byte
        raise DyldInfoError, "unexpected end of opcode stream at offset #{@offset}" if eof?

        byte = @bytes.getbyte(@offset)
        @offset += 1
        byte
      end

      # @return [Integer] the decoded ULEB128 value
      # @raise [DyldInfoError] if the value is truncated or too large
      def read_uleb
        result = 0
        shift = 0

        loop do
          byte = read_byte
          result |= (byte & 0x7F) << shift
          break if (byte & 0x80).zero?

          shift += 7
          raise DyldInfoError, "ULEB128 value too large at offset #{@offset}" if shift > 63
        end

        result
      end

      # @return [Integer] the decoded SLEB128 value
      # @raise [DyldInfoError] if the value is truncated or too large
      def read_sleb
        result = 0
        shift = 0

        loop do
          byte = read_byte
          result |= (byte & 0x7F) << shift
          shift += 7

          if (byte & 0x80).zero?
            result |= -(1 << shift) if (byte & 0x40).nonzero?
            break
          end

          raise DyldInfoError, "SLEB128 value too large at offset #{@offset}" if shift > 63
        end

        result
      end

      # @return [String] the NUL-terminated string at the current offset
      # @raise [DyldInfoError] if no NUL terminator is found
      def read_cstring
        start = @offset
        @offset += 1 until eof? || @bytes.getbyte(@offset).zero?
        raise DyldInfoError, "unterminated string at offset #{start}" if eof?

        string = @bytes.byteslice(start, @offset - start)
        @offset += 1
        string
      end
    end
  end
end
