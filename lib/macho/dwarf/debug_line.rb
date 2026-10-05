# frozen_string_literal: true

module MachO
  # Classes and constants for parsing DWARF debugging data.
  module DWARF
    # Raised when DWARF data is malformed or truncated.
    class DebugLineError < MachOError
    end

    # A reader for the DWARF `.debug_line` section (DWARF versions 2 through 5).
    #
    # A `.debug_line` section consists of one or more concatenated line number
    # programs, each preceded by its own header. Each {Program} is executed by
    # the line number state machine described in the DWARF specification,
    # producing a sequence of {Row} objects that map machine addresses to source
    # file, line, column, and discriminator information.
    #
    # @see https://dwarfstd.org/doc/DWARF5.pdf DWARF 5, section 6.2 "Line Number Information"
    class DebugLine
      # The 32-bit length prefix that introduces a 64-bit DWARF unit.
      DWARF64_LENGTH_PREFIX = 0xffffffff

      # The 32-bit length prefix size (unit_length field only).
      DWARF32_PREFIX_SIZE = 4

      # The 64-bit length prefix size (escape word plus 64-bit unit_length).
      DWARF64_PREFIX_SIZE = 12

      # @return [Array<Program>] the line number programs contained in the section,
      #  in the order in which they appear
      attr_reader :programs

      # @return [Symbol] the endianness of the section (`:little` or `:big`)
      attr_reader :endianness

      # @return [Integer] the size, in bytes, of a target address, used for
      #  `DW_LNE_set_address` operands in DWARF 2-4 programs (which lack an
      #  address size field in their header)
      attr_reader :address_size

      # Creates a new reader over the given `.debug_line` section data.
      # @param data [String] the raw contents of a `.debug_line` section
      # @param endianness [Symbol] the endianness of the data (`:little` or `:big`)
      # @param address_size [Integer] the target address size in bytes for
      #  DWARF 2-4 programs (ignored by DWARF 5 programs, which carry it in their header)
      # @param line_strings [String, nil] the contents of a `.debug_line_str` section,
      #  needed to resolve `DW_FORM_line_strp` file/directory entries
      # @param strings [String, nil] the contents of a `.debug_str` section,
      #  needed to resolve `DW_FORM_strp` file/directory entries
      # @raise [DebugLineError] if the section is malformed or truncated
      def initialize(data, endianness: :little, address_size: 8, line_strings: nil, strings: nil)
        @endianness = endianness
        @address_size = address_size
        @line_strings = line_strings
        @strings = strings
        @programs = []

        parse(BinaryReader.new(data.to_s.b, endianness))
      end

      # Resolves a `DW_FORM_line_strp` reference against the `.debug_line_str` section.
      # @api private
      def resolve_line_string(offset)
        resolve_string(@line_strings, offset, "DW_FORM_line_strp")
      end

      # Resolves a `DW_FORM_strp` reference against the `.debug_str` section.
      # @api private
      def resolve_str(offset)
        resolve_string(@strings, offset, "DW_FORM_strp")
      end

      private

      # Parses every concatenated line number program in the section.
      # @return [void]
      # @api private
        def parse(reader)
          until reader.eof?
            # Some linkers zero-pad the tail of the section.
            saved = reader.pos
            tail = reader.bytes(reader.remaining)
            break if tail.delete("\x00").empty?

            reader.pos = saved
            start = reader.pos
            unit_length = reader.u32

            if unit_length == DWARF64_LENGTH_PREFIX
              offset_size = 8
              unit_length = reader.u64
              prefix_size = DWARF64_PREFIX_SIZE
            else
              offset_size = 4
              prefix_size = DWARF32_PREFIX_SIZE
            end

            # A zero-length unit is treated as trailing padding.
            next if unit_length.zero?

            unit_end = start + prefix_size + unit_length
            if unit_end > reader.size
              raise DebugLineError, "truncated .debug_line unit"
            end

            @programs << Program.parse(reader, unit_end, offset_size, self)
            reader.pos = unit_end
          end
        end

      # Resolves a string reference against a supplementary string section.
      # @return [String] the null-terminated string at the given offset
      # @raise [DebugLineError] if the section is missing or the offset is invalid
      # @api private
      def resolve_string(section, offset, form)
        raise DebugLineError, "#{form} reference without a string section" if section.nil?
        if offset.negative? || offset >= section.bytesize
          raise DebugLineError, "#{form} offset outside of string section"
        end

        end_offset = section.index("\x00", offset)
        raise DebugLineError, "unterminated string in string section" if end_offset.nil?

        section.byteslice(offset, end_offset - offset).force_encoding(Encoding::UTF_8)
      end

      # A minimal cursor over a binary string with DWARF-aware integer readers.
      class BinaryReader
        # @return [Integer] the current read offset
        attr_accessor :pos

        # @param data [String] the data being read
        # @param endianness [Symbol] `:little` or `:big`
        def initialize(data, endianness)
          @data = data
          @endianness = endianness
          @pos = 0
        end

        # @return [Integer] the total size of the data
        def size
          @data.bytesize
        end

        # @return [Integer] the number of unread bytes
        def remaining
          size - @pos
        end

        # @return [Boolean] whether all data has been consumed
        def eof?
          @pos >= size
        end

        # Ensures that at least `count` bytes remain.
        # @param count [Integer] the required number of bytes
        # @return [void]
        # @raise [DebugLineError] if fewer than `count` bytes remain
        def need!(count)
          raise DebugLineError, "unexpected end of .debug_line data" if @pos + count > size
        end

        # Reads `count` raw bytes.
        # @param count [Integer] the number of bytes to read
        # @return [String] the bytes read
        def bytes(count)
          need!(count)
          value = @data.byteslice(@pos, count)
          @pos += count
          value
        end

        # Reads an unsigned 8-bit integer.
        # @return [Integer]
        def u8
          bytes(1).unpack1("C")
        end

        # Reads an unsigned 16-bit integer.
        # @return [Integer]
        def u16
          bytes(2).unpack1(@endianness == :big ? "n" : "v")
        end

        # Reads an unsigned 32-bit integer.
        # @return [Integer]
        def u32
          bytes(4).unpack1(@endianness == :big ? "N" : "V")
        end

        # Reads an unsigned 64-bit integer.
        # @return [Integer]
        def u64
          bytes(8).unpack1(@endianness == :big ? "Q>" : "Q<")
        end

        # Reads an unsigned integer of the given byte size (1, 2, 4, or 8).
        # @param size [Integer] the number of bytes to read
        # @return [Integer]
        def uint(size)
          format = { 1 => "C", 2 => (@endianness == :big ? "n" : "v"),
                     4 => (@endianness == :big ? "N" : "V"),
                     8 => (@endianness == :big ? "Q>" : "Q<") }[size]
          raise DebugLineError, "unsupported integer size #{size}" if format.nil?

          bytes(size).unpack1(format)
        end

        # Reads an unsigned LEB128-encoded integer.
        # @return [Integer]
        def uleb128
          result = 0
          shift = 0
          loop do
            byte = u8
            result |= (byte & 0x7f) << shift
            return result if byte & 0x80 == 0

            shift += 7
          end
        end

        # Reads a signed LEB128-encoded integer.
        # @return [Integer]
        def sleb128
          result = 0
          shift = 0
          byte = nil
          loop do
            byte = u8
            result |= (byte & 0x7f) << shift
            shift += 7
            break if byte & 0x80 == 0
          end
          result |= -(1 << shift) if byte & 0x40 != 0
          result
        end

        # Reads a null-terminated string.
        # @return [String]
        def string
          end_offset = @data.index("\x00", @pos)
          raise DebugLineError, "unterminated string in .debug_line" if end_offset.nil?

          value = @data.byteslice(@pos, end_offset - @pos)
          @pos = end_offset + 1
          value.force_encoding(Encoding::UTF_8)
        end
      end

      # A source file entry in a line number program's file name table.
      class FileEntry
        # @return [String] the file name (possibly a full path)
        attr_reader :name

        # @return [Integer] the directory index as stored in the table
        #  (1-based in DWARF 2-4, 0-based in DWARF 5)
        attr_reader :directory_index

        # @return [Integer] the declared modification time of the file (0 if unknown)
        attr_reader :mtime

        # @return [Integer] the declared size of the file in bytes (0 if unknown)
        attr_reader :size

        # @return [String, nil] the MD5 checksum declared by a DWARF 5 entry
        attr_reader :md5

        # @api private
        def initialize(name, directory_index, mtime = 0, size = 0, md5 = nil)
          @name = name
          @directory_index = directory_index
          @mtime = mtime
          @size = size
          @md5 = md5
        end
      end

      # A single row emitted by the line number state machine. Rows are frozen
      # snapshots of the machine's registers at the time of emission.
      class Row
        # @return [Integer] the program-counter value (section-relative address)
        attr_reader :address

        # @return [Integer] the index of the operation within a VLIW instruction at {#address}
        attr_reader :op_index

        # @return [String, nil] the source file name, or nil if the row carries no file
        attr_reader :file

        # @return [Integer, nil] the source line number, or nil if the row carries no line
        attr_reader :line

        # @return [Integer] the source column number (0 indicates the start of the line)
        attr_reader :column

        # @return [Integer] the discriminator value assigned to the row
        attr_reader :discriminator

        # @return [Boolean] whether the row terminates a sequence (`DW_LNE_end_sequence`)
        attr_reader :end_sequence

        # @return [Boolean] the `DW_LNS_set_basic_block` / `DW_LNE_set_basic_block` flag
        attr_reader :basic_block

        # @return [Boolean] the `DW_LNE_prologue_end` flag
        attr_reader :prologue_end

        # @return [Boolean] the `DW_LNE_epilogue_begin` flag
        attr_reader :epilogue_begin

        # @return [Integer] the instruction-set architecture of the row
        attr_reader :isa

        # @api private
        def initialize(program, state)
          @address = state.address
          @op_index = state.op_index
          @file = program.file_name(state.file) if state.file
          @line = state.line
          @column = state.column
          @discriminator = state.discriminator
          @end_sequence = state.end_sequence
          @basic_block = state.basic_block
          @prologue_end = state.prologue_end
          @epilogue_begin = state.epilogue_begin
          @is_stmt = state.is_stmt
          @isa = state.isa
        end

        # @return [Boolean] whether the row was emitted with the
        #  `default_is_stmt` flag set
        def statement?
          @is_stmt
        end

        # @return [Hash] a hash representation of this row
        def to_h
          {
            "address" => address,
            "op_index" => op_index,
            "file" => file,
            "line" => line,
            "column" => column,
            "discriminator" => discriminator,
            "end_sequence" => end_sequence,
            "basic_block" => basic_block,
            "prologue_end" => prologue_end,
            "epilogue_begin" => epilogue_begin,
            "isa" => isa,
          }
        end
      end

      # A single line number program (one compilation unit's contribution to
      # the `.debug_line` section). Executing a program yields a list of {Row}s
      # partitioned into sequences.
      class Program
        # Standard opcode mnemonics, indexed by their 1-based opcode number.
        STANDARD_OPCODES = {
          1 => :copy,
          2 => :advance_pc,
          3 => :advance_line,
          4 => :set_file,
          5 => :set_column,
          6 => :negate_stmt,
          7 => :set_basic_block,
          8 => :const_add_pc,
          9 => :fixed_advance_pc,
          10 => :set_prologue_end,
          11 => :set_epilogue_begin,
          12 => :set_isa,
        }.freeze

        # Extended opcode numbers.
        EXT_END_SEQUENCE      = 1 # DW_LNE_end_sequence
        EXT_SET_ADDRESS       = 2 # DW_LNE_set_address
        EXT_DEFINE_FILE       = 3 # DW_LNE_define_file (DWARF 2-4)
        EXT_SET_DISCRIMINATOR = 4 # DW_LNE_set_discriminator (DWARF 4+)

        # Attribute forms permitted in DWARF 5 file/directory entries.
        FORM_STRING    = 0x08 # DW_FORM_string
        FORM_DATA1     = 0x0b # DW_FORM_data1
        FORM_DATA2     = 0x05 # DW_FORM_data2
        FORM_DATA4     = 0x06 # DW_FORM_data4
        FORM_DATA8     = 0x07 # DW_FORM_data8
        FORM_SDATA     = 0x0d # DW_FORM_sdata
        FORM_UDATA     = 0x0f # DW_FORM_udata
        FORM_STRP      = 0x0e # DW_FORM_strp
        FORM_LINE_STRP = 0x1e # DW_FORM_line_strp

        # @return [Integer] the DWARF version of the program (2 through 5)
        attr_reader :version

        # @return [Integer] the size in bytes of offsets in the unit (4 or 8)
        attr_reader :offset_size

        # @return [Integer] the target address size in bytes
        attr_reader :address_size

        # @return [Integer] the segment selector size in bytes (DWARF 5 only)
        attr_reader :segment_selector_size

        # @return [Array<Row>] all rows emitted by executing the program
        attr_reader :rows

        # @return [Array<String>] the include-directories table
        attr_reader :directories

        # @return [Array<FileEntry>] the file-name table
        attr_reader :files

        # @return [Integer] the minimum instruction length declared by the header
        attr_reader :minimum_instruction_length

        # @return [Integer] the maximum number of operations per instruction
        attr_reader :maximum_operations_per_instruction

        # @return [Integer] the `default_is_stmt` value declared by the header
        attr_reader :default_is_stmt

        # @return [Integer] the line base value declared by the header
        attr_reader :line_base

        # @return [Integer] the line range value declared by the header
        attr_reader :line_range

        # @return [Integer] the first special opcode value
        attr_reader :opcode_base

        # Parses a single program starting at the reader's current position.
        # @param reader [BinaryReader] the section cursor (positioned after the
        #  unit length prefix)
        # @param unit_end [Integer] the offset immediately past the unit's data
        # @param offset_size [Integer] 4 for 32-bit DWARF, 8 for 64-bit DWARF
        # @param section [DebugLine] the containing section reader
        # @return [Program]
        # @raise [DebugLineError] if the program is malformed
        # @api private
        def self.parse(reader, unit_end, offset_size, section)
          program = allocate
          program.send(:parse_header, reader, unit_end, offset_size, section)
          program.send(:execute, reader, unit_end)
          program
        end

        # @return [Array<Array<Row>>] the program's rows grouped into sequences.
        #  Each complete sequence ends with the row on which `end_sequence?` is
        #  true. An end_sequence row closes only its own sequence; subsequent
        #  rows begin a new one.
        def sequences
          groups = []
          current = []
          rows.each do |row|
            current << row
            next unless row.end_sequence

            groups << current
            current = []
          end
          groups << current unless current.empty?
          groups
        end

        # @param address [Integer] the file-relative address to look up
        # @return [Row, nil] the selected row for `address`, or nil if no
        #  sequence covers it. Selection uses the documented rule of DWARF 5
        #  section 6.2.5.3: a row applies to an address if that address is the
        #  row's address or lies between it and the next row's address. When
        #  several rows were emitted at the same address, the first of them is
        #  the selected row. The end_sequence address never matches.
        def at(address)
          non_terminal = rows_for(address)
          return nil if non_terminal.nil?

          first_at_address = non_terminal.index { |row| row.address == address }
          return non_terminal[first_at_address] if first_at_address

          non_terminal.reverse_each.find { |row| row.address < address }
        end

        # Returns every raw row emitted at exactly `address`.
        # @param address [Integer] the file-relative address to look up
        # @return [Array<Row>] all rows at `address`, in emission order
        #  (excluding end_sequence markers)
        def rows_at(address)
          rows.select { |row| !row.end_sequence && row.address == address }
        end

        # @return [Array<Row>, nil] all non-terminal rows of the sequence that
        #  covers `address`, or nil if no sequence covers it.
        def rows_for(address)
          sequences.each do |sequence|
            first = sequence.first
            last = sequence.last
            next if first.nil? || !last.end_sequence
            next unless first.address <= address && address < last.address

            return sequence[0...-1]
          end
          nil
        end

        # Resolves a file table index to its stored file name.
        # @param index [Integer] the index as held by the state machine
        #  (1-based in DWARF 2-4, 0-based in DWARF 5)
        # @return [String, nil] the file name, or nil for an invalid index
        def file_name(index)
          entry = version >= 5 ? files[index] : files[index - 1]
          entry&.name
        end

        private

        # The mutable line number state-machine registers.
        State = Struct.new(:address, :op_index, :file, :line, :column,
                           :is_stmt, :basic_block, :end_sequence,
                           :prologue_end, :epilogue_begin, :isa, :discriminator)

        # Parses the program header, leaving the cursor at the first opcode.
        # @return [void]
        # @api private
        def parse_header(reader, _unit_end, offset_size, section)
          @offset_size = offset_size
          @section = section
          @rows = []

          @version = reader.u16
          unless (2..5).cover?(@version)
            raise DebugLineError, "unsupported .debug_line version #{@version}"
          end

          if @version >= 5
            @address_size = reader.u8
            @segment_selector_size = reader.u8
            header_length = read_offset(reader)
            header_end = reader.pos + header_length
          else
            read_offset(reader) # header_length in DWARF 2-4
            @address_size = section.address_size
            @segment_selector_size = 0
            header_end = nil
          end

          @minimum_instruction_length = reader.u8
          @maximum_operations_per_instruction = @version >= 5 ? reader.u8 : 1
          @maximum_operations_per_instruction = 1 if @maximum_operations_per_instruction.zero?
          @default_is_stmt = reader.u8
          @line_base = sign_extend_byte(reader.u8)
          @line_range = reader.u8
          raise DebugLineError, "line_range must be nonzero" if @line_range.zero?
          @opcode_base = reader.u8

          @standard_opcode_lengths = [nil]
          (@opcode_base - 1).times { @standard_opcode_lengths << reader.uleb128 }

          read_tables(reader, section)

          return if header_end.nil? # DWARF 2-4 tables are self-terminating

          if reader.pos > header_end
            raise DebugLineError, "line number program header exceeds declared length"
          end
          reader.pos = header_end
        end

        # Interprets an unsigned byte as a signed 8-bit value.
        # @return [Integer]
        # @api private
        def sign_extend_byte(value)
          value >= 128 ? value - 256 : value
        end

        # Reads an offset-sized value using the unit's offset width.
        # @return [Integer]
        # @api private
        def read_offset(reader)
          offset_size == 8 ? reader.u64 : reader.u32
        end

        # Reads the directory and file-name tables appropriate for the version.
        # @return [void]
        # @api private
        def read_tables(reader, section)
          if @version >= 5
            @directories = read_v5_path_table(reader, section)
            @files = read_v5_file_table(reader, section)
          else
            @directories = read_legacy_directories(reader)
            @files = read_legacy_files(reader)
          end
        end

        # Reads the DWARF 2-4 include-directory table (NUL-terminated strings).
        # @return [Array<String>]
        # @api private
        def read_legacy_directories(reader)
          directories = []
          loop do
            name = reader.string
            break if name.empty?

            directories << name
          end
          directories
        end

        # Reads the DWARF 2-4 file-name table.
        # @return [Array<FileEntry>]
        # @api private
        def read_legacy_files(reader)
          files = []
          loop do
            name = reader.string
            break if name.empty?

            directory_index = reader.uleb128
            mtime = reader.uleb128
            size = reader.uleb128
            files << FileEntry.new(name, directory_index, mtime, size)
          end
          files
        end

        # Reads the DWARF 5 directory entry table.
        # @return [Array<String>]
        # @api private
        def read_v5_path_table(reader, section)
          count = reader.uleb128
          descriptions = read_v5_form_descriptions(reader, reader.uleb128)
          Array.new(count) do
            path = nil
            descriptions.each do |content_type, form|
              path = read_form_value(reader, form, section) if content_type == 1 # DW_LNCT_path
              read_form_value(reader, form, section) unless content_type == 1
            end
            path.to_s
          end
        end

        # Reads the DWARF 5 file-name entry table.
        # @return [Array<FileEntry>]
        # @api private
        def read_v5_file_table(reader, section)
          count = reader.uleb128
          descriptions = read_v5_form_descriptions(reader, reader.uleb128)
          Array.new(count) do
            name = nil
            directory_index = 0
            mtime = 0
            size = 0
            md5 = nil
            descriptions.each do |content_type, form|
              case content_type
              when 1 then name = read_form_value(reader, form, section) # DW_LNCT_path
              when 2 then directory_index = read_form_value(reader, form, section) # DW_LNCT_directory_index
              when 3 then mtime = read_form_value(reader, form, section) # DW_LNCT_timestamp
              when 4 then size = read_form_value(reader, form, section) # DW_LNCT_size
              when 5 then md5 = reader.bytes(16) # DW_LNCT_MD5 (16 raw bytes)
              else read_form_value(reader, form, section)
              end
            end
            FileEntry.new(name.to_s, directory_index, mtime, size, md5)
          end
        end

        # Reads `description_count` (content type, form) pairs.
        # @return [Array<Array(Integer, Integer)>] the pairs
        # @api private
        def read_v5_form_descriptions(reader, description_count)
          Array.new(description_count) { [reader.uleb128, reader.uleb128] }
        end

        # Reads a value of an attribute form allowed in a path entry.
        # @return [Object] the decoded value (a String for string forms)
        # @raise [DebugLineError] for unsupported forms
        # @api private
        def read_form_value(reader, form, section)
          case form
          when FORM_STRING then reader.string
          when FORM_LINE_STRP then section.resolve_line_string(read_offset(reader))
          when FORM_STRP then section.resolve_str(read_offset(reader))
          when FORM_DATA1 then reader.u8
          when FORM_DATA2 then reader.u16
          when FORM_DATA4 then reader.u32
          when FORM_DATA8 then reader.u64
          when FORM_SDATA then reader.sleb128
          when FORM_UDATA then reader.uleb128
          else
            raise DebugLineError, "unsupported attribute form 0x#{form.to_s(16)} in .debug_line"
          end
        end

        # Executes the line number program, appending rows in emission order.
        # @return [void]
        # @api private
        def execute(reader, unit_end)
          state = initial_state

          while reader.pos < unit_end
            opcode = reader.u8

            if opcode.zero? # extended opcode
              execute_extended(reader, state)
            elsif opcode < opcode_base # standard opcode
              execute_standard(reader, opcode, state)
            else # special opcode
              execute_special(opcode, state)
            end
          end
        end

        # @return [State] the initial line number machine registers
        # @api private
        def initial_state
          State.new(
            0,          # address
            0,          # op_index
            version >= 5 ? 0 : 1, # file
            1,          # line
            0,          # column
            default_is_stmt, # is_stmt
            false,      # basic_block
            false,      # end_sequence
            false,      # prologue_end
            false,      # epilogue_begin
            0,          # isa
            0,          # discriminator
          )
        end

        # Resets the state machine registers to their initial values in place.
        # @return [void]
        # @api private
        def reset_state(state)
          initial = initial_state
          initial.members.each { |member| state[member] = initial[member] }
        end

        # Appends a snapshot of the state and resets the per-row registers.
        # @return [void]
        # @api private
        def append_row(state)
          @rows << Row.new(self, state)

          state.basic_block = false
          state.prologue_end = false
          state.epilogue_begin = false
          state.discriminator = 0
        end

        # Advances the address/op_index registers by the given number of
        # operations, folding op_index into address at the VLIW boundary.
        # @return [void]
        # @api private
        def advance_operation(state, operation_advance)
          new_op_index = state.op_index + operation_advance
          state.address += minimum_instruction_length *
                           (new_op_index / maximum_operations_per_instruction)
          state.op_index = new_op_index % maximum_operations_per_instruction
        end

        # Handles one special opcode.
        # @return [void]
        # @api private
        def execute_special(opcode, state)
          adjusted = opcode - opcode_base
          advance_operation(state, adjusted / line_range)
          state.line += line_base + (adjusted % line_range)
          append_row(state)
        end

        # Handles one standard opcode, skipping any declared operands of
        # opcodes not understood by this reader.
        # @return [void]
        # @api private
        def execute_standard(reader, opcode, state)
          case STANDARD_OPCODES[opcode]
          when :copy
            append_row(state)
          when :advance_pc
            advance_operation(state, reader.uleb128)
          when :advance_line
            state.line += reader.sleb128
          when :set_file
            state.file = reader.uleb128
          when :set_column
            state.column = reader.uleb128
          when :negate_stmt
            state.is_stmt = !state.is_stmt
          when :set_basic_block
            state.basic_block = true
          when :const_add_pc
            advance_operation(state, (255 - opcode_base) / line_range)
          when :fixed_advance_pc
            state.address += reader.u16
            state.op_index = 0
          when :set_prologue_end
            state.prologue_end = true
          when :set_epilogue_begin
            state.epilogue_begin = true
          when :set_isa
            state.isa = reader.uleb128
          else
            skip_standard_operands(reader, opcode)
          end
        end

        # Skips the LEB128 operands declared for an unknown standard opcode.
        # @return [void]
        # @api private
        def skip_standard_operands(reader, opcode)
          count = @standard_opcode_lengths[opcode]
          raise DebugLineError, "standard opcode #{opcode} exceeds opcode_base" if count.nil?

          count.times { reader.uleb128 }
        end

        # Handles one extended opcode.
        # @return [void]
        # @api private
        def execute_extended(reader, state)
          length = reader.uleb128
          end_pos = reader.pos + length
          if end_pos > reader.size
            raise DebugLineError, "extended opcode runs past the end of .debug_line"
          end
          sub_opcode = reader.u8

          case sub_opcode
          when EXT_END_SEQUENCE
            state.end_sequence = true
            append_row(state)
            reset_state(state)
          when EXT_SET_ADDRESS
            if version >= 5
              reader.bytes(@segment_selector_size)
            end
            state.address = reader.uint(address_size)
            state.op_index = 0
          when EXT_DEFINE_FILE
            name = reader.string
            directory_index = reader.uleb128
            mtime = reader.uleb128
            size = reader.uleb128
            @files << FileEntry.new(name, directory_index, mtime, size)
          when EXT_SET_DISCRIMINATOR
            state.discriminator = reader.uleb128
          end

          if reader.pos > end_pos
            raise DebugLineError, "extended opcode #{sub_opcode} body exceeds declared length"
          end
          reader.pos = end_pos
        end
      end

    end
  end
end
