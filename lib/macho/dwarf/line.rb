# frozen_string_literal: true

module MachO
  # Readers for DWARF debugging information embedded in Mach-O binaries.
  module DWARF
    # Raised when DWARF data is malformed or uses an unsupported feature.
    class Error < MachOError
    end

    # DWARF line number content types, used by the version 5 directory and
    #  file name entry formats.
    module LineContentType
      # The path component of an entry.
      PATH = 0x01

      # An index into the directory table.
      DIRECTORY_INDEX = 0x02

      # A last-modification timestamp.
      TIMESTAMP = 0x03

      # The size of the source file in bytes.
      SIZE = 0x04

      # A 16-byte MD5 checksum of the source file.
      MD5 = 0x05
    end

    # A byte cursor over a String of DWARF data. All scalar reads are
    #  little-endian, matching the DWARF emitted for Mach-O targets.
    class Cursor
      # @return [Integer] the current read offset
      attr_reader :pos

      # @param data [String] the bytes to read from
      # @param pos [Integer] the initial read offset
      def initialize(data, pos = 0)
        @data = data
        @pos = pos
      end

      # Moves the read offset.
      # @param pos [Integer] the new read offset
      # @return [void]
      def seek(pos)
        @pos = pos
      end


      # @return [Integer] the total number of bytes in the data
      def size
        @data.bytesize
      end

      # Reads +length+ raw bytes.
      # @param length [Integer] the number of bytes to read
      # @return [String] the bytes read
      # @raise [Error] if fewer than +length+ bytes remain
      def bytes(length)
        chunk = @data.byteslice(@pos, length)
        raise Error, "unexpected end of DWARF data" if chunk.nil? || chunk.bytesize < length

        @pos += length
        chunk
      end

      # @return [Integer] an unsigned 8-bit integer
      def u8
        bytes(1).unpack1("C")
      end

      # @return [Integer] a signed 8-bit integer
      def i8
        bytes(1).unpack1("c")
      end

      # @return [Integer] an unsigned 16-bit integer
      def u16
        bytes(2).unpack1("S<")
      end

      # @return [Integer] an unsigned 32-bit integer
      def u32
        bytes(4).unpack1("L<")
      end

      # @return [Integer] an unsigned 64-bit integer
      def u64
        bytes(8).unpack1("Q<")
      end

      # @return [Integer] an unsigned LEB128 integer
      def uleb128
        result = 0
        shift = 0
        loop do
          byte = u8
          result |= (byte & 0x7f) << shift
          break if (byte & 0x80).zero?

          shift += 7
        end
        result
      end

      # @return [Integer] a signed LEB128 integer
      def sleb128
        result = 0
        shift = 0
        byte = 0
        loop do
          byte = u8
          result |= (byte & 0x7f) << shift
          shift += 7
          break if (byte & 0x80).zero?
        end
        result |= -(1 << shift) if (byte & 0x40) != 0
        result
      end

      # @return [String] a NUL-terminated string (without the terminator)
      # @raise [Error] if no terminator is found
      def cstring
        start = @pos
        @pos += 1 while @pos < @data.bytesize && @data.getbyte(@pos) != 0
        raise Error, "unterminated string in DWARF data" if @pos >= @data.bytesize

        string = @data.byteslice(start, @pos - start)
        @pos += 1
        string
      end

      # @param size [Integer] the number of bytes to read
      # @return [Integer] an unsigned little-endian integer of +size+ bytes
      def uint_of_size(size)
        value = 0
        bytes(size).each_byte.with_index do |byte, index|
          value |= byte << (8 * index)
        end
        value
      end
    end

    # A single entry in a line program header's file name table.
    class FileEntry
      # @return [String] the file name
      attr_reader :name

      # @return [Integer, nil] the raw directory index recorded for the file,
      #   or nil if none was recorded
      attr_reader :directory_index

      # @return [String, nil] the directory the file lives in, resolved
      #   against the header's directory table, or nil when the file is
      #   relative to the compilation directory (version 2-4 index 0)
      attr_reader :directory

      # @return [Integer, nil] the last-modification time, if recorded
      attr_reader :timestamp

      # @return [Integer, nil] the file size in bytes, if recorded
      attr_reader :size

      # @return [String, nil] the 16-byte MD5 checksum, if recorded
      attr_reader :md5

      # @param name [String] the file name
      # @param directory_index [Integer, nil] the raw directory table index
      # @param directory [String, nil] the resolved directory path
      # @param timestamp [Integer, nil] the last-modification time
      # @param size [Integer, nil] the file size in bytes
      # @param md5 [String, nil] the 16-byte MD5 checksum
      def initialize(name:, directory_index: nil, directory: nil, timestamp: nil, size: nil, md5: nil)
        @name = name
        @directory_index = directory_index
        @directory = directory
        @timestamp = timestamp
        @size = size
        @md5 = md5
      end

      # @return [String] the file path, prefixed with its directory when known
      def path
        return @name if @directory.nil? || @directory.empty?

        File.join(@directory, @name)
      end
    end

    # A single row emitted by the line number machine. Rows where
    #  {#sequence_end?} is true terminate a sequence and carry no source
    #  mapping of their own.
    class Row
      # @return [Integer] the machine address for this row
      attr_reader :address

      # @return [Integer] the operation index within a VLIW instruction
      attr_reader :op_index

      # @return [Integer] the raw value of the machine's file register
      attr_reader :file_index

      # @return [FileEntry, nil] the source file, or nil when the file
      #   register pointed outside the header's file table
      attr_reader :file

      # @return [Integer] the source line number (1-based)
      attr_reader :line

      # @return [Integer] the source column number (0 means none)
      attr_reader :column

      # @return [Integer] the discriminator distinguishing multiple blocks
      #   on the same line (0 means none)
      attr_reader :discriminator

      # @return [Integer] the instruction set architecture selector
      attr_reader :isa

      # @param address [Integer] the machine address
      # @param op_index [Integer] the VLIW operation index
      # @param file_index [Integer] the raw file register value
      # @param file [FileEntry, nil] the resolved source file
      # @param line [Integer] the source line number
      # @param column [Integer] the source column number
      # @param discriminator [Integer] the block discriminator
      # @param isa [Integer] the ISA selector
      # @param statement [Boolean] whether the row is a recommended
      #   breakpoint location
      # @param basic_block [Boolean] whether the row begins a basic block
      # @param prologue_end [Boolean] whether the row ends a function prologue
      # @param epilogue_begin [Boolean] whether the row begins a function
      #   epilogue
      # @param sequence_end [Boolean] whether the row terminates its sequence
      def initialize(address:, op_index:, file_index:, file:, line:, column:, discriminator:, isa:,
                     statement:, basic_block:, prologue_end:, epilogue_begin:, sequence_end:)
        @address = address
        @op_index = op_index
        @file_index = file_index
        @file = file
        @line = line
        @column = column
        @discriminator = discriminator
        @isa = isa
        @statement = statement
        @basic_block = basic_block
        @prologue_end = prologue_end
        @epilogue_begin = epilogue_begin
        @sequence_end = sequence_end
      end

      # @return [Boolean] whether the row is a recommended breakpoint location
      def statement?
        @statement
      end

      # @return [Boolean] whether the row begins a basic block
      def basic_block?
        @basic_block
      end

      # @return [Boolean] whether the row ends a function prologue
      def prologue_end?
        @prologue_end
      end

      # @return [Boolean] whether the row begins a function epilogue
      def epilogue_begin?
        @epilogue_begin
      end

      # @return [Boolean] whether the row terminates its sequence
      def sequence_end?
        @sequence_end
      end
    end

    # A contiguous run of rows bounded by an end_sequence row. Addresses in
    #  [start_address, end_address) are covered by the sequence.
    class Sequence
      # @return [Integer] the first address covered by the sequence
      attr_reader :start_address

      # @return [Integer] the first address not covered by the sequence
      attr_reader :end_address

      # @return [Array<Row>] the rows of the sequence, in emission order
      #   (addresses are non-decreasing)
      attr_reader :rows

      # @param start_address [Integer] the first covered address
      # @param end_address [Integer] the first uncovered address
      # @param rows [Array<Row>] the rows of the sequence
      def initialize(start_address, end_address, rows)
        @start_address = start_address
        @end_address = end_address
        @rows = rows
      end

      # @param address [Integer] the address to test
      # @return [Boolean] whether the sequence covers +address+
      def cover?(address)
        address >= @start_address && address < @end_address
      end
    end

    # An address-to-source index built from the rows of a {LineProgram}.
    #
    #  Selection rules for queries:
    #
    #  * A row governs the addresses from its own address up to (but not
    #    including) the address of the next row in the same sequence.
    #  * Sequences never leak: an address in a gap between two sequences, or
    #    outside every sequence, matches nothing.
    #  * The machine may emit several rows at the same address (for example
    #    two consecutive copy opcodes). {#rows_at} and {#rows_in} return all
    #    of them in emission order; {#lookup} returns the last one emitted,
    #    since it reflects the final machine state at that address.
    #  * Rows flagged as sequence terminators ({Row#sequence_end?}) carry no
    #    source mapping and are skipped by every query; the raw rows remain
    #    available through {#rows} and {Sequence#rows}.
    class LineTable
      # @return [Array<Row>] every emitted row, in emission order
      attr_reader :rows

      # @return [Array<Sequence>] the sequences the rows belong to
      attr_reader :sequences

      # @param sequences [Array<Sequence>] the sequences to index
      def initialize(sequences)
        @sequences = sequences
        @rows = sequences.flat_map(&:rows)
      end

      # @param address [Integer] the address to test
      # @return [Boolean] whether any sequence covers +address+
      def cover?(address)
        @sequences.any? { |sequence| sequence.cover?(address) }
      end

      # Returns every non-terminator row emitted at exactly +address+.
      # @param address [Integer] the address to look up
      # @return [Array<Row>] the matching rows, in emission order
      def rows_at(address)
        @rows.select { |row| !row.sequence_end? && row.address == address }
      end

      # Returns every non-terminator row whose address falls within +range+.
      # @param range [Range] the address range to look up
      # @return [Array<Row>] the matching rows, in emission order
      def rows_in(range)
        @rows.select { |row| !row.sequence_end? && range.cover?(row.address) }
      end

      # Returns the row governing +address+, or nil when no sequence covers
      #  it. See the class documentation for the selection rules.
      # @param address [Integer] the address to look up
      # @return [Row, nil] the governing row
      def lookup(address)
        sequence = @sequences.find { |candidate| candidate.cover?(address) }
        return nil if sequence.nil?

        governing = nil
        sequence.rows.each do |row|
          next if row.sequence_end?
          break if row.address > address

          governing = row
        end
        governing
      end
    end

    # A parsed `.debug_line` line number program (DWARF versions 2-5).
    #
    #  The line number machine is executed in full: standard, extended, and
    #  special opcodes are all interpreted, and the VLIW operation index
    #  (`op_index`) participates in every address advance. An
    #  `end_sequence` opcode closes only the current sequence; execution
    #  continues with fresh registers so that programs containing several
    #  sequences (for example, non-contiguous address ranges) are decoded
    #  completely.
    class LineProgram
      # The parsed header of a line number program.
      class Header
        # @return [Integer] the DWARF version of the program (2-5)
        attr_reader :version

        # @return [Integer] the target address size in bytes (version 5;
        #   0 for earlier versions, which do not record it)
        attr_reader :address_size

        # @return [Integer] the minimum instruction length in bytes
        attr_reader :min_instruction_length

        # @return [Integer] the maximum number of operations per instruction
        attr_reader :max_ops_per_instruction

        # @return [Integer] the line base for special opcode adjustments
        attr_reader :line_base

        # @return [Integer] the line range for special opcode adjustments
        attr_reader :line_range

        # @return [Integer] the first opcode value used by special opcodes
        attr_reader :opcode_base

        # @return [Array<Integer>] the operand counts of the standard opcodes
        attr_reader :standard_opcode_lengths

        # @return [Array<String>] the directory table
        attr_reader :directories

        # @return [Array<FileEntry>] the file name table
        attr_reader :files

        # @param version [Integer] the DWARF version
        # @param address_size [Integer] the target address size in bytes
        # @param min_instruction_length [Integer] the minimum instruction length
        # @param max_ops_per_instruction [Integer] the maximum operations per
        #   instruction
        # @param default_is_stmt [Boolean] the initial is_stmt register value
        # @param line_base [Integer] the line base
        # @param line_range [Integer] the line range
        # @param opcode_base [Integer] the opcode base
        # @param standard_opcode_lengths [Array<Integer>] the standard opcode
        #   operand counts
        # @param directories [Array<String>] the directory table
        # @param files [Array<FileEntry>] the file name table
        def initialize(version:, address_size:, min_instruction_length:, max_ops_per_instruction:,
                       default_is_stmt:, line_base:, line_range:, opcode_base:,
                       standard_opcode_lengths:, directories:, files:)
          @version = version
          @address_size = address_size
          @min_instruction_length = min_instruction_length
          @max_ops_per_instruction = max_ops_per_instruction
          @default_is_stmt = default_is_stmt
          @line_base = line_base
          @line_range = line_range
          @opcode_base = opcode_base
          @standard_opcode_lengths = standard_opcode_lengths
          @directories = directories
          @files = files
        end

        # @return [Boolean] the initial value of the is_stmt register
        def default_is_stmt?
          @default_is_stmt
        end

        # Resolves a file register value to a file table entry. Versions 2-4
        #  number files from 1; version 5 numbers them from 0.
        # @param register [Integer] the file register value
        # @return [FileEntry, nil] the entry, or nil when out of range
        def file_at(register)
          index = @version >= 5 ? register : register - 1
          return nil if index.negative?

          @files[index]
        end

        # Appends a file entry, as DW_LNE_define_file does.
        # @param entry [FileEntry] the entry to append
        # @return [void]
        def append_file(entry)
          @files << entry
        end
      end

      # @return [Header] the parsed program header
      attr_reader :header

      # @return [Array<Row>] every emitted row, in emission order
      attr_reader :rows

      # @return [Array<Sequence>] the sequences closed by end_sequence rows
      attr_reader :sequences

      # Parses a line number program from `.debug_line` data.
      # @param data [String] the raw `.debug_line` bytes
      # @param offset [Integer] the offset of the program within +data+
      # @param address_size [Integer] the target address size in bytes, used
      #   for DW_LNE_set_address in versions 2-4, which do not record it;
      #   version 5 programs read it from their header instead
      # @param line_str [String, nil] the raw `.debug_line_str` bytes, used
      #   to resolve DW_FORM_line_strp and DW_FORM_strp paths in version 5
      #   headers; required only when the header uses those forms
      # @return [LineProgram] the parsed program
      # @raise [Error] if the data is malformed or unsupported
      def self.parse(data, offset: 0, address_size: 8, line_str: nil)
        program = allocate
        program.send(:initialize, Cursor.new(data, offset), address_size, line_str)
        program
      end

      # @return [LineTable] an address index over the program's rows
      def to_table
        LineTable.new(@sequences)
      end

      def initialize(cursor, default_address_size, line_str)
        @rows = []
        @sequences = []
        @current_rows = []
        @line_str = line_str
        parse_unit(cursor, default_address_size)
      end

      private

      def parse_unit(cursor, default_address_size)
        unit_length = cursor.u32
        dwarf64 = false
        if unit_length == 0xffffffff
          unit_length = cursor.u64
          dwarf64 = true
        end
        unit_end = cursor.pos + unit_length
        raise Error, "truncated .debug_line unit" if unit_end > cursor.size

        version = cursor.u16
        raise Error, "unsupported .debug_line version: #{version}" unless (2..5).cover?(version)

        address_size = 0
        if version >= 5
          address_size = cursor.u8
          cursor.u8 # segment_selector_size, unused here
        end

        header_length = dwarf64 ? cursor.u64 : cursor.u32
        header_end = cursor.pos + header_length
        raise Error, "truncated .debug_line header" if header_end > unit_end

        min_instruction_length = cursor.u8
        max_ops_per_instruction = version >= 4 ? cursor.u8 : 1
        if max_ops_per_instruction.zero?
          raise Error, "invalid maximum operations per instruction: 0"
        end

        default_is_stmt = cursor.u8 != 0
        line_base = cursor.i8
        line_range = cursor.u8
        raise Error, "invalid line range: 0" if line_range.zero?

        opcode_base = cursor.u8
        standard_opcode_lengths = cursor.bytes(opcode_base - 1).bytes

        directories = []
        files = []
        if version >= 5
          parse_v5_tables(cursor, dwarf64, directories, files)
        else
          parse_v2_tables(cursor, directories, files)
        end

        @header = Header.new(
          :version => version,
          :address_size => address_size,
          :min_instruction_length => min_instruction_length,
          :max_ops_per_instruction => max_ops_per_instruction,
          :default_is_stmt => default_is_stmt,
          :line_base => line_base,
          :line_range => line_range,
          :opcode_base => opcode_base,
          :standard_opcode_lengths => standard_opcode_lengths,
          :directories => directories,
          :files => files
        )

        cursor.seek(header_end) if cursor.pos < header_end
        @machine_address_size = version >= 5 ? address_size : default_address_size
        execute(cursor, unit_end)
      end

      def parse_v2_tables(cursor, directories, files)
        loop do
          directory = cursor.cstring
          break if directory.empty?

          directories << directory
        end

        loop do
          name = cursor.cstring
          break if name.empty?

          files << parse_v2_file_entry(cursor, directories, name)
        end
      end

      def parse_v2_file_entry(cursor, directories, name)
        directory_index = cursor.uleb128
        timestamp = cursor.uleb128
        size = cursor.uleb128
        FileEntry.new(
          :name => name,
          :directory_index => directory_index,
          :directory => directory_index.zero? ? nil : directories[directory_index - 1],
          :timestamp => timestamp,
          :size => size
        )
      end

      def parse_v5_tables(cursor, dwarf64, directories, files)
        directory_formats = parse_entry_formats(cursor)
        cursor.uleb128.times do
          values = parse_entry(cursor, directory_formats, dwarf64)
          directories << values.fetch(LineContentType::PATH, "")
        end

        file_formats = parse_entry_formats(cursor)
        cursor.uleb128.times do
          values = parse_entry(cursor, file_formats, dwarf64)
          directory_index = values[LineContentType::DIRECTORY_INDEX]
          files << FileEntry.new(
            :name => values.fetch(LineContentType::PATH, ""),
            :directory_index => directory_index,
            :directory => directory_index.nil? ? nil : directories[directory_index],
            :timestamp => values[LineContentType::TIMESTAMP],
            :size => values[LineContentType::SIZE],
            :md5 => values[LineContentType::MD5]
          )
        end
      end

      def parse_entry_formats(cursor)
        Array.new(cursor.u8) { [cursor.uleb128, cursor.uleb128] }
      end

      def parse_entry(cursor, formats, dwarf64)
        formats.to_h do |content_type, form|
          [content_type, read_form_value(cursor, form, dwarf64)]
        end
      end

      def read_form_value(cursor, form, dwarf64)
        case form
        when 0x05 then cursor.u16 # DW_FORM_data2
        when 0x06 then cursor.u32 # DW_FORM_data4
        when 0x07 then cursor.u64 # DW_FORM_data8
        when 0x08 then cursor.cstring # DW_FORM_string
        when 0x0b then cursor.u8 # DW_FORM_data1
        when 0x0e, 0x1f # DW_FORM_strp, DW_FORM_line_strp
          read_indirect_string(dwarf64 ? cursor.u64 : cursor.u32)
        when 0x0f then cursor.uleb128 # DW_FORM_udata
        when 0x17 then dwarf64 ? cursor.u64 : cursor.u32 # DW_FORM_sec_offset
        when 0x1e then cursor.bytes(16) # DW_FORM_data16
        else
          raise Error, "unsupported DWARF form 0x%02<form>x in line header" % { :form => form }
        end
      end

      def read_indirect_string(offset)
        raise Error, "line header references .debug_line_str, but none was given" if @line_str.nil?
        raise Error, ".debug_line_str offset out of range: #{offset}" if offset >= @line_str.bytesize

        Cursor.new(@line_str, offset).cstring
      end

      def execute(cursor, unit_end)
        reset_registers
        while cursor.pos < unit_end
          opcode = cursor.u8
          if opcode.zero?
            execute_extended(cursor)
          elsif opcode < @header.opcode_base
            execute_standard(opcode, cursor)
          else
            execute_special(opcode)
          end
        end
        finalize
      end

      def execute_extended(cursor)
        length = cursor.uleb128
        sub_end = cursor.pos + length
        sub_opcode = cursor.u8
        case sub_opcode
        when 1 # DW_LNE_end_sequence
          emit_row(true)
        when 2 # DW_LNE_set_address
          @reg_address = cursor.uint_of_size(@machine_address_size)
          @reg_op_index = 0
        when 3 # DW_LNE_define_file
          raise Error, "DW_LNE_define_file is not valid in DWARF 5" if @header.version >= 5

          @header.append_file(parse_v2_file_entry(cursor, @header.directories, cursor.cstring))
        when 4 # DW_LNE_set_discriminator
          @reg_discriminator = cursor.uleb128
        when 5 # DW_LNE_padding
          cursor.seek(sub_end)
        end
        cursor.seek(sub_end) if cursor.pos < sub_end
      end

      def execute_standard(opcode, cursor)
        case opcode
        when 1 # DW_LNS_copy
          emit_row
          clear_ephemeral_registers
        when 2 # DW_LNS_advance_pc
          advance_address(cursor.uleb128)
        when 3 # DW_LNS_advance_line
          @reg_line += cursor.sleb128
        when 4 # DW_LNS_set_file
          @reg_file = cursor.uleb128
        when 5 # DW_LNS_set_column
          @reg_column = cursor.uleb128
        when 6 # DW_LNS_negate_stmt
          @reg_is_stmt = !@reg_is_stmt
        when 7 # DW_LNS_set_basic_block
          @reg_basic_block = true
        when 8 # DW_LNS_const_add_pc
          advance_address((255 - @header.opcode_base) / @header.line_range)
        when 9 # DW_LNS_fixed_advance_pc
          @reg_address += cursor.u16
          @reg_op_index = 0
        when 10 # DW_LNS_set_prologue_end
          @reg_prologue_end = true
        when 11 # DW_LNS_set_epilogue_begin
          @reg_epilogue_begin = true
        when 12 # DW_LNS_set_isa
          @reg_isa = cursor.uleb128
        else
          # Unknown standard opcode: skip its declared operands.
          @header.standard_opcode_lengths[opcode - 1].times { cursor.uleb128 }
        end
      end

      def execute_special(opcode)
        adjusted_opcode = opcode - @header.opcode_base
        advance_address(adjusted_opcode / @header.line_range)
        @reg_line += @header.line_base + (adjusted_opcode % @header.line_range)
        emit_row
        clear_ephemeral_registers
      end

      def advance_address(operation_advance)
        combined = @reg_op_index + operation_advance
        max_ops = @header.max_ops_per_instruction
        @reg_address += @header.min_instruction_length * (combined / max_ops)
        @reg_op_index = combined % max_ops
      end

      def emit_row(sequence_end = false)
        row = Row.new(
          :address => @reg_address,
          :op_index => @reg_op_index,
          :file_index => @reg_file,
          :file => @header.file_at(@reg_file),
          :line => @reg_line,
          :column => @reg_column,
          :discriminator => @reg_discriminator,
          :isa => @reg_isa,
          :statement => @reg_is_stmt,
          :basic_block => @reg_basic_block,
          :prologue_end => @reg_prologue_end,
          :epilogue_begin => @reg_epilogue_begin,
          :sequence_end => sequence_end
        )
        @rows << row
        @current_rows << row
        close_sequence(row.address) if sequence_end
        row
      end

      def close_sequence(end_address)
        @sequences << Sequence.new(@current_rows.first.address, end_address, @current_rows)
        @current_rows = []
        reset_registers
      end

      def finalize
        return if @current_rows.empty?

        close_sequence(@current_rows.last.address + @header.min_instruction_length)
      end

      def reset_registers
        @reg_address = 0
        @reg_op_index = 0
        @reg_file = 1
        @reg_line = 1
        @reg_column = 0
        @reg_is_stmt = @header.default_is_stmt?
        @reg_basic_block = false
        @reg_prologue_end = false
        @reg_epilogue_begin = false
        @reg_isa = 0
        @reg_discriminator = 0
      end

      def clear_ephemeral_registers
        @reg_discriminator = 0
        @reg_basic_block = false
        @reg_prologue_end = false
        @reg_epilogue_begin = false
      end
    end
  end
end
