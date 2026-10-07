# frozen_string_literal: true

require_relative "exceptions"

module MachO
  module Bindings
    BIND_OPCODE_MASK = 0xf0
    BIND_IMMEDIATE_MASK = 0x0f
    BIND_OPCODE_DONE = 0x00
    BIND_OPCODE_SET_DYLIB_ORDINAL_IMM = 0x10
    BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB = 0x20
    BIND_OPCODE_SET_DYLIB_SPECIAL_IMM = 0x30
    BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM = 0x40
    BIND_OPCODE_SET_TYPE_IMM = 0x50
    BIND_OPCODE_SET_ADDEND_SLEB = 0x60
    BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB = 0x70
    BIND_OPCODE_ADD_ADDR_ULEB = 0x80
    BIND_OPCODE_DO_BIND = 0x90
    BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB = 0xa0
    BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED = 0xb0
    BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB = 0xc0
    BIND_OPCODE_THREADED = 0xd0
    BIND_APPLY_THREADED_BIND_IMMEDIATE = 0x00
    BIND_THREADED_REBASE_IMMEDIATE = 0x01

    BindingRecord = Struct.new(:item_start, :do_start, :do_end, :opcode_end, :end_offset, :has_done,
      :ordinal, :symbol, :flags, :type, :segment, :segment_offset, :addend,
      keyword_init: true)

    def self.rewrite!(macho, stream, source_ordinal, symbol, target_ordinal: nil,
      target_symbol: nil, addend: nil)
      Rewriter.new(macho, stream, source_ordinal, symbol,
        target_ordinal: target_ordinal,
        target_symbol: target_symbol,
        addend: addend).rewrite!
    end

    def self.pack_uleb128(value)
      validate_unsigned!(value)
      bytes = +""
      loop do
        byte = value & 0x7f
        value >>= 7
        bytes << (value.zero? ? byte : byte | 0x80).chr
        break if value.zero?
      end
      bytes
    end

    def self.pack_sleb128(value)
      validate_signed!(value)
      bytes = +""
      loop do
        byte = value & 0x7f
        done = (value == 0 && byte & 0x40 == 0) || (value == -1 && byte & 0x40 != 0)
        value >>= 7
        bytes << (done ? byte : byte | 0x80).chr
        break if done
      end
      bytes
    end

    def self.validate_unsigned!(value)
      raise BindingError, "invalid unsigned LEB128 value: #{value}" unless value.is_a?(Integer) && value >= 0
    end

    def self.validate_signed!(value)
      raise BindingError, "invalid signed LEB128 value: #{value}" unless value.is_a?(Integer)
    end

    class Parser
      def initialize(data, stream, pointer_size)
        @data = data.b
        @stream = stream
        @lazy = stream == :lazy_bind
        @pointer_size = pointer_size
      end

      def parse
        reset_state
        while @position < @data.bytesize
          position = @position
          byte = next_uint8
          opcode = byte & BIND_OPCODE_MASK
          immediate = byte & BIND_IMMEDIATE_MASK
          case opcode
          when BIND_OPCODE_DONE
            handle_done(position)
          when BIND_OPCODE_SET_DYLIB_ORDINAL_IMM then set_ordinal(immediate, position)
          when BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB then @ordinal = read_uleb128(position)
          when BIND_OPCODE_SET_DYLIB_SPECIAL_IMM then @ordinal = immediate.zero? ? 0 : immediate | -16
          when BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM
            @symbol = read_cstring(position)
            @symbol_flags = immediate
          when BIND_OPCODE_SET_TYPE_IMM then @type = immediate
          when BIND_OPCODE_SET_ADDEND_SLEB then @addend = read_sleb128(position)
          when BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB
            @segment = immediate
            @segment_offset = read_uleb128(position)
          when BIND_OPCODE_ADD_ADDR_ULEB then @segment_offset += read_uleb128(position)
          when BIND_OPCODE_DO_BIND then make_record(position, position + 1)
          when BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB then parse_bind_add_addr_uleb(position)
          when BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED
            make_record(position, position + 1)
            @segment_offset += immediate * @pointer_size + @pointer_size
          when BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB
            parse_repeated_bind(position)
          when BIND_OPCODE_THREADED then validate_threaded(immediate, position)
          else raise BindingError, "unsupported bind opcode 0x#{opcode.to_s(16)} at #{position}"
          end
        end
        if @lazy && @records.any? { |record| !record.has_done }
          raise BindingError, "unterminated lazy bind stream"
        end

        @records
      end

      private

      def reset_state
        @position = 0
        @item_start = 0
        @segment = 0
        @segment_offset = 0
        @ordinal = 0
        @symbol = nil
        @symbol_flags = 0
        @type = 0
        @addend = 0
        @records = []
      end

      def handle_done(position)
        if @lazy
          return if @records.any?(&:has_done)

          item_records = @records.count { |record| record.item_start == @item_start }
          raise BindingError, "empty lazy bind item at #{position}" if item_records.zero?
          if item_records > 1
            raise BindingError,
                  "unsupported lazy bind item with multiple do-bind opcodes at #{position}"
          end

          record = @records.last
          record.end_offset = position + 1
          record.has_done = true
          @item_start = position + 1
        else
          @records.each { |record| record.has_done = true }
        end
      end

      def set_ordinal(immediate, position)
        raise BindingError, "invalid immediate dylib ordinal at #{position}" if immediate.zero?

        @ordinal = immediate
      end

      def parse_bind_add_addr_uleb(position)
        do_end = @position
        address_delta = read_uleb128(position)
        make_record(position, do_end)
        @records.last.opcode_end = @position
        @segment_offset += address_delta
      end

      def parse_repeated_bind(position)
        count = read_uleb128(position)
        skip = read_uleb128(position)
        raise BindingError, "invalid repeated bind count at #{position}" if count.zero?
        raise BindingError, "unsupported repeated lazy bind at #{position}" if @lazy

        count.times do
          make_record(position, @position)
          @segment_offset += skip + @pointer_size
        end
        @segment_offset -= skip
      end

      def make_record(do_start, end_offset)
        raise BindingError, "bind opcode without symbol before do-bind at #{do_start}" if @symbol.nil?

        @records << BindingRecord.new(
          item_start: @item_start,
          do_start: do_start,
          do_end: end_offset,
          opcode_end: end_offset,
          end_offset: end_offset,
          has_done: false,
          ordinal: @ordinal,
          symbol: @symbol,
          flags: @symbol_flags,
          type: @type,
          segment: @segment,
          segment_offset: @segment_offset,
          addend: @addend
        )
      end

      def validate_threaded(immediate, position)
        supported = [BIND_APPLY_THREADED_BIND_IMMEDIATE, BIND_THREADED_REBASE_IMMEDIATE]
        return if supported.include?(immediate)

        raise BindingError, "unsupported threaded bind immediate #{immediate} at #{position}"
      end

      def next_uint8
        byte = @data.byteslice(@position, 1)&.ord
        raise BindingError, "truncated bind stream at #{@position}" if byte.nil?

        @position += 1
        byte
      end

      def read_cstring(position)
        terminal = @data.index("\x00", @position)
        raise BindingError, "unterminated bind symbol at #{position}" if terminal.nil?

        @data.byteslice(@position, terminal - @position).dup.force_encoding(Encoding::BINARY).tap do
          @position = terminal + 1
        end
      end

      def read_uleb128(position)
        value = 0
        shift = 0
        loop do
          byte = next_uint8
          raise BindingError, "overflowing ULEB128 at #{position}" if shift >= 64

          value |= (byte & 0x7f) << shift
          return value if byte & 0x80 == 0

          shift += 7
        end
      end

      def read_sleb128(position)
        value = 0
        shift = 0
        loop do
          byte = next_uint8
          raise BindingError, "overflowing SLEB128 at #{position}" if shift >= 64

          value |= (byte & 0x7f) << shift
          shift += 7
          return sign_extend(value, shift) if byte & 0x80 == 0
        end
      end

      def sign_extend(value, bits)
        value -= (1 << bits) if value & (1 << (bits - 1)) != 0
        value
      end
    end
    class Rewriter
      STUB_HELPER_SIZE = 15
      X86_64_FIRST_STUB_HELPER_OFFSET = 16
      X86_64_HELPER_PREFIX = "\x4c\x8d\x1d".b
      X86_64_PUSH = "\x68".b
      X86_64_JMP = "\xe9".b
      X86_64_ABS32 = 4

      def initialize(macho, stream, source_ordinal, symbol, target_ordinal:, target_symbol:, addend:)
        @macho = macho
        @stream = stream
        @lazy = stream == :lazy_bind
        @source_ordinal = source_ordinal
        @symbol = validate_binary_string(symbol, "source symbol")
        @target_ordinal = target_ordinal || source_ordinal
        @target_symbol = target_symbol.nil? ? @symbol : validate_binary_string(target_symbol, "target symbol")
        @addend = addend || 0
        validate_arguments
      end

      def rewrite!
        @command = dyld_info_command
        stream_offset, stream_size = stream_range(@command)
        validate_stream_range(stream_offset, stream_size)
        @stream_offset = stream_offset
        original_stream = @macho.serialize.byteslice(stream_offset, stream_size).b
        records = Parser.new(original_stream, @stream, pointer_size).parse
        selected = select_records(records)
        if selected.empty?
          raise BindingError, "no matching #@stream binding for library ordinal " \
            "#@source_ordinal and symbol #{@symbol.inspect}"
        end

        validate_x86_64_lazy_layout(records) if @lazy
        rewritten = rebuild_stream(original_stream, records, selected)
        delta = rewritten.bytesize - original_stream.bytesize
        @patches = [{ :kind => :bytes, :offset => stream_offset,
                     :old_size => original_stream.bytesize, :bytes => rewritten }]
        add_x86_64_helper_patches if @lazy
        add_linkedit_offset_patches(delta)
        apply_patches
        @macho.populate_fields
        selected.size
      end

      private

      def validate_arguments
        unless %i[bind weak_bind lazy_bind].include?(@stream)
          raise ArgumentError, "stream must be :bind, :weak_bind, or :lazy_bind"
        end
        unless @source_ordinal.is_a?(Integer) && @source_ordinal.positive?
          raise BindingError, "source library ordinal must be a positive integer"
        end
        unless @target_ordinal.is_a?(Integer) && !@target_ordinal.zero?
          raise BindingError, "target library ordinal must be a nonzero integer"
        end

        Bindings.validate_signed!(@addend)
      end

      def validate_binary_string(value, description)
        raise BindingError, "#{description} must be a String" unless value.is_a?(String)

        value = value.b
        raise BindingError, "#{description} must not contain a null byte" if value.include?("\x00")
        raise BindingError, "#{description} must not be empty" if value.empty?

        value
      end

      def dyld_info_command
        @macho.command(:LC_DYLD_INFO).first ||
          @macho.command(:LC_DYLD_INFO_ONLY).first ||
          raise(BindingError, "Mach-O has no LC_DYLD_INFO[_ONLY] load command")
      end

      def stream_range(command)
        case @stream
        when :bind then [command.bind_off, command.bind_size]
        when :weak_bind then [command.weak_bind_off, command.weak_bind_size]
        when :lazy_bind then [command.lazy_bind_off, command.lazy_bind_size]
        end
      end

      def validate_stream_range(offset, size)
        if offset.zero? || size.zero?
          raise BindingError, "#@stream bind stream is absent"
        end
        if offset + size > @macho.serialize.bytesize
          raise BindingError, "#@stream bind stream extends past end of file"
        end
      end

      def select_records(records)
        records.select do |record|
          record.ordinal == @source_ordinal && record.symbol == @symbol
        end
      end

      def rebuild_stream(data, records, selected)
        selected_ids = selected.map(&:object_id)
        output = +"".b
        @lazy_offsets = {}
        cursor = 0
        index = 0
        while index < records.size
          record = records[index]
          selected = selected_ids.include?(record.object_id)
          if @lazy
            next if record.item_start < cursor

            item_end = record.end_offset
            @lazy_offsets[record.item_start] = output.bytesize
            output << data.byteslice(cursor, record.do_start - cursor)
            output << replacement_prefix(record) if selected
            output << data.byteslice(record.do_start, record.do_end - record.do_start)
            output << data.byteslice(item_end - 1, 1)
            cursor = item_end
            index += 1
          elsif selected
            run = [record]
            while index + 1 < records.size && selected_ids.include?(records[index + 1].object_id)
              run << records[index + 1]
              index += 1
            end
            first = run.first
            output << data.byteslice(cursor, first.do_start - cursor)
            run.each do |item|
              output << replacement_prefix(item)
              output << data.byteslice(item.do_start, item.do_end - item.do_start)
            end
            output << restore_binding_state(first)
            output << BIND_OPCODE_SET_ADDEND_SLEB.chr + Bindings.pack_sleb128(first.addend)
            cursor = run.last.opcode_end
            index += 1
          else
            next_cursor = record.opcode_end
            output << data.byteslice(cursor, next_cursor - cursor)
            cursor = next_cursor
            index += 1
          end
        end
        if !@lazy && records.last.has_done
          done_position = data.index(BIND_OPCODE_DONE.chr, records.last.do_end)
          cursor = done_position + 1 if done_position
        end
        output << data.byteslice(cursor, data.bytesize - cursor)
        output
      end

      def replacement_prefix(record)
        encode_ordinal(@target_ordinal) +
          (BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | record.flags).chr +
          @target_symbol + "\x00".b +
          BIND_OPCODE_SET_ADDEND_SLEB.chr + Bindings.pack_sleb128(@addend)
      end

      def restore_prefix(record)
        encode_ordinal(record.ordinal) +
          (BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | record.flags).chr +
          record.symbol + "\x00".b +
          BIND_OPCODE_SET_ADDEND_SLEB.chr + Bindings.pack_sleb128(record.addend)
      end

      def restore_binding_state(record)
        encode_ordinal(record.ordinal) +
          (BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | record.flags).chr +
          record.symbol + "\x00".b
      end

      def encode_ordinal(ordinal)
        if ordinal.negative?
          immediate = ordinal & BIND_IMMEDIATE_MASK
          unless ordinal == immediate | -16
            raise BindingError, "unsupported special dylib ordinal #{ordinal}"
          end

          return (BIND_OPCODE_SET_DYLIB_SPECIAL_IMM | immediate).chr
        end

        return (BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | ordinal).chr if ordinal <= 15

        BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB.chr + Bindings.pack_uleb128(ordinal)
      end

      def validate_x86_64_lazy_layout(records)
        unless @macho.magic64? && @macho.endianness == :little &&
               @macho.header.cputype == Headers::CPU_TYPE_X86_64
          raise BindingError, "lazy bind rewriting is only supported for x86_64 Mach-O layouts"
        end

        @lazy_helpers = x86_64_stub_helpers
        records.each do |record|
          helper = @lazy_helpers.find { |candidate| candidate[:bind_offset] == record.item_start }
          unless helper
            raise BindingError,
                  "could not relocate x86_64 stub helper for lazy bind at #{record.item_start}"
          end
        end
        @lazy_helpers = @lazy_helpers.select do |helper|
          records.any? { |record| record.item_start == helper[:bind_offset] }
        end
        unless @lazy_helpers.size == records.size
          raise BindingError, "could not identify x86_64 stub helper for every lazy bind item"
        end
      end

      def x86_64_stub_helpers
        @command ||= dyld_info_command
        helper_section = sections.find { |section| section.sectname == "__stub_helper" }
        lazy_section = sections.find { |section| section.type?(:S_LAZY_SYMBOL_POINTERS) }
        return [] unless helper_section && lazy_section

        helpers = []
        offset = helper_section.offset + X86_64_FIRST_STUB_HELPER_OFFSET
        limit = helper_section.offset + helper_section.size - 1
        while offset < limit
          bytes = @macho.serialize.byteslice(offset, STUB_HELPER_SIZE)
          next if bytes.nil?

          helper = parse_helper(bytes, offset, helper_section, lazy_section)
          helpers << helper if helper
          offset += 1
        end
        helpers
      end

      def parse_helper(bytes, offset, helper_section, lazy_section)
        return if bytes.bytesize < 10
        return unless bytes[0] == X86_64_PUSH && bytes[5] == X86_64_JMP

        bind_offset = bytes.byteslice(1, X86_64_ABS32).unpack1("L<")
        lazy_range = lazy_section.addr...lazy_section.addr + lazy_section.size
        return unless lazy_range.cover?(helper_lazy_address(bytes, offset, helper_section))

        return unless bind_offset < @command.lazy_bind_size

        { :offset => offset, :bind_offset => bind_offset, :size => 15 }
      end

      def helper_lazy_address(bytes, offset, helper_section)
        lea_offset = offset - 16
        lea = @macho.serialize.byteslice(lea_offset, 10)
        return nil unless lea.byteslice(0, 3) == X86_64_HELPER_PREFIX

        helper_section.addr + (offset - helper_section.offset) - 1 +
          lea.byteslice(3, 4).unpack1("l<")
      end

      def sections
        @sections ||= @macho.segments.flat_map(&:sections)
      end

      def add_x86_64_helper_patches(_delta = nil)
        @lazy_helpers.each do |helper|
          new_offset = @lazy_offsets.fetch(helper[:bind_offset], nil)
          next if new_offset.nil?

          patch_uint32(helper[:offset] + 14, new_offset, "lazy stub helper bind offset")
        end
      end

      def add_linkedit_offset_patches(delta)
        boundary = @stream_offset
        shift = ->(offset) { offset >= boundary ? offset + delta : offset }
        move_field_patch = true

        dyld_offsets = {
          :rebase_off => 8,
          :bind_off => 16,
          :weak_bind_off => 24,
          :lazy_bind_off => 32,
          :export_off => 40,
        }
        dyld_offsets.each do |field, relative_offset|
          offset = @command.public_send(field)
          next if offset.zero?

          shifted = shift.call(offset)
          if offset >= @stream_offset && offset < @stream_offset + @patches.first[:old_size]
            shifted = offset
          end
          patch_uint32(@command.view.offset + relative_offset, shifted, field.to_s)
        end

        size_offset = { :bind => 20, :weak_bind => 28, :lazy_bind => 36 }.fetch(@stream)
        patch_uint32(@command.view.offset + size_offset, @patches.first[:bytes].bytesize,
                     "#@stream stream size")

        @macho.load_commands.each do |command|
          next unless command.is_a?(LoadCommands::LinkeditDataCommand)

          unless command.dataoff.zero?
            shifted = move_field_patch && command.dataoff >= @stream_offset
            patch_uint32(command.view.offset + 8, shift.call(command.dataoff),
                         "linkedit data offset", :shift_with_stream => shifted)
          end
        end

        patch_symtab_offsets(shift, move_field_patch)
        patch_dysymtab_offsets(shift, move_field_patch)
        patch_linkedit_segment(delta)
      end

      def patch_symtab_offsets(shift, move_field_patch)
        command = @macho.command(:LC_SYMTAB).first
        return unless command

        { :symoff => 16, :stroff => 32 }.each do |field, relative_offset|
          offset = command.public_send(field)
          next if offset.zero?

          patch_uint32(command.view.offset + relative_offset, shift.call(offset), field.to_s,
                       :shift_with_stream => move_field_patch && offset >= @stream_offset)
        end
      end

      def patch_dysymtab_offsets(shift, move_field_patch)
        command = @macho.command(:LC_DYSYMTAB).first
        return unless command

        fields = {
          :tocoff => 24, :modtaboff => 32, :extrefsymoff => 40,
          :indirectsymoff => 48, :extreloff => 56, :locreloff => 64
        }
        fields.each do |field, relative_offset|
          offset = command.public_send(field)
          next if offset.zero?

          patch_uint32(command.view.offset + relative_offset, shift.call(offset), field.to_s,
                       :shift_with_stream => move_field_patch && offset >= @stream_offset)
        end
      end

      def patch_linkedit_segment(delta)
        linkedit = @macho.segments.find { |segment| segment.segname == "__LINKEDIT" }
        raise BindingError, "Mach-O has no __LINKEDIT segment" unless linkedit

        filesize = linkedit.filesize + delta
        raise BindingError, "negative __LINKEDIT segment size" if filesize.negative?

        if @macho.magic64?
          patch_uint64(linkedit.view.offset + 48, filesize, "__LINKEDIT filesize")
          if filesize > linkedit.vmsize
            vmsize = Utils.round(filesize, 2**@macho.segment_alignment)
            patch_uint64(linkedit.view.offset + 24, vmsize, "__LINKEDIT vmsize")
          end
        else
          patch_uint32(linkedit.view.offset + 36, filesize, "__LINKEDIT filesize")
          if filesize > linkedit.vmsize
            vmsize = Utils.round(filesize, 2**@macho.segment_alignment)
            patch_uint32(linkedit.view.offset + 28, vmsize, "__LINKEDIT vmsize")
          end
        end
      end

      def patch_uint32(offset, value, description, shift_with_stream: false)
        unless value >= 0 && value <= 0xffffffff
          raise BindingError, "#{description} does not fit in uint32"
        end

        @patches << { :kind => :uint32, :offset => offset, :value => value,
                      :shift_with_stream => shift_with_stream }
      end

      def patch_uint64(offset, value, description, shift_with_stream: false)
        unless value >= 0 && value <= 0xffffffffffffffff
          raise BindingError, "#{description} does not fit in uint64"
        end

        @patches << { :kind => :uint64, :offset => offset, :value => value,
                      :shift_with_stream => shift_with_stream }
      end

      def apply_patches
        data = @macho.serialize.dup
        byte_patches = @patches.select { |patch| patch[:kind] == :bytes }
        raise BindingError, "expected exactly one bind stream replacement" unless byte_patches.one?

        byte_patch = byte_patches.first
        @patches.each do |patch|
          next if patch[:kind] == :bytes

          size = patch[:kind] == :uint64 ? 8 : 4
          format = Utils.specialize_format(patch[:kind] == :uint64 ? "Q=" : "L=",
                                           @macho.endianness)
          data[patch[:offset], size] = [patch[:value]].pack(format)
        end
        suffix_offset = byte_patch[:offset] + byte_patch[:old_size]
        data = data.byteslice(0, byte_patch[:offset]) + byte_patch[:bytes] +
               data.byteslice(suffix_offset, data.bytesize - suffix_offset)

        validate_output(data)
        @macho.serialize.replace(data)
      end

      def validate_output(data)
        command_offset = @command.view.offset
        stream_offset = uint32_at(data, command_offset + stream_offset_field)
        stream_size = uint32_at(data, command_offset + stream_size_field)
        stream = data.byteslice(stream_offset, stream_size)
        Parser.new(stream, @stream, pointer_size).parse
        MachOFile.new_from_bin(data)
      end

      def stream_offset_field
        { :bind => 16, :weak_bind => 24, :lazy_bind => 32 }.fetch(@stream)
      end

      def stream_size_field
        { :bind => 20, :weak_bind => 28, :lazy_bind => 36 }.fetch(@stream)
      end

      def uint32_at(data, offset)
        data.byteslice(offset, 4).unpack1(Utils.specialize_format("L=", @macho.endianness))
      end

      def byte_patch_delta(patch)
        patch[:bytes].bytesize - patch[:old_size]
      end

      def pointer_size
        @macho.magic64? ? 8 : 4
      end
    end
  end
end
