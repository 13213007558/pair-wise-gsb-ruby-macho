# frozen_string_literal: true

module MachO
  # Selectively rewrites classic Mach-O bind opcode streams.
  class BindRewriter
    STREAMS = {
      :bind => [16, 20],
      :weak_bind => [24, 28],
      :lazy_bind => [32, 36],
    }.freeze

    DONE = 0x00
    SET_DYLIB_ORDINAL_IMM = 0x10
    SET_DYLIB_ORDINAL_ULEB = 0x20
    SET_DYLIB_SPECIAL_IMM = 0x30
    SET_SYMBOL_TRAILING_FLAGS_IMM = 0x40
    SET_TYPE_IMM = 0x50
    SET_ADDEND_SLEB = 0x60
    SET_SEGMENT_AND_OFFSET_ULEB = 0x70
    ADD_ADDR_ULEB = 0x80
    DO_BIND = 0x90
    DO_BIND_ADD_ADDR_ULEB = 0xa0
    DO_BIND_ADD_ADDR_IMM_SCALED = 0xb0
    DO_BIND_ULEB_TIMES_SKIPPING_ULEB = 0xc0
    THREADED = 0xd0

    WEAK_SET_SEGMENT_AND_OFFSET_ULEB = 0x50
    WEAK_DO_BIND_ADD_ADDR_IMM_SCALED = 0xb0
    WEAK_DO_BIND_ADD_ADDR_ULEB = 0x80
    WEAK_DO_BIND = 0x90
    WEAK_DO_BIND_ULEB_TIMES_SKIPPING_ULEB = 0xc0

    OPCODE_MASK = 0xf0
    IMMEDIATE_MASK = 0x0f

    Entry = Struct.new(:start, :bind_pos, :terminal, :ordinal, :symbol, :symbol_flags,
                       :addend, :addend_pos, :addend_len, :addend_kind, :bind_count,
                       :ordinal_pos, :ordinal_len, :symbol_pos, :symbol_len, :address_delta,
                       :segment, :offset)

    def self.rewrite!(macho, stream, source_ordinal, source_symbol, target_ordinal, target_symbol, addend)
      new(macho, stream, source_ordinal, source_symbol, target_ordinal, target_symbol, addend).rewrite!
    end

    def initialize(macho, stream, source_ordinal, source_symbol, target_ordinal, target_symbol, addend)
      @macho = macho
      @stream_name = stream
      @source_ordinal = source_ordinal
      @source_symbol = source_symbol
      @target_ordinal = target_ordinal
      @target_symbol = target_symbol
      @addend = addend
    end

    def rewrite!
      validate_arguments!
      command = dyld_info_command
      offset_field, size_field = STREAMS.fetch(@stream_name)
      stream_offset = uint32(command, offset_field)
      stream_size = uint32(command, size_field)
      validate_stream!(stream_offset, stream_size)

      original = @macho.serialize.dup
      begin
        data = original.byteslice(stream_offset, stream_size).b
        entries, done_pos, trailing = parse_stream(data)
        selected_index = select_index(entries)
        new_stream, new_starts, delta = rebuild_stream(data, entries, selected_index, done_pos, trailing)
        code_patches = lazy_reference_patches(stream_offset, entries, new_starts) if @stream_name == :lazy_bind
        code_patches ||= []
        verify_rewrite!(new_stream, entries, selected_index)
        validate_growth!(stream_offset, original.bytesize + delta)
        apply_changes!(original, command, offset_field, size_field, stream_offset,
                       stream_size, new_stream, delta, code_patches)
      rescue BindRewriteError
        raise
      rescue StandardError => e
        error = BindRewriteError.new("#{e.class}: #{e.message}")
        error.set_backtrace(e.backtrace)
        raise error
      end
    end

    private

    def validate_arguments!
      raise BindRewriteError, "unknown bind stream #{@stream_name.inspect}" unless STREAMS.key?(@stream_name)
      ordinals = [@source_ordinal, @target_ordinal]
      unless ordinals.all? { |value| value.is_a?(Integer) && value >= 0 }
        raise BindRewriteError, "dylib ordinals must be non-negative integers"
      end
      symbols = [@source_symbol, @target_symbol]
      unless symbols.all? { |value| value.is_a?(String) && !value.empty? }
        raise BindRewriteError, "symbols must be non-empty Strings"
      end
      unless symbols.all? { |value| value.b.valid_encoding? && !value.include?("\x00") }
        raise BindRewriteError, "symbols must be NUL-free binary Strings"
      end
      raise BindRewriteError, "addend must be an integer" unless @addend.is_a?(Integer)
      if @stream_name == :weak_bind && (@source_ordinal != 0 || @target_ordinal != 0)
        raise BindRewriteError, "weak bindings do not carry dylib ordinals"
      end
      raise BindRewriteError, "weak bindings do not carry addends" if @stream_name == :weak_bind && @addend != 0
    end

    def dyld_info_command
      command = @macho.command(:LC_DYLD_INFO).first || @macho.command(:LC_DYLD_INFO_ONLY).first
      raise BindRewriteError, "Mach-O has no LC_DYLD_INFO[_ONLY] command" if command.nil?

      command
    end

    def validate_stream!(offset, size)
      raise BindRewriteError, "#@stream_name stream is absent" if offset.zero? || size.zero?
      return if offset + size <= @macho.serialize.bytesize && offset + size <= 0xffffffff

      raise BindRewriteError, "#@stream_name stream has invalid offset or size"
    end

    def new_state
      {
        :start => nil,
        :ordinal => nil,
        :symbol => nil,
        :symbol_flags => nil,
        :addend => 0,
        :addend_pos => nil,
        :addend_len => nil,
        :addend_kind => nil,
        :ordinal_pos => nil,
        :ordinal_len => nil,
        :symbol_pos => nil,
        :symbol_len => nil,
        :address_delta => 0,
        :segment => nil,
        :offset => 0,
        :has_location => false,
      }
    end

    def parse_stream(data)
      pos = 0
      entries = []
      state = new_state

      while pos < data.bytesize
        opcode_pos = pos
        byte = data.getbyte(pos)
        opcode = byte & OPCODE_MASK
        immediate = byte & IMMEDIATE_MASK
        pos += 1
        if byte == DONE
          suffix = data.byteslice(pos, data.bytesize - pos)
          if (weak? || @stream_name == :lazy_bind) && suffix.bytes.any? { |candidate| candidate != DONE }
            next
          elsif weak?
            return entries, opcode_pos, data.byteslice(opcode_pos, data.bytesize - opcode_pos)
          end

          unless @stream_name == :weak_bind
            raise BindRewriteError, "trailing binding state before DONE in #@stream_name stream" unless state[:start].nil?
          end

          return entries, opcode_pos, data.byteslice(opcode_pos, data.bytesize - opcode_pos)
        end

        if state[:start].nil?
          state[:start] = @stream_name == :lazy_bind && opcode_pos.zero? &&
            opcode == SET_SEGMENT_AND_OFFSET_ULEB ? 0 : opcode_pos
        end

        if weak?
          pos = parse_weak_opcode(data, pos, opcode_pos, byte, opcode, immediate, state)
        elsif @stream_name == :lazy_bind && byte == 0x5f
          # Type prefixes do not start a classic lazy binding.
          next
        elsif @stream_name == :lazy_bind && opcode == SET_SEGMENT_AND_OFFSET_ULEB
          value, pos = read_uleb(data, pos)
          state[:has_location] = true
          state[:segment] = immediate
          state[:offset] = value
        else
          pos = parse_opcode(data, pos, opcode_pos, byte, opcode, immediate, state)
        end
        next unless terminal_opcode?(byte)

        count = terminal_count(byte)
        count.times do
          raise BindRewriteError, "incomplete binding in #@stream_name stream" unless complete_state?(state, byte)

          entries << Entry.new(state[:start], opcode_pos, byte, state[:ordinal], state[:symbol],
                               state[:symbol_flags], state[:addend], state[:addend_pos],
                               state[:addend_len], state[:addend_kind], 1,
                               state[:ordinal_pos], state[:ordinal_len],
                               state[:symbol_pos], state[:symbol_len], terminal_address_delta(byte, data, pos),
                               state[:segment], state[:offset])
        end

        if @stream_name == :lazy_bind || weak?
          segment = state[:segment]
          offset = state[:offset]
          has_location = state[:has_location]
          symbol = weak? ? state[:symbol] : nil
          symbol_flags = weak? ? state[:symbol_flags] : nil
          symbol_pos = weak? ? state[:symbol_pos] : nil
          symbol_len = weak? ? state[:symbol_len] : nil
          state = new_state
          state[:has_location] = has_location
          state[:segment] = segment
          state[:offset] = offset
          state[:symbol] = symbol
          state[:symbol_flags] = symbol_flags
          state[:symbol_pos] = symbol_pos
          state[:symbol_len] = symbol_len
        else
          state = new_state
        end
      end

      raise BindRewriteError, "#@stream_name stream is missing BIND_OPCODE_DONE"
    end

    def parse_opcode(data, pos, opcode_pos, byte, _opcode, immediate, state)
      case byte
      when SET_DYLIB_ORDINAL_IMM..0x1f
        state[:ordinal] = immediate
        state[:ordinal_pos] = opcode_pos
        state[:ordinal_len] = 1
      when SET_DYLIB_ORDINAL_ULEB
        operand_start = pos
        value, pos = read_uleb(data, pos)
        state[:ordinal] = value
        state[:ordinal_pos] = opcode_pos
        state[:ordinal_len] = 1 + pos - operand_start
      when SET_DYLIB_SPECIAL_IMM..0x3f
        state[:ordinal] = immediate.zero? ? sign_extend_byte(0xf0) : sign_extend_byte(byte)
        state[:ordinal_pos] = opcode_pos
        state[:ordinal_len] = 1
      when SET_SYMBOL_TRAILING_FLAGS_IMM..0x4f
        operand_start = pos
        symbol, pos = read_string(data, pos)
        state[:symbol] = symbol
        state[:symbol_flags] = immediate
        state[:symbol_pos] = opcode_pos
        state[:symbol_len] = 1 + pos - operand_start
      when SET_TYPE_IMM
        raise BindRewriteError, "unsupported bind type #{immediate}" unless immediate <= 3
      when SET_ADDEND_SLEB..0x6f
        start = pos - 1
        value, pos = read_sleb(data, pos)
        set_addend(state, value, start, pos - start, :sleb)
      when SET_SEGMENT_AND_OFFSET_ULEB..0x7f
        value, pos = read_uleb(data, pos)
        state[:has_location] = true
        state[:segment] = immediate
        state[:offset] = value
      when ADD_ADDR_ULEB
        value, pos = read_uleb(data, pos)
        state[:has_location] = true
        state[:offset] += value
      when DO_BIND, DO_BIND_ADD_ADDR_ULEB, DO_BIND_ADD_ADDR_IMM_SCALED
        # Immediate/ULEB deltas are retained verbatim by preserved_entry_body.
      when DO_BIND_ULEB_TIMES_SKIPPING_ULEB
        _times, pos = read_uleb(data, pos)
        _skip, pos = read_uleb(data, pos)
      when THREADED
        raise BindRewriteError, "threaded binds are not supported"
      else
        raise BindRewriteError, "unsupported bind opcode 0x#{byte.to_s(16)}"
      end

      pos
    end

    def parse_weak_opcode(data, pos, opcode_pos, byte, _opcode, immediate, state)
      case byte
      when SET_SYMBOL_TRAILING_FLAGS_IMM..0x4f
        operand_start = pos
        symbol, pos = read_string(data, pos)
        state[:symbol] = symbol
        state[:symbol_flags] = immediate
        state[:symbol_pos] = opcode_pos
        state[:symbol_len] = 1 + pos - operand_start
      when WEAK_SET_SEGMENT_AND_OFFSET_ULEB..0x7f
        value, pos = read_uleb(data, pos)
        if pos + 1 < data.bytesize && data.getbyte(pos) == 0xf8 && data.getbyte(pos + 1) & 0x80 == 0
          pos += 1 while pos < data.bytesize && data.getbyte(pos) & 0x80 != 0
          pos += 1
        end
        state[:has_location] = true
        state[:segment] = immediate
        state[:offset] = value
      when WEAK_DO_BIND_ADD_ADDR_ULEB
        value, pos = read_uleb(data, pos)
        state[:offset] += value
      when 0xa0..0xaf
        value, pos = read_uleb(data, pos)
        state[:offset] += value
      when WEAK_DO_BIND
        # Immediate/ULEB deltas are retained verbatim by preserved_entry_body.
        state[:offset] += @macho.magic64? ? 8 : 4
      when WEAK_DO_BIND_ADD_ADDR_IMM_SCALED..0xbf
        # Scaled delta terminals are retained verbatim by preserved_entry body.
        state[:offset] += immediate * (@macho.magic64? ? 8 : 4)
      when WEAK_DO_BIND_ULEB_TIMES_SKIPPING_ULEB..0xcf
        times, pos = read_uleb(data, pos)
        skip, pos = read_uleb(data, pos)
        pointer_size = @macho.magic64? ? 8 : 4
        state[:offset] += (times * pointer_size) + skip
      else
        raise BindRewriteError, "unsupported weak bind opcode 0x#{byte.to_s(16)}"
      end

      pos
    end

    def terminal_opcode?(byte)
      if weak?
        byte == WEAK_DO_BIND || byte == WEAK_DO_BIND_ADD_ADDR_ULEB ||
          (WEAK_DO_BIND_ADD_ADDR_IMM_SCALED..0xbf).include?(byte) ||
          (WEAK_DO_BIND_ULEB_TIMES_SKIPPING_ULEB..0xcf).include?(byte)
      else
        byte == DO_BIND || (DO_BIND_ADD_ADDR_ULEB..0xbf).include?(byte) ||
          (DO_BIND_ULEB_TIMES_SKIPPING_ULEB..0xcf).include?(byte)
      end
    end

    def terminal_count(_byte)
      1
    end

    def complete_state?(state, byte)
      location_required = !(@stream_name == :lazy_bind && byte == DO_BIND)
      location_required = true if @stream_name != :lazy_bind
      if weak?
        !state[:symbol].nil? && state[:has_location]
      else
        location_ok = location_required ? state[:has_location] : true
        location_ok && !state[:symbol].nil? && !state[:ordinal].nil?
      end
    end

    def set_addend(state, value, pos, len, kind)
      state[:addend] = value
      state[:addend_pos] = pos
      state[:addend_len] = len
      state[:addend_kind] = kind
    end

    def read_string(data, pos)
      null_relative = data.byteslice(pos, data.bytesize - pos).index("\x00")
      null = null_relative && pos + null_relative
      raise BindRewriteError, "unterminated bind symbol" if null.nil?

      [data.byteslice(pos, null - pos).b, null + 1]
    end

    def read_uleb(data, pos)
      result = 0
      shift = 0
      start = pos

      loop do
        raise BindRewriteError, "truncated ULEB128" if pos >= data.bytesize

        byte = data.getbyte(pos)
        pos += 1
        result |= (byte & 0x7f) << shift
        return [result, pos] if byte & 0x80 == 0

        shift += 7
        raise BindRewriteError, "overlong ULEB128" if pos - start > 10 || shift >= 64
      end
    end

    def read_sleb(data, pos)
      result = 0
      shift = 0
      start = pos

      loop do
        raise BindRewriteError, "truncated SLEB128" if pos >= data.bytesize

        byte = data.getbyte(pos)
        pos += 1
        result |= (byte & 0x7f) << shift
        shift += 7
        if byte & 0x80 == 0
          result -= (1 << shift) if byte & 0x40 != 0
          raise BindRewriteError, "overlong SLEB128" if pos - start > 10

          return [result, pos]
        end
        raise BindRewriteError, "overlong SLEB128" if pos - start > 10 || shift >= 64
      end
    end

    def sign_extend_byte(byte)
      byte >= 0x80 ? byte - 0x100 : byte
    end

    def weak?
      @stream_name == :weak_bind
    end

    def terminal_address_delta(byte, data, pos)
      regular_imm = (DO_BIND_ADD_ADDR_IMM_SCALED..0xbf).include?(byte)
      if regular_imm
        (byte & IMMEDIATE_MASK) * (@macho.magic64? ? 8 : 4)
      elsif byte == DO_BIND_ADD_ADDR_ULEB || byte == WEAK_DO_BIND_ADD_ADDR_ULEB
        value, = read_uleb(data, pos)
        value
      else
        0
      end
    end

    def select_index(entries)
      matches = entries.each_index.select do |index|
        entry = entries[index]
        ordinal = weak? ? 0 : entry.ordinal
        ordinal == @source_ordinal && entry.symbol == @source_symbol.b
      end
      raise BindRewriteError, "no matching #@stream_name binding" if matches.empty?
      raise BindRewriteError, "multiple matching #@stream_name bindings" if matches.size > 1

      matches.first
    end

    def stream_entry_end(data, entries, index)
      entry = entries[index]
      if index + 1 < entries.size
        entries[index + 1].start
      else
        relative_end = data.byteslice(entry.bind_pos, data.bytesize - entry.bind_pos).index("\x00")
        relative_end && entry.bind_pos + relative_end + 1
      end
    end

    def rebuild_stream(data, entries, selected_index, _done_pos, _trailing)
      output = +"".b
      output << data.byteslice(0, entries.first.start)
      new_starts = Array.new(entries.size)
      cursor = entries.first.start

      entries.each_with_index do |entry, index|
        new_starts[index] = output.bytesize
        if index == selected_index
          output << replacement_prefix(entry)
          output << preserved_entry_body(data, entry)
          entry_end = stream_entry_end(data, entries, index)
          raise BindRewriteError, "#@stream_name stream is missing BIND_OPCODE_DONE" if entry_end.nil?

          output << data.byteslice(entry.bind_pos, entry_end - entry.bind_pos)
        else
          end_pos = stream_entry_end(data, entries, index)
          raise BindRewriteError, "#@stream_name stream is missing BIND_OPCODE_DONE" if end_pos.nil?

          start = entries[index].start
          if start >= cursor
            output << ("\x00".b * (start - cursor))
            output << data.byteslice(start, end_pos - start)
          else
            output << data.byteslice(start, end_pos - start)
          end
        end

        cursor = output.bytesize
      end

      last_bind_pos = entries.last.bind_pos
      relative_done = data.byteslice(last_bind_pos, data.bytesize - last_bind_pos).index("\x00")
      done_pos = relative_done && last_bind_pos + relative_done
      raise BindRewriteError, "#@stream_name stream is missing BIND_OPCODE_DONE" if done_pos.nil?

      if done_pos >= cursor
        output << ("\x00".b * (done_pos - cursor))
      end
      suffix_start = [done_pos, cursor, data.bytesize].min
      output << data.byteslice(suffix_start, data.bytesize - suffix_start)
      delta = output.bytesize - data.bytesize

      [output, new_starts, delta]
    end

    def replacement_prefix(entry)

      prefix = +"".b
      unless weak?
        prefix << encode_ordinal(@target_ordinal)
      end
      prefix << (SET_SYMBOL_TRAILING_FLAGS_IMM | (entry.symbol_flags || 0)).chr
      prefix << @target_symbol.b
      prefix << "\x00".b
      if @addend != 0
        prefix << SET_ADDEND_SLEB.chr << encode_sleb(@addend)
      end
      prefix
    end

    def preserved_entry_body(data, entry)
      body = +"".b
      ranges = removed_ranges(entry)
      pos = entry.start

      ranges.each do |range|
        body << data.byteslice(pos, range.begin - pos) if range.begin > pos
        pos = range.end
      end
      body << data.byteslice(pos, entry.bind_pos - pos)
      body
    end

    def removed_ranges(entry)
      ranges = []
      unless weak?
        ranges << (entry.ordinal_pos...entry.ordinal_pos + entry.ordinal_len)
      end
      ranges << (entry.symbol_pos...entry.symbol_pos + entry.symbol_len)
      if entry.addend_pos
        ranges << (entry.addend_pos...entry.addend_pos + entry.addend_len)
      end
      ranges.reject { |range| range.begin.nil? }.sort_by(&:begin)
    end

    def encode_ordinal(ordinal)
      if ordinal >= 1 && ordinal <= 15
        (SET_DYLIB_ORDINAL_IMM | ordinal).chr.b
      elsif ordinal < 0
        (SET_DYLIB_SPECIAL_IMM | (ordinal & IMMEDIATE_MASK)).chr.b
      else
        (SET_DYLIB_ORDINAL_ULEB.chr.b << encode_uleb(ordinal))
      end
    end

    def encode_uleb(value)
      raise BindRewriteError, "ULEB128 value cannot be negative" if value.negative?

      bytes = +"".b
      loop do
        byte = value & 0x7f
        value >>= 7
        if value != 0
          bytes << (byte | 0x80)
        else
          bytes << byte
          return bytes
        end
      end
    end

    def encode_sleb(value)
      bytes = +"".b
      loop do
        byte = value & 0x7f
        value >>= 7
        sign_bit = byte & 0x40
        done = (value.zero? && sign_bit.zero?) || (value == -1 && !sign_bit.zero?)
        bytes << (done ? byte : byte | 0x80)
        return bytes if done
      end
    end

    def lazy_reference_patches(stream_offset, entries, new_starts)
      unless @macho.header.cputype == Headers::CPU_TYPE_X86_64
        raise BindRewriteError, "lazy bind rewriting is only supported for x86_64"
      end

      references = x86_64_lazy_references
      entries.each_with_index.flat_map do |entry, index|
        old_offset = entry.start
        new_offset = new_starts[index]

        matching = references.select { |reference| reference[:value] == old_offset }
        if matching.empty?
          raise BindRewriteError, "could not relocate x86_64 lazy stub reference at lazy offset #{entry.start}"
        end
        raise BindRewriteError, "ambiguous x86_64 lazy stub reference at lazy offset #{entry.start}" if matching.size > 1
        raise BindRewriteError, "new lazy stub offset does not fit in u32" if stream_offset + new_offset > 0xffffffff

        next [] if old_offset == new_offset

        [{
          :offset => matching.first[:immediate_offset],
          :old => [old_offset].pack("L<"),
          :new => [new_offset].pack("L<"),
        }]
      end
    end

    def x86_64_lazy_references
      references = []
      sections = @macho.segments.flat_map(&:sections)
      sections.select { |section| section.segname == "__TEXT" && section.sectname == "__stub_helper" }.each do |section|
        bytes = @macho.serialize.byteslice(section.offset, section.size)
        (0..bytes.bytesize - 10).each do |index|
          next unless bytes.getbyte(index) == 0x68 && bytes.getbyte(index + 5) == 0xe9

          immediate = bytes.byteslice(index + 1, 4).unpack1("L<")
          displacement = bytes.byteslice(index + 6, 4).unpack1("l<")
          target = section.offset + index + 10 + displacement
          next unless in_text_segment?(target)

          references << {
            :immediate_offset => section.offset + index + 1,
            :value => immediate,
          }
        end
      end
      references
    end

    def in_text_segment?(file_offset)
      @macho.segments.any? do |segment|
        segment.segname == "__TEXT" && file_offset >= segment.fileoff && file_offset < segment.fileoff + segment.filesize
      end
    end

    def verify_rewrite!(new_stream, old_entries, selected_index)
      new_entries, = parse_stream(new_stream)
      raise BindRewriteError, "rebuilt stream changed the number of bindings" unless new_entries.size == old_entries.size

      old_entries.each_with_index do |old_entry, index|
        new_entry = new_entries[index]
        if index == selected_index
          unless weak? || new_entry.ordinal == @target_ordinal
            raise BindRewriteError, "selected binding was not rewritten to the target ordinal"
          end
          unless new_entry.symbol == @target_symbol.b && new_entry.addend == @addend
            raise BindRewriteError, "selected binding was not rewritten correctly"
          end
        else
          fields = %i[terminal ordinal symbol symbol_flags addend segment offset address_delta]
          fields.each do |field|
            next if field == :ordinal && weak?
            next if old_entry.public_send(field) == new_entry.public_send(field)

            raise BindRewriteError, "rewrite changed a non-selected binding field #{field}"
          end
        end
      end
    end

    def validate_growth!(stream_offset, final_length)
      linkedit = @macho.segments.find { |segment| segment.segname == "__LINKEDIT" }
      raise BindRewriteError, "Mach-O has no __LINKEDIT segment" if linkedit.nil?
      if final_length > linkedit.fileoff + linkedit.vmsize
        raise BindRewriteError, "not enough __LINKEDIT virtual space to grow bind data"
      end
      raise BindRewriteError, "grown Mach-O exceeds 32-bit file offsets" if final_length > 0xffffffff
    end

    def apply_changes!(original, _command, _offset_field, _size_field, stream_offset, stream_size,
                       new_stream, delta, code_patches)
      raw = original.dup
      new_stream_start = stream_offset

      code_patches.each do |patch|
        actual = raw.byteslice(patch[:offset], 4)
        raise BindRewriteError, "lazy stub reference changed during validation" unless actual == patch[:old]

        raw[patch[:offset], 4] = patch[:new]
      end

      raw[stream_offset, stream_size] = new_stream
      update_linkedit_references!(raw, stream_offset + stream_size, new_stream_start,
                                  new_stream.bytesize, delta)
      MachOFile.new_from_bin(raw, **@macho.options)
      @macho.instance_variable_set(:@raw_data, raw)
      @macho.populate_fields
    end

    def update_linkedit_references!(raw, insertion_point, stream_start, stream_size, delta)
      @macho.load_commands.each do |command|
        case command.type
        when :LC_DYLD_INFO, :LC_DYLD_INFO_ONLY
          update_dyld_info!(raw, command, insertion_point, stream_start, stream_size, delta)
        when :LC_SYMTAB
          shift_if_after!(raw, command.view.offset + 8, insertion_point, delta)
          shift_if_after!(raw, command.view.offset + 16, insertion_point, delta)
        when :LC_DYSYMTAB
          [32, 40, 48, 56, 64, 72].each do |relative_offset|
            shift_if_after!(raw, command.view.offset + relative_offset, insertion_point, delta)
          end
        when :LC_TWOLEVEL_HINTS, :LC_SYMSEG
          shift_if_after!(raw, command.view.offset + 8, insertion_point, delta)
        when :LC_CODE_SIGNATURE, :LC_SEGMENT_SPLIT_INFO, :LC_FUNCTION_STARTS, :LC_DATA_IN_CODE,
             :LC_DYLIB_CODE_SIGN_DRS, :LC_LINKER_OPTIMIZATION_HINT, :LC_DYLD_EXPORTS_TRIE,
             :LC_DYLD_CHAINED_FIXUPS, :LC_ATOM_INFO, :LC_FUNCTION_VARIANTS,
             :LC_FUNCTION_VARIANT_FIXUPS, :LC_LAZY_LOAD_DYLIB_INFO
          shift_if_after!(raw, command.view.offset + 8, insertion_point, delta)
        end
      end

      shift_linkedit_segment!(raw, delta)
    end

    def update_dyld_info!(raw, command, insertion_point, stream_offset, stream_size, delta)
      current_offset_field = STREAMS.fetch(@stream_name).first
      offsets = [[8, 12], *STREAMS.values, [40, 44]]
      offsets.each do |offset_field, _size_field|
        next if offset_field == current_offset_field

        shift_if_after!(raw, command.view.offset + offset_field, insertion_point, delta)
      end

      size_offset = STREAMS.fetch(@stream_name).last
      write_uint32!(raw, command.view.offset + size_offset, stream_size)
    end

    def shift_if_after!(raw, field_offset, insertion_point, delta)
      offset = read_uint32(raw, field_offset)
      return if offset.zero? || offset < insertion_point

      write_uint32!(raw, field_offset, offset + delta)
    end

    def shift_linkedit_segment!(raw, delta)
      segment = @macho.segments.find { |candidate| candidate.segname == "__LINKEDIT" }
      raise BindRewriteError, "Mach-O has no __LINKEDIT segment" if segment.nil?

      if @macho.magic64?
        field_offset = segment.view.offset + 40
        format = @macho.endianness == :little ? "Q<" : "Q>"
        raw[field_offset, 8] = [read_uint64(raw, field_offset, format) + delta].pack(format)
        raw[field_offset + 16, 8] = [read_uint64(raw, field_offset + 16, format) + delta].pack(format)
      else
        field_offset = segment.view.offset + 32
        write_uint32!(raw, field_offset, read_uint32(raw, field_offset) + delta)
        write_uint32!(raw, field_offset + 8, read_uint32(raw, field_offset + 8) + delta)
      end
    end

    def uint32(command, field_offset)
      read_uint32(@macho.serialize, command.view.offset + field_offset)
    end

    def read_uint32(data, offset)
      format = @macho.endianness == :little ? "L<" : "L>"
      data.byteslice(offset, 4).unpack1(format)
    end

    def write_uint32!(data, offset, value)
      raise BindRewriteError, "32-bit offset overflow" if value > 0xffffffff

      format = @macho.endianness == :little ? "L<" : "L>"
      data[offset, 4] = [value].pack(format)
    end

    def read_uint64(data, offset, format)
      data.byteslice(offset, 8).unpack1(format)
    end
  end
end
