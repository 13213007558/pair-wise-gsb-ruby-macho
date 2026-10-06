# frozen_string_literal: true

require "zlib"

module ChainedFixupsFixtures
  # Builds tiny arm64 Mach-O files carrying an LC_DYLD_CHAINED_FIXUPS payload.
  # Every byte is synthesized in memory so tests don't depend on the host
  # toolchain or a running process.
  class MachOBuilder
    LC_SEGMENT_64 = 0x19
    LC_DYLD_CHAINED_FIXUPS = 0x80000034
    LC_LOAD_DYLIB = 0xC
    MH_MAGIC_64 = 0xFEEDFACF
    PAGE = 0x4000
    SEGMENT_RECORD_FIXED = 22

    attr_reader :raw

    def initialize(pointer_format:, imports_format: 1, compressed_symbols: false)
      @pointer_format = pointer_format
      @imports_format = imports_format
      @compressed_symbols = compressed_symbols
      @pointers = {}
      @imports = []
      @multi_starts = {}
      @explicit_page_starts = nil
      @dylibs = ["@rpath/libdep.dylib"]
      @mutations = []
    end

    def pointer(offset, raw)
      @pointers[offset] = raw
      self
    end

    def import(name, ordinal: 1, weak: false, addend: nil)
      @imports << { :name => name, :ordinal => ordinal, :weak => weak, :addend => addend }
      self
    end

    def dylibs(paths)
      @dylibs = paths
      self
    end

    def page_starts(values)
      @explicit_page_starts = values
      self
    end

    def multi_start(page_index, entries)
      @multi_starts[page_index] = entries
      self
    end

    def mutate(&block)
      @mutations << block
      self
    end

    def build!
      symbols_blob, symbol_offsets = build_symbol_pool
      imports_blob = build_imports_blob(symbol_offsets)
      seg_record, page_count = build_segment_record
      starts_in_image = build_starts_in_image(seg_record)
      header = build_fixup_header(starts_in_image, imports_blob, symbols_blob)
      blob = header + starts_in_image + imports_blob + symbols_blob

      data_page = build_data_page
      cmds = build_load_commands(blob.bytesize)
      mach_header = build_mach_header(cmds.bytesize)
      mach_header[16, 4] = u32(count_load_commands)
      @raw = ((mach_header + cmds).ljust(PAGE, "\0".b) + data_page +
              blob.ljust(PAGE, "\0".b))
      @mutations.each { |mutation| mutation.call(@raw) }
      MachO::MachOFile.new_from_bin(@raw.b)
    end

    # -- pointer encoders --------------------------------------------------

    def rebase64(target:, next_step: 0, high8: 0)
      (target & 0xFFFFFFFFF) | ((high8 & 0xFF) << 36) | (next_step << 52)
    end

    def bind64(ordinal:, addend: 0, next_step: 0)
      (1 << 63) | (ordinal & 0xFFFFFF) | ((addend & 0xFF) << 24) | (next_step << 52)
    end

    def userland_rebase(target:, next_step: 0, high8: 0)
      (target & 0x7FFFFFFFFFF) | ((high8 & 0xFF) << 43) | (next_step << 52)
    end

    def userland_auth_rebase(target:, diversity:, key:, addr_div:, next_step: 0)
      (1 << 62) | (target & 0xFFFFFFFF) | ((diversity & 0xFFFF) << 32) |
        ((addr_div ? 1 : 0) << 48) | ((key & 3) << 49) | (next_step << 52)
    end

    def userland_bind(ordinal:, addend: 0, next_step: 0)
      (1 << 63) | (ordinal & 0xFFFF) | ((addend & 0x7FFFF) << 32) | (next_step << 52)
    end

    def userland_auth_bind(ordinal:, diversity:, key:, addr_div:, next_step: 0)
      (1 << 63) | (1 << 62) | (ordinal & 0xFFFF) |
        ((diversity & 0xFFFF) << 32) | ((addr_div ? 1 : 0) << 48) |
        ((key & 3) << 49) | (next_step << 52)
    end

    private

    def u16(value); [value].pack("S<"); end
    def u32(value); [value].pack("L<"); end
    def u64(value); [value].pack("Q<"); end
    def i32(value); [value].pack("l<"); end
    def i64(value); [value].pack("q<"); end

    def count_load_commands
      @dylibs.size + 4 # three LC_SEGMENT_64 and one LC_DYLD_CHAINED_FIXUPS
    end

    def build_mach_header(sizeofcmds)
      [
        MH_MAGIC_64,
        0x0100000C, # cputype CPU_TYPE_ARM64
        2,           # cpusubtype CPU_SUBTYPE_ARM64_ALL
        6,           # filetype MH_DYLIB
        0,           # ncmds (patched after load commands are built)
        sizeofcmds,
        0x85,
        0,
        0,
      ].pack("L<l<L<L<L<L<L<L<")
    end

    def build_load_commands(fixup_size)
      cmds = +"".b
      @dylibs.each { |path| cmds << dylib_command(path) }
      cmds << segment_command("__TEXT", 0, 0, PAGE)
      cmds << segment_command("__DATA", PAGE, PAGE, PAGE)
      cmds << segment_command("__LINKEDIT", 2 * PAGE, 2 * PAGE, fixup_size)
      cmds << u32(LC_DYLD_CHAINED_FIXUPS) + u32(16) +
             u32(2 * PAGE) + u32(fixup_size)
      cmds
    end

    def dylib_command(path)
      name = path.b + "\0".b
      cmdsize = 24 + name.bytesize
      padding = (4 - (cmdsize % 4)) % 4
      u32(LC_LOAD_DYLIB) + u32(cmdsize + padding) + u32(24) +
        u32(2) + u32(0) + u32(0) + name + ("\0".b * padding)
    end

    def segment_command(name, vmaddr, fileoff, filesize)
      u32(LC_SEGMENT_64) + u32(72) + name.b.ljust(16, "\0".b) +
        u64(vmaddr) + u64(filesize) + u64(fileoff) + u64(filesize) +
        u32(7) + u32(7) + u32(0) + u32(0)
    end

    def build_data_page
      page = "\0".b * PAGE
      @pointers.each do |offset, raw|
        if offset + 8 > PAGE
          raise "pointer offset #{offset} outside data page"
        end
        page[offset, 8] = u64(raw)
      end
      page
    end

    def build_symbol_pool
      offsets = {}
      pool = +"".b
      @imports.each do |imp|
        next if offsets.key?(imp[:name])
        offsets[imp[:name]] = pool.bytesize
        pool << imp[:name].b << "\0".b
      end
      stored = @compressed_symbols ? Zlib.deflate(pool) : pool
      [stored, offsets]
    end

    def build_imports_blob(symbol_offsets)
      blob = +"".b
      @imports.each do |imp|
        name_offset = symbol_offsets.fetch(imp[:name])
        weak = imp[:weak] ? 1 : 0
        case @imports_format
        when 1
          packed = (imp[:ordinal] & 0xFF) | (weak << 8) | (name_offset << 9)
          blob << u32(packed)
        when 2
          packed = (imp[:ordinal] & 0xFF) | (weak << 8) | (name_offset << 9)
          blob << u32(packed) << i32(imp.fetch(:addend, 0))
        when 3
          first = (imp[:ordinal] & 0xFFFF) | (weak << 16) | (name_offset << 32)
          blob << u64(first) << i64(imp.fetch(:addend, 0))
        end
      end
      blob
    end

    def build_segment_record
      overflow_blob = +"".b
      page_starts = resolve_page_starts(overflow_blob)
      page_count = page_starts.size
      page_starts_blob = page_starts.map { |start| u16(start) }.join
      size = SEGMENT_RECORD_FIXED + page_starts_blob.bytesize + overflow_blob.bytesize

      record = +"".b
      record << u32(size) << u16(PAGE) << u16(@pointer_format)
      record << u64(PAGE) << u32(0) << u16(page_count)
      record << page_starts_blob << overflow_blob
      [record, page_count]
    end

    def resolve_page_starts(overflow_blob)
      if @explicit_page_starts
        return @explicit_page_starts.map { |value| value & 0xFFFF }
      end

      page_indices = @pointers.keys.map { |offset| offset / PAGE }
      page_indices.concat(@multi_starts.keys)
      page_count = page_indices.empty? ? 1 : page_indices.max + 1
      starts = Array.new(page_count, 0xFFFF)

      @pointers.keys.group_by { |offset| offset / PAGE }.each do |page, offsets|
        starts[page] = offsets.min % PAGE unless @multi_starts.key?(page)
      end

      @multi_starts.each do |page, entries|
        overflow_offset = SEGMENT_RECORD_FIXED + (2 * starts.size) + overflow_blob.bytesize
        starts[page] = 0x8000 | overflow_offset
        tagged = entries.dup
        tagged[-1] = tagged[-1] | 0x8000 unless tagged.empty?
        tagged.each { |entry| overflow_blob << u16(entry) }
      end
      starts
    end

    def build_starts_in_image(seg_record)
      # Three segments (__TEXT, __DATA, __LINKEDIT); only __DATA (index 1)
      # carries chain starts.
      seg_info_offset = 4 + (4 * 3)
      u32(3) + u32(0) + u32(seg_info_offset) + u32(0) + seg_record
    end

    def build_fixup_header(starts_in_image, imports_blob, symbols_blob)
      starts_offset = 28
      imports_offset = starts_offset + starts_in_image.bytesize
      symbols_offset = imports_offset + imports_blob.bytesize
      u32(0) << u32(starts_offset) << u32(imports_offset) <<
        u32(symbols_offset) << u32(@imports.size) <<
        u32(@imports_format) << u32(@compressed_symbols ? 1 : 0)
    end
  end
end
