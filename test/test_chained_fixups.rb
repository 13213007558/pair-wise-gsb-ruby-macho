# frozen_string_literal: true

require_relative "helpers"

class ChainedFixupsTest < Minitest::Test
  include Helpers

  PAGE = 0x4000
  LC_SEGMENT_64 = 0x19
  LC_DYLD_CHAINED_FIXUPS = 0x80000034

  # A minimal little-endian arm64 Mach-O assembled byte by byte. Layout:
  #   __TEXT     [vmaddr 0x100000000, file 0,          one page]
  #   __DATA     [vmaddr 0x100004000, file 0x4000,     `data_pages` pages]
  #   __LINKEDIT [file 0x4000 + data_pages * page,    0x1000]
  class FakeMachO
    HEADER_SIZE = 32
    SEGMENT_LC_SIZE = 72
    FIXUPS_LC_SIZE = 16

    def initialize(data_pages: 2, page_size: PAGE, linkedit_size: 0x1000)
      @page_size = page_size
      @text_size = page_size
      @data_size = data_pages * page_size
      @linkedit_size = linkedit_size
      @data = +"\0".b * (@text_size + @data_size + linkedit_size)
      @payload = nil
    end

    # Writes a raw 64-bit chained pointer into `__DATA` (page is relative to
    # the start of `__DATA`).
    def set_slot(page, offset, value)
      pos = @text_size + (page * @page_size) + offset
      @data[pos, 8] = [value].pack("Q<")
    end

    def payload=(payload)
      raise "payload too large" if payload.bytesize > @linkedit_size

      @payload = payload
    end

    def file
      MachO::MachOFile.new_from_bin(bin)
    end

    private

    def bin
      raise "payload not set" unless @payload

      data = @data.dup
      fixups_off = @text_size + @data_size
      data[fixups_off, @payload.bytesize] = @payload

      segments = [
        segment_lc("__TEXT", 0x100000000, @text_size, 0, @text_size),
        segment_lc("__DATA", 0x100000000 + @text_size, @data_size, @text_size, @data_size),
      ]
      ncmds = segments.length + 1
      cmds_size = segments.sum(&:bytesize) + FIXUPS_LC_SIZE
      header = [0xfeedfacf, 0x0100000c, 0, 6, ncmds, cmds_size,
                0, 0].pack("L<8")
      cmds = segments.join + fixups_lc(fixups_off)
      raise "load commands overflow page" if HEADER_SIZE + cmds.bytesize > @page_size

      header + cmds + data[HEADER_SIZE + cmds.bytesize..]
    end

    def segment_lc(name, vmaddr, vmsize, fileoff, filesize)
      [LC_SEGMENT_64, SEGMENT_LC_SIZE].pack("L<2") + name.ljust(16, "\0") +
        [vmaddr, vmsize, fileoff, filesize, 7, 3, 0, 0].pack("Q<4L<4")
    end

    def fixups_lc(fixups_off)
      [LC_DYLD_CHAINED_FIXUPS, FIXUPS_LC_SIZE, fixups_off,
       @payload.bytesize].pack("L<4")
    end
  end

  # --- raw pointer encoders (see mach-o/fixup-chains.h) --------------------

  def ptr64_rebase(target_low36:, high8: 0, next_offset: 0)
    target = (target_low36 & 0xfffffffff) | ((high8 & 0xff) << 36)
    (target << 12) | (((next_offset / 4) & 0xfff) << 52)
  end

  def ptr64_bind(ordinal:, addend: 0, next_offset: 0)
    (1 << 63) | ((ordinal & 0xffffff) << 12) | ((addend & 0xff) << 36) |
      ((((next_offset / 4) & 0xfff)) << 52)
  end

  def u9_rebase(target_low43:, high8: 0, next_offset: 0)
    (target_low43 & 0x7ffffffffff) | (high8 << 43) |
      (((next_offset / 8) & 0x7ff) << 51)
  end

  def u9_bind(ordinal:, addend:, next_offset: 0)
    (1 << 63) | ((((next_offset / 8) & 0x7ff) << 51)) |
      ((addend & 0x7ffff) << 32) | (ordinal & 0xffff)
  end

  def u9_auth_rebase(target_runtime:, diversity:, key:, addr_div:,
                     next_offset: 0)
    (1 << 62) | ((((next_offset / 8) & 0x7ff) << 51)) |
      (key << 49) | ((addr_div & 1) << 48) | ((diversity & 0xffff) << 32) |
      (target_runtime & 0xffffffff)
  end

  def u9_auth_bind(ordinal:, diversity:, key:, addr_div:, next_offset: 0)
    (1 << 63) | (1 << 62) | ((((next_offset / 8) & 0x7ff) << 51)) |
      (key << 49) | ((addr_div & 1) << 48) | ((diversity & 0xffff) << 32) |
      (ordinal & 0xffff)
  end

  def build(builder, data_pages: nil)
    data_pages = builder.data_pages if data_pages.nil?
    fake = FakeMachO.new(:data_pages => data_pages)
    yield fake
    fake.payload = builder.build
    fake.file
  end

  # --- tests --------------------------------------------------------------

  def test_absent_payload_is_nil
    fake = FakeMachO.new
    fake.payload = PayloadBuilder.new.build
    file = fake.file
    refute_nil file.chained_fixups
  end

  def test_payload_outside_image_raises
    builder = PayloadBuilder.new(:data_pages => 1)
    builder.set_page_start(0, 0x000)
    payload = builder.build
    fake = FakeMachO.new(:data_pages => 1)
    fake.payload = payload
    file = fake.file
    # Corrupt the load command's dataoff to point past the image.
    lc = file[:LC_DYLD_CHAINED_FIXUPS].first
    file.serialize
    raw = file.instance_variable_get(:@raw_data)
    # dataoff is the first u32 in the linkedit_data_command payload.
    lc_offset = lc.view.offset
    raw[lc_offset + 8, 4] = [raw.bytesize + 0x100].pack("L<")
    error = assert_raises MachO::ChainedFixupError do
      MachO::MachOFile.new_from_bin(raw).chained_fixups
    end
    assert_match(/points outside the image/, error.message)
  end

  def test_ptr64_rebase_and_bind
    builder = PayloadBuilder.new(:pointer_format => 2, :data_pages => 2)
    builder.add_symbol("_foo")
    builder.add_compact_import("_foo", :lib => 0)
    builder.set_page_start(0, 0x010)

    file = build(builder) do |fake|
      fake.set_slot(0, 0x010, ptr64_rebase(:target_low36 => 0x23000,
                                          :next_offset => 0x020))
      fake.set_slot(0, 0x020, ptr64_bind(:ordinal => 0, :addend => 7))
    end
    rebase_f, bind_f = file.chained_fixups.to_a

    assert_equal :rebase, rebase_f.kind
    assert_equal :DYLD_CHAINED_PTR_64, rebase_f.pointer_format
    assert_equal 0x4010, rebase_f.file_offset
    assert_equal 0x4010, rebase_f.runtime_offset
    assert_equal 0x100000000 + 0x23000, rebase_f.target_vmaddr
    assert_equal 0x23000, rebase_f.target_runtime_offset
    assert_equal 0, rebase_f.high8

    assert_equal :bind, bind_f.kind
    assert_equal 0x4020, bind_f.file_offset
    assert_equal 0x4020, bind_f.runtime_offset
    assert_equal "_foo", bind_f.symbol
    assert_equal 0, bind_f.ordinal
    assert_equal 7, bind_f.addend
    refute bind_f.authenticated
  end

  def test_ptr64_offset_rebase_is_image_relative
    builder = PayloadBuilder.new(:imports_format => 2,
                                 :pointer_format => 6, :data_pages => 2)
    builder.add_symbol("_bar")
    builder.add_import("_bar", :addend => -16)
    builder.set_page_start(1, 0x040)

    file = build(builder) do |fake|
      fake.set_slot(1, 0x040,
                    ptr64_rebase(:target_low36 => 0xabcd, :next_offset => 0x050))
      fake.set_slot(1, 0x050, ptr64_bind(:ordinal => 0))
    end
    rebase_f, bind_f = file.chained_fixups.to_a

    assert_equal :DYLD_CHAINED_PTR_64_OFFSET, rebase_f.pointer_format
    assert_nil rebase_f.target_vmaddr
    assert_equal 0xabcd, rebase_f.target_runtime_offset
    assert_equal 2 * PAGE + 0x40, rebase_f.runtime_offset
    assert_equal 2 * PAGE + 0x40, rebase_f.file_offset

    assert_equal :bind, bind_f.kind
    assert_equal -16, bind_f.addend
  end

  def test_import_addend64_weak
    builder = PayloadBuilder.new(:imports_format => 3,
                                 :pointer_format => 2)
    builder.add_symbol("_big")
    builder.add_import("_big", :lib => -1, :weak => true,
                              :addend => 0x100000000)
    builder.set_page_start(0, 0x008)

    file = build(builder) do |fake|
      fake.set_slot(0, 0x008, ptr64_bind(:ordinal => 0))
    end
    fixup = file.chained_fixups.first
    import = fixup.import

    assert_equal "_big", fixup.symbol
    assert import.weak_import
    assert_equal -1, import.lib_ordinal
    assert_equal :EXECUTABLE_ORDINAL, import.dylib_special_ordinal
    assert_equal 0x100000000, fixup.addend
  end

  def test_compressed_symbol_pool
    builder = PayloadBuilder.new(:imports_format => 1,
                                 :symbols_format => 1,
                                 :pointer_format => 2)
    builder.add_symbol("_compressed_symbol")
    builder.add_compact_import("_compressed_symbol")
    builder.set_page_start(0, 0x008)

    file = build(builder) do |fake|
      fake.set_slot(0, 0x008, ptr64_bind(:ordinal => 0))
    end
    assert_equal "_compressed_symbol", file.chained_fixups.first.symbol
  end

  def test_compact_weak_import_encoding
    builder = PayloadBuilder.new(:pointer_format => 2)
    builder.add_symbol("_weak_sym")
    builder.add_compact_import("_weak_sym", :lib => 2, :weak => true)
    builder.set_page_start(0, 0x008)

    file = build(builder) do |fake|
      fake.set_slot(0, 0x008, ptr64_bind(:ordinal => 0))
    end
    import = file.chained_fixups.first.import
    assert import.weak_import
    assert_equal 2, import.lib_ordinal
    assert_equal "_weak_sym", import.name
  end

  def test_arm64e_userland_formats
    builder = PayloadBuilder.new(:pointer_format => 9)
    builder.add_symbol("_auth")
    builder.add_compact_import("_auth", :lib => 2)
    builder.set_page_start(0, 0x000)

    file = build(builder) do |fake|
      fake.set_slot(0, 0x000,
                    u9_rebase(:target_low43 => 0x1234, :high8 => 0xaa,
                              :next_offset => 0x008))
      fake.set_slot(0, 0x008,
                    u9_bind(:ordinal => 0, :addend => -0x1000,
                            :next_offset => 0x010))
      fake.set_slot(0, 0x010,
                    u9_auth_rebase(:target_runtime => 0x7000,
                                   :diversity => 0x1234, :key => 2,
                                   :addr_div => 1, :next_offset => 0x018))
      fake.set_slot(0, 0x018,
                    u9_auth_bind(:ordinal => 0, :diversity => 0x42,
                                 :key => 1, :addr_div => 0))
    end
    unauth_rebase, unauth_bind, auth_rebase, auth_bind = file.chained_fixups.to_a

    assert_equal 0x1234, unauth_rebase.target_runtime_offset
    assert_equal 0xaa, unauth_rebase.high8
    assert_equal 0x100000000 + 0x1234, unauth_rebase.target_vmaddr
    refute unauth_rebase.authenticated

    assert_equal -0x1000, unauth_bind.addend
    refute unauth_bind.authenticated

    assert auth_rebase.authenticated
    assert_equal :DA, auth_rebase.key
    assert_equal 2, auth_rebase.key_discriminator
    assert_equal 0x1234, auth_rebase.diversity
    assert auth_rebase.address_diversity
    assert_equal 0x7000, auth_rebase.target_runtime_offset

    assert auth_bind.authenticated
    assert_equal :IB, auth_bind.key
    assert_equal 0x42, auth_bind.diversity
    refute auth_bind.address_diversity
    assert_equal 2, auth_bind.import.lib_ordinal
  end

  def test_multiple_starts_on_one_page
    builder = PayloadBuilder.new(:pointer_format => 2, :data_pages => 1)
    builder.add_symbol("_a")
    builder.add_compact_import("_a")
    builder.set_page_start(0, [0x010, 0x040])

    file = build(builder) do |fake|
      fake.set_slot(0, 0x010, ptr64_rebase(:target_low36 => 0x1000))
      fake.set_slot(0, 0x040, ptr64_bind(:ordinal => 0))
    end
    fixups = file.chained_fixups.to_a

    assert_equal [0x4010, 0x4040], fixups.map(&:file_offset)
    assert_equal [:rebase, :bind], fixups.map(&:kind)
  end

  def test_chain_walks_beyond_page
    builder = PayloadBuilder.new(:pointer_format => 2, :data_pages => 1)
    builder.set_page_start(0, 0x3ffc)
    error = assert_raises MachO::ChainedFixupError do
      build(builder) do |fake|
        # An 8-byte pointer slot at 0x3ffc extends past the 0x4000 page.
        fake.set_slot(0, 0x3ffc, 0)
      end.chained_fixups
    end
    assert_match(/beyond the end of the 0x4000-byte page/, error.message)
  end

  def test_duplicate_slot_visited
    builder = PayloadBuilder.new(:pointer_format => 2, :data_pages => 1)
    builder.set_page_start(0, [0x010, 0x010])
    error = assert_raises MachO::ChainedFixupError do
      build(builder) do |fake|
        fake.set_slot(0, 0x010, ptr64_rebase(:target_low36 => 0x1000))
      end.chained_fixups
    end
    assert_match(/visited more than once/, error.message)
    assert_match(/file offset 0x4010/, error.message)
  end

  def test_missing_import_ordinal
    builder = PayloadBuilder.new(:pointer_format => 2, :data_pages => 1)
    builder.add_symbol("_only")
    builder.add_compact_import("_only")
    builder.set_page_start(0, 0x000)
    error = assert_raises MachO::ChainedFixupError do
      build(builder) do |fake|
        fake.set_slot(0, 0x000, ptr64_bind(:ordinal => 42))
      end.chained_fixups
    end
    assert_match(/ordinal 42/, error.message)
    assert_match(/contains only 1 entry/, error.message)
  end

  def test_unsupported_pointer_format
    builder = PayloadBuilder.new(:pointer_format => 1, :data_pages => 1)
    builder.set_page_start(0, 0x000)
    error = assert_raises MachO::ChainedFixupError do
      build(builder) do |fake|
        fake.set_slot(0, 0x000, 0)
      end.chained_fixups
    end
    assert_match(/unsupported chained pointer format/, error.message)
    assert_match(/DYLD_CHAINED_PTR_ARM64E\b/, error.message)
  end

  def test_multi_start_index_out_of_bounds
    # Hand-craft a page_start entry pointing past the two legitimate
    # multi-start entries (record size only covers 2 page_starts + 2 entries).
    builder = PayloadBuilder.new(:pointer_format => 2, :data_pages => 1)
    builder.set_page_start(0, 0x010)
    payload = builder.build
    # The page_start for page 0 is the first u16 after the 22-byte segment
    # header; the seg record starts 12 bytes into the starts blob, which itself
    # starts at fixups header offset 28.
    page_start_pos = 28 + 12 + 22
    payload[page_start_pos, 2] = [0x8002].pack("v")

    fake = FakeMachO.new
    fake.set_slot(0, 0x010, ptr64_rebase(:target_low36 => 0x1000))
    fake.payload = payload
    error = assert_raises MachO::ChainedFixupError do
      fake.file.chained_fixups
    end
    assert_match(/multi-start index 2/, error.message)
  end

  # Assembles a dyld_chained_fixups payload with byte-level control.
  class PayloadBuilder
    # @param page_starts [Hash{Integer => Integer,Array<Integer>}]
    def initialize(imports_format: 1, symbols_format: 0, pointer_format: 2,
                   data_pages: 2, page_size: 0x4000)
      @imports_format = imports_format
      @symbols_format = symbols_format
      @pointer_format = pointer_format
      @data_pages = data_pages
      @page_size = page_size
      @names = []
      @imports = []
      @page_starts = {} # page index => Integer or Array<Integer>
    end

    def add_symbol(name)
      @names |= [name]
      name
    end

    # Adds an import using the *classic* dyld_chained_import* bit layout
    # (lib ordinal in the top bits, raw byte offset in the low bits).
    def add_import(name, lib: 1, weak: false, addend: nil)
      @imports << { :name => name, :lib => lib, :weak => weak,
                    :addend => addend, :compact => false }
    end

    def add_compact_import(name, lib: 0, weak: false, addend: nil)
      @imports << { :name => name, :lib => lib, :weak => weak,
                    :addend => addend, :compact => true }
    end

    def set_page_start(page, start)
      @page_starts[page] = start
    end

    attr_reader :data_pages

    def build
      symbols_blob, name_offsets = build_symbols
      imports_blob = build_imports(name_offsets)

      # Gather per-page entries plus any multi-start spillover.
      multi_entries = []
      page_start_words = Array.new(@data_pages, 0xffff)
      @page_starts.each do |page, start|
        starts = Array(start)
        if starts.length == 1
          page_start_words[page] = starts[0]
        else
          index = multi_entries.length
          page_start_words[page] = 0x8000 | index
          starts[0...-1].each { |s| multi_entries << s }
          multi_entries << (starts.last | 0x8000)
        end
      end

      seg_size = 22 + (@data_pages * 2) + (multi_entries.length * 2)
      seg_record = [seg_size, @page_size, @pointer_format, 0x4000,
                    0x10000000, @data_pages].pack("L<v2Q<L<v") +
                   page_start_words.map { |s| [s].pack("v") }.join +
                   multi_entries.map { |s| [s].pack("v") }.join

      # seg_count=2 (__TEXT, __DATA); the __DATA record follows the 12-byte
      # seg_count + seg_info_offset[] header.
      starts_blob = [2, 0, 12].pack("L<3") + seg_record

      starts_size = 28 + starts_blob.bytesize
      imports_off = align8(starts_size)
      symbols_off = align8(imports_off + imports_blob.bytesize)
      header = [0, 28, imports_off, symbols_off,
                @imports.length, @imports_format,
                @symbols_format].pack("L<7")
      header + starts_blob + gap(starts_size, imports_off) +
        imports_blob + gap(imports_off + imports_blob.bytesize, symbols_off) +
        symbols_blob
    end

    private

    def gap(from, to)
      "\0" * (to - from)
    end

    def align8(value)
      (value + 7) & ~7
    end

    def build_symbols
      blob = +"".b
      offsets = {}
      # Modern linkers emit a leading empty placeholder string.
      blob << "\0" if @symbols_format.zero?
      @names.each do |name|
        if @symbols_format.zero?
          offsets[name] = blob.bytesize
          blob << name << "\0"
        else
          offsets[name] = blob.bytesize
          write_uleb128(blob, name.bytesize)
          blob << name
        end
      end
      [blob, offsets]
    end

    def write_uleb128(blob, value)
      loop do
        byte = value & 0x7f
        value >>= 7
        byte |= 0x80 unless value.zero?
        blob << byte.chr(Encoding::BINARY)
        break if value.zero?
      end
    end

    def build_imports(name_offsets)
      @imports.map do |imp|
        name_off = name_offsets.fetch(imp[:name])
        weak = imp[:weak] ? 1 : 0
        if imp[:compact]
          # (byte_offset << 9) | 0x200 marker | (lib << 1) | (weak << 8)
          word = (name_off << 9) | 0x200 | ((imp[:lib] & 0xff) << 1) | (weak << 8)
        else
          word = ((imp[:lib] & 0xff) << 24) | (weak << 23) | name_off
        end
        case @imports_format
        when 1
          [word].pack("L<")
        when 2
          [word].pack("L<") + [(imp[:addend] || 0)].pack("l<")
        when 3
          word64 = if imp[:compact]
            (name_off << 9) | 0x200 | ((imp[:lib] & 0xffff) << 1) | (weak << 8)
          else
            ((imp[:lib] & 0xffff) << 48) | (weak << 47) | name_off
          end
          [word64].pack("Q<") + [(imp[:addend] || 0) & 0xffffffffffffffff].pack("Q<")
        end
      end.join
    end
  end
end
