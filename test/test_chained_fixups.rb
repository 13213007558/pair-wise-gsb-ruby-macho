# frozen_string_literal: true

require_relative "helpers"

class ChainedFixupsTest < Minitest::Test
  include Helpers

  PTR_64 = MachO::ChainedFixups::DYLD_CHAINED_PTR_64
  PTR_64_OFFSET = MachO::ChainedFixups::DYLD_CHAINED_PTR_64_OFFSET
  ARM64E_USERLAND = MachO::ChainedFixups::DYLD_CHAINED_PTR_ARM64E_USERLAND

  # packs a dyld_chained_starts_in_segment blob; each page is nil (no
  # fixups), an Integer (single chain start), or an Array of starts
  def segment_starts(page_size:, pointer_format:, segment_offset:, pages:)
    chain_starts = []
    page_starts = pages.map do |page|
      case page
      when nil
        0xFFFF
      when Integer
        page
      when Array
        index = chain_starts.size
        page.each_with_index do |start, i|
          chain_starts << (i == page.size - 1 ? start | 0x8000 : start)
        end
        0x8000 | index
      end
    end

    body = page_starts + chain_starts
    size = 22 + (body.size * 2)
    [size, page_size, pointer_format].pack("Vv2") +
      [segment_offset].pack("Q<") +
      [0, pages.size].pack("Vv") +
      body.pack("v*")
  end

  # packs a dyld_chained_starts_in_image blob
  def starts_in_image(segments)
    offsets = []
    cursor = 4 + (segments.size * 4)
    segments.each do |segment|
      offsets << cursor
      cursor += segment.bytesize
    end
    [segments.size, *offsets].pack("V*") + segments.join
  end

  # packs the imports table, appending symbol names to symbols_pool
  def imports_table(imports, format, symbols_pool)
    imports.map do |lib_ordinal, weak, name, addend|
      name_offset = symbols_pool.bytesize
      symbols_pool << name << "\0"
      case format
      when 1
        [lib_ordinal | (weak << 8) | (name_offset << 9)].pack("V")
      when 2
        [lib_ordinal | (weak << 8) | (name_offset << 9), addend].pack("Vl<")
      when 3
        [lib_ordinal | (weak << 16) | (name_offset << 32), addend].pack("Q<q<")
      end
    end.join
  end

  # builds a complete LC_DYLD_CHAINED_FIXUPS payload
  def build_payload(segments:, imports: [], imports_format: 1)
    symbols_pool = +""
    imports_blob = imports_table(imports, imports_format, symbols_pool)
    starts_blob = starts_in_image(segments)

    starts_offset = 28
    imports_offset = starts_offset + starts_blob.bytesize
    symbols_offset = imports_offset + imports_blob.bytesize
    header = [0, starts_offset, imports_offset, symbols_offset,
              imports.size, imports_format, 0].pack("V7")
    header + starts_blob + imports_blob + symbols_pool
  end

  # chain entry encoders; each returns a 64-bit Integer

  def ptr64_rebase(target:, high8: 0, next_: 0)
    (target & 0xFFFFFFFFF) | ((high8 & 0xFF) << 36) | (next_ << 51)
  end

  def ptr64_bind(ordinal:, addend: 0, next_: 0)
    ordinal | (addend << 24) | (next_ << 51) | (1 << 63)
  end

  def arm64e_rebase(target:, high8: 0, next_: 0)
    (target & 0x7FFFFFFFFFF) | ((high8 & 0xFF) << 43) | (next_ << 51)
  end

  def arm64e_auth_rebase(target:, diversity:, addr_div:, key:, next_: 0)
    target | (diversity << 32) | (addr_div << 48) | (key << 49) | (next_ << 51) | (1 << 63)
  end

  def arm64e_bind(ordinal:, addend: 0, next_: 0)
    ordinal | ((addend & 0x7FFFF) << 32) | (next_ << 51) | (1 << 62)
  end

  def arm64e_auth_bind(ordinal:, diversity:, addr_div:, key:, next_: 0)
    ordinal | (diversity << 32) | (addr_div << 48) | (key << 49) | (next_ << 51) | (1 << 62) | (1 << 63)
  end

  # builds a fake image from { vm_offset => 64-bit chain entry }
  def image_with(entries, size: 0x20000)
    image = "\0".b * size
    entries.each do |offset, value|
      image[offset, 8] = [value].pack("Q<")
    end
    image
  end

  def parse(payload, image)
    MachO::ChainedFixups.parse_payload(payload) do |offset, length|
      image.byteslice(offset, length)
    end
  end

  def test_ptr64_rebase_and_bind_chain
    payload = build_payload(
      :segments => [segment_starts(:page_size => 0x1000, :pointer_format => PTR_64,
                                   :segment_offset => 0, :pages => [0])],
      :imports => [[1, 0, "_foo", nil]]
    )
    image = image_with({
      0x0 => ptr64_rebase(:target => 0x1234, :next_ => 2),
      0x8 => ptr64_bind(:ordinal => 0, :addend => 5, :next_ => 2),
      0x10 => ptr64_rebase(:target => 0x6000, :high8 => 0xAB)
    })

    entries = parse(payload, image)

    assert_equal 3, entries.size

    rebase = entries[0]
    assert_equal :rebase, rebase.type
    assert_equal 0x0, rebase.offset
    assert_equal 0x1234, rebase.target
    refute rebase.authenticated?

    bind = entries[1]
    assert_equal :bind, bind.type
    assert_equal 0x8, bind.offset
    assert_equal 0, bind.ordinal
    assert_equal "_foo", bind.symbol
    assert_equal 5, bind.addend
    assert_equal 1, bind.library_ordinal
    refute bind.weak_import?
    assert_nil bind.import_addend
    assert_equal 5, bind.total_addend

    high = entries[2]
    assert_equal :rebase, high.type
    assert_equal 0x10, high.offset
    assert_equal 0x6000 | (0xAB << 56), high.target
  end

  def test_ptr64_offset_format
    payload = build_payload(
      :segments => [segment_starts(:page_size => 0x1000, :pointer_format => PTR_64_OFFSET,
                                   :segment_offset => 0x4000, :pages => [8])]
    )
    image = image_with({ 0x4008 => ptr64_rebase(:target => 0x1000) })

    entries = parse(payload, image)

    assert_equal 1, entries.size
    assert_equal :rebase, entries[0].type
    assert_equal 0x4008, entries[0].offset
    assert_equal 0x1000, entries[0].target
  end

  def test_arm64e_userland_format
    payload = build_payload(
      :segments => [segment_starts(:page_size => 0x4000, :pointer_format => ARM64E_USERLAND,
                                   :segment_offset => 0, :pages => [0])],
      :imports => [[2, 1, "_bar", nil], [3, 0, "_baz", nil]]
    )
    image = image_with({
      0x00 => arm64e_rebase(:target => 0x123456789, :next_ => 1),
      0x08 => arm64e_auth_rebase(:target => 0x1000, :diversity => 0x1234,
                                 :addr_div => 1, :key => 2, :next_ => 1),
      0x10 => arm64e_bind(:ordinal => 0, :addend => -7, :next_ => 1),
      0x18 => arm64e_auth_bind(:ordinal => 1, :diversity => 0xABCD,
                               :addr_div => 0, :key => 3)
    })

    entries = parse(payload, image)

    assert_equal 4, entries.size

    rebase = entries[0]
    assert_equal :rebase, rebase.type
    assert_equal 0x123456789, rebase.target
    refute rebase.authenticated?
    assert_nil rebase.key

    auth_rebase = entries[1]
    assert_equal :rebase, auth_rebase.type
    assert auth_rebase.authenticated?
    assert_equal 0x1000, auth_rebase.target
    assert_equal 2, auth_rebase.key
    assert_equal 0x1234, auth_rebase.diversity
    assert_equal true, auth_rebase.addr_div

    bind = entries[2]
    assert_equal :bind, bind.type
    assert_equal(-7, bind.addend)
    assert_equal "_bar", bind.symbol
    assert bind.weak_import?
    refute bind.authenticated?

    auth_bind = entries[3]
    assert_equal :bind, auth_bind.type
    assert auth_bind.authenticated?
    assert_equal "_baz", auth_bind.symbol
    assert_equal 3, auth_bind.key
    assert_equal 0xABCD, auth_bind.diversity
    assert_equal false, auth_bind.addr_div
    assert_equal 0, auth_bind.addend
  end

  def test_multiple_starts_on_one_page
    payload = build_payload(
      :segments => [segment_starts(:page_size => 0x1000, :pointer_format => PTR_64,
                                   :segment_offset => 0, :pages => [[0, 0x100]])]
    )
    image = image_with({
      0x0 => ptr64_rebase(:target => 0x10, :next_ => 2),
      0x8 => ptr64_rebase(:target => 0x20),
      0x100 => ptr64_rebase(:target => 0x30)
    })

    entries = parse(payload, image)

    assert_equal [0x0, 0x8, 0x100], entries.map(&:offset)
    assert_equal [0x10, 0x20, 0x30], entries.map(&:target)
  end

  def test_import_addend_format
    payload = build_payload(
      :segments => [segment_starts(:page_size => 0x1000, :pointer_format => PTR_64,
                                   :segment_offset => 0, :pages => [0])],
      :imports => [[1, 0, "_neg", -16]],
      :imports_format => 2
    )
    image = image_with({ 0x0 => ptr64_bind(:ordinal => 0) })

    bind = parse(payload, image).first

    assert_equal(-16, bind.import_addend)
    assert_equal 0, bind.addend
    assert_equal(-16, bind.total_addend)
  end

  def test_import_addend64_format
    payload = build_payload(
      :segments => [segment_starts(:page_size => 0x1000, :pointer_format => PTR_64,
                                   :segment_offset => 0, :pages => [0])],
      :imports => [[1, 0, "_neg64", -5_000_000_000]],
      :imports_format => 3
    )
    image = image_with({ 0x0 => ptr64_bind(:ordinal => 0, :addend => 3) })

    bind = parse(payload, image).first

    assert_equal(-5_000_000_000, bind.import_addend)
    assert_equal 3, bind.addend
    assert_equal 3 - 5_000_000_000, bind.total_addend
  end

  def test_skips_empty_pages_and_segments
    segments = [
      segment_starts(:page_size => 0x1000, :pointer_format => PTR_64,
                     :segment_offset => 0, :pages => [nil, 4]),
      segment_starts(:page_size => 0x1000, :pointer_format => PTR_64,
                     :segment_offset => 0x8000, :pages => [0]),
    ]
    payload = build_payload(:segments => segments)
    image = image_with({
      0x1004 => ptr64_rebase(:target => 0x50),
      0x8000 => ptr64_rebase(:target => 0x60)
    })

    entries = parse(payload, image)

    assert_equal [0x1004, 0x8000], entries.map(&:offset)
    assert_equal [0x50, 0x60], entries.map(&:target)
  end

  def test_revisited_location_raises
    payload = build_payload(
      :segments => [segment_starts(:page_size => 0x1000, :pointer_format => PTR_64,
                                   :segment_offset => 0, :pages => [[0, 0x8]])]
    )
    image = image_with({
      0x0 => ptr64_rebase(:target => 1, :next_ => 2),
      0x8 => ptr64_rebase(:target => 2)
    })

    error = assert_raises(MachO::ChainedFixupsError) { parse(payload, image) }
    assert_match(/revisits/, error.message)
  end

  def test_chain_past_end_of_page_raises
    payload = build_payload(
      :segments => [segment_starts(:page_size => 0x1000, :pointer_format => PTR_64,
                                   :segment_offset => 0, :pages => [0xFF8])]
    )
    image = image_with({ 0xFF8 => ptr64_rebase(:target => 1, :next_ => 2) })

    error = assert_raises(MachO::ChainedFixupsError) { parse(payload, image) }
    assert_match(/past end of page/, error.message)
  end

  def test_fixup_past_end_of_page_raises
    payload = build_payload(
      :segments => [segment_starts(:page_size => 0x1000, :pointer_format => PTR_64,
                                   :segment_offset => 0, :pages => [0xFFC])]
    )
    image = image_with({ 0xFFC => ptr64_rebase(:target => 1) })

    error = assert_raises(MachO::ChainedFixupsError) { parse(payload, image) }
    assert_match(/past end of page/, error.message)
  end

  def test_unmapped_fixup_location_raises
    payload = build_payload(
      :segments => [segment_starts(:page_size => 0x1000, :pointer_format => PTR_64,
                                   :segment_offset => 0x1000, :pages => [0])]
    )
    image = image_with({}, :size => 0x100)

    error = assert_raises(MachO::ChainedFixupsError) { parse(payload, image) }
    assert_match(/cannot read fixup/, error.message)
  end

  def test_bind_ordinal_out_of_range_raises
    payload = build_payload(
      :segments => [segment_starts(:page_size => 0x1000, :pointer_format => PTR_64,
                                   :segment_offset => 0, :pages => [0])],
      :imports => [[1, 0, "_foo", nil]]
    )
    image = image_with({ 0x0 => ptr64_bind(:ordinal => 1) })

    error = assert_raises(MachO::ChainedFixupsError) { parse(payload, image) }
    assert_match(/ordinal 1 is out of range/, error.message)
  end

  def test_symbol_offset_out_of_bounds_raises
    payload = build_payload(
      :segments => [segment_starts(:page_size => 0x1000, :pointer_format => PTR_64,
                                   :segment_offset => 0, :pages => [0])],
      :imports => [[1, 0, "_foo", nil]]
    )
    # corrupt the import's name_offset to point past the end of the payload
    imports_offset = payload.unpack1("V", :offset => 8)
    payload[imports_offset, 4] = [1 | (0x7FFFFF << 9)].pack("V")
    image = image_with({ 0x0 => ptr64_bind(:ordinal => 0) })

    error = assert_raises(MachO::ChainedFixupsError) { parse(payload, image) }
    assert_match(/symbol name offset/, error.message)
  end

  def test_unsupported_pointer_format_raises
    payload = build_payload(
      :segments => [segment_starts(:page_size => 0x1000, :pointer_format => 3,
                                   :segment_offset => 0, :pages => [0])]
    )

    error = assert_raises(MachO::ChainedFixupsError) { parse(payload, image_with({})) }
    assert_match(/unsupported chained fixups pointer format: 3/, error.message)
  end

  def test_truncated_payload_raises
    error = assert_raises(MachO::ChainedFixupsError) { parse("too short", image_with({})) }
    assert_match(/too small for header/, error.message)
  end

  def test_to_h
    payload = build_payload(
      :segments => [segment_starts(:page_size => 0x1000, :pointer_format => PTR_64,
                                   :segment_offset => 0, :pages => [0])],
      :imports => [[1, 0, "_foo", nil]]
    )
    image = image_with({
      0x0 => ptr64_rebase(:target => 0x1234, :next_ => 2),
      0x8 => ptr64_bind(:ordinal => 0, :addend => 5)
    })

    rebase, bind = parse(payload, image)

    assert_equal({
      "type" => :rebase,
      "offset" => 0x0,
      "target" => 0x1234,
      "authenticated" => false,
    }, rebase.to_h)
    assert_equal({
      "type" => :bind,
      "offset" => 0x8,
      "ordinal" => 0,
      "symbol" => "_foo",
      "addend" => 5,
      "library_ordinal" => 1,
      "weak_import" => false,
      "authenticated" => false,
    }, bind.to_h)
  end

  # builds a minimal x86_64 MH_EXECUTE containing one __DATA segment and a
  # LC_DYLD_CHAINED_FIXUPS command
  def build_macho(payload, image)
    segment = [
      0x19, 72, "__DATA".ljust(16, "\0"),
      0x100000000, 0x1000, 0x1000, 0x1000,
      7, 7, 0, 0,
    ].pack("V2a16Q<4V4")
    fixups_command = [0x80000034, 16, 0x2000, payload.bytesize].pack("V4")
    header = [0xFEEDFACF, 0x01000007, 3, 2, 2, segment.bytesize + fixups_command.bytesize, 0, 0].pack("V8")

    bin = header + segment + fixups_command
    bin << "\0" * (0x1000 - bin.bytesize)
    bin << image.byteslice(0, 0x1000)
    bin << "\0" * (0x2000 - bin.bytesize)
    bin << payload
    MachO::MachOFile.new_from_bin(bin)
  end

  def test_parse_macho_file
    payload = build_payload(
      :segments => [segment_starts(:page_size => 0x1000, :pointer_format => PTR_64,
                                   :segment_offset => 0, :pages => [0])],
      :imports => [[1, 0, "_foo", nil]]
    )
    image = image_with({
      0x0 => ptr64_rebase(:target => 0x1234, :next_ => 2),
      0x8 => ptr64_bind(:ordinal => 0)
    })
    macho = build_macho(payload, image)

    entries = macho.chained_fixups

    assert_equal 2, entries.size
    assert_equal :rebase, entries[0].type
    assert_equal 0x0, entries[0].offset
    assert_equal 0x1234, entries[0].target
    assert_equal :bind, entries[1].type
    assert_equal "_foo", entries[1].symbol
  end

  def test_parse_macho_file_without_command
    macho = MachO::MachOFile.new_from_bin(File.binread(fixture(:x86_64, "hello.bin")))

    assert_equal [], macho.chained_fixups
  end
end
