# frozen_string_literal: true

require_relative "helpers"

class ChainedFixupsTest < Minitest::Test
  include Helpers

  LC_REQ_DYLD = 0x80000000
  LC_SEGMENT_64 = 0x19
  LC_DYLD_CHAINED_FIXUPS = LC_REQ_DYLD | 0x34
  MH_MAGIC_64 = 0xfeedfacf
  CPU_TYPE_X86_64 = 0x01000007
  CPU_TYPE_ARM64 = 0x0100000c
  CPU_SUBTYPE_X86_64_ALL = 3
  CPU_SUBTYPE_ARM64E = 2
  MH_DYLIB = 6

  PTR_64 = 2
  PTR_64_OFFSET = 6
  PTR_ARM64E_USERLAND = 9

  IMPORT_FORMAT = 1
  IMPORT_ADDEND_FORMAT = 2
  IMPORT_ADDEND64_FORMAT = 3

  PAGE_SIZE = 0x1000
  DATA_VMADDR = 0x1000
  DATA_FILE_OFFSET = 0x1000
  PAYLOAD_OFFSET = 0x2000
  FILE_SIZE = 0x3000

  def test_multiple_starts_and_aligned_strides
    pointers = {
      0 => [rebase_64(0x234, 2, 2), :rebase],
      0x8 => [bind_64_offset(0, 0, 0), :bind],
      0x28 => [bind_64_offset(1, 0, 0), :bind]
    }
    imports = [
      import_entry(1, "_foo", 0),
      import_entry(1, "_foo", 0, 3),
    ]
    payload = build_payload(PTR_64_OFFSET, imports, pointers.keys, pointers,
                            1, [0x8000 | 24], [0, 0x28 | 0x8000])
    fixups = macho_with_payload(payload, pointers).chained_fixups

    assert_equal [0, 8, 0x28], fixups.fixups.map(&:page_offset)
    assert_equal %i[rebase bind bind], fixups.fixups.map(&:kind)
    assert_equal [0x2000000234], fixups.fixups.select(&:rebase?).map(&:target)
    assert_equal [DATA_VMADDR + 0x2000000234],
                 fixups.fixups.select(&:rebase?).map(&:target_address)
    assert_equal [2], fixups.fixups.select(&:rebase?).map(&:high8)
    assert_equal ["_foo", "_foo"], fixups.fixups.select(&:bind?).map { |fixup| fixup.import.name }
    assert_equal [0, 3], fixups.fixups.select(&:bind?).map(&:addend)
    assert_equal [2, 0, 0], fixups.fixups.map(&:chain_next)
  end

  def test_absolute_rebase_with_negative_import_addend
    pointers = {
      0 => [rebase_64(0x12345678, 2, 0), :rebase],
      0x8 => [bind_64(0, 0, 0), :bind],
    }
    imports = [import_entry(1, "_neg", 0, -9)]
    payload = build_payload(PTR_64, imports, pointers.keys, pointers, 1, [0])
    fixups = macho_with_payload(payload, pointers).chained_fixups
    rebase = fixups.fixups.find(&:rebase?)
    bind = fixups.fixups.find(&:bind?)

    assert_equal :DYLD_CHAINED_PTR_64, fixups.pointer_formats.first
    assert_equal 0x12345678, rebase.target
    assert_equal 0x12345678, rebase.target_address
    assert_equal "_neg", bind.import.name
    assert_equal(-9, bind.addend)
  end

  def test_arm64e_userland_signed_addend_and_auth_fields
    pointers = {
      0 => [arm64e_bind(0, -16, 1), :bind],
      0x8 => [arm64e_auth_bind(1, 0x1234, true, 2, 0), :bind],
      0x28 => [arm64e_auth_rebase(0x2000, 0xabcd, false, 1, 0), :rebase],
    }
    imports = [
      import64_entry(1, "_plain", 0, 0),
      import64_entry(1, "_auth", 7, -32),
    ]
    payload = build_payload(PTR_ARM64E_USERLAND, imports, pointers.keys, pointers,
                            1, [0x8000 | 24], [0, 0x28 | 0x8000], IMPORT_ADDEND64_FORMAT)
    fixups = macho_with_payload(payload, pointers, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E).chained_fixups
    unauth_bind, auth_bind, auth_rebase = fixups.fixups

    assert_equal :DYLD_CHAINED_PTR_ARM64E_USERLAND, fixups.pointer_formats.first
    assert_equal [false, true, true], fixups.fixups.map(&:authenticated)
    assert_equal(-16, unauth_bind.addend)
    assert_equal(-32, auth_bind.addend)
    assert_equal "_auth", auth_bind.import.name
    assert_equal 1, auth_bind.import.ordinal
    assert_nil unauth_bind.key
    assert_equal 2, auth_bind.key
    assert_equal 0x1234, auth_bind.diversity
    assert_equal true, auth_bind.addr_div
    assert_equal 0x2000, auth_rebase.target
    assert_equal DATA_VMADDR + 0x2000, auth_rebase.target_address
    assert_equal 1, auth_rebase.key
    assert_equal 0xabcd, auth_rebase.diversity
    assert_equal false, auth_rebase.addr_div
  end

  def test_bad_import_ordinal
    pointers = {
      0 => [rebase_64(0x100, 2, 0), :rebase],
      0x8 => [bind_64(99, 0, 0), :bind],
    }
    payload = build_payload(PTR_64, [], pointers.keys, pointers, 1, [0])

    assert_raises MachO::ChainedFixupsError do
      macho_with_payload(payload, pointers).chained_fixups
    end
  end

  def test_bad_chain_crosses_page_boundary
    raw = bind_64(0, PAGE_SIZE / 4, 0)
    pointers = { 0 => [raw, :bind] }
    payload = build_payload(PTR_64, [], [0], pointers, 1, [0])
    bin = macho_with_payload(payload, pointers).serialize

    assert_raises MachO::ChainedFixupsError do
      MachO::MachOFile.new_from_bin(bin).chained_fixups
    end
  end

  def test_duplicate_locations_from_multiple_starts
    pointers = {
      0 => [bind_64(0, 0, 0), :bind],
    }
    payload = build_payload(PTR_64, [], [0], pointers, 1, [0, 0])
    bin = macho_with_payload(payload, pointers).serialize

    assert_raises MachO::ChainedFixupsError do
      MachO::MachOFile.new_from_bin(bin).chained_fixups
    end
  end

  private

  def macho_with_payload(payload, pointers, cputype = CPU_TYPE_X86_64,
                        cpusubtype = CPU_SUBTYPE_X86_64_ALL)
    bin = +"\0" * FILE_SIZE
    header_size = 32
    segment_cmd_size = 72
    fixup_cmd_size = 16
    bin[0, header_size] = [
      MH_MAGIC_64, cputype, cpusubtype, MH_DYLIB, 2,
      segment_cmd_size + fixup_cmd_size, 0, 0,
    ].pack("L<8")
    bin[header_size, segment_cmd_size] = [
      LC_SEGMENT_64, segment_cmd_size, "__DATA\0",
      DATA_VMADDR, PAGE_SIZE, DATA_FILE_OFFSET, PAGE_SIZE,
      3, 3, 0, 0,
    ].pack("L<2Z16Q<4L<4")
    bin[header_size + segment_cmd_size, fixup_cmd_size] = [
      LC_DYLD_CHAINED_FIXUPS, fixup_cmd_size, PAYLOAD_OFFSET, payload.bytesize,
    ].pack("L<4")
    bin[PAYLOAD_OFFSET, payload.bytesize] = payload
    pointers.each do |offset, (raw, _kind)|
      bin[DATA_FILE_OFFSET + offset, 8] = [raw].pack("Q<")
    end
    MachO::MachOFile.new_from_bin(bin)
  end

  def build_payload(pointer_format, imports, _first_chain, pointers, page_count,
                    page_starts, chain_starts = [], imports_format = IMPORT_ADDEND_FORMAT)
    symbols = build_symbols(imports)
    imports_blob = build_imports(imports, imports_format)
    page_start_blob = page_starts.map { |entry| [entry].pack("S<") }.join
    chain_start_blob = chain_starts.map { |entry| [entry].pack("S<") }.join
    segment_data_size = 22 + page_start_blob.bytesize + chain_start_blob.bytesize
    segment_size = (segment_data_size + 3) & ~3
    segment_padding = "\0" * (segment_size - segment_data_size)
    segment = [
      segment_size, PAGE_SIZE, pointer_format, 0, 0, page_count,
    ].pack("L<S<S<Q<L<S<") + page_start_blob + chain_start_blob + segment_padding
    starts = [1, 8].pack("L<2") + segment
    imports_offset = 32 + starts.bytesize
    symbols_offset = imports_offset + imports_blob.bytesize
    [0, 32, imports_offset, symbols_offset, imports.size, imports_format, 0].pack("L<7") +
      "\0" * 4 +
      starts + imports_blob + symbols
  end

  def build_symbols(imports)
    imports.map { |entry| entry[:name] + "\0" }.uniq.join
  end

  def symbol_offset(symbols, name)
    symbols.index(name + "\0")
  end

  def build_imports(imports, format)
    symbols = build_symbols(imports)
    imports.map { |entry|
      name_offset = entry[:name_offset] || symbol_offset(symbols, entry[:name])
      if format == IMPORT_ADDEND64_FORMAT
        raw = (entry[:library] & 0xffff) | (name_offset << 32)
        [raw].pack("Q<") + [entry[:addend].to_i].pack("q<")
      else
        raw = (entry[:library] & 0xff) | (name_offset << 9)
        blob = [raw].pack("L<")
        if format == IMPORT_ADDEND_FORMAT
          blob + [entry[:addend].to_i].pack("l<")
        else
          blob
        end
      end
    }.join
  end

  def import_entry(library, name, name_offset = 0, addend = 0)
    { :library => library, :name => name, :name_offset => name_offset, :addend => addend }
  end

  alias import64_entry import_entry

  def rebase_64(target, chain_next, high8 = (target >> 36) & 0xff)
    (target & 0xfffffffff) | (high8 << 36) | (chain_next << 51)
  end

  def bind_64(ordinal, chain_next, addend = 0)
    ordinal | (addend << 24) | (chain_next << 51) | (1 << 63)
  end

  def bind_64_offset(ordinal, chain_next, addend = 0)
    ordinal | (addend << 24) | (chain_next << 51) | (1 << 63)
  end

  def arm64e_bind(ordinal, addend, chain_next)
    ordinal | ((addend & 0x7ffff) << 32) | (chain_next << 51) | (1 << 62)
  end

  def arm64e_auth_bind(ordinal, diversity, addr_div, key, chain_next)
    ordinal | (diversity << 32) | ((addr_div ? 1 : 0) << 48) |
      (key << 49) | (chain_next << 51) | (3 << 62)
  end

  def arm64e_rebase(target, chain_next, high8 = (target >> 43) & 0xff)
    (target & 0x7ffffffffff) | (high8 << 43) | (chain_next << 51)
  end

  def arm64e_auth_rebase(target, diversity, addr_div, key, chain_next)
    target | (diversity << 32) | ((addr_div ? 1 : 0) << 48) |
      (key << 49) | (chain_next << 51) | (1 << 63)
  end
end
