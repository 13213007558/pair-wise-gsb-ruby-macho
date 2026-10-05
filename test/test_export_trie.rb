# frozen_string_literal: true

require_relative "helpers"

class ExportTrieTest < Minitest::Test
  include Helpers

  def test_empty_prefix_includes_terminal_root
    trie = node_bytes(terminal_bytes(0, 0x1000), [])

    export = MachO::ExportTrie.query(trie, "").first

    assert_equal "", export.name
    assert_equal 0x1000, export.address
    assert_equal :regular, export.kind
    assert_empty MachO::ExportTrie.query(trie, "a")
  end

  def test_shared_prefix_reexport_and_stub_resolver
    exports = MachO::ExportTrie.query(small_trie, "")
    by_name = exports.to_h { |export| [export.name, export] }

    assert_equal %w[foo fooA fooB re], exports.map(&:name).sort
    assert_equal 0x1000, by_name["foo"].address

    foo_a = by_name["fooA"]
    assert_equal 0x1010, foo_a.address
    assert_predicate foo_a, :weak_defined?

    foo_b = by_name["fooB"]
    assert_equal :stub_and_resolver, foo_b.kind
    assert_equal 0x1020, foo_b.address
    assert_equal 0x2000, foo_b.stub_offset
    assert_equal 0x3000, foo_b.resolver_offset

    reexport = by_name["re"]
    assert_equal :reexport, reexport.kind
    assert_equal 1, reexport.reexport_ordinal
    assert_equal "target", reexport.reexport_name
    assert_equal(
      {
        :ordinal => 1,
        :dylib_name => nil,
        :symbol_name => "target",
      },
      reexport.to_h["reexport"]
    )
  end

  def test_prefix_walk_prunes_unrelated_edges
    exports = MachO::ExportTrie.query(malicious_back_edge_trie, "foo")

    assert_equal %w[foo fooA fooB], exports.map(&:name).sort
  end

  def test_malicious_back_edge_fails
    assert_raises MachO::ExportTrieError do
      MachO::ExportTrie.query(malicious_back_edge_trie, "")
    end
  end

  def test_out_of_bounds_edge_fails
    trie = node_bytes("", [["a", 127]])

    assert_raises MachO::ExportTrieError do
      MachO::ExportTrie.query(trie, "")
    end
  end

  def test_cycle_to_root_fails
    child = node_bytes("", [["back", 0]])
    root = node_bytes("", [["a", 8], ["bad", 10]])
    trie = root + node_bytes("", []) + child

    assert_raises MachO::ExportTrieError do
      MachO::ExportTrie.query(trie, "")
    end
  end

  def test_node_merge_fails
    shared_child = node_bytes("", [])
    middle = node_bytes("", [["one", 16], ["two", 16]])
    root = node_bytes("", [["a", 8]])
    trie = root + middle + shared_child

    assert_raises MachO::ExportTrieError do
      MachO::ExportTrie.query(trie, "")
    end
  end

  def test_cycle_to_ancestor_fails
    back_node = node_bytes("", [["back", 8]])
    root = node_bytes("", [["a", 8], ["b", 10]])
    trie = root + back_node

    assert_raises MachO::ExportTrieError do
      MachO::ExportTrie.query(trie, "")
    end
  end

  def test_terminal_out_of_bounds_fails
    trie = "\x7f\x00"

    assert_raises MachO::ExportTrieError do
      MachO::ExportTrie.query(trie, "")
    end
  end

  def test_overlong_uleb128_fails
    trie = "\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x01"

    assert_raises MachO::ExportTrieError do
      MachO::ExportTrie.query(trie, "")
    end
  end

  def test_malformed_noncanonical_uleb128_fails
    trie = "\x80\x00"

    assert_raises MachO::ExportTrieError do
      MachO::ExportTrie.query(trie, "")
    end
  end

  def test_uleb128_overflow_fails
    trie = "\xff" * 9 + "\x02\x00"

    assert_raises MachO::ExportTrieError do
      MachO::ExportTrie.query(trie, "")
    end
  end

  def test_terminal_with_trailing_bytes_fails
    terminal = terminal_bytes(0, 0x1000) + "\x00".b
    trie = uleb128(terminal.bytesize) + terminal + uleb128(0)

    assert_raises MachO::ExportTrieError do
      MachO::ExportTrie.query(trie, "")
    end
  end

  def test_exports_trie_load_command_in_full_binary
    file = MachO::MachOFile.new_from_bin(macho_with_exports_trie)
    exports = file.exported_symbols("foo")

    assert_equal %w[foo fooA fooB], exports.map(&:name).sort
    assert_equal "LC_DYLD_EXPORTS_TRIE", exports.first.source[:type]

    reexport = file.exported_symbols("re").first
    assert_equal "/usr/lib/libz.dylib", reexport.reexport_dylib_name
  end

  def test_dyld_info_export_area_in_full_binary
    file = MachO::MachOFile.new_from_bin(macho_with_dyld_info)
    exports = file.exported_symbols("")

    assert_equal %w[foo fooA fooB re], exports.map(&:name).sort
    assert_equal "LC_DYLD_INFO", exports.first.source[:type]
  end

  def test_dyld_info_only_export_area_in_full_binary
    file = MachO::MachOFile.new_from_bin(macho_with_dyld_info(:LC_DYLD_INFO_ONLY))
    exports = file.exported_symbols

    assert_equal %w[foo fooA fooB re], exports.map(&:name).sort
    assert_equal "LC_DYLD_INFO_ONLY", exports.first.source[:type]
  end

  def test_binary_content_entry_point
    exports = MachO.exported_symbols(macho_with_exports_trie, "fooA")

    assert_equal %w[fooA], exports.map(&:name)
  end

  def test_missing_export_area_returns_no_exports
    header = mach_header(1, 48)
    file = MachO::MachOFile.new_from_bin(header + minimal_dyld_info)

    assert_empty file.exported_symbols
  end

  def test_export_area_outside_binary_fails
    command = dyld_info_command(999, small_trie.bytesize)
    bin = mach_header(1, command.bytesize) + command + small_trie

    assert_raises MachO::ExportTrieError do
      MachO::MachOFile.new_from_bin(bin).exported_symbols
    end
  end

  private

  def uleb128(value)
    return "\x00".b if value.zero?

    bytes = "".b
    loop do
      byte = value & 0x7f
      value >>= 7
      if value.zero?
        bytes << byte
        return bytes
      end
      bytes << (byte | 0x80)
    end
  end

  def terminal_bytes(flags, *values)
    uleb128(flags) + values.map { |value| uleb128(value) }.join
  end

  def node_bytes(payload, edges)
    bytes = +(uleb128(payload.bytesize) + payload.b + uleb128(edges.size))
    edges.each do |label, offset|
      bytes << label.b << "\x00".b << uleb128(offset)
    end
    bytes
  end

  def node_size(payload, edge_count)
    node_bytes(payload, Array.new(edge_count) { ["x", 0] }).bytesize
  end

  def small_trie
    @small_trie ||= build_small_trie(false)
  end

  def malicious_back_edge_trie
    @malicious_back_edge_trie ||= build_small_trie(true)
  end

  def build_small_trie(with_bad_edge)
    foo_payload = terminal_bytes(0, 0x1000)
    foo_a_payload = terminal_bytes(4, 0x1010)
    foo_b_payload = terminal_bytes(0x10) + uleb128(0x1020) + uleb128(0x2000) + uleb128(0x3000)
    reexport_payload = terminal_bytes(8, 1) + "target\x00".b

    root_labels = %w[foo re]
    root_labels << "bad" if with_bad_edge
    root_size = 1 + 1 + root_labels.sum { |label| label.bytesize + 2 }
    foo_offset = root_size
    foo_size = node_size(foo_payload, 2)
    foo_a_offset = foo_offset + foo_size
    foo_a_size = node_size(foo_a_payload, 0)
    foo_b_offset = foo_a_offset + foo_a_size
    foo_b_size = node_size(foo_b_payload, 0)
    reexport_offset = foo_b_offset + foo_b_size
    reexport_size = node_size(reexport_payload, 0)

    root_edges = [["foo", foo_offset], ["re", reexport_offset]]
    bytes = node_bytes("", root_edges)
    bytes << node_bytes(foo_payload, [["A", foo_a_offset], ["B", foo_b_offset]])
    bytes << node_bytes(foo_a_payload, [])
    bytes << node_bytes(foo_b_payload, [])
    bytes << node_bytes(reexport_payload, [])

    if with_bad_edge
      bad_offset = reexport_offset + reexport_size
      bad_node = node_bytes("", [["x", bad_offset]])
      bytes = node_bytes("", root_edges + [["bad", bad_offset]])
      bytes << node_bytes(foo_payload, [["A", foo_a_offset], ["B", foo_b_offset]])
      bytes << node_bytes(foo_a_payload, [])
      bytes << node_bytes(foo_b_payload, [])
      bytes << node_bytes(reexport_payload, [])
      bytes << bad_node
    end

    bytes
  end

  def mach_header(ncmds, sizeofcmds)
    [0xfeedfacf, 0x01000007, 3, 6, ncmds, sizeofcmds, 0, 0].pack("L<" * 8)
  end

  def reexport_dylib_command
    name = "/usr/lib/libz.dylib"
    cmdsize = 48
    header = [0x8000001f, cmdsize, 24, 0, 0, 0].pack("L<" * 6)
    header + name.b + "\x00".b * (cmdsize - header.bytesize - name.bytesize)
  end

  def exports_trie_command(offset, size)
    [0x80000033, 16, offset, size].pack("L<" * 4)
  end

  def macho_with_exports_trie
    @macho_with_exports_trie ||= begin
      dylib_command = reexport_dylib_command
      trie_offset = 32 + dylib_command.bytesize + 16
      command = exports_trie_command(trie_offset, small_trie.bytesize)
      mach_header(2, dylib_command.bytesize + command.bytesize) + dylib_command + command + small_trie
    end
  end

  def minimal_dyld_info
    @minimal_dyld_info ||= dyld_info_command(0, 0)
  end

  def dyld_info_command(export_offset, export_size, cmd = 0x22)
    values = [cmd, 48, 0, 0, 0, 0, 0, 0, 0, 0]
    values.concat([export_offset, export_size])
    values.pack("L<" * 12)
  end

  def macho_with_dyld_info(type = :LC_DYLD_INFO)
    command_size = 48
    trie_offset = 32 + command_size
    cmd = type == :LC_DYLD_INFO_ONLY ? (0x80000000 | 0x22) : 0x22
    command = dyld_info_command(trie_offset, small_trie.bytesize, cmd)
    mach_header(1, command_size) + command + small_trie
  end
end
