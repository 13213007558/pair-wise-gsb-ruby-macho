# frozen_string_literal: true

require_relative "helpers"

class ExportTrieTest < Minitest::Test
  include Helpers

  def test_empty_prefix_returns_root_shared_prefix_reexport_and_stub_exports
    macho = MachO::MachOFile.new_from_bin(macho_with_exports_trie(valid_trie))
    exports = macho.exports

    assert_equal ["", "abc", "abx", "re"], exports.map(&:name)

    root, abc, abx, reexport = exports
    assert_equal :regular, root.kind
    assert_equal 0x42, root.address

    assert_equal :regular, abc.kind
    assert_equal 0x1000, abc.address

    assert_equal :regular, abx.kind
    assert_equal 0x10, abx.flags
    assert abx.stub_and_resolver?
    assert_equal 0x4000, abx.address
    assert_equal 0x2000, abx.stub_offset
    assert_equal 0x3000, abx.resolver_offset

    assert_equal :reexport, reexport.kind
    assert_equal 0x8, reexport.flags
    assert_equal 2, reexport.reexport_ordinal
    assert_equal "target", reexport.reexport_symbol
    assert_nil reexport.address
    same_name = MachO::ExportTrie.query(node(terminal(8, uleb(2**64 - 1) + "\x00"), []), "").first
    assert_equal "", same_name.reexport_symbol
    assert_equal(-1, same_name.reexport_ordinal)
  end

  def test_prefix_query_walks_only_matching_edges
    macho = MachO::MachOFile.new_from_bin(macho_with_exports_trie(valid_trie))

    assert_equal %w[abc abx], macho.exports("ab").map(&:name)
    assert_equal ["abc"], macho.exports("abc").map(&:name)
    assert_equal ["re"], macho.exports("re").map(&:name)
    assert_empty macho.exports("zzz")
  end

  def test_utf8_prefix_is_compared_as_symbol_bytes
    child = node(terminal(0, uleb(0)), [])
    child_offset = 2 + ("héllo\x00".b.bytesize + 1)
    trie = node(uleb(0), [["héllo".b, child_offset]]) + child

    assert_equal ["héllo".b], MachO::ExportTrie.query(trie, "hé").map(&:name)
  end

  def test_lc_dyld_info_export_region_is_supported
    macho = MachO::MachOFile.new_from_bin(macho_with_dyld_info_trie(valid_trie))

    assert_equal ["", "abc", "abx", "re"], macho.exports.map(&:name)
    assert_equal %w[abc abx], macho.exports("ab").map(&:name)
  end

  def test_cyclic_back_edge_is_rejected_when_the_prefix_reaches_it
    trie = cyclic_trie
    macho = MachO::MachOFile.new_from_bin(macho_with_exports_trie(trie))

    assert_equal ["safe"], macho.exports("safe").map(&:name)

    error = assert_raises(MachO::ExportTrieError) { macho.exports("") }
    assert_match(/cycle or shared node/, error.message)
  end

  def test_out_of_bounds_child_offset_is_rejected_only_for_matching_prefix
    trie = [0, 1].pack("CC") + "x\x00" + [100].pack("C")
    macho = MachO::MachOFile.new_from_bin(macho_with_exports_trie(trie))

    assert_empty macho.exports("y")
    assert_raises(MachO::ExportTrieError) { macho.exports("x") }
  end

  def test_too_long_uleb128_is_rejected
    trie = "\x80" * 10
    macho = MachO::MachOFile.new_from_bin(macho_with_exports_trie(trie))

    assert_raises(MachO::ExportTrieError) { macho.exports }
  end

  def test_terminal_integer_cannot_read_past_declared_terminal
    trie = [2, 0x80, 0, 0].pack("C4")

    assert_raises(MachO::ExportTrieError) { MachO::ExportTrie.query(trie, "") }
  end

  private

  def uleb(value)
    bytes = +"".b

    loop do
      byte = value & 0x7f
      value >>= 7
      byte |= 0x80 unless value.zero?
      bytes << byte
      break if value.zero?
    end

    bytes
  end

  def terminal(flags, payload)
    terminal_data = uleb(flags) + payload
    uleb(terminal_data.bytesize) + terminal_data
  end

  def node(terminal_data, edges)
    terminal_data + uleb(edges.size) + edges.map { |label, offset| "#{label}\x00" + uleb(offset) }.join
  end

  def valid_trie
    root_terminal = terminal(0, uleb(0x42))
    abc = node(terminal(0, uleb(0x1000)), [])
    abx = node(terminal(0x10, uleb(0x4000) + uleb(0x2000) + uleb(0x3000)), [])
    reexport = node(terminal(0x8, uleb(2) + "target\x00"), [])

    root_edges_start = root_terminal.bytesize + 1
    abc_offset = root_edges_start + "abc\x00".bytesize + 1 + "abx\x00".bytesize + 1 + "re\x00".bytesize + 1
    abx_offset = abc_offset + abc.bytesize
    reexport_offset = abx_offset + abx.bytesize

    root = node(root_terminal, [
      ["abc", abc_offset],
      ["abx", abx_offset],
      ["re", reexport_offset],
    ])

    root + abc + abx + reexport
  end

  def cyclic_trie
    safe_node = node(terminal(0, uleb(0x99)), [])
    root_edges_start = 2
    safe_offset = root_edges_start + "safe\x00".bytesize + 1 + "bad\x00".bytesize + 1
    bad_offset = safe_offset + safe_node.bytesize
    root = node(uleb(0), [
      ["safe", safe_offset],
      ["bad", bad_offset],
    ])
    bad_node = node(uleb(0), [["x", 0]])

    assert_equal safe_offset, root.bytesize
    root + safe_node + bad_node
  end

  def macho_header(ncmds, sizeofcmds)
    [
      MachO::Headers::MH_MAGIC_64,
      MachO::Headers::CPU_TYPE_ARM64,
      0,
      MachO::Headers::MH_DYLIB,
      ncmds,
      sizeofcmds,
      0,
      0,
    ].pack("L<8")
  end

  def linkedit_segment(total_size)
    [
      0x19,
      72,
    ].pack("L<2") + "__LINKEDIT\x00".ljust(16, "\x00") + [
      0x100000000,
      0x4000,
      0,
      total_size,
      7,
      1,
      0,
      0,
    ].pack("Q<4L<4")
  end

  def exports_command(trie_size)
    [MachO::LoadCommands::LC_REQ_DYLD | 0x33, 16, 128, trie_size].pack("L<4")
  end

  def dyld_info_command(trie_size)
    fields = Array.new(12, 0)
    fields[0] = MachO::LoadCommands::LC_REQ_DYLD | 0x22
    fields[1] = 48
    fields[10] = 160
    fields[11] = trie_size
    fields.pack("L<12")
  end

  def macho_with_exports_trie(trie)
    commands = linkedit_segment(128 + trie.bytesize) + exports_command(trie.bytesize)
    macho_header(2, commands.bytesize) + commands.b + ("\x00".b * 8) + trie.b
  end

  def macho_with_dyld_info_trie(trie)
    commands = linkedit_segment(128 + trie.bytesize) + dyld_info_command(trie.bytesize)
    macho_header(2, commands.bytesize) + commands.b + ("\x00".b * 8) + trie.b
  end
end
