# frozen_string_literal: true

require_relative "helpers"

class ExportTrieTest < Minitest::Test
  include Helpers

  def test_parses_legacy_dyld_info_export_trie
    file = MachO::MachOFile.new(fixture(:x86_64, "libhello.dylib"))
    export = file.export_trie["_hello"]

    assert_equal "_hello", export.name
    assert_equal MachO::ExportTrie::KIND_REGULAR, export.terminal.kind
    assert_equal 0xf40, export.terminal.address
    assert export.terminal.regular?
    refute export.terminal.weak_definition?
  end

  def test_parses_modern_empty_export_trie
    file = MachO::MachOFile.new(fixture(:x86_64, "libdupe.dylib"))

    assert file.export_trie.empty?
    assert_equal 0, file.export_trie.size
    assert_equal "\x00\x00".b, file.export_trie.serialize
  end

  def test_fat_file_exposes_each_slices_export_trie
    file = MachO.open(fixture([:i386, :x86_64], "libhello.dylib"))

    assert_equal 2, file.export_tries.size
    assert file.export_tries.all? { |trie| trie["_hello"] }
  end

  def test_rejects_malformed_trie_data
    assert_raises MachO::ExportTrieError do
      MachO::ExportTrie.new("\x02\x00".b)
    end

    assert_raises MachO::ExportTrieError do
      MachO::ExportTrie.new(("\xff" * 10) + "\x00".b)
    end
  end

  def test_accepts_zero_padded_terminal_information
    padded_trie = "\x00\x01_foo\x00\x0c" + ("\x00" * 4) + "\x03\x00\x9c\x07\x00" + ("\x00" * 7)
    trie = MachO::ExportTrie.new(padded_trie)

    assert_equal 0x39c, trie["_foo"].terminal.address
  end

  def test_exact_lookup_and_prefix_enumeration
    trie = MachO::ExportTrie.serialize_exports(sample_entries).then { |data| MachO::ExportTrie.new(data) }

    assert_equal "", trie.find("").name
    assert_nil trie.find("missing")
    assert_equal(%w[prefix_absolute prefix_reexport prefix_reexport_same_name prefix_regular prefix_stub prefix_thread],
                 trie.with_prefix("prefix_").map(&:name))
  end

  def test_round_trips_all_terminal_kinds
    entries = sample_entries
    trie = MachO::ExportTrie.new(MachO::ExportTrie.serialize_exports(entries))

    expected = entries.sort_by(&:first).map { |name, terminal| [name, terminal.to_h] }
    actual = trie.exports.map { |export| [export.name, export.terminal.to_h] }

    assert_equal expected, actual
  end

  def test_round_trips_long_common_prefix_and_uleb128_offset_boundaries
    entries = large_shared_prefix_entries
    data = MachO::ExportTrie.serialize_exports(entries)
    trie = MachO::ExportTrie.new(data)

    edge_position = data.index("aa_shared_".b) + "aa_shared_".bytesize + 1
    child_offset = read_uleb128(data, edge_position)
    assert_operator child_offset, :>, 16_383
    assert_equal entries.sort_by(&:first).map(&:first), trie.exports.map(&:name)
  end

  def test_add_delete_and_reserialize
    trie = MachO::ExportTrie.new(MachO::ExportTrie.serialize_exports(sample_entries))

    removed = trie.delete("prefix_reexport")
    assert_equal "prefix_reexport", removed.name
    assert_nil trie.delete("prefix_reexport")

    trie.add("prefix_added", MachO::ExportTrie::Terminal.absolute(99))
    trie.add("prefix_regular", MachO::ExportTrie::Terminal.regular(100), :replace => true)

    retried = MachO::ExportTrie.new(trie.serialize)
    assert_equal 99, retried["prefix_added"].terminal.address
    assert_equal 100, retried["prefix_regular"].terminal.address
    assert_equal 2, retried["prefix_reexport_same_name"].terminal.library_ordinal
    assert_equal "", retried["prefix_reexport_same_name"].terminal.imported_name
    assert_nil retried["prefix_reexport"]
  end

  def test_rejects_duplicate_and_invalid_symbols
    trie = MachO::ExportTrie.new
    trie.add("symbol", MachO::ExportTrie::Terminal.regular(1))

    assert_raises MachO::ExportSymbolError do
      trie.add("symbol", MachO::ExportTrie::Terminal.regular(2))
    end

    assert_raises MachO::ExportSymbolError do
      trie.add("bad\x00name", MachO::ExportTrie::Terminal.regular(2))
    end

    assert_raises MachO::ExportSymbolError do
      trie.add("bad-terminal", Object.new)
    end
  end

  private

  def sample_entries
    [
      ["", MachO::ExportTrie::Terminal.regular(1)],
      ["prefix_regular", MachO::ExportTrie::Terminal.regular(0x123456789abc)],
      ["prefix_thread", MachO::ExportTrie::Terminal.thread_local(2, :weak => true)],
      ["prefix_absolute", MachO::ExportTrie::Terminal.absolute(3)],
      ["prefix_reexport", MachO::ExportTrie::Terminal.reexport(0x80, "renamed", :kind => 1)],
      ["prefix_reexport_same_name", MachO::ExportTrie::Terminal.reexport(2)],
      ["prefix_stub", MachO::ExportTrie::Terminal.stub_and_resolver(0x100, 0x200, :weak => true)],
    ]
  end

  def large_shared_prefix_entries
    entries = 100.times.map do |index|
      [format("a%03d_%s", index, "x" * 170), MachO::ExportTrie::Terminal.regular(index)]
    end

    entries << ["aaa_shared_tail", MachO::ExportTrie::Terminal.regular(1)]
    entries << ["aaa_shared_other", MachO::ExportTrie::Terminal.thread_local(2)]
    entries
  end

  def read_uleb128(data, position)
    value = 0
    shift = 0

    loop do
      byte = data.getbyte(position)
      value |= (byte & 0x7f) << shift
      position += 1
      shift += 7
      return value unless byte.anybits?(0x80)
    end
  end
end
