# frozen_string_literal: true

require_relative "helpers"

class MachOExportsTrieTest < Minitest::Test
  include Helpers

  ExportsTrie = MachO::ExportsTrie

  def entry(flags, **kwargs)
    ExportsTrie::Entry.new(flags, **kwargs)
  end

  def test_uleb128_round_trip
    [0, 1, 127, 128, 300, 16_383, 16_384, 2_097_151, 2_097_152, 2**32, 2**63 - 1].each do |value|
      encoded = ExportsTrie.uleb128(value)
      assert_equal ExportsTrie.uleb128_size(value), encoded.bytesize
      assert_equal [value, encoded.bytesize], ExportsTrie.read_uleb128(encoded, 0)
    end

    assert_raises(ArgumentError) { ExportsTrie.uleb128(-1) }
    assert_raises(ArgumentError) { ExportsTrie.uleb128_size(-1) }
    assert_raises(MachO::ExportsTrieError) { ExportsTrie.read_uleb128("\x80".b, 0) }
    assert_raises(MachO::ExportsTrieError) { ExportsTrie.read_uleb128("\xff".b * 10, 0) }
  end

  def test_parses_exports_from_dyld_info
    file = MachO.open(fixture(:x86_64, "hello.bin"))
    trie = file.exports_trie

    refute_nil trie
    assert_equal %w[__mh_execute_header _main], trie.names.sort

    header = trie.lookup("__mh_execute_header")
    assert_equal 0, header.address
    assert_equal :regular, header.kind
    refute_predicate header, :reexport?

    main = trie["_main"]
    assert_equal 0xf40, main.address
    assert_nil trie.lookup("_nonexistent")

    assert_equal trie, file[:LC_DYLD_INFO_ONLY].first.exports_trie
  end

  def test_parses_exports_from_all_fixtures
    expectations = {
      "hello.bin" => %w[__mh_execute_header _main],
      "libhello.dylib" => %w[_hello],
      "hellobundle.so" => %w[_hello],
      "hello.o" => nil,
    }

    %i[x86_64 i386].each do |arch|
      expectations.each do |name, names|
        trie = MachO.open(fixture(arch, name)).exports_trie
        if names.nil?
          assert_nil trie, "#{arch}/#{name}"
        else
          assert_equal names, trie.names.sort, "#{arch}/#{name}"
        end
      end
    end
  end

  def test_no_exports_trie
    assert_nil MachO.open(fixture(:ppc, "hello.bin")).exports_trie
    assert_nil MachO.open(fixture(:x86_64, "hello.o")).exports_trie
  end

  def macho_with_exports_trie_command(trie_bytes)
    template = File.binread("test/bin/yaml2obj/minimal.macho")
    command = [
      0x80000033, # LC_DYLD_EXPORTS_TRIE
      16, # cmdsize
      template.bytesize + 16, # dataoff
      trie_bytes.bytesize, # datasize
    ].pack("V4")
    header = template.dup
    header[16, 8] = [1, 16].pack("V2") # ncmds, sizeofcmds
    header + command + trie_bytes
  end

  def test_parses_exports_from_exports_trie_command
    trie = ExportsTrie::Trie.new
    trie.add("_hello", entry(0, :address => 0x1000))
    trie.add("_goodbye", entry(ExportsTrie::EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL, :address => 0x2000))

    file = MachO::MachOFile.new_from_bin(macho_with_exports_trie_command(trie.serialize))

    assert_equal trie, file.exports_trie
    assert_equal trie, file[:LC_DYLD_EXPORTS_TRIE].first.exports_trie
  end

  def test_exports_trie_command_type_check
    file = MachO.open(fixture(:x86_64, "hello.bin"))
    lc = file[:LC_FUNCTION_STARTS].first

    error = assert_raises(MachO::ExportsTrieError) { lc.exports_trie }
    assert_match(/does not contain an export trie/, error.message)
  end

  # A symbol set exercising an empty prefix, symbols that prefix other
  # symbols, a long common prefix, every terminal kind, and enough
  # long-named symbols to push node offsets across ULEB128 size tiers.
  def acceptance_entries
    long_prefix = "_a_very_long_common_prefix_" + "abcdefghij" * 20
    entries = {
      "" => entry(0, :address => 0),
      "_a" => entry(0, :address => 1),
      "_ab" => entry(0, :address => 2),
      "_regular" => entry(0, :address => 0x1000),
      "_weak" => entry(ExportsTrie::EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION, :address => 0x2000),
      "_thread_local" => entry(ExportsTrie::EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL, :address => 0x3000),
      "_absolute" => entry(ExportsTrie::EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE, :address => 0xdead),
      "_reexport" => entry(ExportsTrie::EXPORT_SYMBOL_FLAGS_REEXPORT, :other => 2, :imported_name => "_real_name"),
      "_reexport_same_name" => entry(ExportsTrie::EXPORT_SYMBOL_FLAGS_REEXPORT, :other => 3),
      "_stub_and_resolver" => entry(ExportsTrie::EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER,
                                    :resolver_offset => 0x40, :stub_offset => 0x50),
      "#{long_prefix}_one" => entry(0, :address => 0x4000),
      "#{long_prefix}_two" => entry(0, :address => 0x5000),
    }

    700.times do |i|
      entries["_exported_symbol_number_#{i}_with_a_fairly_long_name"] = entry(0, :address => 0x10000 + i)
    end

    entries
  end

  def build_trie(entries)
    trie = ExportsTrie::Trie.new
    entries.each { |name, terminal| trie.add(name, terminal) }
    trie
  end

  def test_round_trip_preserves_every_entry
    entries = acceptance_entries
    trie = build_trie(entries)

    bytes = trie.serialize
    # offsets cross the 2-byte and 3-byte ULEB128 tiers
    assert_operator bytes.bytesize, :>, 16_384

    reparsed = ExportsTrie::Trie.parse(bytes)
    assert_equal entries.size, reparsed.entries.size
    entries.each do |name, terminal|
      assert_equal terminal, reparsed.lookup(name), "mismatch for #{name.inspect}"
    end
    assert_equal trie, reparsed

    # serialization is deterministic and stable across round trips
    assert_equal bytes, reparsed.serialize
    assert_equal bytes, build_trie(entries).serialize
  end

  def test_round_trip_preserves_terminal_kinds
    reparsed = ExportsTrie::Trie.parse(build_trie(acceptance_entries).serialize)

    assert_equal :regular, reparsed.lookup("_regular").kind
    assert_equal :thread_local, reparsed.lookup("_thread_local").kind
    assert_equal :absolute, reparsed.lookup("_absolute").kind
    assert_predicate reparsed.lookup("_weak"), :weak_definition?

    reexport = reparsed.lookup("_reexport")
    assert_predicate reexport, :reexport?
    assert_equal 2, reexport.other
    assert_equal "_real_name", reexport.imported_name

    same_name = reparsed.lookup("_reexport_same_name")
    assert_predicate same_name, :reexport?
    assert_equal 3, same_name.other
    assert_nil same_name.imported_name

    stub = reparsed.lookup("_stub_and_resolver")
    assert_predicate stub, :stub_and_resolver?
    assert_equal 0x40, stub.resolver_offset
    assert_equal 0x50, stub.stub_offset
  end

  def test_add_splits_and_delete_merges_shared_prefixes
    trie = ExportsTrie::Trie.new
    foo = entry(0, :address => 1)
    foobar = entry(0, :address => 2)
    fop = entry(0, :address => 3)

    trie.add("_foo", foo)
    trie.add("_foobar", foobar)
    trie.add("_fop", fop)

    assert_equal foo, trie.lookup("_foo")
    assert_equal foobar, trie.lookup("_foobar")
    assert_equal fop, trie.lookup("_fop")
    assert_equal trie, ExportsTrie::Trie.parse(trie.serialize)

    # replacing an existing symbol keeps everything else intact
    new_foo = entry(0, :address => 10)
    trie.add("_foo", new_foo)
    assert_equal new_foo, trie.lookup("_foo")
    assert_equal 3, trie.entries.size

    assert_equal new_foo, trie.delete("_foo")
    assert_nil trie.lookup("_foo")
    assert_equal foobar, trie.lookup("_foobar")
    assert_equal trie, ExportsTrie::Trie.parse(trie.serialize)

    assert_equal foobar, trie.delete("_foobar")
    assert_equal fop, trie.delete("_fop")
    assert_empty trie.names
    assert_predicate trie, :empty?

    assert_nil trie.delete("_never_existed")
  end

  def test_delete_terminal_on_shared_prefix_node
    trie = ExportsTrie::Trie.new
    trie.add("_foo", entry(0, :address => 1))
    trie.add("_foobar", entry(0, :address => 2))

    # deleting "_foo" must not merge away the node still needed by "_foobar"
    trie.delete("_foo")
    assert_equal %w[_foobar], trie.names
    assert_equal 2, trie.lookup("_foobar").address
    assert_equal trie, ExportsTrie::Trie.parse(trie.serialize)
  end

  def test_prefix_enumeration
    trie = ExportsTrie::Trie.new
    trie.add("", entry(0, :address => 0))
    trie.add("_foo", entry(0, :address => 1))
    trie.add("_foobar", entry(0, :address => 2))
    trie.add("_foos", entry(0, :address => 3))
    trie.add("_bar", entry(0, :address => 4))

    assert_equal %w[_foo _foobar _foos], trie.each("_foo").map { |name, _terminal| name }.sort
    assert_equal %w[_foo _foobar _foos], trie.each("_fo").map { |name, _terminal| name }.sort
    assert_equal %w[_foobar], trie.each("_foob").map { |name, _terminal| name }
    assert_equal %w[_bar _foo _foobar _foos], trie.each("_").map { |name, _terminal| name }.sort
    assert_empty trie.each("_nope").to_a
    assert_empty trie.each("_foox").to_a

    all = trie.each.to_a
    assert_equal 5, all.size
    assert_equal trie.entries, trie.each.to_h

    # prefix enumeration also works with a block
    yielded = []
    trie.each("_bar") { |name, terminal| yielded << [name, terminal] }
    assert_equal [["_bar", trie.lookup("_bar")]], yielded
  end

  def test_enumerator_without_block
    trie = build_trie(acceptance_entries)
    enum = trie.each("_exported_symbol_number_1")

    assert_kind_of Enumerator, enum
    assert_equal 111, enum.count
  end

  def test_rejects_malformed_data
    # truncated ULEB128 terminal size
    assert_raises(MachO::ExportsTrieError) { ExportsTrie::Trie.parse("\x80".b) }
    # terminal overruns the data
    assert_raises(MachO::ExportsTrieError) { ExportsTrie::Trie.parse("\x05\x00".b) }
    # missing child count byte
    assert_raises(MachO::ExportsTrieError) { ExportsTrie::Trie.parse("\x00".b) }
    # unterminated edge label
    assert_raises(MachO::ExportsTrieError) { ExportsTrie::Trie.parse("\x00\x01a".b) }
    # child pointing at the root: cycle
    assert_raises(MachO::ExportsTrieError) { ExportsTrie::Trie.parse("\x00\x01a\x00\x00".b) }
    # child offset out of bounds
    assert_raises(MachO::ExportsTrieError) { ExportsTrie::Trie.parse("\x00\x01a\x00\x7f".b) }
    # terminal size mismatch
    assert_raises(MachO::ExportsTrieError) { ExportsTrie::Trie.parse("\x01\x00\x00".b) }
  end

  def test_empty_trie
    trie = ExportsTrie::Trie.new

    assert_predicate trie, :empty?
    assert_empty trie.names
    assert_equal trie, ExportsTrie::Trie.parse(trie.serialize)
    assert_equal ExportsTrie::Trie.new, ExportsTrie::Trie.parse("")
  end

  def test_to_h
    trie = ExportsTrie::Trie.new
    trie.add("_sym", entry(0, :address => 0x1234))

    entry_hash = trie.lookup("_sym").to_h
    assert_equal 0, entry_hash["flags"]
    assert_equal :regular, entry_hash["kind"]
    assert_equal 0x1234, entry_hash["address"]

    trie_hash = trie.to_h
    assert_equal 1, trie_hash["exports"].size
    assert_equal "_sym", trie_hash["exports"].first["name"]
    assert_equal entry_hash, trie_hash["exports"].first.except("name")
  end
end
