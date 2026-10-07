# frozen_string_literal: true

require_relative "helpers"

class BindingsTest < Minitest::Test
  include Helpers

  def test_rewrite_only_selected_normal_binding
    file = prepared_hello
    command = file[:LC_DYLD_INFO_ONLY].first
    original_size = command.bind_size
    stream = bind_stream(1, "_a", 0) + bind_stream(2, "_a", 8) + "\x00".b
    replace_stream(file, command.bind_off, original_size, stream)

    file.bind(1, "_a", :target_ordinal => 2, :target_symbol => "_b", :addend => 7)
    command = file[:LC_DYLD_INFO_ONLY].first
    records = parse_stream(file, command.bind_off, command.bind_size, :bind)

    assert_equal [[2, "_b", 7, 0], [2, "_a", 0, 0]],
                 records.map { |record| [record.ordinal, record.symbol, record.addend, record.segment_offset] }
  end

  def test_rewrite_lazy_binding_and_linkedit_offsets
    file = prepared_hello
    original = file.serialize
    command = file[:LC_DYLD_INFO_ONLY].first
    original_export_off = command.export_off
    original_lazy_bind_size = command.lazy_bind_size
    original_symoff = file.command(:LC_SYMTAB).first.symoff
    original_indirectsymoff = file.command(:LC_DYSYMTAB).first.indirectsymoff

    file.lazy_bind(1, "_printf", :target_ordinal => 1, :target_symbol => "_compatible", :addend => -3)
    command = file[:LC_DYLD_INFO_ONLY].first
    records = parse_stream(file, command.lazy_bind_off, command.lazy_bind_size, :lazy_bind)

    assert_equal [[1, "_compatible", -3]], records.map { |record| [record.ordinal, record.symbol, record.addend] }
    delta = command.lazy_bind_size - original_lazy_bind_size
    assert_equal original_export_off + delta, command.export_off
    assert_equal original_symoff,
                 file.command(:LC_SYMTAB).first.symoff
    assert_equal original_indirectsymoff,
                 file.command(:LC_DYSYMTAB).first.indirectsymoff
    assert_operator file.serialize.bytesize, :>=, original.bytesize
    assert_equal file.serialize.bytesize - 8192,
                 file.segments.find { |segment| segment.segname == "__LINKEDIT" }.filesize
  end

  def test_weak_binding_is_rewritten_without_stub_helper_requirement
    file = prepared_hello
    command = file[:LC_DYLD_INFO_ONLY].first
    stream = weak_binding_stream(1, "_shared") + weak_binding_stream(2, "_shared") + "\x00".b
    file.serialize[command.view.offset + 24, 4] = [command.bind_off + command.bind_size].pack("L<")
    insert_stream(file, :weak_bind, stream)

    file.weak_bind(1, "_shared", :target_ordinal => 2, :target_symbol => "_other")
    command = file[:LC_DYLD_INFO_ONLY].first
    records = parse_stream(file, command.weak_bind_off, command.weak_bind_size, :weak_bind)

    assert_equal [[2, "_other"], [2, "_shared"]],
                 records.map { |record| [record.ordinal, record.symbol] }
  end

  def test_lazy_binding_without_relocatable_helper_leaves_bytes_unchanged
    file = prepared_hello
    original = file.serialize
    helper = file.segments.flat_map(&:sections).find { |section| section.sectname == "__stub_helper" }
    file.serialize[helper.offset + 16, 1] = "\x90".b
    file.populate_fields

    assert_raises MachO::BindingError do
      file.lazy_bind(1, "_printf", :target_ordinal => 1, :target_symbol => "_compatible")
    end

    assert_equal original, file.serialize
  end

  def test_lazy_binding_rejects_non_x86_64_layouts
    file = MachO::MachOFile.new(fixture(:i386, "hello.bin"))

    assert_raises MachO::BindingError do
      file.lazy_bind(1, "_printf", :target_ordinal => 1, :target_symbol => "_compatible")
    end
  end

  private

  def prepared_hello
    MachO::MachOFile.new(fixture(:x86_64, "hello.bin"))
  end

  def bind_stream(ordinal, symbol, address)
    [0x10 | ordinal, 0x40].pack("C2") + symbol.b + "\x00".b +
      [0x70, 0].pack("C2") + MachO::Bindings.pack_uleb128(address) +
      [0x90].pack("C")
  end

  def weak_binding_stream(ordinal, symbol)
    [0x40].pack("C") + symbol.b + "\x00".b +
      [0x60, 0, 0x10 | ordinal, 0x90].pack("C4")
  end

  def replace_stream(file, offset, old_size, stream)
    raise "test stream too large" if stream.bytesize > old_size

    file.serialize[offset, old_size] = stream.ljust(old_size, "\x00".b)
    file.populate_fields
  end

  def insert_stream(file, _stream_name, stream)
    command = file[:LC_DYLD_INFO_ONLY].first
    bind_end = command.bind_off + command.bind_size
    data = file.serialize
    file.serialize.replace(data.byteslice(0, bind_end) + stream + data.byteslice(bind_end, data.bytesize - bind_end))
    file.serialize[command.view.offset + 24, 4] = [bind_end].pack("L<")
    file.serialize[command.view.offset + 28, 4] = [stream.bytesize].pack("L<")
    file.populate_fields
    command = file[:LC_DYLD_INFO_ONLY].first
    { :weak_bind_off => 24, :lazy_bind_off => 32, :export_off => 40 }.each do |field, offset|
      value = command.public_send(field)
      next if value.zero? || field == :weak_bind_off || value < bind_end

      file.serialize[command.view.offset + offset, 4] = [value + stream.bytesize].pack("L<")
    end
    file.populate_fields
  end

  def parse_stream(file, offset, size, stream)
    symbol = stream == :lazy_bind ? :lazy : :bind
    MachO::Bindings::Parser.new(file.serialize.byteslice(offset, size), symbol, 8).parse
  end
end
