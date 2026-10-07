# frozen_string_literal: true

require_relative "helpers"

class BindRewritingTest < Minitest::Test
  include Helpers

  def test_rewrite_only_matching_regular_binding
    bin = duplicate_regular_bindings
    original = bin.dup
    file = MachO::MachOFile.new_from_bin(bin)

    file.bind!(1, "_sh", 1, "_renamed", 42)
    result = file.serialize
    old_bindings = parse_bindings(bin, :bind, MachO::MachOFile.new_from_bin(bin))
    new_bindings = parse_bindings(result, :bind, MachO::MachOFile.new_from_bin(result))

    expected_old = [
      { :ordinal => 1, :symbol => "_sh", :addend => 0, :address => 0x100000000 },
      { :ordinal => 2, :symbol => "_sh", :addend => 0, :address => 0x100000000 },
    ]
    expected_new = [
      { :ordinal => 1, :symbol => "_renamed", :addend => 42, :address => 0x100000000 },
      { :ordinal => 2, :symbol => "_sh", :addend => 0, :address => 0x100000000 },
    ]
    actual_old = old_bindings.map { |binding| binding.slice(:ordinal, :symbol, :addend, :address) }
    actual_new = new_bindings.map { |binding| binding.slice(:ordinal, :symbol, :addend, :address) }
    assert_equal expected_old, actual_old
    assert_equal expected_new, actual_new
    assert_operator result.bytesize, :>, original.bytesize
  end

  def test_rewrite_weak_binding_without_lazy_layout_restriction
    bin = weak_bind_fixture
    file = MachO::MachOFile.new_from_bin(bin)

    file.weak_bind!("_weak_one", "_weak_renamed", 0)
    result = file.serialize
    bindings = parse_bindings(result, :weak_bind, MachO::MachOFile.new_from_bin(result))

    assert_equal(
      [
        { :symbol => "_weak_renamed", :addend => 0, :address => 0x100001018 },
        { :symbol => "_weak_two", :addend => 0, :address => 0x100001020 },
      ],
      bindings.map { |binding| binding.slice(:symbol, :addend, :address) }
    )
    assert_operator result.bytesize, :>, bin.bytesize
  end

  def test_rewrite_only_matching_lazy_binding_and_relocates_stub_helper
    bin = duplicate_lazy_bindings
    file = MachO::MachOFile.new_from_bin(bin)

    file.lazy_bind!(2, "_shared", 3, "_shared_renamed", 0)
    result = file.serialize
    bindings = parse_bindings(result, :lazy_bind, MachO::MachOFile.new_from_bin(result))
    dyld = dyld_info(result)

    assert_equal [[1, "_shared"], [3, "_shared_renamed"], [1, "_dlsym"], [1, "_printf"], [1, "_strcmp"]],
                 bindings.map { |binding| [binding[:ordinal], binding[:symbol]] }
    assert_equal 9, result.bytesize - bin.bytesize
    assert_equal 8305, dyld["export_off"]
    assert_equal 9, dyld["lazy_bind_size"] - 72
    assert_equal [14].pack("L<"), result.byteslice(stub_helper_immediate_offset(result, 14), 4)
    assert_equal [36].pack("L<"), result.byteslice(stub_helper_immediate_offset(result, 36), 4)
    assert_equal [0].pack("L<"), result.byteslice(stub_helper_immediate_offset(result, 0), 4)
  end

  def test_non_x86_64_lazy_layout_is_rejected_without_changing_bytes
    bin = File.binread(fixture(:i386, "hello.bin"))
    original = bin.dup
    file = MachO::MachOFile.new_from_bin(bin)

    assert_raises MachO::BindRewriteError do
      file.lazy_bind!(1, "_printf", 1, "_printf_renamed", 0)
    end

    assert_equal original, file.serialize
  end

  private

  def dyld_info(bin)
    MachO::MachOFile.new_from_bin(bin).command(:LC_DYLD_INFO_ONLY).first.to_h
  end

  def parse_bindings(bin, stream, file = MachO::MachOFile.new_from_bin(bin))
    command = file.command(:LC_DYLD_INFO_ONLY).first || file.command(:LC_DYLD_INFO).first
    offset, size = case stream
    when :bind then [command.bind_off, command.bind_size]
    when :weak_bind then [command.weak_bind_off, command.weak_bind_size]
    when :lazy_bind then [command.lazy_bind_off, command.lazy_bind_size]
    end
    parser = MachO::BindRewriter.new(file, stream, 0, "", 0, "", 0)
    parser.send(:parse_stream, bin.byteslice(offset, size)).first.map do |entry|
      normal_segments = file.segments.reject { |candidate| candidate.segname == "__PAGEZERO" }
      segment = entry.segment && normal_segments[entry.segment - 1]
      {
        :ordinal => entry.ordinal,
        :symbol => entry.symbol,
        :addend => entry.addend,
        :address => segment ? segment.vmaddr + entry.offset : entry.offset,
      }
    end
  end

  def duplicate_regular_bindings
    bin = File.binread(fixture(:x86_64, "hello.bin"))
    stream = "\x11\x71\x00\x11\x40_sh\x00\x90\x12\x71\x00\x12\x40_sh\x00\x90\x00".b
    bin[8200, 24] = stream.ljust(24, "\x00".b)
    bin
  end

  def weak_bind_fixture
    bin = File.binread(fixture(:x86_64, "hello.bin"))
    first = "\x40_weak_one\x00\x72\x10\x90".b
    second = "\x40_weak_two\x00\x72\x18\x90".b
    stream = (first + second + "\x00").b
    insert_linkedit(bin, 8224, stream)
    command = MachO::MachOFile.new_from_bin(bin).command(:LC_DYLD_INFO_ONLY).first.view.offset
    bin[command + 24, 4] = [8224].pack("L<")
    bin[command + 28, 4] = [stream.bytesize].pack("L<")
    bin
  end

  def duplicate_lazy_bindings
    bin = File.binread(fixture(:x86_64, "libextrahello.dylib"))
    bin[8224 + 4, 8] = "_shared\x00".b
    second_entry = 8224 + 14
    bin.getbyte(second_entry) == 0x71 or raise "unexpected libextrahello layout"
    bin.setbyte(second_entry + 2, 0x12)
    bin[second_entry + 4, 8] = "_shared\x00".b
    bin
  end

  def insert_linkedit(bin, offset, bytes)
    insertion = bytes.bytesize
    bin[offset, 0] = bytes
    shift_field(bin, 960 + 16, insertion, offset)
    shift_field(bin, 960 + 24, insertion, offset)
    shift_field(bin, 960 + 32, insertion, offset)
    shift_field(bin, 960 + 40, insertion, offset)
    shift_field(bin, 1008 + 8, insertion, offset)
    shift_field(bin, 1008 + 16, insertion, offset)
    shift_field(bin, 1032 + 32, insertion, offset)
    shift_field(bin, 1032 + 40, insertion, offset)
    shift_field(bin, 1032 + 48, insertion, offset)
    shift_field(bin, 1032 + 56, insertion, offset)
    shift_field(bin, 1032 + 64, insertion, offset)
    shift_field(bin, 1032 + 72, insertion, offset)
    shift_field(bin, 1312 + 8, insertion, offset)
    shift_field(bin, 1328 + 8, insertion, offset)
    bin
  end

  def shift_field(bin, field_offset, delta, insertion_offset)
    value = bin.byteslice(field_offset, 4).unpack1("L<")
    bin[field_offset, 4] = [value + delta].pack("L<") if value >= insertion_offset
  end

  def stub_helper_immediate_offset(bin, value)
    file = MachO::MachOFile.new_from_bin(bin)
    section = file.segments.flat_map(&:sections).find do |candidate|
      candidate.segname == "__TEXT" && candidate.sectname == "__stub_helper"
    end
    bytes = bin.byteslice(section.offset, section.size)
    index = (0..bytes.bytesize - 10).find do |candidate|
      bytes.getbyte(candidate) == 0x68 &&
        bytes.getbyte(candidate + 5) == 0xe9 &&
        bytes.byteslice(candidate + 1, 4).unpack1("L<") == value
    end
    refute_nil index
    section.offset + index + 1
  end
end
