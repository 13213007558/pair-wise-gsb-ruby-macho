# frozen_string_literal: true

require_relative "helpers"
require "json"

class ObjC2Test < Minitest::Test
  include Helpers

  BASE = 0x1_0000_0000
  # Unmapped vmaddr; chosen so that FAST_DATA_MASK leaves it unchanged.
  BAD_ADDRESS = 0x7ead_beef_0000

  # Builds a synthetic 64-bit Mach-O fixed image carrying objc2 metadata.
  # The whole file lives in a single __DATA segment mapped at BASE with
  # fileoff 0, so vmaddr BASE + n corresponds to file offset n.
  class FixtureImage
    MH_MAGIC_64 = 0xfeedfacf
    CPU_TYPE_ARM64 = 0x0100000c
    MH_DYLIB = 0x6
    LC_SEGMENT_64 = 0x19
    LC_ENCRYPTION_INFO_64 = 0x2c

    def initialize(base, encrypted: false)
      @base = base
      @encrypted = encrypted
      @header_size = 32 + 72 + (3 * 80) + (encrypted ? 24 : 0)
      @body = "".b
      @sections = {}
    end

    # @return [Integer] the vmaddr of the next byte to be emitted
    def addr
      @base + @header_size + @body.bytesize
    end

    def align(alignment = 8)
      pad = (alignment - (@body.bytesize % alignment)) % alignment
      @body << ("\0" * pad)
    end

    def emit(bytes)
      at = addr
      @body << bytes
      at
    end

    def u64(value)
      emit([value].pack("Q<"))
    end

    def u32(value)
      emit([value].pack("L<"))
    end

    def i32(value)
      emit([value].pack("l<"))
    end

    def cstring(string)
      emit(string.b + "\0")
    end

    def patch_u64(at, value)
      @body[at - @base - @header_size, 8] = [value].pack("Q<")
    end

    def section(name)
      start = addr
      yield
      @sections[name] = [start, addr - start]
    end

    def build
      total = @header_size + @body.bytesize
      sizeofcmds = @header_size - 32
      image = [
        MH_MAGIC_64,
        CPU_TYPE_ARM64,
        0, # cpusubtype
        MH_DYLIB,
        @encrypted ? 2 : 1, # ncmds
        sizeofcmds,
        0, # flags
        0, # reserved
      ].pack("L<8")

      image << [LC_SEGMENT_64, 72 + (3 * 80)].pack("L<2")
      image << "__DATA".ljust(16, "\0")
      image << [@base, total, 0, total, 3, 3, 3, 0].pack("Q<4L<4")

      %w[__objc_classlist __objc_catlist __objc_protolist].each do |name|
        addr, size = @sections.fetch(name)
        image << name.ljust(16, "\0")
        image << "__DATA".ljust(16, "\0")
        image << [addr, size, addr - @base, 3, 0, 0, 0, 0, 0, 0].pack("Q<2L<8")
      end

      # LC_ENCRYPTION_INFO_64 with cryptid 1 marks the image as encrypted.
      image << [LC_ENCRYPTION_INFO_64, 24, 0x1000, 0x1000, 1, 0].pack("L<6") if @encrypted

      image << @body
      image
    end
  end

  def setup
    @image_bytes = build_image
    @macho = MachO::MachOFile.new_from_bin(@image_bytes)
    @graph = MachO::ObjC2.browse(@macho)
  end

  def test_graph_is_serializable
    assert_equal "macho-objc2-graph/1", @graph["format"]
    assert_equal @graph, JSON.parse(JSON.generate(@graph))
  end

  def test_class_hierarchy_and_metaclass
    base = classes_by_name.fetch("Base")
    derived = classes_by_name.fetch("Derived")

    assert_equal base["id"], derived["superclass"]
    assert_nil base["superclass"]

    metaclass = @graph["metaclasses"].find { |node| node["id"] == derived["metaclass"] }
    refute_nil metaclass
    assert_equal "Derived", metaclass["name"]
    assert_equal base["metaclass"], metaclass["superclass"]

    class_method = methods_by_id.fetch(metaclass["methods"].first)
    assert_equal "derivedClassMethod", class_method["name"]
    assert_equal "class", class_method["kind"]
    assert_equal "class", class_method["source"]
  end

  def test_normal_and_relative_method_lists
    base = classes_by_name.fetch("Base")
    shared = owned_methods(base).find { |method| method["name"] == "sharedMethod" }
    assert_equal "normal", shared["list"]
    assert_equal "instance", shared["kind"]
    assert_equal "v16@0:8", shared["types"]

    derived = classes_by_name.fetch("Derived")
    derived_only = owned_methods(derived).find { |method| method["name"] == "derivedOnly" }
    assert_equal "relative", derived_only["list"]
  end

  def test_category_same_name_method_preserved
    category = @graph["categories"].find { |node| node["name"] == "Additions" }
    refute_nil category
    assert_equal classes_by_name.fetch("Derived")["id"], category["class"]
    assert_equal %w[catOnly sharedMethod], method_names(category).sort

    shared = @graph["methods"].select { |method| method["name"] == "sharedMethod" }
    assert_equal 2, shared.size
    assert_equal 2, shared.map { |method| method["id"] }.uniq.size

    provenance = shared.map { |method| [method["source"], method["owner"]] }
    assert_includes provenance, ["class", classes_by_name.fetch("Base")["id"]]
    assert_includes provenance, ["category", category["id"]]
  end

  def test_shared_protocol_identity
    protocols = @graph["protocols"].select { |node| node["name"] == "SharedProto" }
    assert_equal 1, protocols.size

    shared = protocols.first
    derived = classes_by_name.fetch("Derived")
    category = @graph["categories"].find { |node| node["name"] == "Additions" }
    assert_equal [shared["id"]], derived["protocols"]
    assert_equal [shared["id"]], category["protocols"]

    instance_names = shared["instance_methods"].map { |id| methods_by_id.fetch(id)["name"] }
    class_names = shared["class_methods"].map { |id| methods_by_id.fetch(id)["name"] }
    assert_equal ["protoInstance"], instance_names
    assert_equal ["protoClass"], class_names
  end

  def test_cyclic_protocols
    loop_a = @graph["protocols"].find { |node| node["name"] == "LoopA" }
    loop_b = @graph["protocols"].find { |node| node["name"] == "LoopB" }
    refute_nil loop_a
    refute_nil loop_b
    assert_equal [loop_b["id"]], loop_a["protocols"]
    assert_equal [loop_a["id"]], loop_b["protocols"]
  end

  def test_bad_address_diagnostics
    broken = @graph["classes"].find { |node| node["name"].nil? }
    refute_nil broken
    assert_equal "unreadable class_ro data", broken["error"]

    diagnostic = @graph["diagnostics"].find do |entry|
      (BAD_ADDRESS...(BAD_ADDRESS + 0x40)).cover?(entry["address"])
    end
    refute_nil diagnostic
    assert_equal "warning", diagnostic["level"]
    assert_match(/unmapped pointer 0x7eadbeef/, diagnostic["message"])

    # extraction continued past the broken class
    assert_equal %w[Base Derived], classes_by_name.keys.sort
  end

  def test_caller_provided_mapper
    data = @image_bytes
    mapper = lambda do |vmaddr|
      offset = vmaddr - BASE
      offset >= 0 && offset < data.bytesize ? offset : nil
    end

    sections = {}
    @macho.segments.each do |segment|
      segment.sections.each do |section|
        sections[section.section_name] = [section.addr, section.size]
      end
    end

    graph = MachO::ObjC2.extract(
      :data => data,
      :mapper => mapper,
      :classlist => sections["__objc_classlist"],
      :catlist => sections["__objc_catlist"],
      :protolist => sections["__objc_protolist"]
    )

    assert_equal @graph["classes"], graph["classes"]
    assert_equal @graph["methods"], graph["methods"]
    assert_equal @graph["protocols"], graph["protocols"]
  end

  def test_rejects_non_macho_file
    fat = MachO::FatFile.new(fixture(%i[i386 x86_64], "hello.bin"))
    assert_raises(MachO::ObjC2Error) { MachO::ObjC2.browse(fat) }
  end

  def test_rejects_32_bit
    macho = MachO::MachOFile.new(fixture(:i386, "hello.bin"))
    error = assert_raises(MachO::ObjC2Error) { MachO::ObjC2.browse(macho) }
    assert_match(/64-bit/, error.message)
  end

  def test_rejects_encrypted
    macho = MachO::MachOFile.new_from_bin(build_image(:encrypted => true))
    error = assert_raises(MachO::ObjC2Error) { MachO::ObjC2.browse(macho) }
    assert_match(/encrypted/, error.message)
  end

  private

  def classes_by_name
    @graph["classes"].reject { |node| node["name"].nil? }.to_h { |node| [node["name"], node] }
  end

  def methods_by_id
    @graph["methods"].to_h { |node| [node["id"], node] }
  end

  def method_names(node)
    node["methods"].map { |id| methods_by_id.fetch(id)["name"] }
  end

  def owned_methods(node)
    node["methods"].map { |id| methods_by_id.fetch(id) }
  end

  def build_image(encrypted: false)
    image = FixtureImage.new(BASE, :encrypted => encrypted)

    s_base = image.cstring("Base")
    s_derived = image.cstring("Derived")
    s_additions = image.cstring("Additions")
    s_shared_proto = image.cstring("SharedProto")
    s_loop_a = image.cstring("LoopA")
    s_loop_b = image.cstring("LoopB")
    m_shared = image.cstring("sharedMethod")
    m_base_only = image.cstring("baseOnly")
    m_derived_only = image.cstring("derivedOnly")
    m_derived_class = image.cstring("derivedClassMethod")
    m_cat_only = image.cstring("catOnly")
    m_proto_instance = image.cstring("protoInstance")
    m_proto_class = image.cstring("protoClass")
    t_void = image.cstring("v16@0:8")
    image.align

    imp = ->(index) { BASE + 0x4000 + (index * 0x10) }

    # Base uses a normal method list; everything else uses relative ones.
    base_methods = method_list_normal(image, [
      [m_shared, t_void, imp.call(1)],
      [m_base_only, t_void, imp.call(2)],
    ])
    derived_methods = method_list_relative(image, [
      [m_derived_only, t_void, imp.call(3)],
    ])
    derived_meta_methods = method_list_relative(image, [
      [m_derived_class, t_void, imp.call(4)],
    ])
    cat_methods = method_list_relative(image, [
      [m_shared, t_void, imp.call(5)],
      [m_cat_only, t_void, imp.call(6)],
    ])
    proto_instance_methods = method_list_normal(image, [
      [m_proto_instance, t_void, imp.call(7)],
    ])
    proto_class_methods = method_list_normal(image, [
      [m_proto_class, t_void, imp.call(8)],
    ])

    shared_proto = protocol(image, s_shared_proto, 0, proto_instance_methods, proto_class_methods)

    # LoopA and LoopB reference each other, forming a protocol cycle.
    loop_a = image.addr
    image.u64(0)
    image.u64(s_loop_a)
    loop_a_protos_ptr = image.addr
    image.u64(0)
    5.times { image.u64(0) }

    loop_b = image.addr
    image.u64(0)
    image.u64(s_loop_b)
    loop_b_protos_ptr = image.addr
    image.u64(0)
    5.times { image.u64(0) }

    image.patch_u64(loop_a_protos_ptr, protocol_list(image, [loop_b]))
    image.patch_u64(loop_b_protos_ptr, protocol_list(image, [loop_a]))

    derived_protos = protocol_list(image, [shared_proto])
    cat_protos = protocol_list(image, [shared_proto])

    base_ro = class_ro(image, 0, s_base, base_methods, 0)
    base_meta_ro = class_ro(image, 1, s_base, 0, 0)
    derived_ro = class_ro(image, 0, s_derived, derived_methods, derived_protos)
    derived_meta_ro = class_ro(image, 1, s_derived, derived_meta_methods, 0)

    base_meta = objc_class(image, 0, 0, base_meta_ro)
    base_cls = objc_class(image, base_meta, 0, base_ro)
    derived_meta = objc_class(image, 0, base_meta, derived_meta_ro)
    derived_cls = objc_class(image, derived_meta, base_cls, derived_ro)
    broken_cls = objc_class(image, 0, 0, BAD_ADDRESS)

    additions = category(image, s_additions, derived_cls, cat_methods, 0, cat_protos)

    image.section("__objc_classlist") do
      image.u64(base_cls)
      image.u64(derived_cls)
      image.u64(broken_cls)
    end
    image.section("__objc_catlist") { image.u64(additions) }
    image.section("__objc_protolist") do
      image.u64(shared_proto)
      image.u64(loop_a)
      image.u64(loop_b)
    end

    image.build
  end

  def method_list_normal(image, entries)
    at = image.addr
    image.u32(24)
    image.u32(entries.size)
    entries.each do |name, types, imp|
      image.u64(name)
      image.u64(types)
      image.u64(imp)
    end
    at
  end

  def method_list_relative(image, entries)
    at = image.addr
    image.u32(12 | 3)
    image.u32(entries.size)
    entries.each do |name, types, imp|
      entry = image.addr
      image.i32(name - entry)
      image.i32(types - (entry + 4))
      image.i32(imp - (entry + 8))
    end
    at
  end

  def protocol_list(image, protocols)
    at = image.addr
    image.u64(protocols.size)
    protocols.each { |protocol| image.u64(protocol) }
    at
  end

  def protocol(image, name, protocols, instance_methods, class_methods)
    at = image.addr
    image.u64(0) # isa
    image.u64(name)
    image.u64(protocols)
    image.u64(instance_methods)
    image.u64(class_methods)
    image.u64(0) # optionalInstanceMethods
    image.u64(0) # optionalClassMethods
    image.u64(0) # instanceProperties
    at
  end

  def class_ro(image, flags, name, methods, protocols)
    at = image.addr
    image.u32(flags)
    image.u32(0) # instanceStart
    image.u32(0) # instanceSize
    image.u32(0) # reserved
    image.u64(0) # ivarLayout
    image.u64(name)
    image.u64(methods)
    image.u64(protocols)
    image.u64(0) # ivars
    image.u64(0) # weakIvarLayout
    image.u64(0) # baseProperties
    at
  end

  def objc_class(image, isa, superclass, data)
    at = image.addr
    image.u64(isa)
    image.u64(superclass)
    image.u64(0) # cache
    image.u64(0) # vtable
    image.u64(data)
    at
  end

  def category(image, name, cls, instance_methods, class_methods, protocols)
    at = image.addr
    image.u64(name)
    image.u64(cls)
    image.u64(instance_methods)
    image.u64(class_methods)
    image.u64(protocols)
    image.u64(0) # instanceProperties
    at
  end
end
