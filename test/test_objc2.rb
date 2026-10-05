# frozen_string_literal: true

require_relative "helpers"
require "json"

# Builds a synthetic 64-bit Mach-O file image carrying ObjC2 metadata.
# Blobs are allocated sequentially after the load commands; pointer and
# relative-offset fixups are applied once every address is known.
class ObjC2FixtureBuilder
  VMADDR = 0x1_0000_0000
  HEADER_SIZE = 32
  SEGMENT_COMMAND_64_SIZE = 72
  SECTION_64_SIZE = 80
  ENCRYPTION_COMMAND_64_SIZE = 24

  Blob = Struct.new(:data, :align, :addr, :offset)

  def initialize(encrypted: false)
    @encrypted = encrypted
    @blobs = []
    @fixups = []
    @sections = []
  end

  def blob(data, align: 8, section: nil)
    entry = Blob.new(data.b, align, nil, nil)
    @blobs << entry
    @sections << [section, entry] unless section.nil?
    entry
  end

  def cstring(string)
    blob("#{string}\x00".b, :align => 1)
  end

  # patches an 8-byte pointer at +at+ within +into+ to point at +target+
  def pointer(into, at, target)
    @fixups << -> { into.data[at, 8] = [target.addr].pack("Q<") }
  end

  # patches a signed 32-bit offset at +at+ within +into+, relative to the
  # address of the field itself, targeting +target+
  def relative32(into, at, target)
    @fixups << -> { into.data[at, 4] = [target.addr - (into.addr + at)].pack("l<") }
  end

  # patches a signed 32-bit offset at +at+ within +into+, relative to the
  # address of the field itself, targeting the absolute address +addr+
  def relative32_to_addr(into, at, addr)
    @fixups << -> { into.data[at, 4] = [addr - (into.addr + at)].pack("l<") }
  end

  def build
    command_size = SEGMENT_COMMAND_64_SIZE + (@sections.size * SECTION_64_SIZE)
    command_size += ENCRYPTION_COMMAND_64_SIZE if @encrypted
    ncmds = @encrypted ? 2 : 1

    offset = HEADER_SIZE + command_size
    @blobs.each do |entry|
      offset = align_up(offset, entry.align)
      entry.offset = offset
      entry.addr = VMADDR + offset
      offset += entry.data.bytesize
    end
    @fixups.each(&:call)

    image = "\x00".b * offset
    image[0, HEADER_SIZE] = [0xfeedfacf, 0x01000007, 3, 6, ncmds, command_size, 0, 0].pack("L<8")

    segment = [
      0x19, SEGMENT_COMMAND_64_SIZE + (@sections.size * SECTION_64_SIZE),
      "__DATA", VMADDR, image.bytesize, 0, image.bytesize, 7, 7, @sections.size, 0,
    ].pack("L<2a16Q<4L<4")
    image[HEADER_SIZE, segment.bytesize] = segment

    cursor = HEADER_SIZE + segment.bytesize
    @sections.each do |name, entry|
      section = [
        name, "__DATA", entry.addr, entry.data.bytesize,
        entry.offset, Math.log2(entry.align).to_i, 0, 0, 0, 0, 0, 0,
      ].pack("a16a16Q<2L<8")
      image[cursor, SECTION_64_SIZE] = section
      cursor += SECTION_64_SIZE
    end

    if @encrypted
      image[cursor, ENCRYPTION_COMMAND_64_SIZE] =
        [0x2c, ENCRYPTION_COMMAND_64_SIZE, 0x1000, 0x1000, 1, 0].pack("L<6")
    end

    @blobs.each do |entry|
      image[entry.offset, entry.data.bytesize] = entry.data
    end

    image
  end

  private

  def align_up(value, alignment)
    (value + alignment - 1) & -alignment
  end
end

class ObjC2Tests < Minitest::Test
  BAD_ADDR = 0xdead0000

  def image
    @image ||= build_objc2_image
  end

  def graph
    @graph ||= MachO::ObjC2.browse(image, mapper_for(image))
  end

  def mapper_for(img)
    base = ObjC2FixtureBuilder::VMADDR
    ->(vmaddr) { vmaddr >= base && vmaddr < base + img.bytesize ? vmaddr - base : nil }
  end

  def find_by_name(nodes, name)
    nodes.find { |node| node["name"] == name }
  end

  def method_names(methods)
    methods.map { |method| method["name"] }
  end

  def class_ro(builder, flags:, name:, methods: nil, protocols: nil)
    ro = builder.blob("\x00".b * 72)
    ro.data[0, 4] = [flags].pack("L<")
    ro.data[8, 4] = [32].pack("L<")
    builder.pointer(ro, 24, name)
    builder.pointer(ro, 32, methods) unless methods.nil?
    builder.pointer(ro, 40, protocols) unless protocols.nil?
    ro
  end

  def class_struct(builder, isa: nil, superclass: nil, data: nil)
    klass = builder.blob("\x00".b * 40)
    builder.pointer(klass, 0, isa) unless isa.nil?
    builder.pointer(klass, 8, superclass) unless superclass.nil?
    if data.is_a?(Integer)
      klass.data[32, 8] = [data].pack("Q<")
    elsif !data.nil?
      builder.pointer(klass, 32, data)
    end
    klass
  end

  def protocol_list(builder, protocols)
    list = builder.blob("\x00".b * (8 + (8 * protocols.size)))
    list.data[0, 8] = [protocols.size].pack("Q<")
    protocols.each_with_index do |protocol, index|
      builder.pointer(list, 8 + (index * 8), protocol)
    end
    list
  end

  def protocol_struct(builder, name:, methods: nil, optional_methods: nil)
    protocol = builder.blob("\x00".b * 72)
    builder.pointer(protocol, 8, name)
    builder.pointer(protocol, 24, methods) unless methods.nil?
    builder.pointer(protocol, 40, optional_methods) unless optional_methods.nil?
    protocol.data[64, 4] = [72].pack("L<")
    protocol
  end

  def category_struct(builder, name:, cls: nil, methods: nil, class_methods: nil)
    category = builder.blob("\x00".b * 56)
    builder.pointer(category, 0, name)
    if cls.is_a?(Integer)
      category.data[8, 8] = [cls].pack("Q<")
    elsif !cls.nil?
      builder.pointer(category, 8, cls)
    end
    builder.pointer(category, 16, methods) unless methods.nil?
    builder.pointer(category, 24, class_methods) unless class_methods.nil?
    category
  end

  def classic_method_list(builder, entries)
    list = builder.blob([24, entries.size].pack("L<2") + ("\x00".b * (24 * entries.size)))
    entries.each_with_index do |(sel, types, imp), index|
      base = 8 + (index * 24)
      builder.pointer(list, base, sel)
      builder.pointer(list, base + 8, types)
      list.data[base + 16, 8] = [imp].pack("Q<")
    end
    list
  end

  def build_objc2_image(encrypted: false)
    builder = ObjC2FixtureBuilder.new(:encrypted => encrypted)

    sel_init = builder.cstring("init")
    sel_do_thing = builder.cstring("doThing")
    sel_extra_thing = builder.cstring("extraThing")
    sel_meta_extra = builder.cstring("metaExtra")
    sel_make_thing = builder.cstring("makeThing")
    sel_proto_req = builder.cstring("protoReq")
    sel_proto_opt = builder.cstring("protoOpt")
    sel_proto_b_req = builder.cstring("protoBReq")
    types_void = builder.cstring("v16@0:8")
    types_id = builder.cstring("@16@0:8")
    name_base = builder.cstring("Base")
    name_derived = builder.cstring("Derived")
    name_extras = builder.cstring("Extras")
    name_ghost = builder.cstring("Ghost")
    name_proto_a = builder.cstring("ProtoA")
    name_proto_b = builder.cstring("ProtoB")

    # classic method list: Base#init
    base_methods = classic_method_list(builder, [[sel_init, types_id, 0x100003000]])

    # relative method list (direct selector names): Derived#doThing
    derived_methods = builder.blob([13, 1].pack("L<2") + ("\x00".b * 12))
    builder.relative32(derived_methods, 8, sel_do_thing)
    builder.relative32(derived_methods, 12, types_void)
    builder.relative32_to_addr(derived_methods, 16, 0x100004000)

    # relative method list (indirect selector references): Derived+makeThing
    make_thing_ref = builder.blob("\x00".b * 8)
    builder.pointer(make_thing_ref, 0, sel_make_thing)
    derived_meta_methods = builder.blob([15, 1].pack("L<2") + ("\x00".b * 12))
    builder.relative32(derived_meta_methods, 8, make_thing_ref)
    builder.relative32(derived_meta_methods, 12, types_id)
    builder.relative32_to_addr(derived_meta_methods, 16, 0x100005000)

    # category Extras on Derived, re-declaring the doThing selector
    extras_methods = classic_method_list(builder, [
      [sel_do_thing, types_void, 0x100006000],
      [sel_extra_thing, types_void, 0x100007000],
    ])
    extras_class_methods = classic_method_list(builder, [[sel_meta_extra, types_id, 0x100008000]])

    proto_a_methods = classic_method_list(builder, [[sel_proto_req, types_void, 0x100009000]])
    proto_a_optional = classic_method_list(builder, [[sel_proto_opt, types_void, 0x10000a000]])
    proto_b_methods = classic_method_list(builder, [[sel_proto_b_req, types_void, 0x10000b000]])

    # ProtoA adopts ProtoB and ProtoB adopts ProtoA (a cycle)
    proto_a = protocol_struct(builder, :name => name_proto_a, :methods => proto_a_methods,
                                       :optional_methods => proto_a_optional)
    proto_b = protocol_struct(builder, :name => name_proto_b, :methods => proto_b_methods)
    builder.pointer(proto_a, 16, protocol_list(builder, [proto_b]))
    builder.pointer(proto_b, 16, protocol_list(builder, [proto_a]))

    base_ro = class_ro(builder, :flags => 0, :name => name_base, :methods => base_methods,
                                :protocols => protocol_list(builder, [proto_a]))
    base_meta_ro = class_ro(builder, :flags => 1, :name => name_base)
    derived_ro = class_ro(builder, :flags => 0, :name => name_derived, :methods => derived_methods)
    derived_meta_ro = class_ro(builder, :flags => 1, :name => name_derived, :methods => derived_meta_methods)

    base_klass = class_struct(builder, :data => base_ro)
    base_meta = class_struct(builder, :data => base_meta_ro)
    builder.pointer(base_klass, 0, base_meta)
    builder.pointer(base_meta, 0, base_meta)
    builder.pointer(base_meta, 8, base_klass)

    derived_klass = class_struct(builder, :superclass => base_klass, :data => derived_ro)
    derived_meta = class_struct(builder, :superclass => base_meta, :data => derived_meta_ro)
    builder.pointer(derived_klass, 0, derived_meta)
    builder.pointer(derived_meta, 0, base_meta)

    # class_ro_t pointer that cannot be mapped
    corrupt_klass = class_struct(builder, :data => BAD_ADDR)

    extras = category_struct(builder, :name => name_extras, :cls => derived_klass,
                                      :methods => extras_methods, :class_methods => extras_class_methods)
    # category whose class pointer cannot be mapped
    ghost = category_struct(builder, :name => name_ghost, :cls => BAD_ADDR)

    classlist = builder.blob("\x00".b * 24, :section => "__objc_classlist")
    builder.pointer(classlist, 0, base_klass)
    builder.pointer(classlist, 8, derived_klass)
    builder.pointer(classlist, 16, corrupt_klass)

    catlist = builder.blob("\x00".b * 16, :section => "__objc_catlist")
    builder.pointer(catlist, 0, extras)
    builder.pointer(catlist, 8, ghost)

    protolist = builder.blob("\x00".b * 16, :section => "__objc_protolist")
    builder.pointer(protolist, 0, proto_a)
    builder.pointer(protolist, 8, proto_b)

    builder.build
  end

  def test_graph_is_json_serializable
    assert_equal graph, JSON.parse(JSON.generate(graph))
  end

  def test_class_hierarchy
    base = find_by_name(graph["classes"], "Base")
    derived = find_by_name(graph["classes"], "Derived")

    refute_nil base
    refute_nil derived
    assert_equal "class", base["kind"]
    assert_nil base["superclass"]
    assert_equal base["id"], derived["superclass"]
  end

  def test_metaclasses_and_class_methods
    base = find_by_name(graph["classes"], "Base")
    derived = find_by_name(graph["classes"], "Derived")
    base_meta = find_by_name(graph["metaclasses"], "Base")
    derived_meta = find_by_name(graph["metaclasses"], "Derived")

    refute_nil base_meta
    refute_nil derived_meta
    assert_equal "metaclass", derived_meta["kind"]
    assert_equal base_meta["id"], base["metaclass"]
    assert_equal derived_meta["id"], derived["metaclass"]

    # root metaclass: isa points to itself, superclass to the root class
    assert_equal base_meta["id"], base_meta["isa"]
    assert_equal base["id"], base_meta["superclass"]

    # metaclass hierarchy mirrors the class hierarchy
    assert_equal base_meta["id"], derived_meta["superclass"]
    assert_equal base_meta["id"], derived_meta["isa"]

    # class methods live on the metaclass and are mirrored on the class
    assert_equal ["makeThing"], method_names(derived_meta["methods"])
    assert_equal derived_meta["methods"], derived["class_methods"]
  end

  def test_classic_and_relative_method_lists
    base = find_by_name(graph["classes"], "Base")
    derived = find_by_name(graph["classes"], "Derived")

    init = base["instance_methods"].first
    assert_equal "init", init["name"]
    assert_equal "@16@0:8", init["types"]
    assert_equal "0x100003000", init["imp"]
    assert_equal "class:Base", init["origin"]

    # relative method list with direct selector names
    do_thing = derived["instance_methods"].first
    assert_equal "doThing", do_thing["name"]
    assert_equal "v16@0:8", do_thing["types"]
    assert_equal "0x100004000", do_thing["imp"]
    assert_equal "class:Derived", do_thing["origin"]

    # relative method list with indirect selector references
    make_thing = derived["class_methods"].first
    assert_equal "makeThing", make_thing["name"]
    assert_equal "@16@0:8", make_thing["types"]
    assert_equal "0x100005000", make_thing["imp"]
    assert_equal "metaclass:Derived", make_thing["origin"]
  end

  def test_category_origin_and_duplicate_selectors
    derived = find_by_name(graph["classes"], "Derived")
    extras = find_by_name(graph["categories"], "Extras")

    refute_nil extras
    assert_equal %w[doThing extraThing], method_names(extras["instance_methods"])
    assert_equal ["metaExtra"], method_names(extras["class_methods"])
    assert(extras["instance_methods"].all? { |method| method["origin"] == "category:Extras" })

    # the duplicate selector survives on both the class and the category
    class_do_thing = derived["instance_methods"].find { |method| method["name"] == "doThing" }
    category_do_thing = extras["instance_methods"].find { |method| method["name"] == "doThing" }
    refute_nil class_do_thing
    refute_nil category_do_thing
    assert_equal "class:Derived", class_do_thing["origin"]
    assert_equal "category:Extras", category_do_thing["origin"]
    refute_equal class_do_thing["imp"], category_do_thing["imp"]
  end

  def test_shared_object_identity
    base = find_by_name(graph["classes"], "Base")
    derived = find_by_name(graph["classes"], "Derived")
    extras = find_by_name(graph["categories"], "Extras")
    proto_a = find_by_name(graph["protocols"], "ProtoA")
    proto_b = find_by_name(graph["protocols"], "ProtoB")

    # the category and the classlist reference the same class node
    assert_equal derived["id"], extras["class"]
    assert_equal [extras["id"]], derived["categories"]

    # the class and the protolist reference the same protocol node
    assert_equal [proto_a["id"]], base["protocols"]
    assert_equal proto_b["id"], proto_a["protocols"].first
  end

  def test_cyclic_protocols
    proto_a = find_by_name(graph["protocols"], "ProtoA")
    proto_b = find_by_name(graph["protocols"], "ProtoB")

    refute_nil proto_a
    refute_nil proto_b
    assert_equal [proto_b["id"]], proto_a["protocols"]
    assert_equal [proto_a["id"]], proto_b["protocols"]
    assert_equal ["protoReq"], method_names(proto_a["instance_methods"])
    assert_equal ["protoOpt"], method_names(proto_a["optional_instance_methods"])
    assert_equal ["protoBReq"], method_names(proto_b["instance_methods"])
  end

  def test_bad_address_diagnostics
    # the class with the unmappable class_ro_t pointer is still reported
    corrupt = graph["classes"].find { |klass| klass["name"].nil? }
    refute_nil corrupt
    assert_empty corrupt["instance_methods"]

    # the category with the unmappable class pointer keeps a nil class
    ghost = find_by_name(graph["categories"], "Ghost")
    refute_nil ghost
    assert_nil ghost["class"]

    diagnostics = graph["diagnostics"]
    assert(diagnostics.all? { |entry| entry["severity"] == "warning" })
    bad = "0x%x" % BAD_ADDR
    assert(diagnostics.any? { |entry| entry["message"].include?(bad) && entry["address"] == bad })
  end

  def test_encrypted_image_rejected
    encrypted = build_objc2_image(:encrypted => true)
    error = assert_raises(MachO::ObjC2EncryptedImageError) do
      MachO::ObjC2.browse(encrypted, mapper_for(encrypted))
    end
    assert_match(/encrypted/, error.message)
  end

  def test_non_macho_image_rejected
    junk = "this is definitely not a mach-o image"
    assert_raises(MachO::ObjC2Error) do
      MachO::ObjC2.browse(junk, ->(_vmaddr) { nil })
    end
  end
end
