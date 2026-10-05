# frozen_string_literal: true

module MachO
  # Offline Objective-C 2.0 ("modern runtime") metadata browser.
  #
  # {ObjC2} extracts classes, metaclasses, categories, protocols and their
  # methods from an unencrypted 64-bit Mach-O file image without loading the
  # Objective-C runtime. The result is a plain, serializable relation graph
  # made of hashes, arrays, strings and integers only.
  #
  # All pointers are resolved through a caller-provided mapper, so the browser
  # works on any fixed file image (or slice of one) regardless of how its
  # virtual addresses are laid out.
  #
  # @example
  #   image = File.binread("libhello.dylib")
  #   mapper = ->(vmaddr) { vmaddr2off.fetch(vmaddr, nil) }
  #   graph = MachO::ObjC2.browse(image, mapper)
  module ObjC2
    # name of the section holding the list of class pointers
    CLASSLIST_SECTION = "__objc_classlist"

    # name of the section holding the list of category pointers
    CATLIST_SECTION = "__objc_catlist"

    # name of the section holding the list of protocol pointers
    PROTOLIST_SECTION = "__objc_protolist"

    # Extracts the ObjC2 relation graph from a 64-bit Mach-O file image.
    # @param image [String] raw bytes of an unencrypted 64-bit Mach-O file image
    # @param mapper [#call] callable mapping a virtual address to a file offset
    #   (Integer), returning nil for addresses not present in the image
    # @return [Hash] a serializable relation graph; see {Browser#graph}
    # @raise [ObjC2Error] if the image is not a 64-bit Mach-O
    # @raise [ObjC2EncryptedImageError] if the image is encrypted
    def self.browse(image, mapper)
      Browser.new(image, mapper).graph
    end

    # Browses ObjC2 metadata in a single 64-bit Mach-O file image.
    class Browser
      # version of the {#graph} output format
      FORMAT_VERSION = 1

      # size of mach_header_64
      HEADER_SIZE = 32

      # size of segment_command_64 (without sections)
      SEGMENT_COMMAND_64_SIZE = 72

      # size of section_64
      SECTION_64_SIZE = 80

      # size of the 64-bit class_t structure
      CLASS_SIZE = 40

      # size of the 64-bit class_ro_t structure
      CLASS_RO_SIZE = 72

      # size of the 64-bit category_t structure
      CATEGORY_SIZE = 56

      # size of the 64-bit protocol_t structure (without extended fields)
      PROTOCOL_SIZE = 72

      # size of a classic 64-bit method_t entry
      METHOD_SIZE = 24

      # size of a relative_method_t entry (three signed 32-bit offsets)
      RELATIVE_METHOD_SIZE = 12

      # mask applied to class_t.data to obtain the class_ro_t pointer
      FAST_DATA_MASK = 0x0000_7fff_ffff_fff8

      # class_ro_t flag marking a metaclass
      RO_META = 0x1

      # method_list_t flag marking a relative method list
      METHOD_LIST_RELATIVE = 0x1

      # method_list_t flag marking indirect (selector reference) names in a
      # relative method list
      METHOD_LIST_INDIRECT_SELECTORS = 0x2

      # mask for the flag bits stored in method_list_t.entsize
      METHOD_LIST_FLAGS_MASK = 0x3

      # sanity limit for method list and protocol list entry counts
      MAX_LIST_COUNT = 65_536

      # sanity limit for C string lengths
      MAX_CSTRING_LENGTH = 1024

      # 64-bit segment load command
      LC_SEGMENT_64 = 0x19

      # encryption load commands
      LC_ENCRYPTION_INFO = 0x21
      LC_ENCRYPTION_INFO_64 = 0x2c

      # @param image [String] raw bytes of an unencrypted 64-bit Mach-O file
      #   image
      # @param mapper [#call] callable mapping a virtual address to a file
      #   offset (Integer), returning nil for addresses not present in the
      #   image
      # @raise [ObjC2Error] if the image is not a 64-bit Mach-O
      # @raise [ObjC2EncryptedImageError] if the image is encrypted
      def initialize(image, mapper)
        @image = image
        @mapper = mapper
        @diagnostics = []
        @sections = {}
        @nodes = {}
        @class_ids = {}
        @category_ids = {}
        @protocol_ids = {}
        @classes = []
        @metaclasses = []
        @categories = []
        @protocols = []
        parse_header
      end

      # Builds the ObjC2 relation graph. Should only be called once per
      # browser instance.
      # @return [Hash] a serializable hash with "classes", "metaclasses",
      #   "categories", "protocols" and "diagnostics" entries; nodes reference
      #   each other by their "id" strings
      def graph
        parse_list_section(CLASSLIST_SECTION) { |address| parse_class(address, :class) }
        parse_list_section(CATLIST_SECTION) { |address| parse_category(address) }
        parse_list_section(PROTOLIST_SECTION) { |address| parse_protocol(address) }

        {
          "format_version" => FORMAT_VERSION,
          "classes" => @classes,
          "metaclasses" => @metaclasses,
          "categories" => @categories,
          "protocols" => @protocols,
          "diagnostics" => @diagnostics,
        }
      end

      private
      private

      def parse_header
        raise ObjC2Error, "Image is too small to be a 64-bit Mach-O" if @image.bytesize < HEADER_SIZE

        magic = @image.byteslice(0, 4).unpack1("N")
        case magic
        when Headers::MH_CIGAM_64
          @little_endian = true
        when Headers::MH_MAGIC_64
          @little_endian = false
        else
          raise ObjC2Error, "Image is not a 64-bit Mach-O (magic 0x%08<magic>x)" % { :magic => magic }
        end

        @u64 = @little_endian ? "Q<" : "Q>"
        @u32 = @little_endian ? "L<" : "L>"
        @i32 = @little_endian ? "l<" : "l>"

        ncmds = @image.byteslice(16, 4).unpack1(@u32)
        offset = HEADER_SIZE
        ncmds.times do
          break if offset + 8 > @image.bytesize

          cmd, cmdsize = @image.byteslice(offset, 8).unpack("#{@u32}2")
          break if cmdsize < 8

          case cmd
          when LC_SEGMENT_64
            parse_segment_sections(offset)
          when LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64
            cryptid = @image.byteslice(offset + 16, 4)&.unpack1(@u32)
            raise ObjC2EncryptedImageError if cryptid && cryptid.nonzero?
          end

          offset += cmdsize
        end
      end

      def parse_segment_sections(command_offset)
        nsects = @image.byteslice(command_offset + 64, 4)&.unpack1(@u32)
        return if nsects.nil?

        nsects.times do |index|
          section_offset = command_offset + SEGMENT_COMMAND_64_SIZE + (index * SECTION_64_SIZE)
          break if section_offset + SECTION_64_SIZE > @image.bytesize

          name = @image.byteslice(section_offset, 16).unpack1("Z*")
          address = @image.byteslice(section_offset + 32, 8).unpack1(@u64)
          size = @image.byteslice(section_offset + 40, 8).unpack1(@u64)
          @sections[name] = [address, size]
        end
      end

      def parse_list_section(section_name)
        section = @sections[section_name]
        return if section.nil?

        address, size = section
        (size / 8).times do |index|
          pointer = read_u64(address + (index * 8), "#{section_name} entry #{index}")
          yield pointer if pointer && pointer.nonzero?
        end
      end

      def parse_class(vmaddr, hint)
        return nil if vmaddr.nil? || vmaddr.zero?

        existing = @class_ids[vmaddr]
        return existing if existing

        context = "class #{hex(vmaddr)}"
        raw = read_bytes(vmaddr, CLASS_SIZE, context)
        return nil if raw.nil?

        isa, superclass, _cache, _vtable, data = raw.unpack("#{@u64}5")
        ro_addr = data & FAST_DATA_MASK
        ro = ro_addr.zero? ? nil : read_bytes(ro_addr, CLASS_RO_SIZE, "class_ro_t for #{context}")
        meta = ro.nil? ? hint == :meta : (ro.unpack1(@u32) & RO_META) != 0

        id = "#{meta ? "meta" : "class"}:#{hex(vmaddr)}"
        node = meta ? new_metaclass_node(id, vmaddr) : new_class_node(id, vmaddr)
        @class_ids[vmaddr] = id
        @nodes[id] = node
        (meta ? @metaclasses : @classes) << node

        fill_class_ro(node, ro, context, meta) unless ro.nil?

        isa_id = parse_class(isa, :meta)
        superclass_id = parse_class(superclass, meta ? :meta : :class)

        if meta
          node["isa"] = isa_id
          node["superclass"] = superclass_id
        else
          node["metaclass"] = isa_id
          node["superclass"] = superclass_id
          metaclass_node = isa_id && @nodes[isa_id]
          node["class_methods"] = metaclass_node ? metaclass_node["methods"] : []
        end

        id
      end

      def new_class_node(id, vmaddr)
        {
          "id" => id,
          "kind" => "class",
          "name" => nil,
          "address" => hex(vmaddr),
          "superclass" => nil,
          "metaclass" => nil,
          "instance_methods" => [],
          "class_methods" => [],
          "protocols" => [],
          "categories" => [],
        }
      end

      def new_metaclass_node(id, vmaddr)
        {
          "id" => id,
          "kind" => "metaclass",
          "name" => nil,
          "address" => hex(vmaddr),
          "isa" => nil,
          "superclass" => nil,
          "methods" => [],
        }
      end

      def fill_class_ro(node, ro, context, meta)
        name_addr = ro[24, 8].unpack1(@u64)
        methods_addr = ro[32, 8].unpack1(@u64)
        protocols_addr = ro[40, 8].unpack1(@u64)

        node["name"] = read_cstring(name_addr, "name of #{context}")
        origin = meta ? "metaclass:#{node["name"]}" : "class:#{node["name"]}"
        methods = parse_method_list(methods_addr, origin)

        if meta
          node["methods"] = methods
        else
          node["instance_methods"] = methods
          node["protocols"] = parse_protocol_refs(protocols_addr)
        end
      end

      def parse_category(vmaddr)
        return nil if vmaddr.nil? || vmaddr.zero?

        existing = @category_ids[vmaddr]
        return existing if existing

        id = "category:#{hex(vmaddr)}"
        node = {
          "id" => id,
          "name" => nil,
          "address" => hex(vmaddr),
          "class" => nil,
          "instance_methods" => [],
          "class_methods" => [],
          "protocols" => [],
        }
        @category_ids[vmaddr] = id
        @categories << node

        raw = read_bytes(vmaddr, CATEGORY_SIZE, "category #{hex(vmaddr)}")
        return id if raw.nil?

        name_addr, class_addr, instance_methods_addr, class_methods_addr, protocols_addr =
          raw.unpack("#{@u64}5")

        node["name"] = read_cstring(name_addr, "name of category #{hex(vmaddr)}")
        origin = "category:#{node["name"]}"
        class_id = parse_class(class_addr, :class)
        node["class"] = class_id
        class_node = class_id && @nodes[class_id]
        class_node["categories"] << id if class_node
        node["instance_methods"] = parse_method_list(instance_methods_addr, origin)
        node["class_methods"] = parse_method_list(class_methods_addr, origin)
        node["protocols"] = parse_protocol_refs(protocols_addr)
        id
      end

      def parse_protocol(vmaddr)
        return nil if vmaddr.nil? || vmaddr.zero?

        existing = @protocol_ids[vmaddr]
        return existing if existing

        id = "protocol:#{hex(vmaddr)}"
        node = {
          "id" => id,
          "name" => nil,
          "address" => hex(vmaddr),
          "protocols" => [],
          "instance_methods" => [],
          "class_methods" => [],
          "optional_instance_methods" => [],
          "optional_class_methods" => [],
        }
        @protocol_ids[vmaddr] = id
        @protocols << node

        raw = read_bytes(vmaddr, PROTOCOL_SIZE, "protocol #{hex(vmaddr)}")
        return id if raw.nil?

        name_addr, protocols_addr, instance_methods_addr, class_methods_addr,
          optional_instance_methods_addr, optional_class_methods_addr =
          raw.unpack("x8#{@u64}7")

        node["name"] = read_cstring(name_addr, "name of protocol #{hex(vmaddr)}")
        origin = "protocol:#{node["name"]}"
        node["protocols"] = parse_protocol_refs(protocols_addr)
        node["instance_methods"] = parse_method_list(instance_methods_addr, origin)
        node["class_methods"] = parse_method_list(class_methods_addr, origin)
        node["optional_instance_methods"] = parse_method_list(optional_instance_methods_addr, origin)
        node["optional_class_methods"] = parse_method_list(optional_class_methods_addr, origin)
        id
      end

      def parse_protocol_refs(vmaddr)
        return [] if vmaddr.nil? || vmaddr.zero?

        count = read_u64(vmaddr, "protocol list #{hex(vmaddr)}")
        return [] if count.nil?

        if count > MAX_LIST_COUNT
          diagnose("protocol list #{hex(vmaddr)} has implausible count #{count}", vmaddr)
          return []
        end

        (0...count).filter_map do |index|
          ref = read_u64(vmaddr + 8 + (index * 8), "protocol list #{hex(vmaddr)}")
          parse_protocol(ref) if ref
        end
      end

      def parse_method_list(vmaddr, origin)
        return [] if vmaddr.nil? || vmaddr.zero?

        header = read_bytes(vmaddr, 8, "method list for #{origin}")
        return [] if header.nil?

        entsize_and_flags, count = header.unpack("#{@u32}2")
        relative = (entsize_and_flags & METHOD_LIST_RELATIVE) != 0
        indirect = (entsize_and_flags & METHOD_LIST_INDIRECT_SELECTORS) != 0
        stride = entsize_and_flags & ~METHOD_LIST_FLAGS_MASK
        minimum = relative ? RELATIVE_METHOD_SIZE : METHOD_SIZE

        if stride < minimum
          diagnose("method list for #{origin} has invalid entry size #{stride}", vmaddr)
          return []
        end

        if count > MAX_LIST_COUNT
          diagnose("method list for #{origin} has implausible count #{count}", vmaddr)
          return []
        end

        (0...count).map do |index|
          entry = vmaddr + 8 + (index * stride)
          if relative
            parse_relative_method(entry, indirect, origin)
          else
            parse_classic_method(entry, origin)
          end
        end
      end

      def parse_classic_method(entry, origin)
        raw = read_bytes(entry, METHOD_SIZE, "method for #{origin}")
        return broken_method(origin) if raw.nil?

        name_addr, types_addr, imp = raw.unpack("#{@u64}3")
        {
          "name" => read_cstring(name_addr, "method name for #{origin}"),
          "types" => read_cstring(types_addr, "method types for #{origin}"),
          "imp" => hex(imp),
          "origin" => origin,
        }
      end

      def parse_relative_method(entry, indirect, origin)
        raw = read_bytes(entry, RELATIVE_METHOD_SIZE, "relative method for #{origin}")
        return broken_method(origin) if raw.nil?

        name_off, types_off, imp_off = raw.unpack("#{@i32}3")
        name_addr = name_off.zero? ? nil : entry + name_off
        types_addr = types_off.zero? ? nil : entry + 4 + types_off
        imp_addr = imp_off.zero? ? nil : entry + 8 + imp_off
        name_addr = read_u64(name_addr, "selector reference for #{origin}") if indirect && name_addr

        {
          "name" => name_addr && read_cstring(name_addr, "method name for #{origin}"),
          "types" => types_addr && read_cstring(types_addr, "method types for #{origin}"),
          "imp" => imp_addr && hex(imp_addr),
          "origin" => origin,
        }
      end

      def broken_method(origin)
        {
          "name" => nil,
          "types" => nil,
          "imp" => nil,
          "origin" => origin,
        }
      end

      def read_u64(vmaddr, context)
        bytes = read_bytes(vmaddr, 8, context)
        bytes&.unpack1(@u64)
      end

      def read_bytes(vmaddr, length, context)
        offset = mapped_offset(vmaddr, context)
        return nil if offset.nil?

        if offset + length > @image.bytesize
          diagnose("truncated #{length}-byte read while reading #{context}", vmaddr)
          return nil
        end

        @image.byteslice(offset, length)
      end

      def mapped_offset(vmaddr, context)
        offset = @mapper.call(vmaddr)
        if offset.nil? || offset.negative? || offset >= @image.bytesize
          diagnose("unmapped pointer #{hex(vmaddr)} while reading #{context}", vmaddr)
          return nil
        end

        offset
      end

      def read_cstring(vmaddr, context)
        return nil if vmaddr.nil? || vmaddr.zero?

        offset = mapped_offset(vmaddr, context)
        return nil if offset.nil?

        chunk = @image.byteslice(offset, MAX_CSTRING_LENGTH)
        terminator = chunk.index("\x00")
        if terminator.nil?
          diagnose("unterminated string while reading #{context}", vmaddr)
          return nil
        end

        chunk.byteslice(0, terminator).force_encoding(Encoding::UTF_8).scrub
      end

      def diagnose(message, address = nil)
        entry = { "severity" => "warning", "message" => message }
        entry["address"] = hex(address) unless address.nil?
        @diagnostics << entry
        nil
      end

      def hex(value)
        "0x%x" % value
      end
    end
  end
end
