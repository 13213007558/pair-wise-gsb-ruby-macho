# frozen_string_literal: true

module MachO
  module ObjC2
    # Walks objc2 metadata structures and builds a serializable relation
    # graph. Nodes are deduplicated by address, so shared structures (for
    # example a protocol referenced by both a class and a category) appear
    # exactly once and are referenced elsewhere by id.
    class Extractor
      # @param data [String] the raw file bytes
      # @param mapper [#call] maps a vmaddr to a file offset or nil
      def initialize(data, mapper)
        @reader = Reader.new(data, mapper)
        @classes = {}
        @metaclasses = {}
        @categories = {}
        @protocols = {}
        @methods = []
      end

      # Extracts the relation graph.
      # @param classlist [Array(Integer, Integer), nil] vmaddr and byte size
      #   of the class pointer section
      # @param catlist [Array(Integer, Integer), nil] vmaddr and byte size of
      #   the category pointer section
      # @param protolist [Array(Integer, Integer), nil] vmaddr and byte size
      #   of the protocol pointer section
      # @return [Hash] a serializable graph with "classes", "metaclasses",
      #   "categories", "protocols", "methods" and "diagnostics" keys
      def extract(classlist: nil, catlist: nil, protolist: nil)
        walk_pointer_section(classlist, "class list") { |address| parse_class(address) }
        walk_pointer_section(protolist, "protocol list") { |address| parse_protocol(address) }
        walk_pointer_section(catlist, "category list") { |address| parse_category(address) }

        {
          "format" => GRAPH_FORMAT,
          "classes" => @classes.values,
          "metaclasses" => @metaclasses.values,
          "categories" => @categories.values,
          "protocols" => @protocols.values,
          "methods" => @methods,
          "diagnostics" => @reader.diagnostics,
        }
      end

      private

      def walk_pointer_section(section, description)
        return if section.nil?

        vmaddr, size = section
        count = size / 8
        if count > MAX_LIST_COUNT
          @reader.diagnose(vmaddr, "implausible entry count #{count}", description)
          return
        end

        count.times do |index|
          address = @reader.u64(vmaddr + (index * 8), :context => description)
          next if address.nil? || address.zero?

          yield address
        end
      end

      def parse_class(address, metaclass: false)
        registry = metaclass ? @metaclasses : @classes
        id = "#{metaclass ? "meta" : "class"}:0x#{address.to_s(16)}"
        return id if registry.key?(address)

        context = "#{metaclass ? "metaclass" : "class"} 0x#{address.to_s(16)}"
        node = {
          "id" => id,
          "address" => address,
          "name" => nil,
          "superclass" => nil,
          "protocols" => [],
          "methods" => [],
        }
        node["metaclass"] = nil unless metaclass
        registry[address] = node

        isa = @reader.u64(address, :context => context)
        superclass = @reader.u64(address + 8, :context => context)
        data = @reader.u64(address + 32, :context => context)
        if isa.nil? || superclass.nil? || data.nil?
          node["error"] = "unreadable class structure"
          return id
        end

        ro = read_class_ro(data & FAST_DATA_MASK, context)
        if ro.nil?
          node["error"] = "unreadable class_ro data"
          return id
        end

        node["name"] = @reader.cstring(ro[:name], :context => "#{context} name")
        node["methods"] = parse_method_list(ro[:methods],
                                            :owner => id,
                                            :kind => metaclass ? "class" : "instance",
                                            :source => "class")
        node["protocols"] = parse_protocol_list(ro[:protocols], context)
        node["superclass"] = parse_class(superclass, :metaclass => metaclass) if superclass != 0
        node["metaclass"] = parse_class(isa, :metaclass => true) if !metaclass && isa != 0
        id
      end

      def read_class_ro(address, context)
        name = @reader.u64(address + 24, :context => "#{context} class_ro")
        methods = @reader.u64(address + 32, :context => "#{context} class_ro")
        protocols = @reader.u64(address + 40, :context => "#{context} class_ro")
        return if name.nil? || methods.nil? || protocols.nil?

        { :name => name, :methods => methods, :protocols => protocols }
      end

      def parse_protocol(address)
        id = "protocol:0x#{address.to_s(16)}"
        return id if @protocols.key?(address)

        context = "protocol 0x#{address.to_s(16)}"
        node = {
          "id" => id,
          "address" => address,
          "name" => nil,
          "protocols" => [],
          "instance_methods" => [],
          "class_methods" => [],
        }
        @protocols[address] = node

        name = @reader.u64(address + 8, :context => context)
        protocols = @reader.u64(address + 16, :context => context)
        instance_methods = @reader.u64(address + 24, :context => context)
        class_methods = @reader.u64(address + 32, :context => context)
        optional_instance = @reader.u64(address + 40, :context => context)
        optional_class = @reader.u64(address + 48, :context => context)
        if [name, protocols, instance_methods, class_methods, optional_instance, optional_class].any?(&:nil?)
          node["error"] = "unreadable protocol structure"
          return id
        end

        node["name"] = @reader.cstring(name, :context => "#{context} name")
        node["protocols"] = parse_protocol_list(protocols, context)
        node["instance_methods"] = parse_method_list(instance_methods,
                                                     :owner => id, :kind => "instance", :source => "protocol")
        node["class_methods"] = parse_method_list(class_methods,
                                                  :owner => id, :kind => "class", :source => "protocol")
        node["instance_methods"] += parse_method_list(optional_instance,
                                                      :owner => id, :kind => "instance", :source => "protocol",
                                                      :optional => true)
        node["class_methods"] += parse_method_list(optional_class,
                                                   :owner => id, :kind => "class", :source => "protocol",
                                                   :optional => true)
        id
      end

      def parse_category(address)
        id = "category:0x#{address.to_s(16)}"
        return id if @categories.key?(address)

        context = "category 0x#{address.to_s(16)}"
        node = {
          "id" => id,
          "address" => address,
          "name" => nil,
          "class" => nil,
          "protocols" => [],
          "methods" => [],
        }
        @categories[address] = node

        name = @reader.u64(address, :context => context)
        cls = @reader.u64(address + 8, :context => context)
        instance_methods = @reader.u64(address + 16, :context => context)
        class_methods = @reader.u64(address + 24, :context => context)
        protocols = @reader.u64(address + 32, :context => context)
        if [name, cls, instance_methods, class_methods, protocols].any?(&:nil?)
          node["error"] = "unreadable category structure"
          return id
        end

        node["name"] = @reader.cstring(name, :context => "#{context} name")
        node["class"] = parse_class(cls) if cls != 0
        node["methods"] = parse_method_list(instance_methods,
                                            :owner => id, :kind => "instance", :source => "category")
        node["methods"] += parse_method_list(class_methods,
                                             :owner => id, :kind => "class", :source => "category")
        node["protocols"] = parse_protocol_list(protocols, context)
        id
      end

      def parse_protocol_list(address, context)
        return [] if address.nil? || address.zero?

        context = "#{context} protocol refs"
        count = @reader.u64(address, :context => context)
        return [] if count.nil?

        if count > MAX_LIST_COUNT
          @reader.diagnose(address, "implausible protocol count #{count}", context)
          return []
        end

        ids = []
        count.times do |index|
          pointer = @reader.u64(address + 8 + (index * 8), :context => context)
          next if pointer.nil? || pointer.zero?

          ids << parse_protocol(pointer)
        end
        ids
      end

      def parse_method_list(address, owner:, kind:, source:, optional: false)
        return [] if address.nil? || address.zero?

        context = "#{source} #{owner} method list"
        raw_entsize = @reader.u32(address, :context => context)
        count = @reader.u32(address + 4, :context => context)
        return [] if raw_entsize.nil? || count.nil?

        relative = (raw_entsize & 0x3) != 0
        stride = raw_entsize & ~0x3
        minimum = relative ? 12 : 24
        if stride < minimum
          @reader.diagnose(address, "implausible method entry size #{stride}", context)
          return []
        end
        if count > MAX_LIST_COUNT
          @reader.diagnose(address, "implausible method count #{count}", context)
          return []
        end

        ids = []
        count.times do |index|
          entry = address + 8 + (index * stride)
          name_address, types_address, imp = read_method_entry(entry, relative, context)
          next if name_address.nil?

          ids << add_method(entry, name_address, types_address, imp,
                            :owner => owner, :kind => kind, :source => source,
                            :relative => relative, :optional => optional)
        end
        ids
      end

      def read_method_entry(entry, relative, context)
        if relative
          name_offset = @reader.i32(entry, :context => context)
          types_offset = @reader.i32(entry + 4, :context => context)
          imp_offset = @reader.i32(entry + 8, :context => context)
          return if name_offset.nil? || types_offset.nil? || imp_offset.nil?

          [entry + name_offset, entry + 4 + types_offset, entry + 8 + imp_offset]
        else
          name = @reader.u64(entry, :context => context)
          types = @reader.u64(entry + 8, :context => context)
          imp = @reader.u64(entry + 16, :context => context)
          return if name.nil? || types.nil? || imp.nil?

          [name, types, imp]
        end
      end

      def add_method(entry, name_address, types_address, imp, owner:, kind:, source:, relative:, optional:)
        context = "method entry 0x#{entry.to_s(16)}"
        id = "method:0x#{entry.to_s(16)}"
        node = {
          "id" => id,
          "address" => entry,
          "name" => name_address.zero? ? nil : @reader.cstring(name_address, :context => context),
          "types" => types_address.zero? ? nil : @reader.cstring(types_address, :context => context),
          "imp" => imp,
          "kind" => kind,
          "source" => source,
          "owner" => owner,
          "list" => relative ? "relative" : "normal",
        }
        node["optional"] = true if optional
        @methods << node
        id
      end
    end
  end
end

