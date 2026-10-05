# frozen_string_literal: true

module MachO
  # A mutable representation of the export information encoded as a Mach-O
  #  dyld export trie.
class ExportTrie
  include Enumerable

    KIND_REGULAR = 0
    KIND_THREAD_LOCAL = 1
    KIND_ABSOLUTE = 2

    FLAG_WEAK_DEFINITION = 0x04
    FLAG_REEXPORT = 0x08
    FLAG_STUB_AND_RESOLVER = 0x10
    FLAG_STATIC_RESOLVER = 0x20

    MAX_UINT64 = 0xFFFFFFFFFFFFFFFF

    # Terminal information for an exported symbol.
    class Terminal
      attr_reader :kind, :flags, :address, :stub_address, :resolver_address,
                  :library_ordinal, :imported_name

      def self.regular(address, weak: false)
        new(KIND_REGULAR, :address => address, :weak => weak)
      end

      def self.thread_local(address, weak: false)
        new(KIND_THREAD_LOCAL, :address => address, :weak => weak)
      end

      def self.absolute(address, weak: false)
        new(KIND_ABSOLUTE, :address => address, :weak => weak)
      end

      def self.reexport(library_ordinal, imported_name = "", weak: false, kind: KIND_REGULAR)
        new(kind, :library_ordinal => library_ordinal, :imported_name => imported_name,
                 :weak => weak, :reexport => true)
      end

      def self.stub_and_resolver(stub_address, resolver_address, weak: false, kind: KIND_REGULAR)
        new(kind, :stub_address => stub_address, :resolver_address => resolver_address,
                 :weak => weak, :stub_and_resolver => true)
      end

      def self.static_resolver(resolver_address, weak: false, kind: KIND_REGULAR)
        new(kind, :resolver_address => resolver_address, :weak => weak,
                 :static_resolver => true)
      end

      def initialize(kind, address: nil, stub_address: nil, resolver_address: nil,
                     library_ordinal: nil, imported_name: nil, weak: false,
                     reexport: false, stub_and_resolver: false,
                     static_resolver: false, flags: nil)
        @kind = kind
        @address = address
        @stub_address = stub_address
        @resolver_address = resolver_address
        @library_ordinal = library_ordinal
        @imported_name = binary_name(imported_name.to_s)
        @flags = flags || build_flags(weak, reexport, stub_and_resolver, static_resolver)

        validate!
      end

      def regular?
        kind == KIND_REGULAR
      end

      def thread_local?
        kind == KIND_THREAD_LOCAL
      end

      def absolute?
        kind == KIND_ABSOLUTE
      end

      def weak_definition?
        flags.anybits?(FLAG_WEAK_DEFINITION)
      end

      def reexport?
        flags.anybits?(FLAG_REEXPORT)
      end

      def stub_and_resolver?
        flags.anybits?(FLAG_STUB_AND_RESOLVER)
      end

      def static_resolver?
        flags.anybits?(FLAG_STATIC_RESOLVER)
      end

      def ==(other)
        other.is_a?(Terminal) && to_h == other.to_h
      end

      alias eql? ==

      def hash
        to_h.hash
      end

      def to_h
        {
          "kind" => kind,
          "flags" => flags,
          "address" => address,
          "stub_address" => stub_address,
          "resolver_address" => resolver_address,
          "library_ordinal" => library_ordinal,
          "imported_name" => imported_name.dup,
        }
      end

      def payload
        bytes = ExportTrie.uleb128(flags)

        if reexport?
          bytes << ExportTrie.uleb128(library_ordinal)
          bytes << imported_name
          bytes << "\x00".b
        elsif stub_and_resolver?
          bytes << ExportTrie.uleb128(stub_address)
          bytes << ExportTrie.uleb128(resolver_address)
        elsif static_resolver?
          bytes << ExportTrie.uleb128(resolver_address)
        else
          bytes << ExportTrie.uleb128(address)
        end

        bytes
      end

      private

      def build_flags(weak, reexport, stub_and_resolver, static_resolver)
        value = kind
        value |= FLAG_WEAK_DEFINITION if weak
        value |= FLAG_REEXPORT if reexport
        value |= FLAG_STUB_AND_RESOLVER if stub_and_resolver
        value |= FLAG_STATIC_RESOLVER if static_resolver
        value
      end

      def validate!
        raise ExportTrieError, "unknown terminal kind: #{kind}" unless [KIND_REGULAR, KIND_THREAD_LOCAL, KIND_ABSOLUTE].include?(kind)
        raise ExportTrieError, "terminal flags do not match kind: 0x#{flags.to_s(16)}" unless (flags & 0x03) == kind

        if reexport?
          validate_uint64(library_ordinal, "library ordinal")
          validate_name(imported_name, "imported name")
        elsif stub_and_resolver?
          validate_uint64(stub_address, "stub address")
          validate_uint64(resolver_address, "resolver address")
        elsif static_resolver?
          validate_uint64(resolver_address, "resolver address")
        else
          validate_uint64(address, "address")
        end
      end

      def validate_uint64(value, label)
        return if value.is_a?(Integer) && value >= 0 && value <= MAX_UINT64

        raise ExportTrieError, "#{label} must be an unsigned 64-bit integer"
      end

      def validate_name(value, label)
        return unless value.include?("\x00".b)

        raise ExportTrieError, "#{label} cannot contain a null byte"
      end

      def binary_name(value)
        value.b.freeze
      end
    end

    # An exported symbol and its terminal information.
    class Export
      attr_reader :name, :terminal

      def initialize(name, terminal)
        @name = name.to_s.b.freeze
        @terminal = terminal
        validate!
      end

      def ==(other)
        other.is_a?(Export) && name == other.name && terminal == other.terminal
      end

      alias eql? ==

      def hash
        [name, terminal].hash
      end

      def to_h
        {
          "name" => name.dup,
          "terminal" => terminal.to_h,
        }
      end

      private

      def validate!
        return unless name.include?("\x00".b) || !terminal.is_a?(Terminal)

        raise ExportSymbolError, "invalid export symbol: #{name.inspect}"
      end
    end

    Entry = Export

    class Node
      attr_accessor :terminal, :children

      def initialize(terminal = nil, children = {})
        @terminal = terminal
        @children = children
      end
    end

    private_constant :Node

    # Parses a Mach-O export trie byte string.
    # @param data [String] the export trie data
    # @return [ExportTrie]
    def self.parse(data)
      new(data)
    end

    # @param data [String, nil] raw export trie data
    def initialize(data = nil)
      @exports = {}
      return if data.nil? || data.empty?

      raise ExportTrieError, "export trie data must be a String" unless data.is_a?(String)

      @data = data.b

      parser = Parser.new(@data)
      @exports = parser.exports
    end

    # @return [Boolean] whether the trie contains no exports
    def empty?
      exports.empty?
    end

    # @return [Integer] the number of exported symbols
    def size
      exports.size
    end

    # @return [Array<Export>] all exported symbols, sorted by name
    def exports
      @exports.keys.sort_by(&:codepoints).map { |name| Export.new(name, @exports[name]) }
    end

    alias symbols exports

    # Enumerates each exported symbol in name order.
    # @yield [Export] each export
    # @return [Enumerator<Export>] when no block is given
    def each(&block)
      exports.each(&block)
    end

    # @return [Boolean] whether an export with the given exact name exists
    def export?(name)
      @exports.key?(name.to_s.b)
    end

    alias symbol? export?
    alias include? export?

    # Finds an export by exact name.
    # @param name [String] the symbol name
    # @return [Export, nil]
    def find(name)
      terminal = @exports[name.to_s.b]
      Export.new(name.to_s.b, terminal) if terminal
    end

    alias [] find

    # Enumerates exports with the given name prefix.
    # @param prefix [String] the name prefix
    # @return [Array<Export>]
    def with_prefix(prefix = "")
      prefix = prefix.to_s.b
      exports.select { |export| export.name.start_with?(prefix) }
    end

    alias symbols_with_prefix with_prefix
    alias exports_with_prefix with_prefix

    # Adds an export or replaces it when `replace` is true.
    # @param name [String] the symbol name
    # @param terminal [Terminal] terminal information
    # @param replace [Boolean] whether to replace an existing export
    # @return [Export]
    def add(name, terminal, replace: false)
      name = name.to_s.b
      raise ExportSymbolError, "terminal must be an ExportTrie::Terminal" unless terminal.is_a?(Terminal)
      raise ExportSymbolError, "symbol names cannot contain null bytes" if name.include?("\x00".b)
      raise ExportSymbolError, "export already exists: #{name.inspect}" if @exports.key?(name) && !replace

      @exports[name] = terminal
      Export.new(name, terminal)
    end

    alias add_export add
    alias add_symbol add

    # Removes an export by exact name.
    # @param name [String] the symbol name
    # @return [Export, nil] the removed export, or nil when absent
    def delete(name)
      terminal = @exports.delete(name.to_s.b)
      Export.new(name.to_s.b, terminal) if terminal
    end

    alias delete_export delete
    alias delete_symbol delete

    alias find_symbol find
    alias symbol find
    alias export find

    # @return [String] a canonical, reparseable export trie
    def serialize
      self.class.serialize_exports(exports.map { |export| [export.name, export.terminal] })
    end

    # Builds an export trie from name/terminal pairs.
    # @param entries [Array<Array(String, Terminal)>]
    # @return [String] serialized export trie data
    def self.serialize_exports(entries)
      root = build_tree(entries)
      layout = Layout.new(root)
      Serializer.new(root, layout).serialize
    end

    # @return [String] the canonical empty export trie
    def self.empty_trie
      "\x00\x00".b
    end

    def self.uleb128(value)
      raise ExportTrieError, "ULEB128 values must be unsigned 64-bit integers" unless value.is_a?(Integer) && value >= 0 && value <= MAX_UINT64

      bytes = +"".b
      loop do
        byte = value & 0x7f
        value >>= 7
        if value.nonzero?
          bytes << (byte | 0x80)
        else
          bytes << byte
          break
        end
      end
      bytes
    end

    def self.build_tree(entries)
      root = Node.new(nil, {})

      entries.each do |name, terminal|
        name = name.to_s.b
        raise ExportSymbolError, "symbol names cannot contain null bytes" if name.include?("\x00".b)
        raise ExportSymbolError, "terminal must be an ExportTrie::Terminal" unless terminal.is_a?(Terminal)

        insert_terminal(root, name, terminal)
      end

      root
    end

    def self.insert_terminal(node, suffix, terminal)
      if suffix.empty?
        raise ExportSymbolError, "duplicate export symbol: #{terminal.inspect}" if node.terminal

        node.terminal = terminal
        return
      end

      edge, child = node.children.find { |candidate, _| candidate.getbyte(0) == suffix.getbyte(0) }

      unless edge
        node.children[suffix] = Node.new(terminal, {})
        return
      end

      common = common_prefix(edge, suffix)

      if common == edge
        insert_terminal(child, suffix.byteslice(edge.bytesize..), terminal)
      else
        old_suffix = edge.byteslice(common.bytesize..)
        new_suffix = suffix.byteslice(common.bytesize..)
        replacement = Node.new(nil, {})
        replacement.children[old_suffix] = child
        node.children.delete(edge)
        node.children[common] = replacement
        insert_terminal(replacement, new_suffix, terminal)
      end
    end

    def self.common_prefix(left, right)
      length = [left.bytesize, right.bytesize].min.times.find { |index| left.getbyte(index) != right.getbyte(index) }
      left.byteslice(0, length || [left.bytesize, right.bytesize].min)
    end

    private_class_method :build_tree, :insert_terminal, :common_prefix

    # Decodes Mach-O export trie nodes.
    class Parser
      attr_reader :exports

      def initialize(data)
        @data = data
        @position = 0
        @exports = {}
        @visited = {}

        parse_node(0, "".b)
        skip_padding
      end

      private

      def parse_node(offset, name)
        raise ExportTrieError, "export trie node is out of bounds at #{offset}" if offset.negative? || offset >= @data.bytesize
        raise ExportTrieError, "export trie node is shared at #{offset}" if @visited.key?(offset)

        @visited[offset] = true
        @position = offset

        terminal_size = read_uleb128
        terminal = parse_terminal(terminal_size)

        unless terminal.nil?
          raise ExportTrieError, "duplicate export symbol: #{name.inspect}" if @exports.key?(name)

          @exports[name.dup] = terminal
        end

        child_count = read_byte

        children = []
        child_count.times do
          suffix = read_cstring
          raise ExportTrieError, "export trie edge name is empty at #{offset}" if suffix.empty?

          child_offset = read_uleb128
          children << [name + suffix, child_offset]
        end

        children.each do |child_name, child_offset|
          parse_node(child_offset, child_name)
        end
      end

      def parse_terminal(terminal_size)
        return if terminal_size.zero?

        ensure_bytes!(terminal_size, "terminal")
        terminal_end = @position + terminal_size
        flags = read_uleb128(terminal_end)
        kind = flags & 0x03

        terminal = if flags.anybits?(FLAG_REEXPORT)
          library_ordinal = read_uleb128(terminal_end)
          imported_name = read_cstring_within(terminal_end)
          Terminal.new(kind, :flags => flags, :library_ordinal => library_ordinal,
                             :imported_name => imported_name)
        elsif flags.anybits?(FLAG_STUB_AND_RESOLVER)
          stub_address = read_uleb128(terminal_end)
          resolver_address = read_uleb128(terminal_end)
          Terminal.new(kind, :flags => flags, :stub_address => stub_address,
                             :resolver_address => resolver_address)
        elsif flags.anybits?(FLAG_STATIC_RESOLVER)
          resolver_address = read_uleb128(terminal_end)
          Terminal.new(kind, :flags => flags, :resolver_address => resolver_address)
        else
          address = read_uleb128(terminal_end)
          Terminal.new(kind, :flags => flags, :address => address)
        end

        skip_terminal_padding(terminal_end)

        terminal
      end

      def skip_terminal_padding(limit)
        while @position < limit
          byte = read_byte(limit)
          raise ExportTrieError, "non-zero padding byte in terminal at #{@position - 1}" unless byte.zero?
        end
      end

      def skip_padding
        padding = @data.byteslice(@position..) || "".b
        return if padding.empty? || padding.each_byte.all?(&:zero?)

        raise ExportTrieError, "unexpected #{padding.bytesize} trailing bytes in export trie"
      end

      def read_cstring
        ending = @data.index("\x00".b, @position)
        raise ExportTrieError, "unterminated export trie edge name" if ending.nil?

        value = @data.byteslice(@position, ending - @position)
        @position = ending + 1
        value
      end

      def read_cstring_within(limit)
        ending = @data.index("\x00".b, @position)
        raise ExportTrieError, "unterminated re-export name" if ending.nil? || ending >= limit

        value = @data.byteslice(@position, ending - @position)
        @position = ending + 1
        value
      end

      def read_uleb128(limit = @data.bytesize)
        value = 0
        shift = 0

        10.times do |index|
          byte = read_byte(limit)
          value |= (byte & 0x7f) << shift
          unless byte.anybits?(0x80)
            raise ExportTrieError, "ULEB128 value is too large" if value > MAX_UINT64

            return value
          end

          raise ExportTrieError, "ULEB128 value is too large" if index == 9 || shift >= 63

          shift += 7
        end
      end

      def read_byte(limit = @data.bytesize)
        raise ExportTrieError, "unexpected end of export trie" if @position >= limit

        @data.getbyte(@position).tap { @position += 1 }
      end

      def ensure_bytes!(size, label)
        raise ExportTrieError, "#{label} extends beyond export trie" if @position + size > @data.bytesize
      end
    end

    # Computes canonical preorder node offsets after ULEB128 offsets settle.
    class Layout
      attr_reader :offsets

      def initialize(root)
        @root = root
        @offsets = {}
        calculate!
      end

      private

      def calculate!
        nodes = preorder(@root)
        offsets = nodes.to_h { |node| [node, 0] }
        next_offsets = offsets

        100.times do
          sizes = calculate_sizes(@root, offsets)
          next_offsets = {}
          assign_offsets(@root, 0, sizes, offsets, next_offsets)
          if next_offsets == offsets
            @offsets = next_offsets
            return
          end

          offsets = next_offsets
        end

        raise ExportTrieError, "failed to settle export trie node offsets"
      end

      def calculate_sizes(node, current_offsets)
        sizes = {}
        calculate_size(node, sizes, current_offsets)
        sizes
      end

      def calculate_size(node, sizes, offsets)
        children_size = sorted_children(node).sum do |_, child|
          calculate_size(child, sizes, offsets)
        end
        sizes[node] = node_header_size(node, offsets) + children_size
      end

      def assign_offsets(node, offset, sizes, current_offsets, next_offsets)
        next_offsets[node] = offset
        child_offset = offset + node_header_size(node, current_offsets)
        sorted_children(node).each do |_, child|
          subtree_end = assign_offsets(child, child_offset, sizes, current_offsets, next_offsets)
          child_offset = subtree_end
        end

        offset + sizes.fetch(node)
      end

      def node_header_size(node, offsets)
        terminal_bytes = if node.terminal.nil?
          "\x00".b
        else
          ExportTrie.uleb128(node.terminal.payload.bytesize) + node.terminal.payload
        end
        edges = sorted_children(node).flat_map do |edge, child|
          [edge, "\x00".b, ExportTrie.uleb128(offsets.fetch(child))]
        end.join

        terminal_bytes.bytesize + 1 + edges.bytesize
      end

      def preorder(node, result = [])
        result << node
        sorted_children(node).each { |_, child| preorder(child, result) }
        result
      end

      def sorted_children(node)
        node.children.sort_by { |edge, _| edge.codepoints }
      end
    end

    # Serializes a laid-out export trie.
    class Serializer
      def initialize(root, layout)
        @root = root
        @offsets = layout.offsets
        @data = +"".b
      end

      def serialize
        write_node(@root)
        @data
      end

      private

      def write_node(node)
        expected_offset = @offsets.fetch(node)
        raise ExportTrieError, "export trie layout is inconsistent at offset #{expected_offset}" unless @data.bytesize == expected_offset

        if node.terminal.nil?
          @data << "\x00".b
        else
          payload = node.terminal.payload
          @data << ExportTrie.uleb128(payload.bytesize)
          @data << payload
        end

        children = node.children.sort_by { |edge, _| edge.codepoints }
        raise ExportTrieError, "export trie nodes cannot have more than 255 edges" if children.size > 255

        @data << children.size.chr
        children.each do |edge, child|
          @data << edge
          @data << "\x00".b
          @data << ExportTrie.uleb128(@offsets.fetch(child))
        end

        children.each { |_, child| write_node(child) }
      end
    end
  end
end
