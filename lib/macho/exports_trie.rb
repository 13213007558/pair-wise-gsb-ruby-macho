# frozen_string_literal: true

module MachO
  # Parsing, editing, and serialization of the export trie referenced by
  # LC_DYLD_EXPORTS_TRIE and the export region of LC_DYLD_INFO and
  # LC_DYLD_INFO_ONLY.
  module ExportsTrie
    # Mask for the export symbol kind bits of a terminal's flags.
    EXPORT_SYMBOL_FLAGS_KIND_MASK = 0x03

    # A regular exported symbol.
    EXPORT_SYMBOL_FLAGS_KIND_REGULAR = 0x00

    # A thread-local exported symbol.
    EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL = 0x01

    # An absolute exported symbol.
    EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE = 0x02

    # The exported symbol is a weak definition.
    EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION = 0x04

    # The exported symbol is re-exported from another image.
    EXPORT_SYMBOL_FLAGS_REEXPORT = 0x08

    # The exported symbol has a stub and a resolver.
    EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER = 0x10

    # Maps export symbol kind flag values to symbolic names.
    KINDS = {
      EXPORT_SYMBOL_FLAGS_KIND_REGULAR => :regular,
      EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL => :thread_local,
      EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE => :absolute,
    }.freeze

    # Encodes a non-negative integer as ULEB128.
    # @param value [Integer] the value to encode
    # @return [String] the ULEB128-encoded bytes
    # @raise [ArgumentError] if `value` is negative
    def self.uleb128(value)
      raise ArgumentError, "cannot ULEB128-encode negative value: #{value}" if value.negative?

      bytes = []
      loop do
        byte = value & 0x7f
        value >>= 7
        if value.zero?
          bytes << byte.chr(Encoding::BINARY)
          break
        else
          bytes << (byte | 0x80).chr(Encoding::BINARY)
        end
      end
      bytes.join
    end

    # @param value [Integer] a non-negative integer
    # @return [Integer] the number of bytes needed to ULEB128-encode `value`
    # @raise [ArgumentError] if `value` is negative
    def self.uleb128_size(value)
      raise ArgumentError, "cannot ULEB128-encode negative value: #{value}" if value.negative?

      [(value.bit_length + 6) / 7, 1].max
    end

    # Decodes a ULEB128 value from a byte string.
    # @param data [String] the bytes to decode from
    # @param offset [Integer] the offset in `data` to start decoding at
    # @return [Array<Integer>] the decoded value and the offset of the
    #  first byte after it
    # @raise [ExportsTrieError] if the data is truncated or the value is too large
    def self.read_uleb128(data, offset)
      value = 0
      shift = 0
      loop do
        byte = data.getbyte(offset)
        raise ExportsTrieError, "truncated ULEB128 value at offset #{offset}" if byte.nil?

        value |= (byte & 0x7f) << shift
        offset += 1
        break if (byte & 0x80).zero?

        shift += 7
        raise ExportsTrieError, "ULEB128 value at offset #{offset} is too large" if shift > 63
      end
      [value, offset]
    end

    # The terminal information associated with an exported symbol.
    class Entry
      # @return [Integer] the raw EXPORT_SYMBOL_FLAGS_* flags
      attr_accessor :flags

      # @return [Integer] the symbol's address; only meaningful for
      #  regular, thread-local, and absolute symbols
      attr_accessor :address

      # @return [Integer] the ordinal of the image the symbol is
      #  re-exported from; only meaningful for re-exports
      attr_accessor :other

      # @return [String, nil] the name the symbol is imported as in the
      #  other image, or nil if it keeps its exported name; only meaningful
      #  for re-exports
      attr_accessor :imported_name

      # @return [Integer] the file offset of the resolver function; only
      #  meaningful for stub-and-resolver symbols
      attr_accessor :resolver_offset

      # @return [Integer] the file offset of the stub; only meaningful for
      #  stub-and-resolver symbols
      attr_accessor :stub_offset

      # Creates a new Entry.
      # @param flags [Integer] the raw EXPORT_SYMBOL_FLAGS_* flags
      # @param address [Integer] the symbol's address
      # @param other [Integer] the re-export ordinal
      # @param imported_name [String, nil] the imported name of a re-export
      # @param resolver_offset [Integer] the resolver's file offset
      # @param stub_offset [Integer] the stub's file offset
      def initialize(flags, address: 0, other: 0, imported_name: nil, resolver_offset: 0, stub_offset: 0)
        @flags = flags
        @address = address
        @other = other
        @imported_name = imported_name
        @resolver_offset = resolver_offset
        @stub_offset = stub_offset
      end

      # @return [Symbol] the kind of export (`:regular`, `:thread_local`,
      #  or `:absolute`)
      def kind
        KINDS.fetch(flags & EXPORT_SYMBOL_FLAGS_KIND_MASK)
      end

      # @return [Boolean] whether the symbol is re-exported from another image
      def reexport?
        (flags & EXPORT_SYMBOL_FLAGS_REEXPORT) != 0
      end

      # @return [Boolean] whether the symbol is a weak definition
      def weak_definition?
        (flags & EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION) != 0
      end

      # @return [Boolean] whether the symbol has a stub and a resolver
      def stub_and_resolver?
        (flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER) != 0
      end

      # @return [Hash] a hash representation of this {Entry}
      def to_h
        {
          "flags" => flags,
          "kind" => kind,
          "address" => address,
          "other" => self.other,
          "imported_name" => imported_name,
          "resolver_offset" => resolver_offset,
          "stub_offset" => stub_offset,
        }
      end

      def ==(other)
        other.is_a?(Entry) &&
          flags == other.flags &&
          address == other.address &&
          self.other == other.other &&
          imported_name == other.imported_name &&
          resolver_offset == other.resolver_offset &&
          stub_offset == other.stub_offset
      end
    end

    # A mutable export trie. Edges are labeled with (possibly
    # multi-character) string fragments, and every node may carry terminal
    # information for the symbol spelled out by the path to it.
    class Trie
      include Enumerable

      # Creates a trie rooted at `root`.
      # @param root [Node] the root node
      # @api private
      def initialize(root = Node.new)
        @root = root
      end

      # Parses serialized export trie data.
      # @param data [String] the raw export trie bytes
      # @return [Trie] the parsed trie
      # @raise [ExportsTrieError] if the data is malformed
      def self.parse(data)
        data = data.b
        root = Node.new
        return new(root) if data.empty?

        visited = {}
        stack = [[0, root]]
        until stack.empty?
          offset, node = stack.pop
          raise ExportsTrieError, "export trie contains a cycle" if visited[offset]

          visited[offset] = true
          if offset >= data.bytesize
            raise ExportsTrieError, "export trie node offset #{offset} is out of bounds"
          end

          terminal_size, cursor = ExportsTrie.read_uleb128(data, offset)
          terminal_end = cursor + terminal_size
          if terminal_end > data.bytesize
            raise ExportsTrieError, "export trie terminal at offset #{offset} is truncated"
          end

          node.terminal = parse_terminal(data, cursor, terminal_end) if terminal_size.positive?

          if terminal_end >= data.bytesize
            raise ExportsTrieError, "export trie node at offset #{offset} is truncated"
          end

          child_count = data.getbyte(terminal_end)
          cursor = terminal_end + 1
          child_count.times do
            label_end = data.index("\x00".b, cursor)
            if label_end.nil?
              raise ExportsTrieError, "export trie edge label at offset #{cursor} is unterminated"
            end

            label = data.byteslice(cursor...label_end)
            child_offset, cursor = ExportsTrie.read_uleb128(data, label_end + 1)
            child = Node.new
            node.children[label] = child
            stack << [child_offset, child]
          end
        end

        new(root)
      end

      # Looks up the terminal information for an exact symbol name.
      # @param name [String] the exported symbol name
      # @return [Entry, nil] the symbol's terminal information, or nil if
      #  the symbol is not exported
      def lookup(name)
        node = @root
        remaining = name.b
        until remaining.empty?
          match = node.children.find { |label, _child| remaining.start_with?(label) }
          return nil if match.nil?

          label, child = match
          remaining = remaining.byteslice(label.bytesize..)
          node = child
        end
        node.terminal
      end

      alias [] lookup

      # Adds or replaces an exported symbol.
      # @param name [String] the exported symbol name
      # @param entry [Entry] the symbol's terminal information
      # @return [void]
      def add(name, entry)
        node = @root
        remaining = name.b
        until remaining.empty?
          match = node.children.find do |label, _child|
            common_prefix_length(label, remaining).positive?
          end

          if match.nil?
            child = Node.new
            node.children[remaining] = child
            node = child
            remaining = +""
          else
            label, child = match
            common = common_prefix_length(label, remaining)
            child = split_edge(node, label, child, common) if common < label.bytesize
            remaining = remaining.byteslice(common..) || +""
            node = child
          end
        end
        node.terminal = entry
        nil
      end

      # Removes an exported symbol, merging edges that no longer need to
      # be split.
      # @param name [String] the exported symbol name
      # @return [Entry, nil] the removed terminal information, or nil if
      #  the symbol was not exported
      def delete(name)
        node = @root
        path = []
        remaining = name.b
        until remaining.empty?
          match = node.children.find { |label, _child| remaining.start_with?(label) }
          return nil if match.nil?

          label, child = match
          path << [node, label]
          remaining = remaining.byteslice(label.bytesize..)
          node = child
        end

        entry = node.terminal
        return nil if entry.nil?

        node.terminal = nil
        compress(path, node)
        entry
      end

      # Iterates over the exported symbols whose names begin with
      # `prefix`.
      # @param prefix [String] only enumerate symbols with this prefix
      # @yieldparam name [String] the exported symbol name
      # @yieldparam entry [Entry] the symbol's terminal information
      # @return [Enumerator] if no block is given
      def each(prefix = "")
        return enum_for(:each, prefix) unless block_given?

        node = @root
        name = +""
        remaining = prefix.b
        until remaining.empty?
          match = node.children.find do |label, _child|
            label.start_with?(remaining) || remaining.start_with?(label)
          end
          return if match.nil?

          label, child = match
          name << label
          node = child
          remaining = remaining.byteslice(label.bytesize..) || +""
        end
        each_node(node, name) { |symbol, entry| yield symbol, entry }
      end

      # @return [Array<String>] all exported symbol names
      def names
        map { |name, _entry| name }
      end

      # @return [Hash{String => Entry}] all exported symbols and their
      #  terminal information
      def entries
        each.to_h
      end

      # @return [Boolean] whether the trie has no exported symbols
      def empty?
        @root.terminal.nil? && @root.children.empty?
      end

      # Serializes the trie into bytes that {Trie.parse} (and dyld) can
      # read back. Node sizes depend on the ULEB128-encoded offsets of
      # child nodes, so offsets and sizes are iterated to a fixpoint
      # before any bytes are emitted.
      # @return [String] the serialized export trie
      def serialize
        nodes = []
        collect_nodes(@root, nodes)

        sizes = {}
        offsets = {}
        loop do
          offset = 0
          nodes.each do |node|
            offsets[node] = offset
            offset += sizes.fetch(node, 0)
          end

          new_sizes = {}
          nodes.each { |node| new_sizes[node] = node_size(node, offsets) }
          break if new_sizes == sizes

          sizes = new_sizes
        end

        total = nodes.sum { |node| sizes.fetch(node, 0) }
        output = "\x00".b * total
        nodes.each do |node|
          output[offsets.fetch(node), sizes.fetch(node)] = node_bytes(node, offsets)
        end
        output
      end

      # @return [Hash] a hash representation of this {Trie}
      def to_h
        {
          "exports" => map do |name, entry|
            { "name" => name }.merge(entry.to_h)
          end,
        }
      end

      def ==(other)
        other.is_a?(Trie) && entries == other.entries
      end

      private

      # Parses the terminal information of a node.
      # @param data [String] the raw export trie bytes
      # @param cursor [Integer] the offset of the terminal information
      # @param terminal_end [Integer] the offset just past the terminal
      # @return [Entry] the parsed terminal information
      # @raise [ExportsTrieError] if the terminal is malformed
      # @api private
      def self.parse_terminal(data, cursor, terminal_end)
        flags, cursor = ExportsTrie.read_uleb128(data, cursor)
        entry = Entry.new(flags)
        if entry.reexport?
          entry.other, cursor = ExportsTrie.read_uleb128(data, cursor)
          name_end = data.index("\x00".b, cursor)
          if name_end.nil? || name_end >= terminal_end
            raise ExportsTrieError, "export trie re-export name at offset #{cursor} is unterminated"
          end

          imported_name = data.byteslice(cursor...name_end)
          entry.imported_name = imported_name unless imported_name.empty?
          cursor = name_end + 1
        elsif entry.stub_and_resolver?
          entry.resolver_offset, cursor = ExportsTrie.read_uleb128(data, cursor)
          entry.stub_offset, cursor = ExportsTrie.read_uleb128(data, cursor)
        else
          entry.address, cursor = ExportsTrie.read_uleb128(data, cursor)
        end

        if cursor != terminal_end
          raise ExportsTrieError, "export trie terminal at offset #{terminal_end} has a size mismatch"
        end

        entry
      end

      # @return [Integer] the length of the common prefix of two strings
      def common_prefix_length(str1, str2)
        length = 0
        max = [str1.bytesize, str2.bytesize].min
        length += 1 while length < max && str1.getbyte(length) == str2.getbyte(length)
        length
      end

      # Splits the edge from `parent` to `child` at `length`, inserting a
      # new node in between.
      # @return [Node] the newly inserted node
      def split_edge(parent, label, child, length)
        middle = Node.new
        middle.children[label.byteslice(length..)] = child
        parent.children.delete(label)
        parent.children[label.byteslice(0, length)] = middle
        middle
      end

      # Removes or merges nodes on `path` (innermost first) that no longer
      # carry any information.
      # @return [void]
      def compress(path, node)
        until path.empty?
          parent, label = path.pop
          if node.children.empty? && node.terminal.nil?
            parent.children.delete(label)
          elsif node.children.one? && node.terminal.nil?
            child_label, child = node.children.first
            parent.children.delete(label)
            parent.children[label + child_label] = child
          else
            break
          end
          node = parent
        end
        nil
      end

      # Yields each terminal at and below `node`, along with its full
      # symbol name.
      def each_node(node, name)
        yield name, node.terminal if node.terminal
        node.children.each do |label, child|
          each_node(child, name + label) { |symbol, entry| yield symbol, entry }
        end
      end

      # Appends all nodes at and below `node` to `nodes`, parents first, so
      #  that the root is assigned offset 0 as dyld expects.
      def collect_nodes(node, nodes)
        nodes << node
        node.children.sort_by { |label, _child| label }.each do |_label, child|
          collect_nodes(child, nodes)
        end
      end

      # @return [Integer] the serialized size of `node`, given the offsets
      #  of its children
      def node_size(node, offsets)
        terminal = terminal_bytes(node.terminal)
        size = ExportsTrie.uleb128_size(terminal.bytesize) + terminal.bytesize + 1
        node.children.each do |label, child|
          size += label.bytesize + 1 + ExportsTrie.uleb128_size(offsets.fetch(child))
        end
        size
      end

      # @return [String] the serialized bytes of `node`, given the offsets
      #  of its children
      def node_bytes(node, offsets)
        parts = []
        terminal = terminal_bytes(node.terminal)
        parts << ExportsTrie.uleb128(terminal.bytesize) << terminal
        parts << node.children.size.chr(Encoding::BINARY)
        node.children.sort_by { |label, _child| label }.each do |label, child|
          parts << label << "\x00" << ExportsTrie.uleb128(offsets.fetch(child))
        end
        parts.join
      end

      # @return [String] the serialized terminal information for `entry`
      def terminal_bytes(entry)
        return "" if entry.nil?

        parts = [ExportsTrie.uleb128(entry.flags)]
        if entry.reexport?
          parts << ExportsTrie.uleb128(entry.other)
          parts << entry.imported_name.to_s.b << "\x00"
        elsif entry.stub_and_resolver?
          parts << ExportsTrie.uleb128(entry.resolver_offset)
          parts << ExportsTrie.uleb128(entry.stub_offset)
        else
          parts << ExportsTrie.uleb128(entry.address)
        end
        parts.join
      end

      # A node in a {Trie}.
      class Node
        # @return [Entry, nil] the terminal information at this node
        attr_accessor :terminal

        # @return [Hash{String => Node}] this node's children, keyed by
        #  edge label
        attr_reader :children

        def initialize
          @terminal = nil
          @children = {}
        end
      end
    end
  end
end
