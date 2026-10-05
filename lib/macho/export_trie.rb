# frozen_string_literal: true

module MachO
  # A bounded parser for the export tries embedded in Mach-O files.
  class ExportTrie
    # An exported symbol.
    class Export
      # @return [String] the symbol name
      # @return [Symbol] `:regular`, `:thread_local`, `:absolute`, or `:reexport`
      # @return [Integer] the raw export flags
      # @return [Integer, nil] the encoded export address
      # @return [Integer, nil] the stub image offset, when a resolver is present
      # @return [Integer, nil] the resolver image offset, when a stub is present
      # @return [Integer, nil] the re-export dylib ordinal
      # @return [String, nil] the re-exported symbol name, or an empty string for same-name re-exports
      # @return [Integer] the terminal node's offset within the export trie
      attr_reader :name, :kind, :flags, :address, :stub_offset, :resolver_offset,
                  :reexport_ordinal, :reexport_symbol, :node_offset

      def initialize(name, kind, flags:, node_offset:, address: nil, stub_offset: nil,
                     resolver_offset: nil, reexport_ordinal: nil, reexport_symbol: nil)
        @name = name
        @kind = kind
        @flags = flags
        @address = address
        @stub_offset = stub_offset
        @resolver_offset = resolver_offset
        @reexport_ordinal = reexport_ordinal
        @reexport_symbol = reexport_symbol
        @node_offset = node_offset
      end

      def regular?
        kind == :regular
      end

      def thread_local?
        kind == :thread_local
      end

      def absolute?
        kind == :absolute
      end

      def stub_and_resolver?
        !stub_offset.nil?
      end

      def reexport?
        kind == :reexport
      end

      def to_h
        {
          "name" => name,
          "kind" => kind,
          "flags" => flags,
          "address" => address,
          "stub_offset" => stub_offset,
          "resolver_offset" => resolver_offset,
          "reexport_ordinal" => reexport_ordinal,
          "reexport_symbol" => reexport_symbol,
          "node_offset" => node_offset,
        }
      end
    end

    EXPORT_SYMBOL_FLAGS_KIND_MASK = 0x3
    EXPORT_SYMBOL_FLAGS_REEXPORT = 0x8
    EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER = 0x10
    EXPORT_SYMBOL_FLAGS_KNOWN_MASK = 0x1f

    # Queries symbols whose names start with `prefix`.
    # @param trie [String] the raw export trie
    # @param prefix [String] the symbol-name prefix to query
    # @return [Array<Export>] the matching exports
    # @raise [ExportTrieError] if the trie is truncated, cyclic, or otherwise malformed
    def self.query(trie, prefix = "")
      new(trie.b).query(prefix.b)
    end

    def initialize(data)
      @data = data
      @visited = {}
    end

    def query(prefix)
      results = []
      stack = [[0, ""]]

      until stack.empty?
        offset, name = stack.pop
        node = parse_node(offset)
        terminal = node[:terminal]

        results << Export.new(name, terminal[:kind], **terminal.except(:kind)) if terminal && name.start_with?(prefix)

        next unless descend?(name, prefix)

        selected_edges(node, name, prefix).reverse_each do |edge_label, child_offset|
          stack << [child_offset, name + edge_label]
        end
      end

      results
    end

    private

    def descend?(name, prefix)
      name.start_with?(prefix) || prefix.start_with?(name)
    end

    def selected_edges(node, name, prefix)
      return node[:edges] if name.start_with?(prefix)

      remaining = prefix.byteslice(name.bytesize)
      node[:edges].select do |edge_label, _|
        remaining.start_with?(edge_label) || edge_label.start_with?(remaining)
      end
    end

    def parse_node(offset)
      malformed!("export trie node offset out of bounds: #{offset}") unless offset >= 0 && offset < @data.bytesize
      malformed!("export trie contains a cycle or shared node at offset #{offset}") if @visited.key?(offset)

      @visited[offset] = true
      terminal_size, after_terminal_size = read_uleb128(offset)
      terminal_end = after_terminal_size + terminal_size
      malformed!("export trie terminal extends beyond trie") if terminal_end > @data.bytesize

      terminal = parse_terminal(after_terminal_size, terminal_end, offset) if terminal_size.positive?
      child_count, edges_start = read_uleb128(terminal_end)
      remaining_bytes = @data.bytesize - edges_start
      malformed!("export trie child count exceeds available bytes") if child_count > remaining_bytes / 2

      edges = []
      position = edges_start
      child_count.times do
        edge_label, position = read_cstring(position)
        child_offset, position = read_uleb128(position)

        edges << [edge_label, child_offset]
      end

      { :terminal => terminal, :edges => edges }
    end

    def parse_terminal(position, terminal_end, node_offset)
      flags, position = read_uleb128(position, terminal_end)
      malformed!("export trie contains unknown flags: 0x#{flags.to_s(16)}") if (flags & ~EXPORT_SYMBOL_FLAGS_KNOWN_MASK).positive?

      if (flags & EXPORT_SYMBOL_FLAGS_REEXPORT).positive?
        malformed!("re-export cannot also be a stub and resolver") if (flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER).positive?

        ordinal, position = read_uleb128(position, terminal_end)
        imported_name, _ = read_cstring(position, terminal_end)
        malformed!("re-export terminal contains trailing data") unless position + imported_name.bytesize + 1 == terminal_end
        ordinal = { 2**64 - 3 => -3, 2**64 - 2 => -2, 2**64 - 1 => -1 }.fetch(ordinal, ordinal)

        return {
          :kind => :reexport,
          :flags => flags,
          :reexport_ordinal => ordinal,
          :reexport_symbol => imported_name,
          :node_offset => node_offset,
        }
      end

      kind = case flags & EXPORT_SYMBOL_FLAGS_KIND_MASK
      when 0 then :regular
      when 1 then :thread_local
      when 2 then :absolute
      else
        malformed!("export trie contains an invalid export kind: #{flags & EXPORT_SYMBOL_FLAGS_KIND_MASK}")
      end

      address, position = read_uleb128(position, terminal_end)
      attributes = {
        :kind => kind,
        :flags => flags,
        :address => address,
        :node_offset => node_offset,
      }

      if (flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER).positive?
        attributes[:stub_offset], position = read_uleb128(position, terminal_end)
        attributes[:resolver_offset], position = read_uleb128(position, terminal_end)
      end

      malformed!("export trie terminal contains trailing data") unless position == terminal_end

      attributes
    end

    def read_cstring(offset, limit = @data.bytesize)
      malformed!("export trie string starts outside its bounds") unless offset >= 0 && offset <= limit

      null_offset = @data.index("\x00", offset)
      malformed!("export trie string is not null-terminated") if null_offset.nil? || null_offset >= limit

      [@data.byteslice(offset, null_offset - offset), null_offset + 1]
    end

    def read_uleb128(offset, limit = @data.bytesize)
      malformed!("export trie ULEB128 starts outside its bounds") unless offset >= 0 && offset <= limit

      value = 0
      position = offset

      10.times do |byte_index|
        malformed!("export trie ULEB128 is truncated") if position >= limit

        byte = @data.getbyte(position)
        position += 1
        value |= (byte & 0x7f) << (7 * byte_index)

        if (byte & 0x80).zero?
          malformed!("export trie ULEB128 exceeds 64 bits") if byte_index == 9 && byte > 1

          return [value, position]
        end

        malformed!("export trie ULEB128 is too long") if byte_index == 9
      end
    end

    def malformed!(message)
      raise ExportTrieError, message
    end
  end
end
