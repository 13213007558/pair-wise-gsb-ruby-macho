# frozen_string_literal: true

module MachO
  # A parser for the compact dyld export trie used by LC_DYLD_EXPORTS_TRIE and
  # the export area of LC_DYLD_INFO(_ONLY).
  class ExportTrie
    EXPORT_SYMBOL_FLAGS_KIND_MASK = 0x3
    EXPORT_SYMBOL_FLAGS_KIND_REGULAR = 0x0
    EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL = 0x1
    EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE = 0x2
    EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION = 0x4
    EXPORT_SYMBOL_FLAGS_REEXPORT = 0x8
    EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER = 0x10

    # One exported symbol.
    Export = Struct.new(
      :name,
      :flags,
      :address,
      :stub_offset,
      :resolver_offset,
      :reexport_ordinal,
      :reexport_name,
      :reexport_dylib_name,
      :source,
      :node_offset,
      :keyword_init => true
    ) do
      def regular?
        !reexport? && !stub_and_resolver?
      end

      def thread_local?
        regular? && (flags & EXPORT_SYMBOL_FLAGS_KIND_MASK) == EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL
      end

      def absolute?
        regular? && (flags & EXPORT_SYMBOL_FLAGS_KIND_MASK) == EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE
      end

      def weak_defined?
        (flags & EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION).positive?
      end

      def reexport?
        (flags & EXPORT_SYMBOL_FLAGS_REEXPORT).positive?
      end

      def stub_and_resolver?
        (flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER).positive?
      end

      def kind
        return :reexport if reexport?
        return :stub_and_resolver if stub_and_resolver?

        case flags & EXPORT_SYMBOL_FLAGS_KIND_MASK
        when EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL then :thread_local
        when EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE then :absolute
        else :regular
        end
      end

      def target
        return unless reexport?

        {
          :ordinal => reexport_ordinal,
          :dylib_name => reexport_dylib_name,
          :symbol_name => reexport_name,
        }
      end

      def to_h
        {
          "name" => name,
          "flags" => flags,
          "kind" => kind,
          "address" => address,
          "stub_offset" => stub_offset,
          "resolver_offset" => resolver_offset,
          "reexport" => target,
          "source" => source&.transform_keys(&:to_s),
          "node_offset" => node_offset,
        }
      end
    end

    Node = Struct.new(:export, :edges, :keyword_init => true)

    # Returns all exports in a raw export trie.
    # @param trie [String] the complete export trie
    # @param source [Hash, nil] provenance from a load command
    # @param dylib_names [Array<String>] ordered linked-dylib names
    # @return [Array<Export>]
    def self.all(trie, source: nil, dylib_names: [])
      query(trie, "", :source => source, :dylib_names => dylib_names)
    end

    # Returns exports whose names begin with `prefix`.
    # @param trie [String] the complete export trie
    # @param prefix [String] the symbol-name prefix to query
    # @param source [Hash, nil] provenance from a load command
    # @param dylib_names [Array<String>] ordered linked-dylib names
    # @return [Array<Export>]
    # @raise [ExportTrieError] if the trie is truncated, contains an invalid
    #   integer, has an out-of-bounds edge, or contains a cycle
    def self.query(trie, prefix = "", source: nil, dylib_names: [])
      raise ArgumentError, "trie must be a String" unless trie.is_a?(String)
      raise ArgumentError, "prefix must be a String" unless prefix.is_a?(String)

      new(trie.b, prefix.dup.force_encoding(Encoding::BINARY), source, dylib_names).query
    end

    def initialize(data, prefix, source, dylib_names)
      @data = data
      @prefix = prefix
      @source = source
      @dylib_names = dylib_names
      @nodes = {}
    end
    private_class_method :new

    def query
      return [] if @data.empty?

      results = []
      stack = [{ :offset => 0, :name => "".b, :path => { 0 => true } }]
      visited = {}

      until stack.empty?
        state = stack.pop
        if visited.key?(state[:offset])
          raise ExportTrieError, "export trie edge at #{state[:offset]} forms a cycle or merge"
        end

        visited[state[:offset]] = true
        node = parse_node(state[:offset])

        if state[:name].start_with?(@prefix) && node.export
          results << decorate(node.export, state[:name], state[:offset])
        end

        matching_edges(node.edges, state[:name]).reverse_each do |edge|
          child_offset = edge[:offset]
          if state[:path].key?(child_offset)
            raise ExportTrieError, "export trie edge at #{state[:offset]} forms a cycle"
          end

          child_path = state[:path].dup
          child_path[child_offset] = true
          stack << {
            :offset => child_offset,
            :name => state[:name] + edge[:label],
            :path => child_path,
          }
        end
      end

      results
    end

    private

    def matching_edges(edges, name)
      edges.select do |edge|
        child_name = name + edge[:label]
        child_name.start_with?(@prefix) || @prefix.start_with?(child_name)
      end
    end

    def parse_node(offset)
      return @nodes[offset] if @nodes.key?(offset)
      raise ExportTrieError, "export trie node offset #{offset} is out of bounds" unless valid_node_offset?(offset)

      terminal_size, terminal_size_length = read_uleb128(offset)
      terminal_start = offset + terminal_size_length
      terminal_end = terminal_start + terminal_size
      unless terminal_end <= @data.bytesize
        raise ExportTrieError, "export trie terminal at #{offset} is out of bounds"
      end

      export = parse_terminal(offset, terminal_start, terminal_end)
      child_count, child_count_length = read_uleb128(terminal_end)
      cursor = terminal_end + child_count_length
      edges = []
      child_count.times do
        label_end = @data.index("\x00".b, cursor)
        raise ExportTrieError, "export trie edge label at #{offset} is truncated" if label_end.nil? || label_end >= @data.bytesize

        label = @data.byteslice(cursor, label_end - cursor)
        raise ExportTrieError, "export trie edge label at #{offset} is empty" if label.empty?

        cursor = label_end + 1
        child_offset, offset_length = read_uleb128(cursor)
        unless valid_node_offset?(child_offset)
          raise ExportTrieError, "export trie edge at #{offset} points outside the trie"
        end

        cursor += offset_length
        edges << { :label => label, :offset => child_offset }
      end

      raise ExportTrieError, "export trie node at #{offset} is truncated" if cursor > @data.bytesize
      @nodes[offset] = Node.new(:export => export, :edges => edges)
    end

    def valid_node_offset?(offset)
      offset.is_a?(Integer) && offset >= 0 && offset < @data.bytesize
    end

    def parse_terminal(node_offset, start, end_end)
      return nil if end_end == start

      reader = BoundedReader.new(@data, start, end_end)
      flags, = reader.uleb128("export flags")

      if (flags & EXPORT_SYMBOL_FLAGS_REEXPORT).positive?
        ordinal, = reader.uleb128("re-export ordinal")
        imported_name = reader.c_string("re-export name")
        imported_name = nil if imported_name.empty?
        reader.expect_end("terminal")

        return Export.new(
          :flags => flags,
          :reexport_ordinal => ordinal,
          :reexport_name => imported_name,
          :node_offset => node_offset
        )
      end

      address, = reader.uleb128("export address")
      stub_offset = nil
      resolver_offset = nil

      if (flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER).positive?
        stub_offset, = reader.uleb128("stub offset")
        resolver_offset, = reader.uleb128("resolver offset")
      end

      reader.expect_end("terminal")

      Export.new(
        :flags => flags,
        :address => address,
        :stub_offset => stub_offset,
        :resolver_offset => resolver_offset,
        :node_offset => node_offset
      )
    end

    def decorate(export, name, offset)
      values = Export.members.to_h { |member| [member, export[member]] }
      values[:name] = name
      values[:source] = @source
      values[:node_offset] = offset
      if values[:reexport_ordinal].is_a?(Integer) && values[:reexport_ordinal].positive?
        values[:reexport_dylib_name] = @dylib_names.fetch(values[:reexport_ordinal] - 1, nil)
      end
      Export.new(values)
    end

    def read_uleb128(offset)
      BoundedReader.new(@data, offset, @data.bytesize).uleb128("ULEB128")
    end

    # Reads one bounded, canonical unsigned LEB128 integer.
    class BoundedReader
      def initialize(data, offset, limit)
        @data = data
        @offset = offset
        @limit = limit
      end

      def uleb128(description)
        value = 0
        shift = 0
        bytes = 0

        loop do
          byte = read_byte(description)
          bytes += 1
          raise ExportTrieError, "#{description} is encoded with too many bytes" if bytes > 10
          raise ExportTrieError, "#{description} overflows 64 bits" if bytes == 10 && (byte & 0x7f) > 1

          value |= (byte & 0x7f) << shift
          shift += 7

          if (byte & 0x80).zero?
            raise ExportTrieError, "#{description} has an overlong encoding" if bytes > 1 && byte.zero?

            return [value, bytes]
          end
        end
      end

      def c_string(description)
        end_offset = @data.index("\x00".b, @offset)
        raise ExportTrieError, "#{description} is truncated" if end_offset.nil? || end_offset > @limit

        string = @data.byteslice(@offset, end_offset - @offset)
        @offset = end_offset + 1
        string
      end

      def expect_end(description)
        raise ExportTrieError, "#{description} contains unconsumed bytes" unless @offset == @limit
      end

      private

      def read_byte(description)
        raise ExportTrieError, "#{description} is truncated" if @offset >= @limit

        byte = @data.getbyte(@offset)
        @offset += 1
        byte
      end
    end
  end
end
