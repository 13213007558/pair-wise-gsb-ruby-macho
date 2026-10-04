# frozen_string_literal: true

require "rbconfig"

module MachO
  # Resolves the graph of dynamic libraries a Mach-O executable would load,
  # following dyld's search rules for install names that refer to the
  # executable path, loader path, and run-path search list (the
  # "@executable_path", "@loader_path", and "@rpath" placeholders).
  #
  # The resolver never touches the real filesystem. All file contents are
  # obtained through a caller-provided callback, which is only ever used for
  # reading; the caller's file tree is treated as strictly read-only.
  #
  # @example
  #  graph = MachO::DylibGraph.resolve("/bin/my_tool") do |path|
  #    File.binread(path) if File.file?(path)
  #  end
  #  graph.nodes.each { |node| puts node.path }
  class DylibGraph
    # Maps dylib load command types to the kind of edge they produce.
    EDGE_KINDS = {
      :LC_LOAD_DYLIB => :strong,
      :LC_LOAD_WEAK_DYLIB => :weak,
      :LC_REEXPORT_DYLIB => :reexport,
    }.freeze

    # Maps host CPU names to Mach-O CPU type symbols, used to pick a default
    # slice when no explicit architecture is requested.
    HOST_CPU_TYPES = {
      "x86_64" => :x86_64,
      "amd64" => :x86_64,
      "arm64" => :arm64,
      "aarch64" => :arm64,
      "i386" => :i386,
      "i686" => :i386,
    }.freeze

    # A single resolved image in the load graph.
    class Node
      # @return [String] the normalized path the image was resolved to
      attr_reader :path

      # @return [MachOFile] the parsed Mach-O slice selected for the image
      attr_reader :image

      # @return [Array<Edge>] the image's outgoing dependency edges
      attr_reader :edges

      # @api private
      def initialize(path, image)
        @path = path
        @image = image
        @edges = []
      end

      # The image's own install name, if it is a dylib.
      # @return [String, nil] the LC_ID_DYLIB install name
      def install_name
        image.dylib_id
      end
    end

    # A single dependency declared by a dylib load command.
    class Edge
      # @return [String] the raw install name from the load command
      attr_reader :name

      # @return [Symbol] one of :strong, :weak, or :reexport
      attr_reader :kind

      # @return [Node, nil] the resolved image, or nil if unresolved
      attr_reader :target

      # @return [Array<String>] every path that was tried, in search order
      attr_reader :attempted_paths

      # @api private
      def initialize(name, kind, target, attempted_paths)
        @name = name
        @kind = kind
        @target = target
        @attempted_paths = attempted_paths
      end

      # Weak dependencies may be absent without preventing the load.
      # @return [Boolean] true if the edge comes from LC_LOAD_WEAK_DYLIB
      def optional?
        kind == :weak
      end

      # @return [Boolean] true if no compatible image could be resolved
      def missing?
        target.nil?
      end
    end

    # @return [String] the normalized path of the main executable
    attr_reader :main_path

    # @return [Symbol] the CPU type the graph was resolved for
    attr_reader :arch

    # @return [Node] the root node, corresponding to the main executable
    attr_reader :root

    # Resolves the load graph rooted at the given main executable.
    # @param main_path [String] the path of the main executable, as understood
    #  by the fetch callback
    # @param arch [Symbol, nil] the CPU type to resolve for (e.g. :arm64);
    #  when nil, the host architecture is preferred, falling back to the
    #  first available slice
    # @yield [path] callback returning the contents of the file at the given
    #  path, or nil if no such file exists; only ever used for reading
    # @yieldparam path [String] a normalized path to fetch
    # @yieldreturn [String, nil] the file's bytes, or nil when absent
    # @return [DylibGraph] the resolved load graph
    # @raise [ArgumentError] if no callback is given, the main executable is
    #  missing, or it has no slice compatible with the requested architecture
    def self.resolve(main_path, arch: nil, &fetch)
      raise ArgumentError, "a file-fetching block is required" unless fetch

      new(main_path, arch, fetch)
    end

    # All resolved images, in load order (depth-first, main executable first).
    # @return [Array<Node>] the graph's nodes
    def nodes
      @load_order.dup
    end

    # All dependency edges that could not be resolved to a compatible image.
    # Weak edges appear here as optional edges; for strong edges the
    # {Edge#attempted_paths} of each entry report every path that was tried.
    # @return [Array<Edge>] the unresolved edges
    def missing
      @load_order.flat_map(&:edges).select(&:missing?)
    end

    # @api private
    def initialize(main_path, arch, fetch)
      @fetch = fetch
      @bytes = {}
      @nodes_by_path = {}
      @load_order = []
      @main_path = normalize_path(main_path)

      data = read_file(@main_path)
      raise ArgumentError, "#{main_path}: no such file" unless data

      main_image = pick_slice(parse_image(data), arch)
      unless main_image
        raise ArgumentError, "#{main_path}: no Mach-O slice compatible with #{arch.inspect}"
      end

      @arch = main_image.cputype
      @root = build_node(@main_path, main_image, [])
    end

    private_class_method :new

    private

    # Registers a node for the given image and resolves its dependencies.
    # The node is registered before its edges are resolved so that dependency
    # cycles converge on the already-resolved image identity.
    def build_node(path, image, parent_rpaths)
      node = Node.new(path, image)
      @nodes_by_path[path] = node
      @load_order << node

      rpaths = parent_rpaths + image.rpaths.map { |entry| expand_rpath(entry, path) }
      image.dylib_load_commands.each do |command|
        name = command.name.to_s
        kind = EDGE_KINDS.fetch(command.type)
        candidates = candidate_paths(name, path, rpaths)
        target_path = candidates.find { |candidate| @nodes_by_path.key?(candidate) || read_file(candidate) }
        target = resolve_node(target_path, rpaths) if target_path
        node.edges << Edge.new(name, kind, target, candidates)
      end

      node
    end

    # Returns the already-resolved node for a path, or loads and registers a
    # new one. Returns nil when no compatible slice exists at the path.
    def resolve_node(path, rpaths)
      node = @nodes_by_path[path]
      return node if node

      data = read_file(path)
      image = data && pick_slice(parse_image(data), @arch)
      build_node(path, image, rpaths) if image
    end

    # Reads a file through the fetch callback, memoizing both hits and misses
    # so each path is requested at most once.
    def read_file(path)
      return @bytes[path] if @bytes.key?(path)

      @bytes[path] = @fetch.call(path)
    end

    # Parses raw bytes into a MachOFile or FatFile, returning nil for data
    # that is not a recognizable Mach-O.
    def parse_image(data)
      magic = data[0, 4]&.unpack1("N")
      return unless magic

      if Utils.fat_magic?(magic)
        FatFile.new_from_bin(data)
      elsif Utils.magic?(magic)
        MachOFile.new_from_bin(data)
      end
    rescue MachOError
      nil
    end

    # Selects the slice compatible with the requested CPU type. When no
    # preference is given, the host architecture is preferred, falling back
    # to the first available slice.
    def pick_slice(image, preferred)
      return unless image

      slices = image.is_a?(FatFile) ? image.machos : [image]
      return if slices.empty?

      if preferred
        slices.find { |slice| slice.cputype == preferred }
      else
        host = HOST_CPU_TYPES[RbConfig::CONFIG["host_cpu"]]
        slices.find { |slice| slice.cputype == host } || slices.first
      end
    end

    # Expands an install name into the list of candidate paths dyld would
    # try, in search order. @loader_path is expanded against the directory of
    # the image that declares the dependency, never globally.
    def candidate_paths(name, loader_path, rpaths)
      if name.start_with?("@executable_path/")
        [join_path(File.dirname(@main_path), name.delete_prefix("@executable_path/"))]
      elsif name.start_with?("@loader_path/")
        [join_path(File.dirname(loader_path), name.delete_prefix("@loader_path/"))]
      elsif name.start_with?("@rpath/")
        rest = name.delete_prefix("@rpath/")
        rpaths.map { |rpath| join_path(rpath, rest) }
      else
        [normalize_path(name)]
      end
    end

    # Expands an LC_RPATH entry, which may itself refer to @executable_path
    # or @loader_path (of the image declaring the entry).
    def expand_rpath(entry, loader_path)
      expanded = entry.sub("@executable_path", File.dirname(@main_path))
                      .sub("@loader_path", File.dirname(loader_path))
      normalize_path(expanded)
    end

    def join_path(dir, rest)
      normalize_path(File.join(dir, rest))
    end

    # Normalizes a virtual path lexically, resolving "." and ".." components
    # without touching the real filesystem.
    def normalize_path(path)
      parts = []
      path.split("/").each do |part|
        next if part.empty? || part == "."

        if part == ".."
          parts.pop unless parts.empty?
        else
          parts << part
        end
      end

      prefix = path.start_with?("/") ? "/" : ""
      "#{prefix}#{parts.join("/")}"
    end
  end
end
