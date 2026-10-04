# frozen_string_literal: true

module MachO
  # A virtual, read-only Mach-O dynamic-library dependency graph.
  class DependencyGraph
    # A resolved or missing node in a dependency graph.
    Image = Struct.new(:path, :install_name, :arch, :macho, keyword_init: true) do
      def missing?
        macho.nil?
      end

      def identity
        [path, arch].freeze
      end
    end

    # A dependency edge between two image identities.
    Edge = Struct.new(
      :source, :target, :install_name, :load_command, :weak, :reexport,
      :tried_paths, :missing, keyword_init: true
    ) do
      def weak?
        weak
      end

      def reexport?
        reexport
      end

      def optional?
        weak
      end

      def required?
        !weak
      end
    end

    LOAD_COMMANDS = %i[
      LC_LOAD_DYLIB
      LC_LOAD_WEAK_DYLIB
      LC_REEXPORT_DYLIB
    ].freeze

    private_constant :LOAD_COMMANDS

    # @return [Image] the root executable image
    attr_reader :root

    # @return [Hash{Array => Image}] all resolved images by identity
    attr_reader :images

    # @return [Array<Edge>] all dependency edges, including optional missing edges
    attr_reader :edges

    # Builds a dependency graph without reading from the real filesystem.
    # @param executable_path [String] the virtual path of the main executable
    # @param file_reader [#call] a callback returning a binary string or nil
    # @param arch [Symbol, Array<Integer>, nil] the target architecture, or nil
    #  for the first slice in each image
    # @return [DependencyGraph]
    # @raise [DylibNotFoundError] if a required dylib is missing
    def self.build(executable_path, *args, arch: nil, &block)
      raise ArgumentError, "executable_path must be a String" unless executable_path.is_a?(String)
      raise ArgumentError, "wrong number of arguments" unless args.size <= 1

      file_reader = args.first
      file_reader ||= block
      raise ArgumentError, "file_reader must respond to #call" unless file_reader.respond_to?(:call)

      graph = new(file_reader, arch)
      graph.send(:build_graph, executable_path)
      graph
    end

    class << self
      alias resolve build
    end

    # @!visibility private
    def initialize(file_reader, arch)
      @file_reader = file_reader
      @requested_arch = arch
      @read_cache = {}
      @resolved_images = {}
      @images = {}
      @edges = []
      @visited = {}
      @root = nil
    end

    # @return [Array<Image>] resolved and optional missing images in visit order
    def image_list
      @images.values
    end

    alias nodes image_list

    # @return [Array<Edge>] edges from optional missing dylibs
    def missing_edges
      @edges.select(&:missing)
    end

    alias dependencies edges

    # @return [Hash] a compact representation of the graph
    def to_h
      {
        :root => root.identity,
        :images => images.transform_values { |image| image.to_h.except(:macho) },
        :edges => edges.map(&:to_h),
      }
    end

    private

    def build_graph(executable_path)
      root_data = read(executable_path)
      root_file, root_arch = parse(executable_path, root_data)
      @root = add_image(executable_path, root_file, root_arch)
      visit(@root, executable_directory(executable_path))
    end

    def visit(image, loader_directory)
      return if @visited.key?(image.identity)

      @visited[image.identity] = true
      executable_directory = executable_directory(root.path)
      expanded_rpaths = expanded_rpaths(image, loader_directory, executable_directory)

      image.macho.dylib_load_commands.each do |command|
        type = command.type
        next unless LOAD_COMMANDS.include?(type)

        install_name = command.name.to_s
        weak = type == :LC_LOAD_WEAK_DYLIB
        reexport = type == :LC_REEXPORT_DYLIB
        candidates = candidates(install_name, loader_directory, executable_directory, expanded_rpaths)
        resolved_path, _resolved_data, resolved_macho = resolve(candidates, image.arch)

        if resolved_path
          target = find_or_add_image(resolved_path, resolved_macho, image.arch)
          add_edge(image, target, install_name, type, weak, reexport, [], false)
          visit(target, executable_directory(resolved_path))
        else
          target = Image.new(
            :path => install_name,
            :install_name => install_name,
            :arch => image.arch,
            :macho => nil,
          )
          add_edge(image, target, install_name, type, weak, reexport, candidates, true)
          raise DylibNotFoundError.new(install_name, candidates) unless weak
        end
      end
    end

    def find_or_add_image(path, macho, arch)
      identity = [path, arch].freeze
      @resolved_images[identity] ||= add_image(path, macho, arch)
    end

    def add_image(path, macho, arch)
      image = Image.new(
        :path => path,
        :install_name => macho.dylib_id,
        :arch => arch,
        :macho => macho,
      )
      @images[image.identity] = image
      image
    end

    def add_edge(source, target, install_name, type, weak, reexport, tried_paths, missing)
      edge = Edge.new(
        :source => source.identity,
        :target => target.identity,
        :install_name => install_name,
        :load_command => type,
        :weak => weak,
        :reexport => reexport,
        :tried_paths => tried_paths,
        :missing => missing,
      )
      @images[target.identity] ||= target if target.missing?
      @edges << edge unless @edges.any? do |existing|
        existing.source == edge.source &&
          existing.target == edge.target &&
          existing.install_name == install_name &&
          existing.load_command == edge.load_command
      end
      edge
    end

    def read(path)
      @read_cache[path] ||= @file_reader.call(path)
    end

    def parse(path, data, target_arch = nil)
      raise DylibNotFoundError.new(path, [path]) if data.nil?
      raise ArgumentError, "#{path}: expected a binary String" unless data.is_a?(String)

      magic = data.byteslice(0, 4)&.unpack1("N")
      file = if Utils.fat_magic?(magic)
        FatFile.new_from_bin(data)
      else
        MachOFile.new_from_bin(data)
      end
      macho = select_macho(file, target_arch)
      raise DylibNotFoundError.new(path, [path]) if macho.nil?

      [macho, [macho.header.cputype, macho.header.cpusubtype]]
    end

    def select_macho(file, target_arch)
      machos = file.is_a?(FatFile) ? file.machos : [file]
      requested = target_arch || requested_arch(machos)
      matching = machos.select { |macho| compatible?(macho, requested) }
      return if matching.empty?

      exact = matching.find { |macho| macho.header.cputype == requested[0] && macho.header.cpusubtype == requested[1] }
      exact || matching.max_by { |macho| [macho.header.cpusubtype, macho.header.cputype] }
    end

    def requested_arch(machos)
      if @requested_arch.nil?
        first = machos.first
        return [first.header.cputype, first.header.cpusubtype]
      end

      if @requested_arch.is_a?(Symbol) || @requested_arch.is_a?(String)
        cputype = Headers::CPU_TYPES.key(@requested_arch.to_sym)
        raise ArgumentError, "unknown architecture: #{@requested_arch}" if cputype.nil?

        [cputype, default_subtype(cputype)]
      elsif @requested_arch.is_a?(Array)
        raise ArgumentError, "architecture must contain a CPU type and subtype" unless @requested_arch.size == 2

        @requested_arch
      else
        [@requested_arch, default_subtype(@requested_arch)]
      end
    end

    def compatible?(macho, requested)
      cputype, subtype = requested
      return false unless macho.header.cputype == cputype

      actual = macho.header.cpusubtype
      actual == subtype || actual == default_subtype(cputype) || actual < subtype
    end

    def default_subtype(cputype)
      case Headers::CPU_TYPES[cputype]
      when :i386, :x86_64 then Headers::CPU_SUBTYPE_I386
      when :arm, :arm64, :arm64_32 then Headers::CPU_SUBTYPE_ARM_ALL
      when :ppc, :ppc64 then Headers::CPU_SUBTYPE_POWERPC_ALL
      else 0
      end
    end

    def resolve(candidates, arch)
      candidates.each do |path|
        data = read(path)
        next if data.nil?

        begin
          file, selected_arch = parse(path, data, arch)
          next unless selected_arch == arch
        rescue DylibNotFoundError, NotAMachOError, TruncatedFileError, MagicError,
               FatBinaryError, MachOBinaryError
          next
        end

        return [path, data, file]
      end
      nil
    end

    def candidates(install_name, loader_directory, executable_directory, rpaths)
      expanded = substitute(install_name, loader_directory, executable_directory, rpaths)
      expanded.uniq
    end

    def substitute(name, loader_directory, executable_directory, rpaths)
      if name.start_with?("@executable_path/")
        [join_posix(executable_directory, name.delete_prefix("@executable_path/"))]
      elsif name.start_with?("@loader_path/")
        [join_posix(loader_directory, name.delete_prefix("@loader_path/"))]
      elsif name.start_with?("@rpath/")
        suffix = name.delete_prefix("@rpath/")
        rpaths.map { |rpath| join_posix(rpath, suffix) }
      elsif name.start_with?("/")
        [name]
      else
        [normalize(name)]
      end
    end

    def expanded_rpaths(image, loader_directory, executable_directory)
      image_rpath_entries = image.macho.rpaths.map { |rpath| [rpath, loader_directory] }
      entries = if image == root
        image_rpath_entries
      else
        root.macho.rpaths.map { |rpath| [rpath, executable_directory(root.path)] } + image_rpath_entries
      end

      expand_rpath_entries(entries)
    end

    def expand_rpath_entries(entries)
      entries.flat_map.with_index do |entry, index|
        expand_rpath_entry(entry, index, entries, {})
      end.uniq
    end

    def expand_rpath_entry(entry, index, entries, active)
      return [] if active[index]

      rpath, owner_directory = entry
      executable_directory = executable_directory(root.path)

      if rpath.start_with?("@rpath/")
        suffix = rpath.delete_prefix("@rpath/")
        entries.each_with_index.flat_map do |candidate_entry, candidate_index|
          next [] if candidate_index == index

          bases = expand_rpath_entry(candidate_entry, candidate_index, entries,
                                     active.merge(index => true))
          bases.map { |base| join_posix(base, suffix) }
        end
      elsif rpath.start_with?("@loader_path/")
        [join_posix(owner_directory, rpath.delete_prefix("@loader_path/"))]
      elsif rpath.start_with?("@executable_path/")
        [join_posix(executable_directory, rpath.delete_prefix("@executable_path/"))]
      else
        [normalize(rpath)]
      end
    end

    def executable_directory(path)
      dirname_posix(path)
    end

    def join_posix(directory, path)
      return normalize(path) if path.start_with?("/")

      normalized_directory = directory.empty? ? "." : directory
      normalize("#{normalized_directory}/#{path}")
    end

    def dirname_posix(path)
      index = path.rindex("/")
      return "." if index.nil?
      return "/" if index.zero?

      path[0...index]
    end

    def normalize(path)
      absolute = path.start_with?("/")
      parts = path.split("/").each_with_object([]) do |part, stack|
        next if part.empty? || part == "."

        if part == ".."
          stack.pop unless stack.empty? || stack.last == ".."
        else
          stack << part
        end
      end
      normalized = parts.join("/")
      return "/#{normalized}" if absolute
      normalized.empty? ? "." : normalized
    end

  end
end
