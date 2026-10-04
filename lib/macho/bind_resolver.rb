# frozen_string_literal: true

module MachO
  # Resolves symbol bindings offline against a fixed set of images.
  #
  # The resolver mirrors dyld's two-level namespace rules: a symbol reference
  # carries a library ordinal naming the image expected to provide the
  # symbol, and that image's re-exported dependents are searched
  # transparently from there. A symbol is never resolved by taking the first
  # name match across every library unless a flat lookup is explicitly
  # requested (via {DYNAMIC_LOOKUP_ORDINAL} or {#flat_lookup}).
  #
  # The resolver works purely on the in-memory image descriptions it is
  # constructed with. It never locates, opens, or reads files on disk;
  # callers are responsible for gathering the image set (e.g. from already
  # parsed Mach-O files) beforehand.
  #
  # @example
  #   resolver = MachO::BindResolver.new([
  #     MachO::BindResolver::Image.new("app", :executable => true,
  #       :dependents => ["liba.dylib", "libb.dylib"]),
  #     MachO::BindResolver::Image.new("liba.dylib", :exports => ["_run"]),
  #     MachO::BindResolver::Image.new("libb.dylib", :exports => ["_run"]),
  #   ])
  #   resolver.bind(:from => "app", :ordinal => 2, :symbol => "_run")
  #   # => bound to libb.dylib (the ordinal decides, not the name)
  class BindResolver
    # Library ordinal referring to the importing image itself.
    SELF_LIBRARY_ORDINAL = 0x00

    # Highest ordinal that indexes into an image's dependent dylib list.
    MAX_LIBRARY_ORDINAL = 0xFD

    # Library ordinal referring to the main executable.
    EXECUTABLE_ORDINAL = 0xFE

    # Library ordinal requesting a flat (single-level) namespace lookup.
    DYNAMIC_LOOKUP_ORDINAL = 0xFF

    # A single image (executable, dylib, or bundle) known to the resolver.
    class Image
      # @return [String] the image's identifier (usually its install name)
      attr_reader :name

      # @return [Array<String>] symbols this image defines and exports
      attr_reader :exports

      # @return [Array<String>] names of dependent images in load-command
      #   order; ordinals 1 through {BindResolver::MAX_LIBRARY_ORDINAL} index
      #   into this list
      attr_reader :dependents

      # @return [Array<String>] names of dependents whose symbols are
      #   re-exported to this image's clients (e.g. via +LC_REEXPORT_DYLIB+)
      attr_reader :reexports

      # @param name [String] the image's identifier
      # @param exports [Array<String>] symbols defined and exported by the image
      # @param dependents [Array<String>] dependent image names in load order
      # @param reexports [Array<String>] dependents whose symbols are re-exported
      # @param executable [Boolean] whether this image is the main executable
      def initialize(name, exports: [], dependents: [], reexports: [], executable: false)
        @name = name
        @exports = exports
        @dependents = dependents
        @reexports = reexports
        @executable = executable
      end

      # @return [Boolean] whether this image is the main executable
      def executable?
        @executable
      end
    end

    # The result of a successfully bound symbol reference.
    class Bound
      # @return [String] the symbol that was bound
      attr_reader :symbol

      # @return [String] the name of the image that defines the symbol
      attr_reader :image

      # @return [Array<String>] the images traversed to reach the definition,
      #   starting at the image named by the reference's ordinal and ending at
      #   the defining image; longer than one entry when re-exports were
      #   followed
      attr_reader :path

      # @param symbol [String] the bound symbol
      # @param image [String] the defining image's name
      # @param path [Array<String>] the resolution chain
      def initialize(symbol, image, path)
        @symbol = symbol
        @image = image
        @path = path
      end

      # @return [Boolean] true
      def bound?
        true
      end

      # @return [String] a human-readable summary of the binding
      def to_s
        if path.length > 1
          "%<symbol>s => %<image>s (re-exported via %<chain>s)" %
            { :symbol => symbol, :image => image, :chain => path.join(" -> ") }
        else
          "%<symbol>s => %<image>s" % { :symbol => symbol, :image => image }
        end
      end
    end

    # The result of a symbol reference that produced no definition.
    class Unresolved
      # All possible values for {#reason}.
      REASONS = %i[
        unknown_image
        invalid_ordinal
        ordinal_out_of_range
        no_main_executable
        undefined
        weak_undefined
        circular_reexport
      ].freeze

      # @return [String] the symbol that could not be bound
      attr_reader :symbol

      # @return [Symbol] why the reference could not be bound; one of
      #   {REASONS}
      attr_reader :reason

      # @return [String] a human-readable explanation of the failure
      attr_reader :detail

      # @param symbol [String] the unbound symbol
      # @param reason [Symbol] one of {REASONS}
      # @param detail [String] a human-readable explanation
      # @param tolerated [Boolean] whether the reference is a weak import that
      #   may safely bind to null at runtime
      def initialize(symbol, reason, detail, tolerated: false)
        @symbol = symbol
        @reason = reason
        @detail = detail
        @tolerated = tolerated
      end

      # @return [Boolean] false
      def bound?
        false
      end

      # @return [Boolean] true when the reference is a weak import whose
      #   missing definition is tolerated (it binds to null at runtime)
      def tolerated?
        @tolerated
      end

      # @return [String] a human-readable summary of the failure
      def to_s
        suffix = tolerated? ? " (tolerated: weak import binds to null)" : ""
        "%<symbol>s unresolved: %<detail>s%<suffix>s" %
          { :symbol => symbol, :detail => detail, :suffix => suffix }
      end
    end

    # @param images [Array<Image>] the images available for binding, in load
    #   order; flat lookups search the main executable first, then the
    #   remaining images in this order
    # @raise [ArgumentError] if two images share the same name
    def initialize(images)
      @images = {}
      images.each do |image|
        raise ArgumentError, "duplicate image name: #{image.name}" if @images.key?(image.name)

        @images[image.name] = image
      end
      @load_order = images.map(&:name)
    end

    # Binds a two-level namespace symbol reference.
    #
    # The ordinal selects the single library the reference is resolved
    # against (plus its re-exported dependents); other libraries exporting
    # the same name are never consulted.
    #
    # @param from [String] the name of the image containing the reference
    # @param ordinal [Integer] the reference's library ordinal
    #   ({SELF_LIBRARY_ORDINAL}, 1..{MAX_LIBRARY_ORDINAL},
    #   {EXECUTABLE_ORDINAL}, or {DYNAMIC_LOOKUP_ORDINAL})
    # @param symbol [String] the referenced symbol name
    # @param weak [Boolean] whether the reference is a weak import
    # @return [Bound] the binding, when a definition is found
    # @return [Unresolved] the failure, when no definition is found
    def bind(from:, ordinal:, symbol:, weak: false)
      image = @images[from]
      return unresolved(symbol, :unknown_image, "unknown importing image #{from.inspect}") if image.nil?

      case ordinal
      when SELF_LIBRARY_ORDINAL
        resolve_in(symbol, [from], weak)
      when EXECUTABLE_ORDINAL
        main = @load_order.find { |name| @images[name].executable? }
        return unresolved(symbol, :no_main_executable, "no image is marked as the main executable") if main.nil?

        resolve_in(symbol, [main], weak)
      when DYNAMIC_LOOKUP_ORDINAL
        flat_lookup(symbol, :weak => weak)
      when 1..MAX_LIBRARY_ORDINAL
        target = image.dependents[ordinal - 1]
        if target.nil?
          return unresolved(symbol, :ordinal_out_of_range,
                            "ordinal %<ordinal>d exceeds the %<count>d dependent(s) of %<from>s" %
                              { :ordinal => ordinal, :count => image.dependents.length, :from => from })
        end

        resolve_in(symbol, [target], weak)
      else
        unresolved(symbol, :invalid_ordinal, "invalid library ordinal %<ordinal>d" % { :ordinal => ordinal })
      end
    end

    # Binds a symbol using flat (single-level) namespace rules.
    #
    # Unlike {#bind}, this searches by name across the whole image set: the
    # main executable first, then the remaining images in load order,
    # returning the first definition found. This is the only lookup that
    # intentionally takes the first name match across libraries.
    #
    # @param symbol [String] the referenced symbol name
    # @param weak [Boolean] whether the reference is a weak import
    # @return [Bound] the binding, when a definition is found
    # @return [Unresolved] the failure, when no definition is found
    def flat_lookup(symbol, weak: false)
      mains, others = @load_order.partition { |name| @images[name].executable? }
      resolve_in(symbol, mains + others, weak)
    end

    private

    # Searches each root image (and its re-exported dependents) for a symbol.
    # @param symbol [String] the symbol to find
    # @param roots [Array<String>] image names to search, in order
    # @param weak [Boolean] whether the reference is a weak import
    # @return [Bound, Unresolved] the resolution result
    def resolve_in(symbol, roots, weak)
      cycle = false
      roots.each do |root|
        found, hit_cycle = find_definition(root, symbol)
        cycle ||= hit_cycle
        next if found.nil?

        defining_image, path = found
        return Bound.new(symbol, defining_image, path)
      end

      searched = roots.join(", ")
      return unresolved(symbol, :weak_undefined,
                        "no definition found in #{searched}",
                        :tolerated => true) if weak
      return unresolved(symbol, :circular_reexport,
                        "no definition found in #{searched}; re-export cycle detected during the search") if cycle

      unresolved(symbol, :undefined, "no definition found in #{searched}")
    end

    # Searches one image and, transitively, its re-exported dependents for a
    # symbol definition.
    # @param root [String] the image name to start from
    # @param symbol [String] the symbol to find
    # @return [Array((Array(String, Array<String>), nil), Boolean)]
    #   the defining image name and resolution path (or nil) plus whether a
    #   re-export cycle was encountered
    def find_definition(root, symbol)
      visited = {}
      cycle = false
      queue = [[root, [root]]]

      until queue.empty?
        name, path = queue.shift
        next if visited[name]

        visited[name] = true
        image = @images[name]
        next if image.nil?

        return [[name, path], cycle] if image.exports.include?(symbol)

        image.reexports.each do |dependent|
          if visited[dependent]
            cycle = true
          else
            queue.push([dependent, path + [dependent]])
          end
        end
      end

      [nil, cycle]
    end

    # @param symbol [String] the unbound symbol
    # @param reason [Symbol] one of {Unresolved::REASONS}
    # @param detail [String] a human-readable explanation
    # @param tolerated [Boolean] whether the failure is tolerated
    # @return [Unresolved] the failure result
    def unresolved(symbol, reason, detail, tolerated: false)
      Unresolved.new(symbol, reason, detail, :tolerated => tolerated)
    end
  end
end
