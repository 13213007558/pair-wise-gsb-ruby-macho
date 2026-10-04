# frozen_string_literal: true

module MachO
  # Offline resolution of imported symbols against a fixed set of images,
  # following dyld's two-level namespace rules.
  #
  # The resolver works purely on in-memory image descriptions: every image
  # carries its own export table and its ordered list of linked libraries.
  # Nothing is read from disk and no install-name or rpath searching is
  # performed; callers are responsible for gathering the image set (and each
  # image's exports) beforehand.
  #
  # Resolution semantics:
  #
  # * two-level (the default): the import's library ordinal designates one
  #   specific entry in the importing image's linked-library list. Only that
  #   library (and anything it re-exports) is searched. A symbol exported by
  #   some other library is *not* considered, even if the name matches.
  # * +:flat+ (nlist ordinal {DYNAMIC_LOOKUP_ORDINAL}): the main executable
  #   is searched first, then every image in load order. Weak definitions do
  #   not stop the search for a strong one.
  # * +:main_executable+ (nlist ordinal {EXECUTABLE_ORDINAL}): only the main
  #   executable's export table is searched.
  # * +:self+ (nlist ordinal {SELF_LIBRARY_ORDINAL}): only the importing
  #   image itself is searched.
  #
  # Re-exports are followed transparently, both at the library level
  # (LC_REEXPORT_DYLIB) and at the symbol level (an export entry that forwards
  # to another library, possibly under a different name). Cycles in the
  # re-export graph are detected and reported instead of looping forever.
  #
  # @example
  #   app = MachO::SymbolResolver::Image.new("app", :main_executable => true)
  #   liba = MachO::SymbolResolver::Image.new("libA.dylib")
  #   liba.add_export("_foo")
  #   app.link_library(liba)
  #
  #   resolver = MachO::SymbolResolver::Resolver.new([app, liba])
  #   result = resolver.resolve(:symbol => "_foo", :from => app, :ordinal => 1)
  #   result.status # => :bound
  #   result.image  # => liba
  module SymbolResolver
    # nlist library ordinal meaning "defined in this image".
    SELF_LIBRARY_ORDINAL = 0

    # nlist library ordinal meaning "flat lookup at run time".
    DYNAMIC_LOOKUP_ORDINAL = 254

    # nlist library ordinal meaning "defined in the main executable".
    EXECUTABLE_ORDINAL = 255

    # A single image (executable or dylib) with its export table and its
    # ordered list of linked libraries.
    class Image
      # @return [String] identifying name (e.g. install name), used in
      #   results and resolution traces
      attr_reader :name

      # @return [Hash{String => Export}] exported symbols, keyed by name
      attr_reader :exports

      # @return [Array<Image>] linked libraries in load-command order;
      #   two-level ordinal +n+ refers to linked_libraries[n - 1]
      attr_reader :linked_libraries

      # @return [Array<Image>] libraries re-exported by this image
      #   (LC_REEXPORT_DYLIB), searched when a symbol is absent from this
      #   image's own export table
      attr_reader :reexported_libraries

      # @param name [String] identifying name for the image
      # @param main_executable [Boolean] whether this image is the main
      #   executable of the process
      def initialize(name, main_executable: false)
        @name = name
        @main_executable = main_executable
        @exports = {}
        @linked_libraries = []
        @reexported_libraries = []
      end

      # @return [Boolean] whether this image is the main executable
      def main_executable?
        @main_executable
      end

      # Defines +symbol+ in this image's own export table.
      # @param symbol [String] exported symbol name
      # @param weak [Boolean] whether this is a weak (coalesced) definition
      # @return [Image] self, for chaining
      def add_export(symbol, weak: false)
        @exports[symbol] = Export.new(symbol, :weak => weak)
        self
      end

      # Adds an export entry that forwards +symbol+ to +library+ (a symbol
      # re-export, as found in export tries with a re-export flag).
      # @param symbol [String] symbol name visible to clients of this image
      # @param library [Image] image actually providing the symbol
      # @param imported_name [String, nil] name under which +library+ exports
      #   the symbol; defaults to +symbol+
      # @return [Image] self, for chaining
      def add_reexported_export(symbol, library:, imported_name: nil)
        @exports[symbol] = Export.new(
          symbol,
          :reexport_library => library,
          :imported_name => imported_name || symbol
        )
        self
      end

      # Appends +library+ to the linked-library list, giving it the next
      # two-level ordinal.
      # @param library [Image] the linked library
      # @param reexport [Boolean] whether the library is also re-exported
      #   (LC_REEXPORT_DYLIB) and therefore searched through
      # @return [Image] self, for chaining
      def link_library(library, reexport: false)
        @linked_libraries << library
        @reexported_libraries << library if reexport
        self
      end
    end

    # One entry in an image's export table: either a regular definition or a
    # forwarding re-export to another image.
    class Export
      # @return [String] exported symbol name
      attr_reader :name

      # @return [Image, nil] for re-exports, the image providing the symbol
      attr_reader :reexport_library

      # @return [String, nil] for re-exports, the name to look up in
      #   the providing image
      attr_reader :imported_name

      # @api private
      def initialize(name, weak: false, reexport_library: nil, imported_name: nil)
        @name = name
        @weak = weak
        @reexport_library = reexport_library
        @imported_name = imported_name
      end

      # @return [Boolean] whether this is a weak (coalesced) definition
      def weak?
        @weak
      end

      # @return [Boolean] whether this entry forwards to another image
      def reexport?
        !@reexport_library.nil?
      end
    end

    # The outcome of a symbol resolution.
    class Result
      # resolution found a definition
      STATUS_BOUND = :bound

      # resolution failed for a non-weak import
      STATUS_UNRESOLVED = :unresolved

      # resolution failed for a weak import; at run time the symbol would
      # silently bind to null
      STATUS_WEAK_UNRESOLVED = :weak_unresolved

      # @return [Symbol] one of {STATUS_BOUND}, {STATUS_UNRESOLVED} or
      #   {STATUS_WEAK_UNRESOLVED}
      attr_reader :status

      # @return [String] the symbol that was looked up
      attr_reader :symbol

      # @return [Image, nil] the image providing the definition, when bound
      attr_reader :image

      # @return [String, nil] the name the symbol is actually defined under
      #   in the providing image (differs from the imported name after a
      #   renamed re-export)
      attr_reader :defined_as

      # @return [Symbol, nil] why resolution failed:
      #   +:missing_library+ (ordinal designates no linked library),
      #   +:no_main_executable+ (main-executable lookup without one), or
      #   +:symbol_not_found+
      attr_reader :reason

      # @return [Array<String>] human-readable trace of every lookup step
      attr_reader :trace

      # @api private
      def initialize(status, symbol:, image: nil, defined_as: nil, weak_definition: false, reason: nil, trace: [])
        @status = status
        @symbol = symbol
        @image = image
        @defined_as = defined_as
        @weak_definition = weak_definition
        @reason = reason
        @trace = trace
      end

      # @return [Boolean] whether a definition was found
      def bound?
        @status == STATUS_BOUND
      end

      # @return [Boolean] whether the found definition is weak (coalesced)
      def weak_definition?
        @weak_definition
      end
    end

    # Resolves imported symbols against a fixed, load-ordered set of images.
    class Resolver
      # @return [Array<Image>] all known images, in load order
      attr_reader :images

      # @param images [Array<Image>] the image set, in load order
      def initialize(images)
        @images = images
        @main_executable = images.find(&:main_executable?)
      end

      # @return [Image, nil] the main executable of the image set, if any
      def main_executable
        @main_executable
      end

      # Resolves one imported symbol.
      # @param symbol [String] the imported symbol name
      # @param from [Image] the image containing the import
      # @param ordinal [Integer, Symbol] two-level library ordinal:
      #   1-253 index into the linked-library list of +from+;
      #   0 or +:self+ searches +from+ itself;
      #   254 or +:flat+ performs a flat lookup;
      #   255 or +:main_executable+ searches only the main executable
      # @param weak [Boolean] whether the import is weak; a weak import that
      #   cannot be resolved yields {Result::STATUS_WEAK_UNRESOLVED} instead
      #   of an error, and a flat lookup prefers strong definitions
      # @return [Result] the resolution outcome
      # @raise [ArgumentError] if the ordinal is invalid
      def resolve(symbol:, from:, ordinal:, weak: false)
        trace = []
        normalized = normalize_ordinal(ordinal)

        found = case normalized
        when :self
          trace << "#{from.name}: ordinal self; searching own exports"
          find_in_image(from, symbol, {}, trace)
        when :main_executable
          found_main = resolve_in_main_executable(symbol, trace)
          return finish(symbol, found_main, weak, :no_main_executable, trace) if found_main.nil? && @main_executable.nil?

          found_main
        when :flat
          flat_lookup(symbol, trace)
        else
          library = from.linked_libraries[normalized - 1]
          if library.nil?
            trace << "#{from.name}: ordinal #{normalized} designates no linked library"
            return finish(symbol, nil, weak, :missing_library, trace)
          end

          trace << "#{from.name}: ordinal #{normalized} -> #{library.name}"
          find_in_image(library, symbol, {}, trace)
        end

        finish(symbol, found, weak, :symbol_not_found, trace)
      end

      private

      Found = Struct.new(:image, :export)
      private_constant :Found

      def normalize_ordinal(ordinal)
        case ordinal
        when :self, SELF_LIBRARY_ORDINAL then :self
        when :flat, DYNAMIC_LOOKUP_ORDINAL then :flat
        when :main_executable, EXECUTABLE_ORDINAL then :main_executable
        when Integer
          raise ArgumentError, "invalid library ordinal: #{ordinal}" unless ordinal.between?(1, DYNAMIC_LOOKUP_ORDINAL - 1)

          ordinal
        else
          raise ArgumentError, "invalid library ordinal: #{ordinal.inspect}"
        end
      end

      def resolve_in_main_executable(symbol, trace)
        if @main_executable.nil?
          trace << "no main executable in image set"
          return nil
        end

        trace << "main-executable lookup in #{@main_executable.name}"
        find_in_image(@main_executable, symbol, {}, trace)
      end

      # Flat lookup: main executable first, then every image in load order.
      # A weak definition never stops the search for a strong one.
      def flat_lookup(symbol, trace)
        ordered = @images.reject(&:main_executable?)
        ordered.unshift(@main_executable) if @main_executable

        weak_found = nil
        ordered.each do |image|
          trace << "flat lookup: searching #{image.name}"
          found = find_in_image(image, symbol, {}, trace)
          next if found.nil?
          return found unless found.export.weak?

          weak_found ||= found
          trace << "#{image.name}: '#{symbol}' is a weak definition; continuing search for a strong one"
        end
        weak_found
      end

      # Searches +image+ and, transitively, everything it re-exports.
      # +visited+ guards against re-export cycles.
      def find_in_image(image, symbol, visited, trace)
        key = [image, symbol]
        if visited.key?(key)
          trace << "#{image.name}: circular re-export detected for '#{symbol}'; skipping"
          return nil
        end
        visited[key] = true

        export = image.exports[symbol]
        if export
          if export.reexport?
            target = export.imported_name
            trace << "#{image.name}: '#{symbol}' re-exported from #{export.reexport_library.name} as '#{target}'"
            return find_in_image(export.reexport_library, target, visited, trace)
          end

          trace << "#{image.name}: found '#{symbol}'#{export.weak? ? " (weak)" : ""}"
          return Found.new(image, export)
        end

        trace << "#{image.name}: no export '#{symbol}'"
        image.reexported_libraries.each do |library|
          trace << "#{image.name}: following re-export to #{library.name}"
          found = find_in_image(library, symbol, visited, trace)
          return found if found
        end
        nil
      end

      def finish(symbol, found, weak, reason, trace)
        if found
          Result.new(
            Result::STATUS_BOUND,
            :symbol => symbol,
            :image => found.image,
            :defined_as => found.export.name,
            :weak_definition => found.export.weak?,
            :trace => trace
          )
        elsif weak
          trace << "weak import '#{symbol}' unresolved; binds to null at run time"
          Result.new(Result::STATUS_WEAK_UNRESOLVED, :symbol => symbol, :reason => reason, :trace => trace)
        else
          trace << "unable to resolve '#{symbol}': #{reason}"
          Result.new(Result::STATUS_UNRESOLVED, :symbol => symbol, :reason => reason, :trace => trace)
        end
      end
    end
  end
end
