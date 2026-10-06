# frozen_string_literal: true

module MachO
  # Pure-Ruby evaluation of MH_OBJECT relocation entries.
  #
  # RelocationEvaluator does not execute any of the bytes it processes and
  # does not shell out to a linker: it decodes each relocation entry, computes
  # the value that belongs in the patched field, and rewrites that field using
  # only integer arithmetic. Entries are validated (pairs, target symbols,
  # instruction fields and ranges) before any bytes are modified.
  #
  # Supported relocations:
  #
  # x86_64 (:x86_64):
  # - X86_64_RELOC_UNSIGNED (0)
  # - X86_64_RELOC_SIGNED (1)
  # - X86_64_RELOC_BRANCH (2)
  # - X86_64_RELOC_SUBTRACTOR (5, paired with the following UNSIGNED entry)
  #
  # arm64 (:arm64):
  # - ARM64_RELOC_UNSIGNED (0)
  # - ARM64_RELOC_BRANCH26 (2)
  # - ARM64_RELOC_PAGE21 (3)
  # - ARM64_RELOC_PAGEOFF12 (4)
  # - ARM64_RELOC_ADDEND (10, paired with the following entry)
  #
  # Every other relocation type (GOT, TLV, LAZY, POINTER_TO_GOT, scattered,
  # etc.) is rejected with UnsupportedRelocationTypeError.
  module Relocations
    # Bit set in the first relocation word of a scattered entry.
    R_SCATTERED_BIT = 0x80000000

    # Mask for the r_type field (top nibble of the second relocation word).
    R_TYPE_MASK = 0xf0000000

    # Bit offset of r_type within the second relocation word.
    R_TYPE_SHIFT = 28

    # Mask for the r_length field (bits 25..26).
    R_LENGTH_MASK = 0x06000000

    # Bit offset of r_length within the second relocation word.
    R_LENGTH_SHIFT = 25

    # The r_extern bit in the second relocation word (bit 27).
    R_EXTERN_BIT = 0x08000000

    # The r_pcrel bit in the second relocation word (bit 24).
    R_PCREL_BIT = 0x01000000

    # Raw r_type nibble (bits 28..31) that marks an arm64 ADDEND entry on
    # disk. The logical reloc type is 10 (ARM64_RELOC_ADDEND), stored as
    # 0xf, with the signed 24-bit addend replacing r_symbolnum.
    ARM64_ADDEND_RAW_TYPE = 15

    # The raw top-nibble value that marks an ADDEND entry.
    ARM64_ADDEND_TYPE_BITS = ARM64_ADDEND_RAW_TYPE << 28

    # Mask for the signed 24-bit addend in an arm64 ADDEND entry.
    ARM64_ADDEND_MASK = 0x00ffffff

    # The logical reloc type presented for an on-disk ADDEND entry.
    ARM64_ADDEND_TYPE = 10

    # x86_64 relocation types (see x86_64_reloc.h).
    X86_64_RELOC_TYPES = {
      0 => :X86_64_RELOC_UNSIGNED,
      1 => :X86_64_RELOC_SIGNED,
      2 => :X86_64_RELOC_BRANCH,
      3 => :X86_64_RELOC_GOT_LOAD,
      4 => :X86_64_RELOC_GOT,
      5 => :X86_64_RELOC_SUBTRACTOR,
      6 => :X86_64_RELOC_SIGNED_1,
      7 => :X86_64_RELOC_SIGNED_2,
      8 => :X86_64_RELOC_SIGNED_4,
      9 => :X86_64_RELOC_TLV,
    }.freeze

    # x86_64 relocation types understood by the evaluator.
    X86_64_SUPPORTED_TYPES = %i[
      X86_64_RELOC_UNSIGNED
      X86_64_RELOC_SIGNED
      X86_64_RELOC_BRANCH
      X86_64_RELOC_SUBTRACTOR
    ].freeze

    # arm64 relocation types (see arm64_reloc.h).
    ARM64_RELOC_TYPES = {
      0 => :ARM64_RELOC_UNSIGNED,
      1 => :ARM64_RELOC_SUBTRACTOR,
      2 => :ARM64_RELOC_BRANCH26,
      3 => :ARM64_RELOC_PAGE21,
      4 => :ARM64_RELOC_PAGEOFF12,
      5 => :ARM64_RELOC_GOT_LOAD_PAGE21,
      6 => :ARM64_RELOC_GOT_LOAD_PAGEOFF12,
      7 => :ARM64_RELOC_POINTER_TO_GOT,
      8 => :ARM64_RELOC_TLVP_LOAD_PAGE21,
      9 => :ARM64_RELOC_TLVP_LOAD_PAGEOFF12,
      10 => :ARM64_RELOC_ADDEND,
    }.freeze

    # arm64 relocation types understood by the evaluator.
    ARM64_SUPPORTED_TYPES = %i[
      ARM64_RELOC_UNSIGNED
      ARM64_RELOC_BRANCH26
      ARM64_RELOC_PAGE21
      ARM64_RELOC_PAGEOFF12
      ARM64_RELOC_ADDEND
    ].freeze

    # Field byte widths keyed by r_length (0 => 1, 1 => 2, 2 => 4, 3 => 8).
    FIELD_SIZES = [1, 2, 4, 8].freeze

    # Little-endian unsigned pack directives keyed by field byte width.
    UNSIGNED_PACK_FORMATS = { 1 => "C", 2 => "S<", 4 => "L<", 8 => "Q<" }.freeze

    # Little-endian signed pack directives keyed by field byte width.
    SIGNED_PACK_FORMATS = { 1 => "c", 2 => "s<", 4 => "l<", 8 => "q<" }.freeze

    # Maps a numeric Mach-O cputype to an evaluator architecture symbol.
    #
    # @param cputype [Integer] a Mach-O cputype value
    # @return [Symbol] :x86_64 or :arm64
    # @raise [RelocationError] if the architecture is not supported
    def self.architecture_for_cputype(cputype)
      case cputype
      when Headers::CPU_TYPE_X86_64
        :x86_64
      when Headers::CPU_TYPE_ARM64
        :arm64
      else
        raise RelocationError,
          "relocation evaluation is only supported for x86_64 and arm64, " \
          "not cputype 0x#{cputype.to_s(16)}"
      end
    end

    # A single non-scattered relocation_info entry.
    RelocationEntry = Struct.new(:address, :type, :length, :pcrel, :external, :symbol,
                                :keyword_init => true) do
      # Coerces a raw pair of relocation words, a Hash or a RelocationEntry.
      #
      # @param rel [Array, Hash, RelocationEntry] the entry
      # @param index [Integer, nil] the entry index within its section
      # @param arch [Symbol, nil] target architecture (see {.from_words})
      # @return [RelocationEntry]
      def self.coerce(rel, index: nil, arch: nil)
        case rel
        when RelocationEntry
          rel
        when Array
          unless rel.length == 2
            raise RelocationError, error_prefix(index) + "needs two 32-bit words"
          end

          from_words(rel[0], rel[1], index, :arch => arch)
        when Hash
          from_hash(rel, index)
        else
          raise RelocationError,
            error_prefix(index) + "unsupported entry representation #{rel.class}"
        end
      end

      # Builds an entry from the two raw relocation_info words.
      #
      # @param word0 [Integer] the r_address / scattered word
      # @param word1 [Integer] the r_info word
      # @param index [Integer, nil] the entry index, for error messages
      # @param arch [Symbol, nil] when :arm64, a raw r_type nibble of 0xf is
      #  decoded as ARM64_RELOC_ADDEND; otherwise it is left as an ordinary
      #  (unsupported) r_type
      # @return [RelocationEntry]
      def self.from_words(word0, word1, index = nil, arch: nil)
        if (word0 & R_SCATTERED_BIT) != 0
          raise RelocationError, error_prefix(index) + "scattered relocations are not supported"
        end

        arm64_addend = arch == :arm64 && (word1 & R_TYPE_MASK) == ARM64_ADDEND_TYPE_BITS
        symbol = word1 & ARM64_ADDEND_MASK
        symbol = sign_extend_24(symbol) if arm64_addend
        new(
          :address => word0 & 0x00ffffff,
          :type => arm64_addend ? ARM64_ADDEND_TYPE : (word1 & R_TYPE_MASK) >> R_TYPE_SHIFT,
          :length => (word1 & R_LENGTH_MASK) >> R_LENGTH_SHIFT,
          :pcrel => !arm64_addend && (word1 & R_PCREL_BIT) != 0,
          :external => !arm64_addend && (word1 & R_EXTERN_BIT) != 0,
          :symbol => symbol,
        )
      end

      # Sign-extends a raw 24-bit value (used by arm64 ADDEND entries).
      def self.sign_extend_24(value)
        (value ^ 0x800000) - 0x800000
      end
      private_class_method :sign_extend_24

      # Builds an entry from a descriptive Hash.
      #
      # Recognized keys (strings or symbols):
      # - +address+ (required)
      # - +type+ (required): an Integer reloc type or a symbol such as
      #   +:X86_64_RELOC_BRANCH+ or +:ARM64_RELOC_PAGE21+
      # - +length+ / +r_length+ (defaults to 2)
      # - +pcrel+ / +r_pcrel+ (defaults to false)
      # - +external+ / +r_extern+ / +extern+ (defaults to false)
      # - +symbol+ / +symbolnum+ / +r_symbolnum+ / +section+ (defaults to 0)
      #
      # @param hash [Hash] the descriptive Hash
      # @param index [Integer, nil] the entry index, for error messages
      # @return [RelocationEntry]
      def self.from_hash(hash, index = nil)
        h = hash.transform_keys(&:to_s)

        raw_type = h.fetch("type") { raise RelocationError, error_prefix(index) + "missing type" }
        type = raw_type.is_a?(Integer) ? raw_type : type_table.fetch(raw_type.to_sym) do
          raise RelocationError, "unknown relocation type: #{raw_type}"
        end

        length = h.fetch("length", h.fetch("r_length", 2))
        symbol = h["symbol"] || h["symbolnum"] || h["r_symbolnum"] || h["section"] || 0
        address = h.fetch("address") { raise RelocationError, error_prefix(index) + "missing address" }

        new(
          :address => address,
          :type => type,
          :length => length,
          :pcrel => boolean(h["pcrel"] || h["r_pcrel"]),
          :external => boolean(h["external"] || h["r_extern"] || h["extern"]),
          :symbol => symbol,
        )
      end

      # @return [Boolean] whether the r_pcrel bit is set
      alias pcrel? pcrel

      # @return [Boolean] whether the r_extern bit is set
      alias external? external

      # @return [Integer] the field width in bytes described by r_length
      def field_size
        FIELD_SIZES.fetch(length) do
          raise RelocationError, "invalid r_length #{length} (must be 0..3)"
        end
      end

      # @param table [Hash{Integer => Symbol}] a reloc type table
      # @return [Symbol] the symbolic reloc type
      def type_symbol(table)
        table.fetch(type) do
          raise UnsupportedRelocationTypeError, "unknown relocation type #{type}"
        end
      end

      def self.type_table
        X86_64_RELOC_TYPES.invert.merge(ARM64_RELOC_TYPES.invert)
      end
      private_class_method :type_table

      def self.boolean(value)
        value == true || value == 1
      end
      private_class_method :boolean

      def self.error_prefix(index)
        index.nil? ? "relocation entry: " : "relocation entry #{index}: "
      end
      private_class_method :error_prefix
    end

    # The outcome of evaluating one relocation entry (or one half of a pair).
    #
    # @!attribute index
    #  @return [Integer] the entry's index within the section's reloc list
    # @!attribute address
    #  @return [Integer] the section-relative offset that was patched
    # @!attribute type
    #  @return [Symbol] the symbolic reloc type
    # @!attribute size
    #  @return [Integer] the width, in bytes, of the patched field
    # @!attribute old_value
    #  @return [Integer] the field value before relocation
    # @!attribute new_value
    #  @return [Integer] the value written to the field
    # @!attribute target
    #  @return [Integer, nil] the resolved address of the referenced symbol
    # @!attribute addend
    #  @return [Integer] the addend applied (field contents, an ADDEND entry,
    #   or the decoded instruction immediate)
    # @!attribute pcrel
    #  @return [Boolean] whether the relocation was PC-relative
    # @!attribute paired_with
    #  @return [Integer, nil] the index of the other entry in a pair, if any
    # @!attribute detail
    #  @return [Hash] architecture-specific computation details (instruction
    #   fields, page numbers, signed immediates, ...)
    RelocationResult = Struct.new(:index, :address, :type, :size, :old_value, :new_value,
                                  :target, :addend, :pcrel, :paired_with, :detail,
                                  :keyword_init => true) do
      # @return [Hash] a descriptive representation of the result
      def to_h
        {
          "index" => index,
          "address" => address,
          "type" => type,
          "size" => size,
          "old_value" => old_value,
          "new_value" => new_value,
          "target" => target,
          "addend" => addend,
          "pcrel" => pcrel,
          "paired_with" => paired_with,
          "detail" => detail,
        }
      end
    end

    # Evaluates relocation entries for one section of an MH_OBJECT file.
    #
    # The evaluator is architecture-specific and is driven entirely by the
    # caller: symbols are resolved through +symbol_addresses+, local (section)
    # references through +section_addresses+, and no linker is invoked.
    class RelocationEvaluator
      # @return [Symbol] :x86_64 or :arm64
      attr_reader :arch

      # @return [Hash{Integer => Integer}] final (linked) base addresses of
      #  sections, keyed by 1-based section ordinal
      attr_reader :section_addresses

      # @return [Hash{Integer => Integer}] object-file base addresses of
      #  sections (as emitted in the MH_OBJECT), keyed by 1-based section
      #  ordinal. Defaults to {section_addresses}.
      attr_reader :section_origins

      # @param arch [Symbol, Integer] :x86_64, :arm64, or a numeric cputype
      # @param section_bytes [String] the current, mutable-looking bytes of the
      #  section whose relocations are being evaluated. The evaluator never
      #  modifies this string; patched bytes are returned instead.
      # @param relocations [Array] relocation entries in file order (the order
      #  in which they appear in the section's reloc table). Each element may
      #  be a [word0, word1] pair, a descriptive Hash, or a RelocationEntry.
      # @param symbol_addresses [Hash{Integer => Integer}] addresses of
      #  external symbols keyed by symbol table index
      # @param section_addresses [Hash{Integer => Integer}] final base
      #  addresses of sections keyed by 1-based section ordinal. The section
      #  being evaluated is conventionally keyed as its own ordinal; it
      #  defaults to 0 when omitted.
      # @param section_ordinal [Integer, nil] the 1-based ordinal of the
      #  section being evaluated (used to resolve same-section PC-relative
      #  references)
      # @param section_origins [Hash{Integer => Integer}, nil] object-file
      #  section base addresses; defaults to +section_addresses+
      def initialize(arch, section_bytes, relocations, symbol_addresses: {},
                     section_addresses: {}, section_ordinal: nil, section_origins: nil)
        @arch = arch.is_a?(Integer) ? Relocations.architecture_for_cputype(arch) : arch
        unless %i[x86_64 arm64].include?(@arch)
          raise RelocationError, "unsupported relocation architecture: #{arch}"
        end

        @bytes = section_bytes.dup.force_encoding(Encoding::BINARY)
        @entries = relocations.each_with_index.map do |rel, index|
          RelocationEntry.coerce(rel, :index => index, :arch => @arch)
        end
        @symbol_addresses = symbol_addresses
        @section_addresses = section_addresses
        @section_origins = section_origins || section_addresses
        @section_ordinal = section_ordinal
      end

      # @return [Array<Symbol>] the numeric-to-symbolic reloc type table for
      #  this architecture
      def type_table
        x86_64? ? X86_64_RELOC_TYPES : ARM64_RELOC_TYPES
      end

      # @return [Array<Symbol>] reloc types supported on this architecture
      def supported_types
        x86_64? ? X86_64_SUPPORTED_TYPES : ARM64_SUPPORTED_TYPES
      end

      # @return [Boolean] whether the evaluator targets x86_64
      def x86_64?
        arch == :x86_64
      end

      # @return [Boolean] whether the evaluator targets arm64
      def arm64?
        arch == :arm64
      end

      # Validates every entry and computes every new value before touching a
      # single byte, then applies all writes and returns the patched bytes and
      # per-entry details.
      #
      # @return [Array(String, Array<RelocationResult>)] the modified section
      #  bytes (a new String) and one result per entry, ordered by entry index
      # @raise [RelocationError] if any entry is malformed, unsupported,
      #  references an unknown symbol/section, or overflows its field
      def evaluate
        plan = plan_writes

        bytes = @bytes.dup
        plan.each do |write|
          apply_write(bytes, write)
        end

        [bytes, @results]
      end

      private

      # A planned field write together with the public result object.
      Write = Struct.new(:offset, :size, :signed, :value, :result, :instruction,
                         :keyword_init => true)

      # Validates and plans all writes without modifying @bytes.
      #
      # @return [Array<Write>]
      def plan_writes
        writes = []
        results = Array.new(@entries.length)
        index = 0

        while index < @entries.length
          entry = @entries[index]

          if arm64? && type_of(entry) == :ARM64_RELOC_ADDEND
            addend = arm64_addend(entry)
            if index + 1 >= @entries.length
              raise RelocationError,
                "relocation entry #{index}: ARM64_RELOC_ADDEND must be followed by another entry"
            end

            target_entry = @entries[index + 1]
            unless target_entry.address == entry.address
              raise RelocationError,
                "relocation entries #{index} and #{index + 1}: ARM64_RELOC_ADDEND pair must " \
                "share r_address (#{entry.address} != #{target_entry.address})"
            end
            write, target_result = plan_arm64(target_entry, index + 1, addend, index)
            writes << write
            results[index] = addend_result(index, entry, target_entry, addend)
            results[index + 1] = target_result
            index += 2
          elsif x86_64? && type_of(entry) == :X86_64_RELOC_SUBTRACTOR
            subtrahend_index = index
            minuend_index = index + 1
            if minuend_index >= @entries.length
              raise RelocationError,
                "relocation entry #{index}: X86_64_RELOC_SUBTRACTOR must be paired " \
                "with a following X86_64_RELOC_UNSIGNED entry"
            end

            subtrahend = entry
            minuend = @entries[minuend_index]
            write, minuend_result, subtrahend_result =
              plan_x86_64_subtractor(minuend, minuend_index, subtrahend, subtrahend_index)
            writes << write
            results[minuend_index] = minuend_result
            results[subtrahend_index] = subtrahend_result
            index += 2
          else
            write, result = arm64? ? plan_arm64(entry, index, 0, nil) : plan_x86_64(entry, index)
            writes << write
            results[index] = result
            index += 1
          end
        end

        writes.each do |write|
          check_range!(write)
        end

        @results = results
        writes
      end

      # @param entry [RelocationEntry]
      # @return [Symbol] the validated symbolic reloc type
      def type_of(entry)
        sym = entry.type_symbol(type_table)
        unless supported_types.include?(sym)
          raise UnsupportedRelocationTypeError,
            "relocation type #{sym} (#{entry.type}) is not supported for #{arch}"
        end

        sym
      end

      # The signed 24-bit addend carried by an ARM64_RELOC_ADDEND entry.
      #
      # @param entry [RelocationEntry]
      # @return [Integer]
      def arm64_addend(entry)
        entry.symbol
      end

      # Builds the informational result for an ARM64_RELOC_ADDEND half-pair.
      #
      # @return [RelocationResult]
      def addend_result(index, entry, target_entry, addend)
        RelocationResult.new(
          :index => index,
          :address => entry.address,
          :type => :ARM64_RELOC_ADDEND,
          :size => 4,
          :old_value => entry.symbol,
          :new_value => addend,
          :target => nil,
          :addend => addend,
          :pcrel => false,
          :paired_with => index + 1,
          :detail => {
            "paired_type" => target_entry.type_symbol(type_table),
            "encoded_in" => "r_symbolnum (signed 24-bit)",
          },
        )
      end

      # Plans one non-pair x86_64 relocation.
      #
      # @return [Array(Write, RelocationResult)]
      def plan_x86_64(entry, index)
        type = type_of(entry)
        size = entry.field_size

        case type
        when :X86_64_RELOC_UNSIGNED
          validate_flags!(entry, index, :pcrel => false)
          addend = old_value = read_field(entry, false)
          target = resolve_target(entry)
          value = target + addend
          detail = {
            "formula" => "S + A",
            "symbol_address" => target,
          }
          signed = false
        when :X86_64_RELOC_SIGNED, :X86_64_RELOC_BRANCH
          validate_flags!(entry, index, :pcrel => true, :length => 2)
          addend = old_value = read_field(entry, true)
          target = resolve_target(entry)
          own_base = section_base(@section_ordinal, :final)
          if entry.external?
            # S + A - P with P at the end of the relocated instruction
            value = target + addend - (own_base + entry.address + size)
          else
            # Local entries store the displacement from the start of the
            # reloc field to the target in object coordinates.
            target_origin = section_base(entry.symbol, :origin)
            own_origin = section_base(@section_ordinal, :origin)
            value = addend + (target - target_origin) - (own_base - own_origin) - size
          end
          detail = {
            "formula" => "S + A - P",
            "symbol_address" => target,
            "pc" => section_base(@section_ordinal, :final) + entry.address + size,
          }
          signed = true
        when :X86_64_RELOC_SUBTRACTOR
          # Handled by #plan_writes pairing.
          raise RelocationError, "unpaired X86_64_RELOC_SUBTRACTOR at entry #{index}"
        else
          raise UnsupportedRelocationTypeError, "unsupported x86_64 relocation type: #{type}"
        end

        result = RelocationResult.new(
          :index => index,
          :address => entry.address,
          :type => type,
          :size => size,
          :old_value => old_value,
          :new_value => value,
          :target => target,
          :addend => addend,
          :pcrel => entry.pcrel?,
          :paired_with => nil,
          :detail => detail,
        )

        [Write.new(
          :offset => entry.address, :size => size, :signed => signed, :value => value, :result => result
        ), result]
      end

      # Plans an X86_64_RELOC_SUBTRACTOR / X86_64_RELOC_UNSIGNED pair.
      #
      # In file order the SUBTRACTOR entry comes first and carries the
      # subtrahend (S2); the following UNSIGNED entry at the same r_address
      # carries the minuend (S1). The stored field already holds
      # (S1 + A1) - (S2 + A2) in object-file coordinates, so the relocated
      # value is:
      #
      #   field + (final1 - origin1) - (final2 - origin2)
      #
      # @return [Array(Write, RelocationResult, RelocationResult)]
      def plan_x86_64_subtractor(minuend, minuend_index, subtrahend, subtrahend_index)
        minuend_type = type_of(minuend)
        unless minuend_type == :X86_64_RELOC_UNSIGNED
          raise RelocationError,
            "relocation entry #{minuend_index}: X86_64_RELOC_SUBTRACTOR must be followed by " \
            "X86_64_RELOC_UNSIGNED, got #{minuend_type}"
        end
        type_of(subtrahend)
        validate_flags!(minuend, minuend_index, :pcrel => false)
        validate_flags!(subtrahend, subtrahend_index, :pcrel => false)
        unless minuend.address == subtrahend.address
          raise RelocationError,
            "relocation entries #{subtrahend_index} and #{minuend_index}: SUBTRACTOR pair must " \
            "share r_address (#{subtrahend.address} != #{minuend.address})"
        end
        unless minuend.length == subtrahend.length
          raise RelocationError,
            "relocation entries #{subtrahend_index} and #{minuend_index}: SUBTRACTOR pair must " \
            "share r_length (#{subtrahend.length} != #{minuend.length})"
        end

        size = minuend.field_size
        field = read_field(subtrahend, true)
        minuend_origin = origin_base(minuend)
        subtrahend_origin = origin_base(subtrahend)
        minuend_final = resolve_target(minuend)
        subtrahend_final = resolve_target(subtrahend)
        value = field + (minuend_final - minuend_origin) - (subtrahend_final - subtrahend_origin)

        detail = {
          "formula" => "field + (final1 - origin1) - (final2 - origin2)",
          "field" => field,
          "minuend_final" => minuend_final,
          "minuend_origin" => minuend_origin,
          "subtrahend_final" => subtrahend_final,
          "subtrahend_origin" => subtrahend_origin,
        }

        minuend_result = RelocationResult.new(
          :index => minuend_index,
          :address => minuend.address,
          :type => :X86_64_RELOC_UNSIGNED,
          :size => size,
          :old_value => field,
          :new_value => value,
          :target => minuend_final,
          :addend => field,
          :pcrel => false,
          :paired_with => subtrahend_index,
          :detail => detail.merge("role" => "minuend"),
        )
        subtrahend_result = RelocationResult.new(
          :index => subtrahend_index,
          :address => subtrahend.address,
          :type => :X86_64_RELOC_SUBTRACTOR,
          :size => size,
          :old_value => field,
          :new_value => value,
          :target => subtrahend_final,
          :addend => field,
          :pcrel => false,
          :paired_with => minuend_index,
          :detail => detail.merge("role" => "subtrahend"),
        )

        write = Write.new(
          :offset => minuend.address, :size => size, :signed => true, :value => value,
          :result => minuend_result
        )

        [write, minuend_result, subtrahend_result]
      end

      # Plans one arm64 relocation.
      #
      # @param entry [RelocationEntry] the data-bearing entry
      # @param index [Integer] its index
      # @param pair_addend [Integer] the addend from a preceding
      #  ARM64_RELOC_ADDEND entry, or 0
      # @param addend_index [Integer, nil] the index of the ADDEND half-pair
      # @return [Array(Write, RelocationResult)]
      def plan_arm64(entry, index, pair_addend, addend_index)
        type = type_of(entry)
        if type == :ARM64_RELOC_ADDEND
          raise RelocationError,
            "relocation entry #{index}: ARM64_RELOC_ADDEND cannot be the second entry of a pair"
        end
        if !addend_index.nil? && !%i[ARM64_RELOC_UNSIGNED ARM64_RELOC_BRANCH26 ARM64_RELOC_PAGE21].include?(type)
          raise RelocationError,
            "relocation entry #{addend_index}: ARM64_RELOC_ADDEND can only precede UNSIGNED, " \
            "BRANCH26 or PAGE21 (got #{type})"
        end

        case type
        when :ARM64_RELOC_UNSIGNED
          plan_arm64_unsigned(entry, index, pair_addend, addend_index)
        when :ARM64_RELOC_BRANCH26
          plan_arm64_branch26(entry, index, pair_addend, addend_index)
        when :ARM64_RELOC_PAGE21
          plan_arm64_page21(entry, index, pair_addend, addend_index)
        when :ARM64_RELOC_PAGEOFF12
          unless addend_index.nil?
            raise RelocationError,
              "relocation entry #{addend_index}: ARM64_RELOC_ADDEND cannot precede ARM64_RELOC_PAGEOFF12"
          end

          plan_arm64_pageoff12(entry, index)
        else
          raise UnsupportedRelocationTypeError, "unsupported arm64 relocation type: #{type}"
        end
      end

      # ARM64_RELOC_UNSIGNED: an r_length-sized absolute field, holding
      # S + A (external: A from the ADDEND pair or 0; local: A from pair or
      # the section-relative field value).
      def plan_arm64_unsigned(entry, index, pair_addend, addend_index)
        validate_flags!(entry, index, :pcrel => false)
        size = entry.field_size
        addend = addend_index.nil? ? read_field(entry, false) : pair_addend
        target = resolve_target(entry)
        value = target + addend

        result = RelocationResult.new(
          :index => index,
          :address => entry.address,
          :type => :ARM64_RELOC_UNSIGNED,
          :size => size,
          :old_value => read_field(entry, false),
          :new_value => value,
          :target => target,
          :addend => addend,
          :pcrel => false,
          :paired_with => addend_index,
          :detail => {
            "formula" => "S + A",
            "symbol_address" => target,
            "addend_source" => addend_index.nil? ? "field" : "ARM64_RELOC_ADDEND",
          },
        )

        [Write.new(
          :offset => entry.address, :size => size, :signed => false, :value => value, :result => result
        ), result]
      end

      # ARM64_RELOC_BRANCH26: a B/BL instruction. imm26 = (S + A - P) / 4.
      def plan_arm64_branch26(entry, index, pair_addend, addend_index)
        validate_flags!(entry, index, :pcrel => true, :length => 2)
        instruction = read_instruction(entry, index)
        opcode = instruction & 0x7c000000
        unless opcode == 0x14000000
          raise RelocationError,
            "relocation entry #{index}: ARM64_RELOC_BRANCH26 targets a non-branch instruction " \
            "(opcode bits 0x%08x)" % opcode
        end

        target = resolve_target(entry)
        pc = section_base(@section_ordinal, :final) + entry.address
        displacement = target + pair_addend - pc
        if displacement % 4 != 0
          raise RelocationOverflowError,
            "relocation entry #{index}: branch26 displacement #{displacement} is not 4-byte aligned"
        end

        imm26 = displacement / 4
        unless fits_signed?(imm26, 26)
          raise RelocationOverflowError,
            "relocation entry #{index}: branch26 displacement 0x#{displacement.to_s(16)} " \
            "does not fit in signed 26 bits"
        end

        new_instruction = (instruction & 0xfc000000) | (imm26 & 0x03ffffff)

        result = RelocationResult.new(
          :index => index,
          :address => entry.address,
          :type => :ARM64_RELOC_BRANCH26,
          :size => 4,
          :old_value => instruction,
          :new_value => new_instruction,
          :target => target,
          :addend => pair_addend,
          :pcrel => true,
          :paired_with => addend_index,
          :detail => {
            "formula" => "imm26 = (S + A - P) / 4",
            "symbol_address" => target,
            "pc" => section_base(@section_ordinal, :final) + entry.address,
            "displacement" => displacement,
            "imm26" => imm26,
            "link_bit" => (instruction >> 31) & 1,
          },
        )

        [Write.new(
          :offset => entry.address, :size => 4, :signed => false, :value => new_instruction,
          :result => result, :instruction => true
        ), result]
      end

      # ARM64_RELOC_PAGE21: an ADRP instruction.
      # immhi:immlo encode (S_page - P_page) >> 12 as a signed 21-bit value.
      def plan_arm64_page21(entry, index, pair_addend, addend_index)
        validate_flags!(entry, index, :pcrel => true, :length => 2)
        instruction = read_instruction(entry, index)
        unless (instruction & 0x9f000000) == 0x90000000
          raise RelocationError,
            "relocation entry #{index}: ARM64_RELOC_PAGE21 targets a non-ADRP instruction " \
            "(0x%08x)" % instruction
        end

        target = resolve_target(entry)
        pc = section_base(@section_ordinal, :final) + entry.address
        page_delta = ((target + pair_addend) & ~0xfff) - (pc & ~0xfff)
        imm21 = page_delta >> 12
        unless fits_signed?(imm21, 21)
          raise RelocationOverflowError,
            "relocation entry #{index}: page21 delta 0x#{page_delta.to_s(16)} " \
            "does not fit in signed 21 bits"
        end

        rd = instruction & 0x1f
        immlo = imm21 & 3
        immhi = (imm21 >> 2) & 0x7ffff
        new_instruction = (instruction & 0x9f000000) |
                          (immlo << 29) | (immhi << 5) | rd

        result = RelocationResult.new(
          :index => index,
          :address => entry.address,
          :type => :ARM64_RELOC_PAGE21,
          :size => 4,
          :old_value => instruction,
          :new_value => new_instruction,
          :target => target,
          :addend => pair_addend,
          :pcrel => true,
          :paired_with => addend_index,
          :detail => {
            "formula" => "imm21 = (((S + A) & ~0xfff) - (P & ~0xfff)) >> 12",
            "symbol_address" => target,
            "pc" => section_base(@section_ordinal, :final) + entry.address,
            "target_page" => (target + pair_addend) & ~0xfff,
            "pc_page" => pc & ~0xfff,
            "page_delta" => page_delta,
            "imm21" => imm21,
            "rd" => rd,
          },
        )

        [Write.new(
          :offset => entry.address, :size => 4, :signed => false, :value => new_instruction,
          :result => result, :instruction => true
        ), result]
      end

      # ARM64_RELOC_PAGEOFF12: the low 12 bits of S, encoded into an ADD
      # immediate (unshifted, scale 1) or an LDR/STR unsigned immediate
      # (shifted by the access size: 1, 2, 4 or 8).
      def plan_arm64_pageoff12(entry, index)
        validate_flags!(entry, index, :pcrel => false, :length => 2)
        instruction = read_instruction(entry, index)
        target = resolve_target(entry)

        add_immediate = (instruction & 0x1f800000) == 0x11000000
        load_store = !add_immediate && (instruction & 0x0b000000) == 0x09000000

        old_imm = (instruction >> 10) & 0xfff

        if add_immediate
          shift = (instruction >> 22) & 1
          scale = 1 << (12 * shift)
          addend = old_imm * scale
          pageoff = (target + addend) & 0xfff
          if pageoff % scale != 0
            raise RelocationOverflowError,
              "relocation entry #{index}: pageoff12 value 0x#{pageoff.to_s(16)} is not aligned " \
              "to the ADD immediate scale (#{scale})"
          end

          imm12 = pageoff / scale
          encoding = "add_immediate"
        elsif load_store
          size = (instruction >> 30) & 3
          scale = 1 << size
          addend = old_imm * scale
          pageoff = (target + addend) & 0xfff
          if pageoff % scale != 0
            raise RelocationOverflowError,
              "relocation entry #{index}: pageoff12 value 0x#{pageoff.to_s(16)} is not aligned " \
              "to the load/store scale (#{scale})"
          end

          imm12 = pageoff / scale
          encoding = "load_store"
        else
          raise RelocationError,
            "relocation entry #{index}: ARM64_RELOC_PAGEOFF12 targets an instruction that is " \
            "neither ADD immediate nor LDR/STR unsigned immediate (0x%08x)" % instruction
        end

        unless (imm12 & ~0xfff).zero?
          raise RelocationOverflowError,
            "relocation entry #{index}: pageoff12 immediate #{imm12} does not fit in 12 bits"
        end

        new_instruction = (instruction & ~(0xfff << 10)) | (imm12 << 10)

        result = RelocationResult.new(
          :index => index,
          :address => entry.address,
          :type => :ARM64_RELOC_PAGEOFF12,
          :size => 4,
          :old_value => instruction,
          :new_value => new_instruction,
          :target => target,
          :addend => addend,
          :pcrel => false,
          :paired_with => nil,
          :detail => {
            "formula" => "pageoff = (S + A) & 0xfff",
            "symbol_address" => target,
            "pageoff" => pageoff,
            "imm12" => imm12,
            "encoding" => encoding,
            "scale" => scale,
          },
        )

        [Write.new(
          :offset => entry.address, :size => 4, :signed => false, :value => new_instruction,
          :result => result, :instruction => true
        ), result]
      end

      # Validates the expected pcrel bit (and, optionally, r_length) of an
      # entry against what the reloc type requires.
      def validate_flags!(entry, index, pcrel:, length: nil)
        unless entry.pcrel? == pcrel
          raise RelocationError,
            "relocation entry #{index}: #{type_table[entry.type]} requires r_pcrel=#{pcrel ? 1 : 0}"
        end

        return if length.nil? || entry.length == length

        raise RelocationError,
          "relocation entry #{index}: #{type_table[entry.type]} requires r_length=#{length}, " \
          "got #{entry.length}"
      end

      # Reads the field targeted by a relocation entry.
      #
      # @param entry [RelocationEntry]
      # @param signed [Boolean] whether to sign-extend the read value
      # @return [Integer]
      def read_field(entry, signed)
        size = entry.field_size
        check_bounds!(entry.address, size, nil)
        raw = @bytes.byteslice(entry.address, size)
        format = (signed ? SIGNED_PACK_FORMATS : UNSIGNED_PACK_FORMATS).fetch(size)
        raw.unpack1(format)
      end

      # Reads the 4-byte little-endian instruction targeted by an arm64 entry.
      #
      # @return [Integer]
      def read_instruction(entry, index)
        check_bounds!(entry.address, 4, index)
        @bytes.byteslice(entry.address, 4).unpack1("L<")
      end

      # @param address [Integer] section-relative field offset
      # @param size [Integer] field width
      # @param index [Integer, nil] entry index for the error message
      def check_bounds!(address, size, index)
        return if address >= 0 && address + size <= @bytes.bytesize

        raise RelocationError,
          "relocation entry#{index.nil? ? "" : " #{index}"}: field at offset #{address} " \
          "(size #{size}) is outside the section (#{@bytes.bytesize} bytes)"
      end

      # @param entry [RelocationEntry]
      # @return [Integer] the resolved final address of the referenced symbol
      #  or section symbol
      def resolve_target(entry)
        if entry.external?
          unless @symbol_addresses.key?(entry.symbol)
            raise RelocationSymbolError,
              "no address provided for external symbol #{entry.symbol}"
          end

          @symbol_addresses.fetch(entry.symbol)
        else
          section = entry.symbol
          unless section.positive?
            raise RelocationSectionError, "invalid section ordinal #{section} in local relocation"
          end

          section_base(section, :final)
        end
      end

      # @return [Integer] the object-file (origin) base address associated with
      #  an entry: 0 for external symbols, section origin for local ones
      def origin_base(entry)
        entry.external? ? 0 : section_base(entry.symbol, :origin)
      end

      # @param ordinal [Integer, nil] a 1-based section ordinal
      # @param kind [:final, :origin] which address table to use
      # @return [Integer]
      def section_base(ordinal, kind)
        table = kind == :origin ? @section_origins : @section_addresses
        return 0 if ordinal.nil?

        table.fetch(ordinal) do
          raise RelocationSectionError,
            "no #{kind} base address provided for section ordinal #{ordinal}"
        end
      end

      # Raises unless an integer fits the field described by a planned write.
      #
      # @param write [Write]
      def check_range!(write)
        return if write[:instruction]

        bits = write.size * 8
        fits = write.signed ? fits_signed?(write.value, bits) : fits_unsigned?(write.value, bits)
        return if fits

        raise RelocationOverflowError,
          "relocation value 0x#{write.value.to_s(16)} does not fit in an " \
          "#{write.signed ? "signed" : "unsigned"} #{write.size}-byte field"
      end

      # Applies a planned write to the section bytes.
      #
      # @param bytes [String]
      # @param write [Write]
      def apply_write(bytes, write)
        if write[:instruction]
          bytes.setbyte(write.offset, write.value & 0xff)
          bytes.setbyte(write.offset + 1, (write.value >> 8) & 0xff)
          bytes.setbyte(write.offset + 2, (write.value >> 16) & 0xff)
          bytes.setbyte(write.offset + 3, (write.value >> 24) & 0xff)
          return
        end

        format = (write.signed ? SIGNED_PACK_FORMATS : UNSIGNED_PACK_FORMATS).fetch(write.size)
        bytes.bytesplice(write.offset, write.size, [write.value].pack(format))
      end

      # @return [Boolean] whether +value+ fits in +bits+ unsigned bits
      def fits_unsigned?(value, bits)
        value >= 0 && value < (1 << bits)
      end

      # @return [Boolean] whether +value+ fits in +bits+ signed bits
      def fits_signed?(value, bits)
        min = -(1 << (bits - 1))
        max = (1 << (bits - 1)) - 1
        value >= min && value <= max
      end

    end

    # Parses the raw relocation_info words that follow a section header.
    #
    # @param data [String] the Mach-O file bytes
    # @param reloff [Integer] the file offset of the section's reloc table
    # @param nreloc [Integer] the number of relocation entries
    # @return [Array<Array(Integer, Integer)>] [word0, word1] pairs in file
    #  order
    def self.parse_relocation_words(data, reloff, nreloc)
      return [] if nreloc.zero?

      needed = nreloc * 8
      if reloff + needed > data.bytesize
        raise RelocationError,
          "relocation table at offset #{reloff} needs #{needed} bytes but only " \
          "#{data.bytesize - reloff} are available"
      end

      Array.new(nreloc) do |index|
        offset = reloff + (index * 8)
        data.byteslice(offset, 8).unpack("L<L<")
      end
    end

    # Evaluates a section's relocations directly from a parsed {MachOFile}.
    #
    # The file must be an MH_OBJECT for x86_64 or arm64. Sections are located
    # through the file's own LC_SEGMENT(_64) commands: their MH_OBJECT object
    # addresses are used as origins, and +section_addresses+ supplies the
    # final linked addresses (defaulting to the object addresses). The
    # returned bytes are not written back to the file.
    #
    # @param macho_file [MachOFile] an MH_OBJECT MachOFile
    # @param section [Sections::Section, Sections::Section64] the section
    #  whose relocations should be evaluated
    # @param symbol_addresses [Hash{Integer => Integer}] external symbol
    #  addresses keyed by symbol table index
    # @param section_addresses [Hash{Integer => Integer}, nil] final section
    #  base addresses keyed by 1-based global section ordinal
    # @return [Array(String, Array<RelocationResult>)] the patched bytes and
    #  per-entry results
    # @raise [RelocationError] if the Mach-O is not a supported MH_OBJECT
    def self.evaluate_section(macho_file, section, symbol_addresses: {}, section_addresses: nil)
      unless macho_file.object?
        raise RelocationError, "relocation evaluation only supports MH_OBJECT files"
      end

      arch = architecture_for_cputype(macho_file.header.cputype)
      is_64 = macho_file.magic64?
      unless is_64
        raise RelocationError, "relocation evaluation only supports 64-bit Mach-O files"
      end

      sections = macho_file.segments.flat_map(&:sections)
      section_index = sections.index do |candidate|
        candidate.segname == section.segname &&
          candidate.sectname == section.sectname &&
          candidate.offset == section.offset
      end
      if section_index.nil?
        raise RelocationError, "the given section is not part of this Mach-O"
      end
      ordinal = section_index + 1
      origins = sections.each_with_index.to_h { |sect, idx| [idx + 1, sect.addr] }
      finals = section_addresses || origins
      bytes = macho_file.serialize.byteslice(section.offset, section.size)
      words = parse_relocation_words(macho_file.serialize, section.reloff, section.nreloc)

      evaluator = RelocationEvaluator.new(
        arch, bytes, words,
        :symbol_addresses => symbol_addresses,
        :section_addresses => finals,
        :section_origins => origins,
        :section_ordinal => ordinal,
      )
      evaluator.evaluate
    end
  end
end
