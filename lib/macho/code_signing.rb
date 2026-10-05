# frozen_string_literal: true

require "digest/sha1"
require "digest/sha2"
require "set"

module MachO
  # Structures and helpers for embedded Mach-O code signatures.
  module CodeSigning
    CSMAGIC_REQUIREMENT = 0xfade0c00
    CSMAGIC_REQUIREMENTS = 0xfade0c01
    CSMAGIC_CODEDIRECTORY = 0xfade0c02
    CSMAGIC_BLOBWRAPPER = 0xfade0b01
    CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0
    CSMAGIC_DETACHED_SIGNATURE = 0xfade0cc1
    CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xfade7171
    CSMAGIC_EMBEDDED_DER_ENTITLEMENTS = 0xfade7172
    CSMAGIC_EMBEDDED_LAUNCH_CONSTRAINT = 0xfade8181
    CSMAGIC_ENTITLEMENT = CSMAGIC_EMBEDDED_ENTITLEMENTS
    CSMAGIC_ENTITLEMENTDER = CSMAGIC_EMBEDDED_DER_ENTITLEMENTS

    CS_MAGICS = {
      CSMAGIC_REQUIREMENT => :CSMAGIC_REQUIREMENT,
      CSMAGIC_REQUIREMENTS => :CSMAGIC_REQUIREMENTS,
      CSMAGIC_CODEDIRECTORY => :CSMAGIC_CODEDIRECTORY,
      CSMAGIC_BLOBWRAPPER => :CSMAGIC_BLOBWRAPPER,
      CSMAGIC_EMBEDDED_SIGNATURE => :CSMAGIC_EMBEDDED_SIGNATURE,
      CSMAGIC_DETACHED_SIGNATURE => :CSMAGIC_DETACHED_SIGNATURE,
      CSMAGIC_EMBEDDED_ENTITLEMENTS => :CSMAGIC_EMBEDDED_ENTITLEMENTS,
      CSMAGIC_EMBEDDED_DER_ENTITLEMENTS => :CSMAGIC_EMBEDDED_DER_ENTITLEMENTS,
      CSMAGIC_EMBEDDED_LAUNCH_CONSTRAINT => :CSMAGIC_EMBEDDED_LAUNCH_CONSTRAINT,
    }.freeze

    CSSLOT_CODEDIRECTORY = 0
    CSSLOT_INFOSLOT = 1
    CSSLOT_REQUIREMENTS = 2
    CSSLOT_RESOURCEDIR = 3
    CSSLOT_APPLICATION = 4
    CSSLOT_ENTITLEMENTS = 5
    CSSLOT_DER_ENTITLEMENTS = 7
    CSSLOT_LAUNCH_CONSTRAINT_SELF = 8
    CSSLOT_LAUNCH_CONSTRAINT_PARENT = 9
    CSSLOT_LAUNCH_CONSTRAINT_RESPONSIBLE = 10
    CSSLOT_LIBRARY_CONSTRAINT = 11
    CSSLOT_ALTERNATE_CODEDIRECTORIES = 0x1000
    CSSLOT_SIGNATURESLOT = 0x10000

    CS_HASHTYPE_SHA1 = 1
    CS_HASHTYPE_SHA256 = 2
    CS_HASHTYPE_SHA256_TRUNCATED = 3
    CS_HASHTYPE_SHA384 = 4

    CS_HASHTYPES = {
      CS_HASHTYPE_SHA1 => :CS_HASHTYPE_SHA1,
      CS_HASHTYPE_SHA256 => :CS_HASHTYPE_SHA256,
      CS_HASHTYPE_SHA256_TRUNCATED => :CS_HASHTYPE_SHA256_TRUNCATED,
      CS_HASHTYPE_SHA384 => :CS_HASHTYPE_SHA384,
    }.freeze

    CS_ADHOC = 0x2
    CS_HARD = 0x100
    CS_RUNTIME = 0x10000
    CS_LINKER_SIGNED = 0x20000
    CS_EXECSEG_MAIN_BINARY = 0x1
    CS_EXECSEG_JIT = 0x40

    CS_SUPPORTSCODELIMIT64 = 0x20300
    CS_SUPPORTSEXECSEG = 0x20400
    CS_SUPPORTSRUNTIME = 0x20500
    CS_SUPPORTSLINKAGE = 0x20600

    PAGE_SIZE = 4096
    PRESERVED_COMPONENT_SLOTS = [
      CSSLOT_REQUIREMENTS,
      CSSLOT_ENTITLEMENTS,
      CSSLOT_DER_ENTITLEMENTS,
    ].freeze

    HASHES = {
      CS_HASHTYPE_SHA1 => [Digest::SHA1, 20],
      CS_HASHTYPE_SHA256 => [Digest::SHA256, 32],
      CS_HASHTYPE_SHA256_TRUNCATED => [Digest::SHA256, 20],
      CS_HASHTYPE_SHA384 => [Digest::SHA384, 48],
    }.freeze

    SPECIAL_SLOT_NAMES = {
      CSSLOT_INFOSLOT => :info_plist,
      CSSLOT_REQUIREMENTS => :requirements,
      CSSLOT_RESOURCEDIR => :resources,
      CSSLOT_APPLICATION => :application,
      CSSLOT_ENTITLEMENTS => :entitlements,
      CSSLOT_DER_ENTITLEMENTS => :der_entitlements,
      CSSLOT_LAUNCH_CONSTRAINT_SELF => :launch_constraint_self,
      CSSLOT_LAUNCH_CONSTRAINT_PARENT => :launch_constraint_parent,
      CSSLOT_LAUNCH_CONSTRAINT_RESPONSIBLE => :launch_constraint_responsible,
      CSSLOT_LIBRARY_CONSTRAINT => :library_constraint,
    }.freeze

    # An entry in a code-signing SuperBlob index.
    BlobIndex = Struct.new(:type, :offset)

    # A mapping in a CodeDirectory scatter vector.
    ScatterEntry = Struct.new(:count, :base, :target_offset, keyword_init: true)

    # A generic code-signing blob.
    class Blob
      # @return [Integer] the blob magic
      attr_reader :magic

      # @return [Integer] the complete blob length
      attr_reader :length

      # Parses the concrete blob type represented by `data`.
      # @param data [String] raw blob data
      # @return [Blob]
      def self.parse(data)
        raise CodeSigningError, "code-signing blob is truncated" if data.nil? || data.bytesize < 8

        case data.unpack1("N")
        when CSMAGIC_CODEDIRECTORY
          CodeDirectory.new(data)
        when CSMAGIC_EMBEDDED_SIGNATURE
          SuperBlob.new(data)
        else
          new(data)
        end
      end

      # @param data [String] raw blob data
      def initialize(data)
        raise CodeSigningError, "code-signing blob is truncated" if data.nil? || data.bytesize < 8

        @magic, @length = data.unpack("N2")
        raise CodeSigningError, "invalid code-signing blob length: #{length}" if length < 8 || length > data.bytesize

        @raw_data = data.byteslice(0, length).freeze
      end

      # @return [String] raw blob data
      def serialize
        @raw_data
      end

      # @return [Symbol, nil] the symbolic blob magic
      def magic_sym
        CS_MAGICS[magic]
      end

      # @return [Hash] a hash representation of this blob
      def to_h
        {
          "magic" => magic,
          "magic_sym" => magic_sym,
          "length" => length,
        }
      end
    end

    # An embedded-signature SuperBlob.
    class SuperBlob < Blob
      # @return [Integer] the number of indexed blobs
      attr_reader :count

      # @return [Array<BlobIndex>] the blob index
      attr_reader :indices

      # @return [Array<Blob>] the indexed blobs
      attr_reader :blobs

      # Builds a SuperBlob containing the given slot/blob pairs.
      # @param entries [Hash<Integer, String>] blobs keyed by slot
      # @return [String] serialised SuperBlob data
      def self.build(entries)
        entries = entries.sort_by(&:first)
        offset = 12 + (entries.size * 8)
        index = +"".b
        payload = +"".b
        entries.each do |type, blob|
          index << [type, offset].pack("N2")
          payload << blob
          offset += blob.bytesize
        end

        [CSMAGIC_EMBEDDED_SIGNATURE, offset, entries.size].pack("N3") + index + payload
      end

      # @param data [String] raw SuperBlob data
      def initialize(data)
        super
        raise CodeSigningError, "invalid embedded-signature magic: 0x#{magic.to_s(16)}" unless magic == CSMAGIC_EMBEDDED_SIGNATURE
        raise CodeSigningError, "code-signing SuperBlob is truncated" if length < 12

        @count = serialize.unpack1("N", :offset => 8)
        raise CodeSigningError, "code-signing SuperBlob index is truncated" if 12 + (count * 8) > length

        @indices = count.times.map do |index|
          BlobIndex.new(*serialize.unpack("N2", :offset => 12 + (index * 8)))
        end.freeze
        @blobs = indices.map do |entry|
          raise CodeSigningError, "code-signing blob offset is invalid: #{entry.offset}" if entry.offset < 12 + (count * 8) || entry.offset + 8 > length

          Blob.parse(serialize.byteslice(entry.offset, length - entry.offset))
        end.freeze
      end

      # Returns the blob stored in `type`, if present.
      # @param type [Integer] the slot type
      # @return [Blob, nil]
      def blob(type)
        index = indices.index { |entry| entry.type == type }
        blobs[index] if index
      end

      # Yields every index entry.
      # @yieldparam index [BlobIndex]
      # @return [Enumerator, void]
      def each_blob_index(&block)
        return indices.each unless block

        indices.each(&block)
      end

      # Yields every indexed blob.
      # @yieldparam blob [Blob]
      # @return [Enumerator, void]
      def each_blob(&block)
        return blobs.each unless block

        blobs.each(&block)
      end

      # @return [Hash] a hash representation of this SuperBlob
      def to_h
        {
          "count" => count,
          "indices" => indices.map { |entry| { "type" => entry.type, "offset" => entry.offset } },
          "blobs" => blobs.map(&:to_h),
        }.merge super
      end
    end

    # A CodeDirectory describing signed code pages and special components.
    class CodeDirectory < Blob
      attr_reader :version, :flags, :hash_offset, :ident_offset,
                  :n_special_slots, :n_code_slots, :hash_size, :hash_type,
                  :platform, :page_size, :scatter_offset, :team_offset,
                  :code_limit64, :exec_seg_base, :exec_seg_limit,
                  :exec_seg_flags, :runtime, :pre_encrypt_offset,
                  :linkage_hash_type, :linkage_application_type,
                  :linkage_application_subtype, :linkage_offset, :linkage_size

      # Builds a CodeDirectory for `source`.
      # @param source [String] bytes before the embedded signature
      # @param identifier [String] the signing identifier
      # @param hash_type [Integer] the hash algorithm
      # @param flags [Integer] CodeDirectory flags
      # @param special_slots [Hash<Integer, String>] special-slot contents
      # @param exec_seg_base [Integer] executable segment offset
      # @param exec_seg_limit [Integer] executable segment size
      # @param exec_seg_flags [Integer] executable segment flags
      # @param runtime [Integer] hardened runtime version
      # @param hashes [Boolean] whether to calculate hashes
      # @return [String] serialised CodeDirectory data
      def self.build(source, identifier:, hash_type:, flags:, special_slots:,
                     exec_seg_base:, exec_seg_limit:, exec_seg_flags:, runtime:, hashes: true)
        digest, hash_size = HASHES.fetch(hash_type)
        version = runtime.zero? ? CS_SUPPORTSEXECSEG : CS_SUPPORTSRUNTIME
        fixed_size = runtime.zero? ? 88 : 96
        identifier = "#{identifier.b.delete("\x00")}\x00".b
        n_special_slots = special_slots.keys.max || 0
        n_code_slots = (source.bytesize + PAGE_SIZE - 1) / PAGE_SIZE
        hash_offset = fixed_size + identifier.bytesize + (n_special_slots * hash_size)
        length = hash_offset + (n_code_slots * hash_size)
        code_limit = [source.bytesize, 0xffffffff].min
        code_limit64 = source.bytesize > 0xffffffff ? source.bytesize : 0

        data = [CSMAGIC_CODEDIRECTORY, length, version, flags, hash_offset,
                fixed_size, n_special_slots, n_code_slots, code_limit].pack("N9")
        data << [hash_size, hash_type, 0, 12].pack("C4")
        data << [0, 0, 0, 0].pack("N4")
        data << [code_limit64, exec_seg_base, exec_seg_limit, exec_seg_flags].pack("Q>4")
        data << [runtime, 0].pack("N2") unless runtime.zero?
        data << identifier
        if hashes
          n_special_slots.downto(1) do |slot|
            data << if special_slots.key?(slot)
              digest.digest(special_slots.fetch(slot))
            else
              "\x00" * hash_size
            end
          end
          0.step(source.bytesize - 1, PAGE_SIZE) do |offset|
            data << digest.digest(source.byteslice(offset, PAGE_SIZE))
          end
        else
          data << Utils.nullpad((n_special_slots + n_code_slots) * hash_size)
        end
        data
      end

      # @param data [String] raw CodeDirectory data
      def initialize(data)
        super
        raise CodeSigningError, "invalid CodeDirectory magic: 0x#{magic.to_s(16)}" unless magic == CSMAGIC_CODEDIRECTORY
        raise CodeSigningError, "CodeDirectory is truncated" if length < 44

        _, _, @version, @flags, @hash_offset, @ident_offset,
          @n_special_slots, @n_code_slots, @code_limit = serialize.unpack("N9")
        @hash_size, @hash_type, @platform, @page_size = serialize.unpack("C4", :offset => 36)
        fixed_size = 44
        @scatter_offset = unpack_uint32(44) if version >= 0x20100
        fixed_size = 48 if version >= 0x20100
        @team_offset = unpack_uint32(48) if version >= 0x20200
        fixed_size = 52 if version >= 0x20200
        if version >= CS_SUPPORTSCODELIMIT64
          raise CodeSigningError, "CodeDirectory is truncated" if length < 64

          @code_limit64 = serialize.unpack1("Q>", :offset => 56)
          fixed_size = 64
        end
        if version >= CS_SUPPORTSEXECSEG
          raise CodeSigningError, "CodeDirectory is truncated" if length < 88

          @exec_seg_base, @exec_seg_limit, @exec_seg_flags = serialize.unpack("Q>3", :offset => 64)
          fixed_size = 88
        end
        if version >= CS_SUPPORTSRUNTIME
          raise CodeSigningError, "CodeDirectory is truncated" if length < 96

          @runtime, @pre_encrypt_offset = serialize.unpack("N2", :offset => 88)
          fixed_size = 96
        end
        if version >= CS_SUPPORTSLINKAGE
          raise CodeSigningError, "CodeDirectory is truncated" if length < 108

          @linkage_hash_type, @linkage_application_type,
            @linkage_application_subtype, @linkage_offset,
            @linkage_size = serialize.unpack("CCnN2", :offset => 96)
          fixed_size = 108
        end
        raise CodeSigningError, "CodeDirectory identifier offset is invalid" if ident_offset < fixed_size || ident_offset >= length

        terminator = serialize.index("\x00", ident_offset)
        raise CodeSigningError, "CodeDirectory identifier is unterminated" unless terminator && terminator < length
        if hash_size.zero? ||
           hash_offset < fixed_size ||
           hash_offset - (n_special_slots * hash_size) < terminator + 1 ||
           hash_offset + (n_code_slots * hash_size) > length
          raise CodeSigningError, "CodeDirectory hash range is invalid"
        end

        hash_end = hash_offset + (n_code_slots * hash_size)
        if version >= 0x20100 && !scatter_offset.zero? &&
           (scatter_offset < hash_end || scatter_offset + 20 > length)
          raise CodeSigningError, "CodeDirectory scatter vector offset is invalid"
        end

        @identifier = serialize.byteslice(ident_offset, terminator - ident_offset)
      end

      # @return [String] the signing identifier
      attr_reader :identifier

      # @return [Integer] the number of signed bytes
      def code_limit
        version >= CS_SUPPORTSCODELIMIT64 && code_limit64&.positive? ? code_limit64 : @code_limit
      end

      # @return [Boolean] whether this CodeDirectory contains a scatter vector
      def scatter?
        version >= 0x20100 && !scatter_offset.zero?
      end

      # @return [ScatterVector, nil] the parsed scatter vector
      def scatter_vector
        return unless scatter?

        ScatterVector.new(serialize, scatter_offset)
      end

      # Returns a code page hash.
      # @param slot [Integer] a zero-based page slot
      # @return [String, nil]
      def code_hash(slot)
        return if slot.negative? || slot >= n_code_slots

        serialize.byteslice(hash_offset + (slot * hash_size), hash_size)
      end

      # @return [Symbol, nil] the symbolic hash type
      def hash_type_sym
        CS_HASHTYPES[hash_type]
      end

      # Returns a special-slot hash.
      # @param slot [Integer] a positive special-slot number
      # @return [String, nil]
      def special_hash(slot)
        return unless slot.positive? && slot <= n_special_slots

        serialize.byteslice(hash_offset - (slot * hash_size), hash_size)
      end

      # @return [Hash] a hash representation of this CodeDirectory
      def to_h
        {
          "version" => version,
          "flags" => flags,
          "identifier" => identifier,
          "hash_offset" => hash_offset,
          "n_special_slots" => n_special_slots,
          "n_code_slots" => n_code_slots,
          "code_limit" => code_limit,
          "hash_size" => hash_size,
          "hash_type" => hash_type,
          "hash_type_sym" => hash_type_sym,
          "page_size" => page_size,
        }.merge super
      end

      private

      def unpack_uint32(offset)
        raise CodeSigningError, "CodeDirectory is truncated" if length < offset + 4

        serialize.unpack1("N", :offset => offset)
      end
    end

    # A CodeDirectory scatter vector describing non-contiguous code pages.
    class ScatterVector
      # @return [Array<ScatterEntry>] the non-contiguous page mappings
      attr_reader :entries

      # @param data [String] raw CodeDirectory data
      # @param offset [Integer] the scatter vector offset
      def initialize(data, offset)
        @entries = []
        cursor = offset
        loop do
          raise CodeSigningError, "CodeDirectory scatter vector is truncated" if cursor + 20 > data.bytesize

          count, base, target_offset = data.unpack("N2Q>", :offset => cursor)
          break if count.zero?

          raise CodeSigningError, "CodeDirectory scatter vector is truncated" if cursor + 24 > data.bytesize
          spare = data.unpack1("Q>", :offset => cursor + 16)
          unless spare.zero?
            raise CodeSigningError, "CodeDirectory scatter vector reserved field is non-zero"
          end

          @entries << ScatterEntry.new(
            :count => count,
            :base => base,
            :target_offset => target_offset
          )
          cursor += 24
        end
        @entries.freeze
      end

      # Yields each hash slot, file offset, and mapped length in order.
      # @yieldparam slot [Integer] the code hash slot
      # @yieldparam target_offset [Integer] the corresponding file offset
      # @return [Enumerator, void]
      def each_mapping
        return enum_for(:each_mapping) unless block_given?

        entries.each do |entry|
          entry.count.times do |index|
            yield entry.base + index, entry.target_offset + (index * PAGE_SIZE)
          end
        end
      end
    end

    # A mismatch, unverifiable component, or unsigned range found during verification.
    VerificationIssue = Struct.new(:code, :severity, :message, :offset, :length, :slot, keyword_init: true)

    # Verification details for one primary or alternate CodeDirectory.
    CodeDirectoryVerification = Struct.new(
      :slot, :hash_type, :identifier, :flags, :scatter, :issues, keyword_init: true
    ) do
      def valid?
        issues.none?
      end
    end

    # The read-only result of comparing file bytes with an embedded signature.
    class VerificationResult
      # @return [Symbol] :consistent, :inconsistent, :unverifiable, or :malformed
      attr_reader :status

      # @return [Array<VerificationIssue>] mismatches and verification limitations
      attr_reader :issues

      # @return [Array<CodeDirectoryVerification>] verified CodeDirectories
      attr_reader :code_directories

      # @return [Array<VerificationResult>] results for fat-Mach-O slices
      attr_reader :slices

      # @param issues [Array<VerificationIssue>]
      # @param code_directories [Array<CodeDirectoryVerification>]
      # @param slices [Array<VerificationResult>]
      def initialize(issues: [], code_directories: [], slices: [])
        @issues = issues
        @code_directories = code_directories
        @slices = slices
        @status =
          if malformed?
            :malformed
          elsif issues.any? { |issue| issue.severity == :mismatch }
            :inconsistent
          elsif issues.any? { |issue| %i[missing unsupported malformed].include?(issue.severity) }
            :unverifiable
          else
            :consistent
          end
      end

      # @return [Boolean] whether every checked digest matched
      def digests_consistent?
        issues.none? { |issue| issue.severity == :mismatch }
      end

      alias content_digest_consistent? digests_consistent?

      # @return [Boolean] whether no signed component was missing or unsupported
      def complete?
        issues.none? { |issue| %i[missing unsupported malformed].include?(issue.severity) }
      end

      # @return [Boolean] whether there are no unsigned gaps or trailing bytes
      def all_bytes_covered?
        issues.none? { |issue| %i[unsigned_code_gap unsigned_trailing_data].include?(issue.code) }
      end

      # @return [Boolean] whether all embedded hashes matched and all components were checked
      def valid?
        status == :consistent
      end

      # @return [Boolean] whether any CodeDirectory carries the ad-hoc flag
      def adhoc?
        results = slices.any? ? slices : [self]
        results.any? { |result| result.code_directories.any? { |directory| directory.flags.to_i.anybits?(CS_ADHOC) } }
      end

      # @return [Symbol] always :not_evaluated; certificate trust is deliberately not checked
      def signer_trust
        :not_evaluated
      end

      # @return [Boolean] false because this API never evaluates the certificate trust chain
      def trusted_signer?
        false
      end

      # @return [Hash{String => Object}]
      def to_h
        {
          "status" => status,
          "digests_consistent" => digests_consistent?,
          "complete" => complete?,
          "all_bytes_covered" => all_bytes_covered?,
          "valid" => valid?,
          "adhoc" => adhoc?,
          "signer_trust" => signer_trust,
          "trusted_signer" => trusted_signer?,
          "issues" => issues.map { |issue| issue.to_h.compact },
          "code_directories" => code_directories.map { |directory| directory.to_h },
        }.tap do |hash|
          hash["slices"] = slices.map(&:to_h) if slices.any?
        end
      end

      # Combines fat-Mach-O slice results.
      # @param slice_results [Array<VerificationResult>]
      # @return [VerificationResult]
      def self.combine(slice_results)
        issues = slice_results.each_with_index.flat_map do |result, slice|
          result.issues.map do |issue|
            VerificationIssue.new(issue.to_h.merge(:message => "slice #{slice}: #{issue.message}"))
          end
        end
        new(:issues => issues, :slices => slice_results)
      end

      private

      def malformed?
        components = slices.any? ? slices : [self]
        components.any? { |result| result.issues.any? { |issue| issue.severity == :malformed } }
      end
    end

    # Verifies embedded CodeDirectory hashes without modifying a Mach-O slice.
    class SignatureVerifier
      # @param macho [MachOFile] the Mach-O slice
      # @param special_data [#call, Hash, nil] provider for external special-slot data
      def initialize(macho, special_data = nil, slice: nil)
        @macho = macho
        @special_data = special_data
        @slice = slice
        @issues = []
        @code_directories = []
      end

      # @return [VerificationResult]
      def verify
        commands = @macho[:LC_CODE_SIGNATURE]
        return malformed_result("Mach-O contains multiple LC_CODE_SIGNATURE commands") if commands.size > 1
        return malformed_result("Mach-O does not contain an LC_CODE_SIGNATURE command") if commands.empty?

        @command = commands.first
        return malformed_result("LC_CODE_SIGNATURE has no data offset or size") if @command.dataoff.zero? || @command.datasize.zero?
        return malformed_result("LC_CODE_SIGNATURE data range is outside the Mach-O") if signature_end > @macho.serialize.bytesize

        superblob = parse_superblob
        return VerificationResult.new(:issues => @issues) if malformed?

        verify_superblob(superblob)
        add_unsigned_ranges
        VerificationResult.new(:issues => @issues, :code_directories => @code_directories)
      end

      private

      def signature_start
        @command.dataoff
      end

      def signature_end
        signature_start + @command.datasize
      end

      def parse_superblob
        @command.superblob
      rescue CodeSigningError => e
        add_issue(:malformed_signature, :malformed, e.message, signature_start, @command.datasize)
        nil
      end

      def malformed_result(message)
        add_issue(:malformed_signature, :malformed, message)
        VerificationResult.new(:issues => @issues)
      end

      def malformed?
        @issues.any? { |issue| issue.severity == :malformed }
      end

      def verify_superblob(superblob)
        superblob.indices.group_by(&:type).each do |type, indices|
          next unless indices.size > 1

          add_issue(:duplicate_signature_slot, :malformed, "signature slot 0x#{type.to_s(16)} appears more than once")
        end

        directories = code_directory_slots(superblob)
        primary = directories.select { |slot, _| slot == CSSLOT_CODEDIRECTORY }
        add_issue(:missing_code_directory, :malformed, "embedded signature does not contain a primary CodeDirectory") if primary.empty?
        add_issue(:duplicate_code_directory, :malformed, "embedded signature contains multiple primary CodeDirectories") if primary.size > 1

        directories.each do |slot, code_directory|
          verify_code_directory(superblob, code_directory, slot)
        end
      end

      def code_directory_slots(superblob)
        superblob.indices.zip(superblob.blobs).filter_map do |index, blob|
          next unless blob.is_a?(CodeDirectory)
          next unless index.type == CSSLOT_CODEDIRECTORY ||
                      (index.type >= CSSLOT_ALTERNATE_CODEDIRECTORIES && index.type < CSSLOT_ALTERNATE_CODEDIRECTORIES + 5)

          [index.type, blob]
        end
      end

      def verify_code_directory(superblob, code_directory, slot)
        directory_issues = []
        directory = CodeDirectoryVerification.new(
          :slot => slot,
          :hash_type => code_directory.hash_type_sym || code_directory.hash_type,
          :identifier => code_directory.identifier,
          :flags => code_directory.flags,
          :scatter => code_directory.scatter?,
          :issues => directory_issues
        )
        @code_directories << directory

        digest, expected_hash_size = HASHES[code_directory.hash_type]
        unless digest
          add_directory_issue(
            directory_issues,
            :unsupported_hash_type,
            :unsupported,
            "unsupported CodeDirectory hash type #{code_directory.hash_type}"
          )
          return
        end
        unless code_directory.hash_size == expected_hash_size
          add_directory_issue(
            directory_issues,
            :invalid_hash_size,
            :malformed,
            "CodeDirectory hash size #{code_directory.hash_size} does not match #{expected_hash_size}"
          )
          return
        end

        verify_special_slots(superblob, code_directory, digest, directory_issues)
        page_size = page_size(code_directory, directory_issues)
        return if malformed_issue?(directory_issues)

        if code_directory.scatter?
          verify_scatter_code(code_directory, digest, page_size, directory_issues)
        else
          verify_contiguous_code(code_directory, digest, page_size, directory_issues)
        end
      ensure
        @issues.concat(directory_issues) if defined?(directory_issues)
      end

      def page_size(code_directory, issues)
        return nil if code_directory.page_size.zero?

        if code_directory.page_size > 63
          add_issue_to(issues, :invalid_page_size, :malformed,
                       "CodeDirectory page size exponent #{code_directory.page_size} is unsupported")
          return nil
        end

        2**code_directory.page_size
      end

      def verify_special_slots(superblob, code_directory, digest, issues)
        1.upto(code_directory.n_special_slots) do |slot|
          expected = code_directory.special_hash(slot)
          next if expected == "\x00" * code_directory.hash_size

          data = special_slot_data(slot, superblob, code_directory)
          if data.nil?
            add_issue_to(issues, :missing_special_slot_data, :missing,
                         "cannot verify special slot #{special_slot_name(slot)}: no data was provided")
            next
          end

          actual = digest.digest(data.to_s).byteslice(0, code_directory.hash_size)
          next if actual == expected

          add_issue_to(issues, :special_slot_hash_mismatch, :mismatch,
                       "special slot #{special_slot_name(slot)} digest does not match the CodeDirectory")
        end
      end

      def special_slot_data(slot, superblob, code_directory)
        blob = superblob.blob(slot)
        return blob.serialize if blob
        return if @special_data.nil?

        data = if @special_data.respond_to?(:call)
          if @special_data.arity <= 1
            @special_data.call(slot)
          else
            @special_data.call(slot, code_directory)
          end
        elsif @special_data.is_a?(Hash)
          @special_data[slot] || @special_data[SPECIAL_SLOT_NAMES[slot]]
        end
        raise ArgumentError, "special-slot callback must return a binary String or nil" unless data.nil? || data.is_a?(String)

        data
      end

      def special_slot_name(slot)
        SPECIAL_SLOT_NAMES.fetch(slot, "slot_#{slot}").to_s
      end

      def verify_contiguous_code(code_directory, digest, page_size, issues)
        infinite_page = page_size.nil?
        page_size ||= [code_directory.code_limit, 1].max
        expected_slots = if code_directory.code_limit.zero?
          0
        elsif infinite_page
          1
        else
          (code_directory.code_limit.to_f / page_size).ceil
        end
        if expected_slots != code_directory.n_code_slots
          add_issue_to(issues, :invalid_code_slot_count, :malformed,
                       "CodeDirectory has #{code_directory.n_code_slots} code slots but #{expected_slots} are required")
          return
        end
        if code_directory.code_limit > signature_start
          add_issue_to(issues, :code_limit_overlaps_signature, :malformed,
                       "CodeDirectory code limit overlaps the embedded signature",
                       signature_start, code_directory.code_limit - signature_start)
        end

        code_directory.n_code_slots.times do |slot|
          offset = slot * page_size
          length = [page_size, code_directory.code_limit - offset].min
          verify_code_hash(code_directory, digest, slot, offset, length, issues, :code_hash_mismatch)
        end
      end

      def verify_scatter_code(code_directory, digest, page_size, issues)
        scatter = code_directory.scatter_vector
        page_size ||= PAGE_SIZE
        slot_intervals = []
        target_intervals = []
        mappings = []
        valid_entries = []

        scatter.entries.each do |entry|
          end_slot = entry.base + entry.count
          last_target = entry.target_offset + ((entry.count - 1) * page_size)
          last_length = if last_target < code_directory.code_limit
            [[page_size, code_directory.code_limit - last_target].min, 1].max
          else
            page_size
          end
          target_end = last_target + last_length
          invalid = end_slot < entry.base || end_slot > code_directory.n_code_slots
          invalid ||= target_end < entry.target_offset
          if invalid
            add_issue_to(issues, :scatter_entry_out_of_range, :malformed,
                         "scatter vector entry is outside the CodeDirectory or file range",
                         entry.target_offset, entry.count * page_size)
            next
          end
          valid_entries << entry
        end

        valid_entries.each do |entry|
          entry.count.times do |index|
            slot = entry.base + index
            target_offset = entry.target_offset + (index * page_size)
            mapped_length = if target_offset < code_directory.code_limit
              [[page_size, code_directory.code_limit - target_offset].min, 1].max
            else
              page_size
            end
            mappings << [slot, target_offset, mapped_length]
            add_interval(slot_intervals, slot, 1, issues, :scatter_hash_slots_overlap, "scatter vector hash slots overlap")
            add_interval(target_intervals, target_offset, mapped_length, issues,
                         :scatter_targets_overlap, "scatter vector target ranges overlap")
            if interval_overlap?(target_offset, mapped_length, signature_start, @command.datasize)
              add_issue_to(issues, :scatter_target_overlaps_signature, :malformed,
                           "scatter vector target range overlaps the embedded signature",
                           target_offset, mapped_length)
            end
          end
        end

        mapped_slots = mappings.map(&:first).to_set
        code_directory.n_code_slots.times do |slot|
          next if mapped_slots.include?(slot)

          add_issue_to(issues, :scatter_slot_unmapped, :malformed,
                       "scatter vector does not map code hash slot #{slot}")
        end

        mappings.each do |slot, offset, mapped_length|
          verify_code_hash(code_directory, digest, slot, offset, mapped_length, issues, :scatter_hash_mismatch)
        end
      rescue CodeSigningError => e
        add_issue_to(issues, :malformed_scatter_vector, :malformed, e.message)
      end

      def verify_code_hash(code_directory, digest, slot, offset, expected_length, issues, mismatch_code)
        actual = @macho.serialize.byteslice(offset, expected_length)
        if actual.nil? || actual.empty?
          add_issue_to(issues, :missing_code_data, :missing,
                       "file data for code hash slot #{slot} is missing", offset, expected_length)
          return
        end
        if actual.bytesize < expected_length
          add_issue_to(issues, :missing_code_data, :missing,
                       "file data for code hash slot #{slot} is truncated",
                       offset + actual.bytesize, expected_length - actual.bytesize)
          return
        end

        expected = code_directory.code_hash(slot)
        return if digest.digest(actual).byteslice(0, code_directory.hash_size) == expected

        add_issue_to(issues, mismatch_code, :mismatch,
                     "code hash slot #{slot} digest does not match the file bytes",
                     offset,
                     actual.bytesize,
                     slot)
      end

      def add_interval(intervals, offset, length, issues, code, message)
        return if length.zero?

        if intervals.any? { |start, size| interval_overlap?(offset, length, start, size) }
          add_issue_to(issues, code, :malformed, message, offset, length)
        end
        intervals << [offset, length]
      end

      def interval_overlap?(offset, length, other_offset, other_length)
        offset < other_offset + other_length && other_offset < offset + length
      end

      def add_unsigned_ranges
        superblob = @command.superblob
        primary_index = superblob.indices.index { |index| index.type == CSSLOT_CODEDIRECTORY }
        return if primary_index.nil?

        primary = superblob.blobs[primary_index]
        return unless primary

        if primary.code_limit < signature_start
          add_issue(:unsigned_code_gap, :info,
                    "bytes between the signed code limit and the signature are not covered",
                    primary.code_limit, signature_start - primary.code_limit)
        end
        if signature_end < @macho.serialize.bytesize
          add_issue(:unsigned_trailing_data, :info,
                    "trailing bytes after the embedded signature are not covered",
                    signature_end, @macho.serialize.bytesize - signature_end)
        end
      end

      def add_directory_issue(issues, code, severity, message, offset = nil, length = nil)
        add_issue_to(issues, code, severity, message, offset, length)
      end

      def malformed_issue?(issues)
        issues.any? { |issue| issue.severity == :malformed }
      end

      def add_issue_to(issues, code, severity, message, offset = nil, length = nil, slot = nil)
        message = "slice #{@slice}: #{message}" unless @slice.nil?
        issues << VerificationIssue.new(
          :code => code,
          :severity => severity,
          :message => message,
          :offset => offset,
          :length => length,
          :slot => slot
        )
      end

      def add_issue(code, severity, message, offset = nil, length = nil, slot = nil)
        add_issue_to(@issues, code, severity, message, offset, length, slot)
      end
    end

    # Generates and embeds an ad-hoc signature in one Mach-O slice.
    class AdhocSigner
      # @param macho [MachOFile] the slice to sign
      # @param identifier [String] the signing identifier
      def initialize(macho, identifier)
        @macho = macho
        @identifier = identifier
      end

      # Embeds a new signature.
      # @return [void]
      def sign!
        signature_commands = @macho[:LC_CODE_SIGNATURE]
        raise CodeSigningError, "Mach-O contains multiple LC_CODE_SIGNATURE commands" if signature_commands.size > 1

        signature_command = signature_commands.first
        metadata = metadata_from(signature_command)
        remove_signature(signature_command) if signature_command&.datasize&.positive?
        add_signature_command unless signature_command

        signature_command = @macho[:LC_CODE_SIGNATURE].first
        linkedit_segments = @macho.segments.select { |segment| segment.segname == "__LINKEDIT" }
        raise CodeSigningError, "Mach-O must contain exactly one __LINKEDIT segment" unless linkedit_segments.one?

        linkedit = linkedit_segments.first

        @macho.serialize << Utils.nullpad(Utils.padding_for(@macho.serialize.bytesize, 16))
        dataoff = @macho.serialize.bytesize
        raise CodeSigningError, "code signature offset exceeds LC_CODE_SIGNATURE" if dataoff > 0xffffffff

        entries = signature_entries(metadata, :hashes => false)
        datasize = Utils.round(SuperBlob.build(entries).bytesize, 16)

        update_linkedit_data_command(signature_command, dataoff, datasize)
        update_linkedit_segment(linkedit, dataoff + datasize)

        entries = signature_entries(metadata)
        signature = SuperBlob.build(entries)
        @macho.serialize << signature << Utils.nullpad(datasize - signature.bytesize)
        @macho.populate_fields
        nil
      end

      private

      def metadata_from(signature_command)
        return default_metadata unless signature_command&.datasize&.positive?

        superblob = signature_command.superblob
        code_directory = superblob.blobs.grep(CodeDirectory).find { |blob| blob.hash_type == CS_HASHTYPE_SHA256 } ||
                         superblob.blobs.grep(CodeDirectory).first
        return default_metadata unless code_directory
        return default_metadata if code_directory.flags.anybits?(CS_LINKER_SIGNED)

        components = PRESERVED_COMPONENT_SLOTS.to_h do |slot|
          [slot, superblob.blob(slot)&.serialize]
        end.compact
        {
          :components => components,
          :exec_seg_flags => code_directory.exec_seg_flags.to_i,
          :flags => (code_directory.flags & ~CS_LINKER_SIGNED) | CS_ADHOC,
          :runtime => code_directory.runtime.to_i,
        }
      end

      def default_metadata
        {
          :components => {},
          :exec_seg_flags => 0,
          :flags => CS_ADHOC,
          :runtime => 0,
        }
      end

      def remove_signature(signature_command)
        end_offset = signature_command.dataoff + signature_command.datasize
        trailing_data = @macho.serialize.byteslice(end_offset..).to_s
        unless signature_command.dataoff <= @macho.serialize.bytesize &&
               end_offset <= @macho.serialize.bytesize &&
               trailing_data.bytesize <= 15 && trailing_data.bytes.all?(&:zero?)
          raise CodeSigningError, "LC_CODE_SIGNATURE does not point to the end of the Mach-O"
        end

        @macho.serialize.slice!(signature_command.dataoff..)
        @macho.populate_fields
      end

      def add_signature_command
        @macho.add_command(LoadCommands::LoadCommand.create(:LC_CODE_SIGNATURE, 0, 0))
      rescue ModificationError => e
        raise CodeSigningError, e.message
      end

      def signature_entries(metadata, hashes: true)
        components = metadata.fetch(:components).dup
        components[CSSLOT_REQUIREMENTS] ||= [CSMAGIC_REQUIREMENTS, 12, 0].pack("N3")
        special_slots = components.dup
        if (info_plist = CodeSigning.info_plist(@macho))
          special_slots[CSSLOT_INFOSLOT] = info_plist
        end

        text = @macho.segments.find { |segment| segment.segname == "__TEXT" }
        exec_seg_flags = metadata.fetch(:exec_seg_flags)
        if @macho.executable?
          exec_seg_flags |= CS_EXECSEG_MAIN_BINARY
        else
          exec_seg_flags &= ~CS_EXECSEG_MAIN_BINARY
        end
        source = @macho.serialize
        entries = {}
        hash_types.each_with_index do |hash_type, index|
          entries[index.zero? ? CSSLOT_CODEDIRECTORY : CSSLOT_ALTERNATE_CODEDIRECTORIES + index - 1] =
            CodeDirectory.build(source,
                                :identifier => @identifier,
                                :hash_type => hash_type,
                                :flags => metadata.fetch(:flags),
                                :special_slots => special_slots,
                                :exec_seg_base => text&.fileoff.to_i,
                                :exec_seg_limit => text&.filesize.to_i,
                                :exec_seg_flags => exec_seg_flags,
                                :runtime => metadata.fetch(:runtime),
                                :hashes => hashes)
        end
        components.each { |slot, blob| entries[slot] = blob }
        entries[CSSLOT_SIGNATURESLOT] = [CSMAGIC_BLOBWRAPPER, 8].pack("N2")
        entries
      end

      def hash_types
        version = @macho[:LC_VERSION_MIN_MACOSX].first&.version
        build_version = @macho[:LC_BUILD_VERSION].first
        version ||= build_version.minos if build_version&.platform == 1
        version && version < 0x000a0b04 ? [CS_HASHTYPE_SHA1, CS_HASHTYPE_SHA256] : [CS_HASHTYPE_SHA256]
      end

      def update_linkedit_data_command(command, dataoff, datasize)
        format = Utils.specialize_format("L=", @macho.endianness)
        @macho.serialize[command.view.offset + 8, 8] = [dataoff, datasize].pack(format * 2)
      end

      def update_linkedit_segment(segment, final_size)
        filesize = final_size - segment.fileoff
        raise CodeSigningError, "__LINKEDIT extends past the end of the Mach-O" if filesize.negative?
        raise CodeSigningError, "__LINKEDIT exceeds its 32-bit filesize" if @macho.magic32? && filesize > 0xffffffff

        if @macho.magic64?
          format = Utils.specialize_format("Q=", @macho.endianness)
          @macho.serialize[segment.view.offset + 48, 8] = [filesize].pack(format)
          @macho.serialize[segment.view.offset + 32, 8] = [Utils.round(filesize, 2**@macho.segment_alignment)].pack(format) if filesize > segment.vmsize
        else
          format = Utils.specialize_format("L=", @macho.endianness)
          @macho.serialize[segment.view.offset + 36, 4] = [filesize].pack(format)
          @macho.serialize[segment.view.offset + 28, 4] = [Utils.round(filesize, 2**@macho.segment_alignment)].pack(format) if filesize > segment.vmsize
        end
      end
    end

    # Verifies embedded CodeDirectory hashes without modifying the Mach-O.
    # @param macho [MachOFile] the Mach-O slice
    # @param special_data [#call, Hash, nil] external special-slot data
    # @param slice [Integer, nil] fat-Mach-O slice index, used in messages
    # @return [VerificationResult]
    def self.verify(macho, special_data = nil, slice: nil, &block)
      SignatureVerifier.new(macho, special_data || block, :slice => slice).verify
    end

    # Derives the identifier used by Apple's ad-hoc signer for a bare Mach-O.
    # @param macho [MachOFile] a Mach-O slice
    # @param filename [String, nil] its filename
    # @return [String]
    def self.identifier(macho, filename)
      if (match = info_plist(macho)&.match(%r{<key>\s*CFBundleIdentifier\s*</key>\s*<string>\s*([^<]+?)\s*</string>}m))
        return match[1]
      end

      filename = File.basename(filename || "adhoc")
      filename = File.basename(filename, File.extname(filename))
      return filename if filename.include?(".")

      # Apple hex-encodes either "UUID" plus LC_UUID or, for legacy inputs,
      # SHA-1 of the base Mach header and load-command region.
      # https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib/machorep.cpp#L232-L264
      # https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib/signer.cpp#L1025-L1047
      uuid = macho[:LC_UUID].first
      identity = if uuid
        ("UUID".b + uuid.uuid.pack("C*")).unpack1("H*")
      else
        digest = Digest::SHA1.new
        digest << macho.serialize.byteslice(0, Headers::MachHeader.bytesize)
        digest << macho.serialize.byteslice(macho.header.class.bytesize, macho.sizeofcmds)
        digest.hexdigest
      end
      "#{filename}-#{identity}"
    end

    # Returns an embedded Info.plist, if present.
    # @param macho [MachOFile] a Mach-O slice
    # @return [String, nil]
    def self.info_plist(macho)
      section = macho.segments.flat_map(&:sections).find do |candidate|
        candidate.segname == "__TEXT" && candidate.sectname == "__info_plist"
      end
      macho.serialize.byteslice(section.offset, section.size) if section
    end
  end
end
