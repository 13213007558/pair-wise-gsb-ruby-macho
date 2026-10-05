# frozen_string_literal: true

require "digest/sha1"
require "digest/sha2"

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
    CSSLOT_ENTITLEMENTS = 5
    CSSLOT_DER_ENTITLEMENTS = 7
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
    SCATTER_ENTRY_SIZE = 24
    PRESERVED_COMPONENT_SLOTS = [
      CSSLOT_REQUIREMENTS,
      CSSLOT_ENTITLEMENTS,
      CSSLOT_DER_ENTITLEMENTS,
    ].freeze

    CSSLOT_DESCRIPTIONS = {
      CSSLOT_INFOSLOT => "Info.plist",
      CSSLOT_REQUIREMENTS => "requirements",
      CSSLOT_ENTITLEMENTS => "entitlements",
      CSSLOT_DER_ENTITLEMENTS => "DER entitlements",
    }.freeze

    HASHES = {
      CS_HASHTYPE_SHA1 => [Digest::SHA1, 20],
      CS_HASHTYPE_SHA256 => [Digest::SHA256, 32],
    }.freeze

    # An entry in a code-signing SuperBlob index.
    BlobIndex = Struct.new(:type, :offset)

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

        @identifier = serialize.byteslice(ident_offset, terminator - ident_offset)
      end

      # @return [String] the signing identifier
      attr_reader :identifier

      # @return [Integer] the number of signed bytes
      def code_limit
        version >= CS_SUPPORTSCODELIMIT64 && code_limit64&.positive? ? code_limit64 : @code_limit
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

    # The outcome of verifying a signed Mach-O against its embedded
    # CodeDirectories. A valid report only means the content digests match;
    # it says nothing about whether the signer is trusted by the system.
    class VerificationReport
      # @return [Array<CodeDirectoryVerification>] per-CodeDirectory results
      attr_reader :results

      # @param results [Array<CodeDirectoryVerification>]
      def initialize(results)
        @results = results.freeze
      end

      # @return [Symbol] :ok, :mismatch or :unverifiable
      def status
        return :mismatch if results.any? { |result| result.status == :mismatch }
        return :unverifiable if results.any? { |result| result.status == :unverifiable }

        :ok
      end

      # Whether every embedded CodeDirectory matches the file bytes.
      # @return [Boolean]
      def valid?
        status == :ok
      end
      alias content_valid? valid?

      # Whether the signer is trusted by the system. Certificate trust-chain
      # verification is not performed, so this is always false; ad-hoc
      # signatures have no identity to trust in the first place.
      # @return [Boolean]
      def signer_trusted?
        false
      end

      # @return [Symbol] always :not_evaluated; no trust-chain verification is performed
      def trust_status
        :not_evaluated
      end

      # @return [Boolean] whether any CodeDirectory carries the ad-hoc flag
      def adhoc?
        results.any? { |result| result.flags.anybits?(CS_ADHOC) }
      end

      # @return [Array<CodeDirectoryVerification::Mismatch>] all digest mismatches
      def mismatches
        results.flat_map(&:mismatches)
      end

      # @return [Array<CodeDirectoryVerification::Problem>] all verification problems
      def problems
        results.flat_map(&:problems)
      end

      # @return [Hash] a hash representation of this report
      def to_h
        {
          "status" => status,
          "valid" => valid?,
          "content_valid" => content_valid?,
          "signer_trusted" => signer_trusted?,
          "trust_status" => trust_status,
          "adhoc" => adhoc?,
          "results" => results.map(&:to_h),
        }
      end
    end

    # The outcome of verifying a single embedded CodeDirectory.
    class CodeDirectoryVerification
      # A file region or special slot whose digest differs from the CodeDirectory.
      Mismatch = Struct.new(:kind, :slot, :offset, :length, :expected, :actual) do
        # @return [Hash] a hash representation of this mismatch
        def to_h
          {
            "kind" => kind,
            "slot" => slot,
            "offset" => offset,
            "length" => length,
            "expected" => expected.unpack1("H*"),
            "actual" => actual.unpack1("H*"),
          }
        end
      end

      # A condition that prevents (complete) verification, reported with a
      # distinct code: :unsupported_hash_type, :overlapping_ranges,
      # :missing_data, :missing_special_slot_data or :invalid_scatter_vector.
      Problem = Struct.new(:code, :message, :details) do
        # @return [Hash] a hash representation of this problem
        def to_h
          {
            "code" => code,
            "message" => message,
            "details" => details.transform_keys(&:to_s),
          }
        end
      end

      # @return [Integer] the SuperBlob slot of the CodeDirectory
      attr_reader :slot

      # @return [Integer] the CodeDirectory hash type
      attr_reader :hash_type

      # @return [Integer] the CodeDirectory flags
      attr_reader :flags

      # @return [Array<Mismatch>] digest mismatches found so far
      attr_reader :mismatches

      # @return [Array<Problem>] verification problems found so far
      attr_reader :problems

      # @param slot [Integer] the SuperBlob slot of the CodeDirectory
      # @param hash_type [Integer] the CodeDirectory hash type
      # @param flags [Integer] the CodeDirectory flags
      def initialize(slot, hash_type, flags)
        @slot = slot
        @hash_type = hash_type
        @flags = flags
        @mismatches = []
        @problems = []
      end

      # @return [Symbol] :ok, :mismatch or :unverifiable
      def status
        return :mismatch unless mismatches.empty?
        return :unverifiable unless problems.empty?

        :ok
      end

      # @return [Boolean] whether the CodeDirectory fully matches the file bytes
      def valid?
        status == :ok
      end

      # @return [Hash] a hash representation of this result
      def to_h
        {
          "slot" => slot,
          "hash_type" => hash_type,
          "status" => status,
          "mismatches" => mismatches.map(&:to_h),
          "problems" => problems.map(&:to_h),
        }
      end
    end

    # Checks file bytes against the hashes embedded in a CodeDirectory.
    # @api private
    class Verifier
      # @param data [String] the complete Mach-O bytes
      # @param superblob [SuperBlob] the embedded signature
      # @param provider [#call] callback returning external special-slot data
      def initialize(data, superblob, provider)
        @data = data
        @superblob = superblob
        @provider = provider
      end

      # Verifies the primary and every alternate CodeDirectory.
      # @return [VerificationReport]
      def verify
        results = []
        @superblob.indices.each_with_index do |index, position|
          blob = @superblob.blobs[position]
          next unless blob.is_a?(CodeDirectory)
          next unless index.type == CSSLOT_CODEDIRECTORY ||
                      (index.type >= CSSLOT_ALTERNATE_CODEDIRECTORIES && index.type < CSSLOT_SIGNATURESLOT)

          results << verify_code_directory(blob, index.type)
        end
        raise CodeSigningError, "embedded signature contains no CodeDirectory" if results.empty?

        VerificationReport.new(results)
      end

      private

      def verify_code_directory(code_directory, slot)
        result = CodeDirectoryVerification.new(slot, code_directory.hash_type, code_directory.flags)
        hash_info = HASHES[code_directory.hash_type]
        if hash_info.nil? || hash_info.last != code_directory.hash_size
          result.problems << problem(
            :unsupported_hash_type,
            "unsupported CodeDirectory hash type #{code_directory.hash_type} " +              "(hash size #{code_directory.hash_size})",
            :hash_type => code_directory.hash_type, :hash_size => code_directory.hash_size
          )
          return result
        end

        digest = hash_info.first
        page_size = 1 << code_directory.page_size
        code_limit = code_directory.code_limit
        if code_limit > @data.bytesize
          result.problems << problem(
            :missing_data,
            "signed range is #{code_limit} bytes but only #{@data.bytesize} bytes are available",
            :code_limit => code_limit, :available => @data.bytesize
          )
        end

        slots = page_map(code_directory, page_size, code_limit, result)
        report_overlaps(slots, page_size, code_limit, result)
        report_gaps(slots, page_size, code_limit, result)
        verify_code_slots(code_directory, slots, page_size, code_limit, digest, result)
        verify_special_slots(code_directory, digest, result)
        result
      end

      # Maps code slots to file offsets, following the scatter vector when one
      # is present instead of assuming contiguous pages.
      def page_map(code_directory, page_size, code_limit, result)
        if code_directory.scatter_offset.to_i.zero?
          return (0...code_directory.n_code_slots).to_h { |slot| [slot, slot * page_size] }
        end

        map = {}
        offset = code_directory.scatter_offset
        blob = code_directory.serialize
        loop do
          if offset + SCATTER_ENTRY_SIZE > blob.bytesize
            result.problems << problem(:missing_data, "scatter vector is truncated", :offset => offset)
            break
          end

          count, base, target_offset, = blob.unpack("N2Q>2", :offset => offset)
          break if count.zero?

          count.times do |index|
            slot = base + index
            target = target_offset + (index * page_size)
            if slot >= code_directory.n_code_slots || target >= code_limit
              result.problems << problem(
                :invalid_scatter_vector,
                "scatter vector maps slot #{slot} to out-of-range target #{target}",
                :slot => slot, :target => target
              )
              next
            end
            if map.key?(slot)
              result.problems << problem(
                :overlapping_ranges, "slot #{slot} is mapped more than once", :slot => slot
              )
              next
            end
            map[slot] = target
          end
          offset += SCATTER_ENTRY_SIZE
        end
        map
      end

      def report_overlaps(slots, page_size, code_limit, result)
        ranges = slots.map do |slot, offset|
          [offset, offset + chunk_length(offset, page_size, code_limit), slot]
        end.sort
        ranges.each_cons(2) do |(_, finish, slot), (start, _, other)|
          next if start >= finish

          result.problems << problem(
            :overlapping_ranges,
            "slots #{slot} and #{other} map overlapping file ranges",
            :slot => slot, :other_slot => other, :offset => start
          )
        end
      end

      def report_gaps(slots, page_size, code_limit, result)
        covered = 0
        ranges = slots.map { |_, offset| [offset, offset + chunk_length(offset, page_size, code_limit)] }.sort
        ranges.each do |start, finish|
          next if finish <= covered

          if start > covered
            result.problems << problem(
              :missing_data,
              "signed range #{covered}...#{start} is not covered by any hash slot",
              :offset => covered, :length => start - covered
            )
          end
          covered = finish
        end
        return if covered >= code_limit

        result.problems << problem(
          :missing_data,
          "signed range #{covered}...#{code_limit} is not covered by any hash slot",
          :offset => covered, :length => code_limit - covered
        )
      end

      def verify_code_slots(code_directory, slots, page_size, code_limit, digest, result)
        slots.sort.each do |slot, offset|
          expected = code_directory.code_hash(slot)
          if expected.nil?
            result.problems << problem(:invalid_scatter_vector, "slot #{slot} has no hash", :slot => slot)
            next
          end

          length = chunk_length(offset, page_size, code_limit)
          if offset + length > @data.bytesize
            result.problems << problem(
              :missing_data,
              "slot #{slot} needs #{length} bytes at offset #{offset} but the data ends at #{@data.bytesize}",
              :slot => slot, :offset => offset, :length => length
            )
            next
          end

          actual = digest.digest(@data.byteslice(offset, length))
          next if actual == expected

          result.mismatches << CodeDirectoryVerification::Mismatch.new(:code, slot, offset, length, expected, actual)
        end
      end

      def verify_special_slots(code_directory, digest, result)
        1.upto(code_directory.n_special_slots) do |slot|
          expected = code_directory.special_hash(slot)
          next if expected.nil?

          content = @superblob.blob(slot)&.serialize
          content ||= @provider.call(slot)
          if content.nil?
            # A zeroed hash slot means the component is intentionally absent.
            next if expected.bytes.all?(&:zero?)

            result.problems << problem(
              :missing_special_slot_data,
              "special slot #{slot}#{slot_description(slot)} is not part of the signature; " +                "pass its data to verify it",
              :slot => slot
            )
            next
          end

          actual = digest.digest(content)
          next if actual == expected

          result.mismatches << CodeDirectoryVerification::Mismatch.new(:special, slot, nil, content.bytesize, expected, actual)
        end
      end

      def chunk_length(offset, page_size, code_limit)
        [page_size, code_limit - offset].min
      end

      def slot_description(slot)
        CSSLOT_DESCRIPTIONS.key?(slot) ? " (#{CSSLOT_DESCRIPTIONS[slot]})" : ""
      end

      def problem(code, message, details)
        CodeDirectoryVerification::Problem.new(code, message, details)
      end
    end

    # Verifies that the bytes of a signed Mach-O still match its embedded
    # CodeDirectory hashes. This is a read-only operation covering normal
    # pages, the trailing partial page, special slots and alternate
    # CodeDirectories.
    #
    # Special slots whose contents are not carried inside the signature blob
    # (such as the Info.plist slot) can only be checked when their data is
    # supplied through the special_slots keyword (a Hash keyed by slot number,
    # or a callable receiving the slot number) or the block; otherwise they
    # are reported as unverifiable.
    #
    # Note that a valid report only means the content digests match; whether
    # the signer is trusted by the system is never evaluated.
    #
    # @param source [MachOFile, String] a Mach-O or its raw bytes
    # @param special_slots [Hash<Integer, String>, #call, nil] external special-slot data
    # @yield [slot] optional callback returning external special-slot data
    # @return [VerificationReport]
    # @raise [CodeSigningError] if the Mach-O is not signed
    def self.verify(source, special_slots: nil, &block)
      macho = case source
      when MachOFile then source
      when String then MachOFile.new_from_bin(source)
      else raise ArgumentError, "cannot verify #{source.class}"
      end
      commands = macho[:LC_CODE_SIGNATURE]
      raise CodeSigningError, "Mach-O is not signed" if commands.empty?
      raise CodeSigningError, "Mach-O contains multiple LC_CODE_SIGNATURE commands" if commands.size > 1

      Verifier.new(macho.serialize, commands.first.superblob, special_slot_provider(special_slots, block)).verify
    end

    # @api private
    def self.special_slot_provider(special_slots, block)
      sources = [special_slots, block].compact
      lambda do |slot|
        sources.each do |source|
          data = source.respond_to?(:call) ? source.call(slot) : source[slot]
          return data if data
        end
        nil
      end
    end
    private_class_method :special_slot_provider

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
