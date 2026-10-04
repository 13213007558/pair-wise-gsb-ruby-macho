# frozen_string_literal: true

require "forwardable"

module MachO
  # Represents a Mach-O file, which contains a header and load commands
  # as well as binary executable instructions. Mach-O binaries are
  # architecture specific.
  # @see https://en.wikipedia.org/wiki/Mach-O
  # @see FatFile
  class MachOFile
    extend Forwardable

    # @return [String, nil] the filename loaded from, or nil if loaded from a binary
    #  string
    attr_accessor :filename

    # @return [Hash] any parser options that the instance was created with
    attr_reader :options

    # @return [Symbol] the endianness of the file, :big or :little
    attr_reader :endianness

    # @return [Headers::MachHeader] if the Mach-O is 32-bit
    # @return [Headers::MachHeader64] if the Mach-O is 64-bit
    attr_reader :header

    # @return [Array<LoadCommands::LoadCommand>] an array of the file's load
    #  commands
    # @note load commands are provided in order of ascending offset.
    attr_reader :load_commands

    # @return [Integer] the offset of this Mach-O's header within the raw
    #  data. This is 0 for standalone files, and the entry's file offset
    #  ({LoadCommands::FilesetEntryCommand#fileoff}) for sub-images of an
    #  +MH_FILESET+ container, which share the container's raw data.
    # @see #fileset_entry?
    attr_reader :header_offset

    # Creates a new instance from a binary string.
    # @param bin [String] a binary string containing raw Mach-O data
    # @param opts [Hash] options to control the parser with
    # @option opts [Boolean] :permissive whether to ignore unknown load commands
    # @option opts [Boolean] :decompress whether to decompress, if capable
    # @return [MachOFile] a new MachOFile
    # @note The `:decompress` option relies on non-default dependencies. Compression
    #  is only used in niche Mach-Os, so leaving this disabled is a reasonable default for
    #  virtually all normal uses.
    def self.new_from_bin(bin, **opts)
      instance = allocate
      instance.initialize_from_bin(bin, opts)

      instance
    end

    # Creates a new instance from data read from the given filename.
    # @param filename [String] the Mach-O file to load from
    # @param opts [Hash] options to control the parser with
    # @option opts [Boolean] :permissive whether to ignore unknown load commands
    # @option opts [Boolean] :decompress whether to decompress, if capable
    # @raise [ArgumentError] if the given file does not exist
    # @note The `:decompress` option relies on non-default dependencies. Compression
    #  is only used in niche Mach-Os, so leaving this disabled is a reasonable default for
    #  virtually all normal uses.
    def initialize(filename, **opts)
      raise ArgumentError, "#{filename}: no such file" unless File.file?(filename)

      @filename = filename
      @options = opts
      @header_offset = 0
      File.open(@filename, "rb") do |file|
        @raw_data = file.read(Headers::MachHeader.bytesize)
        @raw_data ||= ""
        populate_mach_header if !opts.fetch(:decompress, false) || !Utils.compressed_magic?(@raw_data.unpack1("N"))
        @raw_data << file.read.to_s
      end
      populate_fields
    end

    # Initializes a new MachOFile instance from a binary string with the given options.
    # @see MachO::MachOFile.new_from_bin
    # @api private
    def initialize_from_bin(bin, opts)
      @filename = nil
      @options = opts
      @raw_data = bin
      @header_offset = 0
      populate_fields
    end

    # Creates a new instance that shares another Mach-O's raw data, with its
    # header located at the given offset within that data. No copy of the
    # shared data is made.
    # @param raw_data [String] the shared raw Mach-O data
    # @param header_offset [Integer] the offset of this Mach-O's header
    #  within +raw_data+
    # @param opts [Hash] options to control the parser with
    # @return [MachOFile] a new MachOFile
    # @api private
    def self.new_from_shared_data(raw_data, header_offset, **opts)
      instance = allocate
      instance.initialize_from_shared_data(raw_data, header_offset, opts)

      instance
    end

    # Initializes a new MachOFile instance from shared raw data with the
    # given options.
    # @see MachO::MachOFile.new_from_shared_data
    # @api private
    def initialize_from_shared_data(raw_data, header_offset, opts)
      @filename = nil
      @options = opts
      @raw_data = raw_data
      @header_offset = header_offset
      populate_fields
    end

    # The file's raw Mach-O data. For a fileset sub-image, this is the
    # container's shared raw data, not a copy (see {#fileset_entry?}).
    # @return [String] the raw Mach-O data
    def serialize
      @raw_data
    end

    # @!method magic
    #  @return (see MachO::Headers::MachHeader#magic)
    # @!method ncmds
    #  @return (see MachO::Headers::MachHeader#ncmds)
    # @!method sizeofcmds
    #  @return (see MachO::Headers::MachHeader#sizeofcmds)
    # @!method flags
    #  @return (see MachO::Headers::MachHeader#flags)
    # @!method object?
    #  @return (see MachO::Headers::MachHeader#object?)
    # @!method executable?
    #  @return (see MachO::Headers::MachHeader#executable?)
    # @!method fvmlib?
    #  @return (see MachO::Headers::MachHeader#fvmlib?)
    # @!method core?
    #  @return (see MachO::Headers::MachHeader#core?)
    # @!method preload?
    #  @return (see MachO::Headers::MachHeader#preload?)
    # @!method dylib?
    #  @return (see MachO::Headers::MachHeader#dylib?)
    # @!method dylinker?
    #  @return (see MachO::Headers::MachHeader#dylinker?)
    # @!method bundle?
    #  @return (see MachO::Headers::MachHeader#bundle?)
    # @!method dsym?
    #  @return (see MachO::Headers::MachHeader#dsym?)
    # @!method kext?
    #  @return (see MachO::Headers::MachHeader#kext?)
    # @!method fileset?
    #  @return (see MachO::Headers::MachHeader#fileset?)
    # @!method magic32?
    #  @return (see MachO::Headers::MachHeader#magic32?)
    # @!method magic64?
    #  @return (see MachO::Headers::MachHeader#magic64?)
    # @!method alignment
    #  @return (see MachO::Headers::MachHeader#alignment)
    def_delegators :header, :magic, :ncmds, :sizeofcmds, :flags, :object?,
                   :executable?, :fvmlib?, :core?, :preload?, :dylib?,
                   :dylinker?, :bundle?, :dsym?, :kext?, :magic32?, :magic64?,
                   :fileset?, :alignment

    # @return [String] a string representation of the file's magic number
    def magic_string
      Headers::MH_MAGICS[magic]
    end

    # @return [Symbol] a string representation of the Mach-O's filetype
    def filetype
      Headers::MH_FILETYPES[header.filetype]
    end

    # @return [Symbol] a symbol representation of the Mach-O's CPU type
    def cputype
      Headers::CPU_TYPES[header.cputype]
    end

    # @return [Symbol] a symbol representation of the Mach-O's CPU subtype
    def cpusubtype
      Headers::CPU_SUBTYPES[header.cputype][header.cpusubtype]
    end

    # All load commands of a given name.
    # @example
    #  file.command("LC_LOAD_DYLIB")
    #  file[:LC_LOAD_DYLIB]
    # @param [String, Symbol] name the load command ID
    # @return [Array<LoadCommands::LoadCommand>] an array of load commands
    #  corresponding to `name`
    def command(name)
      @load_commands_by_type.fetch(name.to_sym, []).dup
    end

    alias [] command

    # Whether this Mach-O is a sub-image of an +MH_FILESET+ container,
    # sharing the container's raw data instead of owning a copy. Sub-images
    # are read-only: modify the container instead.
    # @return [Boolean] true if this Mach-O is a fileset sub-image
    def fileset_entry?
      @header_offset.positive?
    end

    # All fileset entries (sub-images) in this Mach-O, keyed by entry ID.
    #
    # Each sub-image is a {MachOFile} that shares this (container) file's raw
    # data, so the container is never copied. Sub-images support the usual
    # load command and section queries, but are read-only.
    #
    # Offsets in a fileset follow these conventions:
    # * *Header offset*: {#header_offset} is the byte offset of a Mach-O
    #   header within the shared data. It is 0 for the container and equals
    #   +LC_FILESET_ENTRY+'s +fileoff+ for each sub-image.
    # * *File offsets*: segment +fileoff+s, section +offset+s and all other
    #   file offsets stored in a sub-image's load commands are relative to
    #   the beginning of the *container*, not to the sub-image's header, so
    #   they index directly into the shared data.
    # * *VM addresses*: a sub-image's segments map VM addresses to file
    #   offsets exactly as in a standalone Mach-O:
    #   +file_offset = addr - segment.vmaddr + segment.fileoff+, yielding a
    #   container-relative file offset. +LC_FILESET_ENTRY+'s +vmaddr+ is the
    #   VM address of the sub-image's header.
    #
    # @example
    #  kc = MachO::MachOFile.new("BootKernelExtensions.kc")
    #  kc.fileset_entries["com.apple.driver.AppleSSE"].segments
    # @return [Hash{String => MachOFile}] the fileset's sub-images, keyed by
    #  entry ID. Empty if the Mach-O has no +LC_FILESET_ENTRY+ commands.
    # @raise [FilesetEntryError] if an entry is out of bounds, points into
    #  another entry's header, or duplicates another entry's ID
    def fileset_entries
      @fileset_entries ||= populate_fileset_entries
      @fileset_entries.dup
    end

    # The fileset entry (sub-image) with the given entry ID.
    # @param entry_id [String] the entry's ID
    #  ({LoadCommands::FilesetEntryCommand#entry_id})
    # @return [MachOFile, nil] the sub-image, or nil if there is no such entry
    # @see #fileset_entries
    def fileset_entry(entry_id)
      fileset_entries[entry_id.to_s]
    end

    # Inserts a load command at the given offset.
    # @param offset [Integer] the offset to insert at
    # @param lc [LoadCommands::LoadCommand] the load command to insert
    # @param options [Hash]
    # @option options [Boolean] :repopulate (true) whether or not to repopulate
    #  the instance fields
    # @raise [OffsetInsertionError] if the offset is not in the load command region
    # @raise [HeaderPadError] if the new command exceeds the header pad buffer
    # @note Calling this method with an arbitrary offset in the load command region
    # **will leave the object in an inconsistent state**.
    def insert_command(offset, lc, options = {})
      raise ModificationError, "cannot modify a fileset sub-image" if fileset_entry?

      context = LoadCommands::LoadCommand::SerializationContext.context_for(self)
      cmd_raw = lc.serialize(context)
      fileoff = offset + cmd_raw.bytesize

      raise OffsetInsertionError, offset if offset < header.class.bytesize || fileoff > low_fileoff

      new_sizeofcmds = sizeofcmds + cmd_raw.bytesize

      raise HeaderPadError, @filename if header.class.bytesize + new_sizeofcmds > low_fileoff

      # update Mach-O header fields to account for inserted load command
      update_ncmds(ncmds + 1)
      update_sizeofcmds(new_sizeofcmds)

      @raw_data.insert(offset, cmd_raw)
      @raw_data.slice!(header.class.bytesize + new_sizeofcmds, cmd_raw.bytesize)

      populate_fields if options.fetch(:repopulate, true)
    end

    # Replace a load command with another command in the Mach-O, preserving location.
    # @param old_lc [LoadCommands::LoadCommand] the load command being replaced
    # @param new_lc [LoadCommands::LoadCommand] the load command being added
    # @return [void]
    # @raise [HeaderPadError] if the new command exceeds the header pad buffer
    # @see #insert_command
    # @note This is public, but methods like {#dylib_id=} should be preferred.
    def replace_command(old_lc, new_lc)
      context = LoadCommands::LoadCommand::SerializationContext.context_for(self)
      cmd_raw = new_lc.serialize(context)
      new_sizeofcmds = sizeofcmds + cmd_raw.bytesize - old_lc.cmdsize

      raise HeaderPadError, @filename if header.class.bytesize + new_sizeofcmds > low_fileoff

      delete_command(old_lc)
      insert_command(old_lc.view.offset, new_lc)
    end

    # Appends a new load command to the Mach-O.
    # @param lc [LoadCommands::LoadCommand] the load command being added
    # @param options [Hash]
    # @option f [Boolean] :repopulate (true) whether or not to repopulate
    #  the instance fields
    # @return [void]
    # @see #insert_command
    # @note This is public, but methods like {#add_rpath} should be preferred.
    #  Setting `repopulate` to false **will leave the instance in an
    #  inconsistent state** unless {#populate_fields} is called **immediately**
    #  afterwards.
    def add_command(lc, options = {})
      insert_command(header.class.bytesize + sizeofcmds, lc, options)
    end

    # Delete a load command from the Mach-O.
    # @param lc [LoadCommands::LoadCommand] the load command being deleted
    # @param options [Hash]
    # @option options [Boolean] :repopulate (true) whether or not to repopulate
    #  the instance fields
    # @return [void]
    # @note This is public, but methods like {#delete_rpath} should be preferred.
    #  Setting `repopulate` to false **will leave the instance in an
    #  inconsistent state** unless {#populate_fields} is called **immediately**
    #  afterwards.
    def delete_command(lc, options = {})
      raise ModificationError, "cannot modify a fileset sub-image" if fileset_entry?

      @raw_data.slice!(lc.view.offset, lc.cmdsize)

      # update Mach-O header fields to account for deleted load command
      update_ncmds(ncmds - 1)
      update_sizeofcmds(sizeofcmds - lc.cmdsize)

      # pad the space after the load commands to preserve offsets
      @raw_data.insert(header.class.bytesize + sizeofcmds - lc.cmdsize, Utils.nullpad(lc.cmdsize))

      populate_fields if options.fetch(:repopulate, true)
    end

    # Populate the instance's fields with the raw Mach-O data.
    # @return [void]
    # @note This method is public, but should (almost) never need to be called.
    #  The exception to this rule is when methods like {#add_command} and
    #  {#delete_command} have been called with `repopulate = false`.
    def populate_fields
      clear_memoization_cache
      @header = populate_mach_header
      @load_commands = populate_load_commands
    end

    # All load commands responsible for loading dylibs.
    # @return [Array<LoadCommands::DylibCommand>] an array of DylibCommands
    def dylib_load_commands
      @dylib_load_commands ||= load_commands.select { |lc| LoadCommands::DYLIB_LOAD_COMMANDS.include?(lc.type) }
      @dylib_load_commands.dup
    end

    # All segment load commands in the Mach-O.
    # @return [Array<LoadCommands::SegmentCommand>] if the Mach-O is 32-bit
    # @return [Array<LoadCommands::SegmentCommand64>] if the Mach-O is 64-bit
    def segments
      if magic32?
        command(:LC_SEGMENT)
      else
        command(:LC_SEGMENT_64)
      end
    end

    # The segment alignment for the Mach-O. Guesses conservatively.
    # @return [Integer] the alignment, as a power of 2
    # @note This is **not** the same as {#alignment}!
    # @note See `get_align` and `get_align_64` in `cctools/misc/lipo.c`
    def segment_alignment
      @segment_alignment ||= calculate_segment_alignment
    end

    # The Mach-O's dylib ID, or `nil` if not a dylib.
    # @example
    #  file.dylib_id # => 'libBar.dylib'
    # @return [String, nil] the Mach-O's dylib ID
    def dylib_id
      return unless dylib?

      dylib_id_cmd = command(:LC_ID_DYLIB).first

      dylib_id_cmd.name.to_s
    end

    # Changes the Mach-O's dylib ID to `new_id`. Does nothing if not a dylib.
    # @example
    #  file.change_dylib_id("libFoo.dylib")
    # @param new_id [String] the dylib's new ID
    # @param _options [Hash]
    # @return [void]
    # @raise [ArgumentError] if `new_id` is not a String
    # @note `_options` is currently unused and is provided for signature
    #  compatibility with {MachO::FatFile#change_dylib_id}
    def change_dylib_id(new_id, _options = {})
      raise ArgumentError, "new ID must be a String" unless new_id.is_a?(String)
      return unless dylib?

      old_lc = command(:LC_ID_DYLIB).first
      raise DylibIdMissingError unless old_lc

      new_lc = LoadCommands::LoadCommand.create(:LC_ID_DYLIB, new_id,
                                                old_lc.timestamp,
                                                old_lc.current_version,
                                                old_lc.compatibility_version)

      replace_command(old_lc, new_lc)
    end

    alias dylib_id= change_dylib_id

    # All shared libraries linked to the Mach-O.
    # @return [Array<String>] an array of all shared libraries
    def linked_dylibs
      # Some linkers produce multiple `LC_LOAD_DYLIB` load commands for the same
      # library, but at this point we're really only interested in a list of
      # unique libraries this Mach-O file links to, thus: `uniq`. (This is also
      # for consistency with `FatFile` that merges this list across all archs.)
      @linked_dylibs ||= dylib_load_commands.map { |lc| lc.name.to_s }.uniq
      @linked_dylibs.dup
    end

    # Changes the shared library `old_name` to `new_name`
    # @example
    #  file.change_install_name("abc.dylib", "def.dylib")
    # @param old_name [String] the shared library's old name
    # @param new_name [String] the shared library's new name
    # @param _options [Hash]
    # @return [void]
    # @raise [DylibUnknownError] if no shared library has the old name
    # @note `_options` is currently unused and is provided for signature
    #  compatibility with {MachO::FatFile#change_install_name}
    def change_install_name(old_name, new_name, _options = {})
      old_lc = dylib_load_commands.find { |d| d.name.to_s == old_name }
      raise DylibUnknownError, old_name if old_lc.nil?

      args = [new_name, old_lc.timestamp, old_lc.current_version,
              old_lc.compatibility_version]
      args << old_lc.flags if old_lc.is_a?(LoadCommands::DylibUseCommand)
      new_lc = LoadCommands::LoadCommand.create(old_lc.type, *args)

      replace_command(old_lc, new_lc)
    end

    alias change_dylib change_install_name

    # All runtime paths searched by the dynamic linker for the Mach-O.
    # @return [Array<String>] an array of all runtime paths
    def rpaths
      @rpaths ||= command(:LC_RPATH).map { |lc| lc.path.to_s }
      @rpaths.dup
    end

    # Changes the runtime path `old_path` to `new_path`
    # @example
    #  file.change_rpath("/usr/lib", "/usr/local/lib")
    # @param old_path [String] the old runtime path
    # @param new_path [String] the new runtime path
    # @param options [Hash]
    # @option options [Boolean] :uniq (false) if true, change duplicate
    #  rpaths simultaneously.
    # @return [void]
    # @raise [RpathUnknownError] if no such old runtime path exists
    def change_rpath(old_path, new_path, options = {})
      old_lc = command(:LC_RPATH).find { |r| r.path.to_s == old_path }
      raise RpathUnknownError, old_path if old_lc.nil?

      new_lc = LoadCommands::LoadCommand.create(:LC_RPATH, new_path)

      delete_rpath(old_path, options)
      insert_command(old_lc.view.offset, new_lc)
    end

    # Add the given runtime path to the Mach-O.
    # @example
    #  file.rpaths # => ["/lib"]
    #  file.add_rpath("/usr/lib")
    #  file.rpaths # => ["/lib", "/usr/lib"]
    # @param path [String] the new runtime path
    # @param _options [Hash]
    # @return [void]
    # @raise [RpathExistsError] if the runtime path already exists
    # @note `_options` is currently unused and is provided for signature
    #  compatibility with {MachO::FatFile#add_rpath}
    def add_rpath(path, _options = {})
      raise RpathExistsError, path if rpaths.include?(path)

      rpath_cmd = LoadCommands::LoadCommand.create(:LC_RPATH, path)
      add_command(rpath_cmd)
    end

    # Delete the given runtime path from the Mach-O.
    # @example
    #  file1.rpaths # => ["/lib", "/usr/lib", "/lib"]
    #  file1.delete_rpath("/lib")
    #  file1.rpaths # => ["/usr/lib", "/lib"]
    #  file2.rpaths # => ["foo", "foo"]
    #  file2.delete_rpath("foo", :uniq => true)
    #  file2.rpaths # => []
    #  file3.rpaths # => ["foo", "bar", "foo"]
    #  file3.delete_rpath("foo", :last => true)
    #  file3.rpaths # => ["foo", "bar"]
    # @param path [String] the runtime path to delete
    # @param options [Hash]
    # @option options [Boolean] :uniq (false) if true, also delete
    #  duplicates of the requested path. If false, delete the first
    #  instance (by offset) of the requested path, unless :last is true.
    #  Incompatible with :last.
    # @option options [Boolean] :last (false) if true, delete the last
    #  instance (by offset) of the requested path. Incompatible with :uniq.
    # @return void
    # @raise [RpathUnknownError] if no such runtime path exists
    # @raise [ArgumentError] if both :uniq and :last are true
    def delete_rpath(path, options = {})
      uniq = options.fetch(:uniq, false)
      last = options.fetch(:last, false)
      raise ArgumentError, "Cannot set both :uniq and :last to true" if uniq && last

      search_method = uniq || last ? :select : :find
      rpath_cmds = command(:LC_RPATH).public_send(search_method) { |r| r.path.to_s == path }
      rpath_cmds = rpath_cmds.last if last

      # Cast rpath_cmds into an Array so we can handle the uniq and non-uniq cases the same way
      rpath_cmds = Array(rpath_cmds)
      raise RpathUnknownError, path if rpath_cmds.empty?

      # delete the commands in reverse order, offset descending.
      rpath_cmds.reverse_each { |cmd| delete_command(cmd) }
    end

    # Replaces the embedded signature with a pure-Ruby ad-hoc signature.
    # @param identifier [String, nil] the signing identifier
    # @return [void]
    def codesign!(identifier: nil)
      raise ModificationError, "cannot modify a fileset sub-image" if fileset_entry?

      CodeSigning::AdhocSigner.new(self, identifier || CodeSigning.identifier(self, filename)).sign!
    end

    # Write all Mach-O data to the given filename.
    # @param filename [String] the file to write to
    # @return [void]
    def write(filename)
      File.binwrite(filename, @raw_data)
    end

    # Write all Mach-O data to the file used to initialize the instance.
    # @return [void]
    # @raise [MachOError] if the instance was initialized without a file
    # @note Overwrites all data in the file!
    def write!
      raise MachOError, "no initial file to write to" if @filename.nil?

      File.binwrite(@filename, @raw_data)
    end

    # @return [Hash] a hash representation of this {MachOFile}
    def to_h
      {
        "header" => header.to_h,
        "load_commands" => load_commands.map(&:to_h),
      }
    end

    private

    # Clears all memoized values. Called when the file is repopulated.
    # @return [void]
    # @api private
    def clear_memoization_cache
      @linked_dylibs = nil
      @rpaths = nil
      @dylib_load_commands = nil
      @load_commands_by_type = nil
      @segment_alignment = nil
      @fileset_entries = nil
    end

    # The file's Mach-O header structure.
    # @return [Headers::MachHeader] if the Mach-O is 32-bit
    # @return [Headers::MachHeader64] if the Mach-O is 64-bit
    # @raise [TruncatedFileError] if the file is too small to have a valid header
    # @api private
    def populate_mach_header
      # the smallest Mach-O header is 28 bytes
      raise TruncatedFileError if @raw_data.size - @header_offset < 28

      magic = @raw_data[@header_offset, 4].unpack1("N")
      populate_prelinked_kernel_header if Utils.compressed_magic?(magic)

      magic = populate_and_check_magic
      mh_klass = Utils.magic32?(magic) ? Headers::MachHeader : Headers::MachHeader64
      mh = mh_klass.new_from_bin(endianness, @raw_data[@header_offset, mh_klass.bytesize])

      check_cputype(mh.cputype)
      check_cpusubtype(mh.cputype, mh.cpusubtype)
      check_filetype(mh.filetype)

      mh
    end

    # Read a compressed Mach-O header and check its validity, as well as whether we're able
    # to parse it.
    # @return [void]
    # @raise [CompressedMachOError] if we weren't asked to perform decompression
    # @raise [DecompressionError] if decompression is impossible or fails
    # @api private
    def populate_prelinked_kernel_header
      raise CompressedMachOError unless options.fetch(:decompress, false)

      @plh = Headers::PrelinkedKernelHeader.new_from_bin :big, @raw_data[@header_offset, Headers::PrelinkedKernelHeader.bytesize]

      raise DecompressionError, "unsupported compression type: LZSS" if @plh.lzss?
      raise DecompressionError, "unknown compression type: 0x#{plh.compress_type.to_s 16}" unless @plh.lzvn?

      decompress_macho_lzvn
    end

    # Attempt to decompress a Mach-O file from the data specified in a prelinked kernel header.
    # @return [void]
    # @raise [DecompressionError] if decompression is impossible or fails
    # @api private
    # @note This method rewrites the internal state of {MachOFile} to pretend as if it was never
    #  compressed to begin with, allowing all other APIs to transparently act on compressed Mach-Os.
    def decompress_macho_lzvn
      begin
        require "lzfse"
      rescue LoadError
        raise DecompressionError, "LZVN required but the optional 'lzfse' gem is not installed"
      end

      # From this point onwards, the internal buffer of this MachOFile refers to the decompressed
      # contents specified by the prelinked kernel header.
      begin
        @raw_data = LZFSE.lzvn_decompress @raw_data.slice(@header_offset + Headers::PrelinkedKernelHeader.bytesize, @plh.compressed_size)
        @header_offset = 0
        # Sanity checks.
        raise DecompressionError if @raw_data.size != @plh.uncompressed_size
        # TODO: check the adler32 CRC in @plh
      rescue LZFSE::DecodeError
        raise DecompressionError, "LZVN decompression failed"
      end
    end

    # Read just the file's magic number and check its validity.
    # @return [Integer] the magic
    # @raise [MagicError] if the magic is not valid Mach-O magic
    # @raise [FatBinaryError] if the magic is for a Fat file
    # @api private
    def populate_and_check_magic
      magic = @raw_data[@header_offset, 4].unpack1("N")

      raise MagicError, magic unless Utils.magic?(magic)
      raise FatBinaryError if Utils.fat_magic?(magic)

      @endianness = Utils.little_magic?(magic) ? :little : :big

      magic
    end

    # Check the file's CPU type.
    # @param cputype [Integer] the CPU type
    # @raise [CPUTypeError] if the CPU type is unknown
    # @api private
    def check_cputype(cputype)
      raise CPUTypeError, cputype unless Headers::CPU_TYPES.key?(cputype)
    end

    # Check the file's CPU type/subtype pair.
    # @param cpusubtype [Integer] the CPU subtype
    # @raise [CPUSubtypeError] if the CPU sub-type is unknown
    # @api private
    def check_cpusubtype(cputype, cpusubtype)
      # Only check sub-type w/o capability bits (see `populate_mach_header`).
      raise CPUSubtypeError.new(cputype, cpusubtype) unless Headers::CPU_SUBTYPES[cputype].key?(cpusubtype)
    end

    # Check the file's type.
    # @param filetype [Integer] the file type
    # @raise [FiletypeError] if the file type is unknown
    # @api private
    def check_filetype(filetype)
      raise FiletypeError, filetype unless Headers::MH_FILETYPES.key?(filetype)
    end

    # All load commands in the file.
    # @return [Array<LoadCommands::LoadCommand>] an array of load commands
    # @raise [TruncatedFileError] if the declared load command data is incomplete
    # @raise [LoadCommandError] if an unknown load command is encountered
    # @raise [LoadCommandSizeError] if a load command's size is invalid
    # @api private
    def populate_load_commands
      permissive = options.fetch(:permissive, false)
      offset = @header_offset + header.class.bytesize
      load_commands_end = offset + sizeofcmds
      raise TruncatedFileError if load_commands_end > @raw_data.bytesize

      load_commands = []
      @load_commands_by_type = Hash.new { |h, k| h[k] = [] }

      header.ncmds.times do
        raise TruncatedFileError if offset + LoadCommands::LoadCommand.bytesize > load_commands_end

        fmt = Utils.specialize_format("L=", endianness)
        cmd = @raw_data.slice(offset, 4).unpack1(fmt)
        cmdsize = @raw_data.slice(offset + 4, 4).unpack1(fmt)
        raise LoadCommandSizeError, cmdsize if cmdsize % 4 != 0 || offset + cmdsize > load_commands_end

        cmd_sym = LoadCommands::LOAD_COMMANDS[cmd]

        raise LoadCommandError, cmd unless cmd_sym || permissive

        # If we're here, then either cmd_sym represents a valid load
        # command *or* we're in permissive mode.
        klass = if (klass_str = LoadCommands::LC_STRUCTURES[cmd_sym])
          LoadCommands.const_get klass_str
        else
          LoadCommands::LoadCommand
        end

        raise LoadCommandSizeError, cmdsize if cmdsize < klass.bytesize

        view = MachOView.new(self, @raw_data, endianness, offset)
        command = klass.new_from_bin(view)

        load_commands << command
        @load_commands_by_type[command.type] << command
        offset += command.cmdsize
      end

      load_commands
    end

    # All fileset entries in the file, keyed by entry ID.
    # @return [Hash{String => MachOFile}] the fileset's sub-images by entry ID
    # @raise [FilesetEntryError] if an entry is out of bounds, points into
    #  another entry's header, or duplicates another entry's ID
    # @api private
    def populate_fileset_entries
      entries = {}
      entry_commands = command(:LC_FILESET_ENTRY)
      return entries if entry_commands.empty?

      # Header regions that no entry may point into: the container's own
      # header and load commands, then each validated entry's.
      header_regions = [(0...(header.class.bytesize + sizeofcmds))]

      entry_commands.sort_by(&:fileoff).each do |cmd|
        entry_id = cmd.entry_id.to_s
        raise FilesetEntryError, "duplicate fileset entry ID: #{entry_id}" if entries.key?(entry_id)

        entry_offset = cmd.fileoff
        if entry_offset + Headers::MachHeader.bytesize > @raw_data.bytesize
          raise FilesetEntryError, "fileset entry #{entry_id} is out of bounds: " \
                                   "header offset 0x#{entry_offset.to_s(16)}, " \
                                   "file size 0x#{@raw_data.bytesize.to_s(16)}"
        end

        if (region = header_regions.find { |r| r.cover?(entry_offset) })
          raise FilesetEntryError, "fileset entry #{entry_id} header offset " \
                                   "0x#{entry_offset.to_s(16)} falls within another " \
                                   "header region: 0x#{region.begin.to_s(16)}..0x#{region.end.to_s(16)}"
        end

        sub_image = begin
          MachOFile.new_from_shared_data(@raw_data, entry_offset, **options)
        rescue MachOError => e
          raise FilesetEntryError, "invalid fileset entry #{entry_id} at header offset " \
                                   "0x#{entry_offset.to_s(16)}: #{e.message}"
        end

        header_regions << (entry_offset...(entry_offset + sub_image.header.class.bytesize + sub_image.sizeofcmds))
        entries[entry_id] = sub_image
      end

      entries
    end

    # Calculate the segment alignment for the Mach-O. Guesses conservatively.
    # @return [Integer] the alignment, as a power of 2
    # @api private
    def calculate_segment_alignment
      # special cases: 12 for x86/64/PPC/PP64, 14 for ARM/ARM64
      return 12 if %i[i386 x86_64 ppc ppc64].include?(cputype)
      return 14 if %i[arm arm64].include?(cputype)

      cur_align = Sections::MAX_SECT_ALIGN

      segments.each do |segment|
        if filetype == :object
          # start with the smallest alignment, and work our way up
          align = magic32? ? 2 : 3
          segment.sections.each do |section|
            align = section.align unless section.align <= align
          end
        else
          align = segment.guess_align
        end
        cur_align = align if align < cur_align
      end

      cur_align
    end

    # The low file offset (offset to first section data).
    # @return [Integer] the offset
    # @api private
    def low_fileoff
      offset = @raw_data.size

      segments.each do |seg|
        offset = seg.fileoff if seg.nsects.zero? && seg.fileoff.positive? &&
                                seg.filesize.positive? && seg.fileoff < offset

        seg.sections.each do |sect|
          next if sect.empty?
          next if sect.type?(:S_ZEROFILL)
          next if sect.type?(:S_THREAD_LOCAL_ZEROFILL)
          next unless sect.offset < offset

          offset = sect.offset
        end
      end

      offset
    end

    # Updates the number of load commands in the raw data.
    # @param ncmds [Integer] the new number of commands
    # @return [void]
    # @api private
    def update_ncmds(ncmds)
      fmt = Utils.specialize_format("L=", endianness)
      ncmds_raw = [ncmds].pack(fmt)
      @raw_data[@header_offset + 16, 4] = ncmds_raw
    end

    # Updates the size of all load commands in the raw data.
    # @param size [Integer] the new size, in bytes
    # @return [void]
    # @api private
    def update_sizeofcmds(size)
      fmt = Utils.specialize_format("L=", endianness)
      size_raw = [size].pack(fmt)
      @raw_data[@header_offset + 20, 4] = size_raw
    end
  end
end
