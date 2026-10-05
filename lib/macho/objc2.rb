# frozen_string_literal: true

module MachO
  # Offline Objective-C 2.0 metadata browsing.
  #
  # This module reads the objc2 metadata sections (`__objc_classlist`,
  # `__objc_catlist` and `__objc_protolist`) of an unencrypted 64-bit Mach-O
  # fixed image and produces a serializable relation graph of classes,
  # metaclasses, categories, protocols and methods. It never loads or
  # executes the Objective-C runtime: every pointer is resolved through a
  # caller-provided mapper, so the image is treated as pure data.
  module ObjC2
    # Graph format identifier emitted as the `"format"` key.
    GRAPH_FORMAT = "macho-objc2-graph/1"

    # Mask applied to the class data pointer to strip FAST_DATA flag bits.
    FAST_DATA_MASK = 0x0000_7fff_ffff_fff8

    # `class_ro_t` flag marking a metaclass.
    RO_META = 0x1

    # Upper bound for list counts read from untrusted metadata.
    MAX_LIST_COUNT = 1 << 20

    # Upper bound for C strings read from untrusted metadata.
    MAX_CSTRING_LENGTH = 65_536

    # Browses the objc2 metadata of an unencrypted 64-bit Mach-O file.
    # @param macho [MachO::MachOFile] the Mach-O to browse
    # @return [Hash] a serializable relation graph (see {Extractor#extract})
    # @raise [ObjC2Error] if the file is not a 64-bit Mach-O or is encrypted
    def self.browse(macho)
      raise ObjC2Error, "expected a MachO::MachOFile" unless macho.is_a?(MachOFile)
      raise ObjC2Error, "only 64-bit Mach-O images can be browsed" unless macho.magic64?

      cryptids = (macho[:LC_ENCRYPTION_INFO] + macho[:LC_ENCRYPTION_INFO_64]).map(&:cryptid)
      if cryptids.any? { |cryptid| cryptid != 0 }
        raise ObjC2Error, "cannot browse objc2 metadata of an encrypted Mach-O"
      end

      sections = {}
      macho.segments.each do |segment|
        segment.sections.each do |section|
          key = case section.section_name
          when "__objc_classlist" then :classlist
          when "__objc_catlist" then :catlist
          when "__objc_protolist" then :protolist
          end
          sections[key] ||= [section.addr, section.size] if key
        end
      end

      extract(:data => macho.serialize, :mapper => SegmentMapper.new(macho), **sections)
    end

    # Extracts objc2 metadata from a fixed 64-bit file image.
    # @param data [String] the raw file bytes
    # @param mapper [#call] maps a vmaddr to a file offset (Integer) or nil
    #   when the address is not mapped
    # @param classlist [Array(Integer, Integer), nil] vmaddr and byte size of
    #   the `__objc_classlist` pointer section
    # @param catlist [Array(Integer, Integer), nil] vmaddr and byte size of
    #   the `__objc_catlist` pointer section
    # @param protolist [Array(Integer, Integer), nil] vmaddr and byte size of
    #   the `__objc_protolist` pointer section
    # @return [Hash] a serializable relation graph
    def self.extract(data:, mapper:, classlist: nil, catlist: nil, protolist: nil)
      extractor = Extractor.new(data, mapper)
      extractor.extract(:classlist => classlist, :catlist => catlist, :protolist => protolist)
    end
  end
end

require_relative "objc2/reader"
require_relative "objc2/segment_mapper"
require_relative "objc2/extractor"

