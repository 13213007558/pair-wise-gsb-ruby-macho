# frozen_string_literal: true

module MachO
  module ObjC2
    # Maps vmaddrs of a fixed (unslid) 64-bit file image to file offsets
    # using the Mach-O's segment load commands.
    class SegmentMapper
      # @param macho [MachO::MachOFile] the Mach-O whose segments are mapped
      def initialize(macho)
        @ranges = macho.segments.map do |segment|
          [segment.vmaddr, segment.filesize, segment.fileoff]
        end
      end

      # @param vmaddr [Integer] the virtual address to resolve
      # @return [Integer, nil] the file offset, or nil if unmapped
      def call(vmaddr)
        @ranges.each do |segment_vmaddr, filesize, fileoff|
          next if filesize.zero?
          next if vmaddr < segment_vmaddr || vmaddr >= segment_vmaddr + filesize

          return fileoff + (vmaddr - segment_vmaddr)
        end

        nil
      end
    end
  end
end

