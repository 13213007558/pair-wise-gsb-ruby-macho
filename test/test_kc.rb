# frozen_string_literal: true

require_relative "helpers"

BOOT_KERNEL_COLLECTION = "/System/Library/KernelCollections/BootKernelExtensions.kc"

if File.exist? BOOT_KERNEL_COLLECTION
  class KextCollectionTests < Minitest::Test
    include Helpers

    def test_load_kc
      MachO.open BOOT_KERNEL_COLLECTION
    end

    def test_navigate_fileset_command
      macho = MachO.open BOOT_KERNEL_COLLECTION

      fileset_entry = macho.command(:LC_FILESET_ENTRY).first
      assert(fileset_entry.segment)
    end

    def test_fileset_entries
      macho = MachO.open BOOT_KERNEL_COLLECTION

      entries = macho.fileset_entries
      refute_empty entries

      entries.each_value do |sub_image|
        assert_kind_of MachO::MachOFile, sub_image
        assert sub_image.fileset_entry?
        assert_same macho.serialize, sub_image.serialize
      end

      entry_id = entries.keys.first
      assert_same entries[entry_id], macho.fileset_entry(entry_id)
    end
  end
end
