ruby-macho
================

[![Gem Version](https://badge.fury.io/rb/ruby-macho.svg)](https://badge.fury.io/rb/ruby-macho)
[![CI](https://github.com/Homebrew/ruby-macho/actions/workflows/tests.yml/badge.svg)](https://github.com/Homebrew/ruby-macho/actions/workflows/tests.yml)
[![Coverage Status](https://codecov.io/gh/Homebrew/ruby-macho/branch/main/graph/badge.svg)](https://codecov.io/gh/Homebrew/ruby-macho)

A Ruby library for examining and modifying Mach-O files.

### What is a Mach-O file?

The [Mach-O file format](https://en.wikipedia.org/wiki/Mach-O) is used by macOS
and iOS (among others) as a general purpose binary format for object files,
executables, dynamic libraries, and so forth.

### Installation

ruby-macho can be installed via RubyGems:

```bash
$ gem install ruby-macho
```

### Documentation

Full documentation is available on [RubyDoc](https://www.rubydoc.info/gems/ruby-macho/).

A quick example of what ruby-macho can do:

```ruby
require 'macho'

file = MachO::MachOFile.new("/path/to/my/binary")

# get the file's type (object, dynamic lib, executable, etc)
file.filetype # => :execute

# get all load commands in the file and print their offsets:
file.load_commands.each do |lc|
  puts "#{lc.type}: offset #{lc.offset}, size: #{lc.cmdsize}"
end

# access a specific load command
lc_vers = file[:LC_VERSION_MIN_MACOSX].first
puts lc_vers.version_string # => "10.10.0"
```

### Ad-hoc code signing

Changing a Mach-O load command invalidates any existing code signature. This is
especially important when Homebrew pours bottles on Apple Silicon, where native
code must remain signed after its paths are rewritten. `MachO.codesign!` creates
the required ad-hoc signature in Ruby instead of invoking `/usr/bin/codesign`:

```ruby
MachO.codesign!("/path/to/my/binary")
```

### Filesets (MH_FILESET)

`MH_FILESET` files (such as kernel collections) bundle several Mach-O
sub-images into one container. Each sub-image is described by an
`LC_FILESET_ENTRY` load command and can be accessed by its entry ID:

```ruby
file = MachO::MachOFile.new("/path/to/BootKernelExtensions.kc")
file.fileset? # => true

# all sub-images, keyed by entry ID:
file.fileset_entries # => { "com.apple.driver.AppleSSE" => #<MachO::MachOFile>, ... }

# a single sub-image; load command and section queries work as usual:
kext = file.fileset_entry("com.apple.driver.AppleSSE")
kext.load_commands.each { |lc| puts lc.type }
kext.segments.first.sections
```

Sub-images share the container's raw data instead of copying it, and are
read-only. Offsets in a fileset follow these conventions:

* **Header offset** (`MachOFile#header_offset`): the byte offset of a Mach-O
  header within the shared data. It is 0 for standalone files and containers,
  and equals the entry's `LC_FILESET_ENTRY` `fileoff` for sub-images.
* **File offsets**: segment `fileoff`s, section `offset`s and all other file
  offsets stored in a sub-image's load commands are relative to the
  *beginning of the container*, not to the sub-image's header, so they index
  directly into the shared data.
* **VM addresses**: a sub-image's segments map VM addresses to file offsets
  exactly as in a standalone Mach-O: `file_offset = addr - segment.vmaddr +
  segment.fileoff`, yielding a container-relative file offset. The entry's
  `LC_FILESET_ENTRY` `vmaddr` is the VM address of the sub-image's header.


### What works?

* Reading data from x86/x86_64/arm64/PPC Mach-O files (other architectures are unsupported, but may work)
* Changing the IDs of Mach-O and Fat dylibs
* Changing install names in Mach-O and Fat files
* Adding, deleting, and modifying rpaths.
* Parsing embedded code signatures and applying ad-hoc signatures in pure Ruby.

### Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for repository setup, checks, fixture
guidance, and the contribution process.

### Attribution

* Constants were taken from Apple, Inc's
[`loader.h` in `cctools/include/mach-o`](https://opensource.apple.com/source/cctools/cctools-973.0.1/include/mach-o/loader.h.auto.html).
(Apple Public Source License 2.0).
* Code-signing constants and structures follow Apple, Inc's
[`cs_blobs.h` in XNU](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h).
* Binary files used for testing were taken from The LLVM Project. ([Apache License v2.0 with LLVM Exceptions](test/bin/llvm/LICENSE.txt)).

### License

`ruby-macho` is licensed under the MIT License.

For the exact terms, see the [license](LICENSE) file.
