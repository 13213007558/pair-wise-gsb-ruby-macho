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

### Filesets (`MH_FILESET`)

Mach-O filesets (such as kernel collections) embed several Mach-Os in one
container, each described by an `LC_FILESET_ENTRY` load command. Entries can
be looked up by their entry ID and examined like standalone Mach-Os:

```ruby
file = MachO::MachOFile.new("/System/Library/KernelCollections/BootKernelExtensions.kc")
file.fileset? # => true
file.fileset_entries.keys # => ["com.apple.kpi.mach", ...]

entry = file.fileset_entry("com.apple.kpi.mach")
entry.load_commands # works as usual
entry.segments.first.sections # so do section queries
```

Entry objects are read-only views that share the container's data buffer —
the container is never copied — so serialization and modifying methods raise
`MachO::MachOError` on them.

Offset conventions:

* The *header offset* of an entry is the file offset of the entry's own
  Mach-O header within the container's data. It is declared by the entry's
  `LC_FILESET_ENTRY` command (`fileoff`) and exposed as `entry.view_offset`.
* *File offsets* recorded in an entry's own load commands and sections are
  relative to the entry's header, exactly as if the entry were a standalone
  Mach-O. Add `entry.view_offset` to obtain a container-absolute file offset.
  Offsets exposed through `MachO::MachOView` (for example, load command
  views) are already container-absolute, since the entry shares the
  container's data buffer.
* *VM addresses* are taken as recorded: `LC_FILESET_ENTRY`'s `vmaddr` is the
  address at which the entry is mapped in the fileset's shared address
  space, and the entry's own segment and section addresses are used as-is.
  No relocation is applied by this library.

Malformed containers are rejected with dedicated errors: out-of-bounds
entries (`MachO::FilesetEntryBoundsError`), entries pointing into a Mach-O
header (`MachO::FilesetEntryOverlapError`), duplicate entry IDs
(`MachO::DuplicateFilesetEntryError`), and unknown entry IDs
(`MachO::FilesetEntryUnknownError`).


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
