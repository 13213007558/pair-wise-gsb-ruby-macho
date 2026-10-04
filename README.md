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

### Offline symbol binding

`MachO::BindResolver` resolves symbol references against an in-memory set of
images, following dyld's two-level namespace rules: the reference's library
ordinal selects the expected defining dylib, re-exported dependents are
traced transparently, and a name is never matched across every library unless
a flat lookup is explicitly requested. Weak imports, the main-executable
ordinal, and circular re-exports are reported as structured results. The
resolver never touches the filesystem; callers supply the image set:

```ruby
resolver = MachO::BindResolver.new([
  MachO::BindResolver::Image.new("app", :executable => true,
                                 :dependents => ["libfoo.dylib"]),
  MachO::BindResolver::Image.new("libfoo.dylib", :exports => ["_run"]),
])

resolver.bind(:from => "app", :ordinal => 1, :symbol => "_run")
# => #<MachO::BindResolver::Bound ...> bound to libfoo.dylib
```

See `examples/bind_resolver_demo.rb` for a walkthrough of duplicate exports,
indirect re-exports, weak undefined symbols, and circular re-exports.

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
