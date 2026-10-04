# frozen_string_literal: true

# Demonstrates offline two-level namespace symbol binding with
# MachO::BindResolver. Run from the repository root:
#
#   ruby -Ilib examples/bind_resolver_demo.rb

require "macho"

Image = MachO::BindResolver::Image

def show(label, result)
  status = result.bound? ? "bound     " : "unresolved"
  puts "  #{label}"
  puts "    [#{status}] #{result}"
end

puts "== 1. Two dylibs export the same symbol =="
resolver = MachO::BindResolver.new([
  Image.new("app", :executable => true,
            :dependents => ["libfoo.dylib", "libbar.dylib"]),
  Image.new("libfoo.dylib", :exports => %w[_compute _foo_version]),
  Image.new("libbar.dylib", :exports => %w[_compute _bar_version]),
])
show("ordinal 1 (libfoo):", resolver.bind(:from => "app", :ordinal => 1, :symbol => "_compute"))
show("ordinal 2 (libbar):", resolver.bind(:from => "app", :ordinal => 2, :symbol => "_compute"))
show("flat lookup:", resolver.flat_lookup("_compute"))
puts

puts "== 2. Indirect re-export (app -> libkit -> libcore) =="
resolver = MachO::BindResolver.new([
  Image.new("app", :executable => true, :dependents => ["libkit.dylib"]),
  Image.new("libkit.dylib", :exports => %w[_kit_open],
            :dependents => ["libcore.dylib"], :reexports => ["libcore.dylib"]),
  Image.new("libcore.dylib", :exports => %w[_core_init]),
])
show("ordinal 1, _core_init:", resolver.bind(:from => "app", :ordinal => 1, :symbol => "_core_init"))
show("ordinal 1, _kit_open:", resolver.bind(:from => "app", :ordinal => 1, :symbol => "_kit_open"))
puts

puts "== 3. Weak vs. strong undefined =="
resolver = MachO::BindResolver.new([
  Image.new("app", :executable => true, :dependents => ["libfeature.dylib"]),
  Image.new("libfeature.dylib", :exports => %w[_feature_required]),
])
show("weak _feature_optional:",
     resolver.bind(:from => "app", :ordinal => 1, :symbol => "_feature_optional", :weak => true))
show("strong _feature_optional:",
     resolver.bind(:from => "app", :ordinal => 1, :symbol => "_feature_optional"))
puts

puts "== 4. Circular re-export (libping <-> libpong) =="
resolver = MachO::BindResolver.new([
  Image.new("app", :executable => true, :dependents => ["libping.dylib"]),
  Image.new("libping.dylib", :reexports => ["libpong.dylib"]),
  Image.new("libpong.dylib", :exports => %w[_pong], :reexports => ["libping.dylib"]),
])
show("defined _pong:", resolver.bind(:from => "app", :ordinal => 1, :symbol => "_pong"))
show("undefined _missing:", resolver.bind(:from => "app", :ordinal => 1, :symbol => "_missing"))
puts

puts "== 5. Main executable ordinal (0xFE) =="
resolver = MachO::BindResolver.new([
  Image.new("app", :executable => true, :exports => %w[_app_delegate],
            :dependents => ["libplugin.dylib"]),
  Image.new("libplugin.dylib"),
])
show("plugin -> _app_delegate:",
     resolver.bind(:from => "libplugin.dylib", :ordinal => 0xFE, :symbol => "_app_delegate"))
