# frozen_string_literal: true

require_relative "helpers"

class SymbolResolverTest < Minitest::Test
  Image = MachO::SymbolResolver::Image
  Resolver = MachO::SymbolResolver::Resolver

  # Two dylibs export the same symbol; the two-level ordinal, not the name,
  # decides which one each import binds to.
  def test_two_level_binds_to_ordinal_library_not_first_name_match
    app = Image.new("app", :main_executable => true)
    liba = Image.new("libA.dylib")
    libb = Image.new("libB.dylib")
    liba.add_export("_shared")
    libb.add_export("_shared")
    app.link_library(liba)
    app.link_library(libb)

    resolver = Resolver.new([app, liba, libb])

    via_a = resolver.resolve(:symbol => "_shared", :from => app, :ordinal => 1)
    assert_predicate via_a, :bound?
    assert_same liba, via_a.image

    via_b = resolver.resolve(:symbol => "_shared", :from => app, :ordinal => 2)
    assert_predicate via_b, :bound?
    assert_same libb, via_b.image
  end

  # A symbol that only exists in libB must not be found through an ordinal
  # that designates libA: two-level lookup never falls back to other images.
  def test_two_level_does_not_fall_back_to_other_libraries
    app = Image.new("app", :main_executable => true)
    liba = Image.new("libA.dylib")
    libb = Image.new("libB.dylib")
    libb.add_export("_only_in_b")
    app.link_library(liba)
    app.link_library(libb)

    resolver = Resolver.new([app, liba, libb])
    result = resolver.resolve(:symbol => "_only_in_b", :from => app, :ordinal => 1)

    refute_predicate result, :bound?
    assert_equal :unresolved, result.status
    assert_equal :symbol_not_found, result.reason
  end

  # libUmbrella re-exports libImpl (LC_REEXPORT_DYLIB): a symbol missing from
  # the umbrella's own export table is found in the re-exported library.
  def test_library_level_reexport_is_followed
    app = Image.new("app", :main_executable => true)
    umbrella = Image.new("libUmbrella.dylib")
    impl = Image.new("libImpl.dylib")
    impl.add_export("_real")
    app.link_library(umbrella)
    umbrella.link_library(impl, :reexport => true)

    resolver = Resolver.new([app, umbrella, impl])
    result = resolver.resolve(:symbol => "_real", :from => app, :ordinal => 1)

    assert_predicate result, :bound?
    assert_same impl, result.image
    assert_equal "_real", result.defined_as
  end

  # libMid forwards "_public" to "_private" in libCore (symbol-level
  # re-export with a different imported name).
  def test_symbol_level_reexport_with_rename
    app = Image.new("app", :main_executable => true)
    mid = Image.new("libMid.dylib")
    core = Image.new("libCore.dylib")
    core.add_export("_private")
    mid.add_reexported_export("_public", :library => core, :imported_name => "_private")
    app.link_library(mid)

    resolver = Resolver.new([app, mid, core])
    result = resolver.resolve(:symbol => "_public", :from => app, :ordinal => 1)

    assert_predicate result, :bound?
    assert_same core, result.image
    assert_equal "_private", result.defined_as
    assert(result.trace.any? { |step| step.include?("re-exported from libCore.dylib") })
  end

  # A weak import that resolves nowhere is not an error: it would bind to
  # null at run time. The same import without the weak flag is unresolved.
  def test_weak_undefined_import
    app = Image.new("app", :main_executable => true)
    liba = Image.new("libA.dylib")
    app.link_library(liba)

    resolver = Resolver.new([app, liba])

    weak = resolver.resolve(:symbol => "_maybe", :from => app, :ordinal => 1, :weak => true)
    assert_equal :weak_unresolved, weak.status
    refute_predicate weak, :bound?
    assert_equal :symbol_not_found, weak.reason

    strong = resolver.resolve(:symbol => "_maybe", :from => app, :ordinal => 1)
    assert_equal :unresolved, strong.status
    assert_equal :symbol_not_found, strong.reason
  end

  # libX and libY re-export each other and neither defines the symbol:
  # resolution terminates and reports the cycle instead of looping.
  def test_circular_reexport_terminates_unresolved
    app = Image.new("app", :main_executable => true)
    libx = Image.new("libX.dylib")
    liby = Image.new("libY.dylib")
    app.link_library(libx)
    libx.link_library(liby, :reexport => true)
    liby.link_library(libx, :reexport => true)

    resolver = Resolver.new([app, libx, liby])
    result = resolver.resolve(:symbol => "_ghost", :from => app, :ordinal => 1)

    assert_equal :unresolved, result.status
    assert_equal :symbol_not_found, result.reason
    assert(result.trace.any? { |step| step.include?("circular re-export detected") })
  end

  # The cycle does not prevent finding a symbol that is actually defined.
  def test_circular_reexport_still_finds_defined_symbol
    app = Image.new("app", :main_executable => true)
    libx = Image.new("libX.dylib")
    liby = Image.new("libY.dylib")
    liby.add_export("_real")
    app.link_library(libx)
    libx.link_library(liby, :reexport => true)
    liby.link_library(libx, :reexport => true)

    resolver = Resolver.new([app, libx, liby])
    result = resolver.resolve(:symbol => "_real", :from => app, :ordinal => 1)

    assert_predicate result, :bound?
    assert_same liby, result.image
  end

  # Flat lookup (DYNAMIC_LOOKUP_ORDINAL) searches the main executable first,
  # then the remaining images in load order.
  def test_flat_lookup_prefers_main_executable
    app = Image.new("app", :main_executable => true)
    liba = Image.new("libA.dylib")
    app.add_export("_dup")
    liba.add_export("_dup")
    app.link_library(liba)

    resolver = Resolver.new([app, liba])
    result = resolver.resolve(:symbol => "_dup", :from => liba, :ordinal => :flat)

    assert_predicate result, :bound?
    assert_same app, result.image
  end

  # In a flat lookup a weak definition does not stop the search: a strong
  # definition in a later image wins.
  def test_flat_lookup_strong_definition_beats_weak
    app = Image.new("app", :main_executable => true)
    libweak = Image.new("libWeak.dylib")
    libstrong = Image.new("libStrong.dylib")
    libweak.add_export("_maybe", :weak => true)
    libstrong.add_export("_maybe")
    app.link_library(libweak)
    app.link_library(libstrong)

    resolver = Resolver.new([app, libweak, libstrong])
    result = resolver.resolve(:symbol => "_maybe", :from => app, :ordinal => 254, :weak => true)

    assert_predicate result, :bound?
    assert_same libstrong, result.image
    refute_predicate result, :weak_definition?
  end

  # Only weak definitions exist: the first one is used and flagged as weak.
  def test_flat_lookup_falls_back_to_weak_definition
    app = Image.new("app", :main_executable => true)
    libweak = Image.new("libWeak.dylib")
    libweak.add_export("_maybe", :weak => true)
    app.link_library(libweak)

    resolver = Resolver.new([app, libweak])
    result = resolver.resolve(:symbol => "_maybe", :from => app, :ordinal => :flat)

    assert_predicate result, :bound?
    assert_same libweak, result.image
    assert_predicate result, :weak_definition?
  end

  # EXECUTABLE_ORDINAL searches only the main executable, even when a dylib
  # exports the same name.
  def test_main_executable_ordinal
    app = Image.new("app", :main_executable => true)
    liba = Image.new("libA.dylib")
    app.add_export("_entry")
    liba.add_export("_entry")
    app.link_library(liba)

    resolver = Resolver.new([app, liba])
    result = resolver.resolve(:symbol => "_entry", :from => liba, :ordinal => :main_executable)

    assert_predicate result, :bound?
    assert_same app, result.image
  end

  def test_main_executable_ordinal_without_main_executable
    liba = Image.new("libA.dylib")
    liba.add_export("_entry")

    resolver = Resolver.new([liba])
    result = resolver.resolve(:symbol => "_entry", :from => liba, :ordinal => 255)

    assert_equal :unresolved, result.status
    assert_equal :no_main_executable, result.reason
  end

  def test_self_ordinal
    liba = Image.new("libA.dylib")
    liba.add_export("_local")

    resolver = Resolver.new([liba])
    result = resolver.resolve(:symbol => "_local", :from => liba, :ordinal => 0)

    assert_predicate result, :bound?
    assert_same liba, result.image
  end

  def test_missing_library_ordinal
    app = Image.new("app", :main_executable => true)
    liba = Image.new("libA.dylib")
    app.link_library(liba)

    resolver = Resolver.new([app, liba])
    result = resolver.resolve(:symbol => "_anything", :from => app, :ordinal => 2)

    assert_equal :unresolved, result.status
    assert_equal :missing_library, result.reason
  end

  def test_invalid_ordinal_raises
    resolver = Resolver.new([])
    liba = Image.new("libA.dylib")

    assert_raises(ArgumentError) { resolver.resolve(:symbol => "_x", :from => liba, :ordinal => -1) }
    assert_raises(ArgumentError) { resolver.resolve(:symbol => "_x", :from => liba, :ordinal => 256) }
    assert_raises(ArgumentError) { resolver.resolve(:symbol => "_x", :from => liba, :ordinal => "1") }
  end
end
