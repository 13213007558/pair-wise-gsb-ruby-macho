# frozen_string_literal: true

require_relative "helpers"

class BindResolverTest < Minitest::Test
  Image = MachO::BindResolver::Image

  def resolver(*images)
    MachO::BindResolver.new(images)
  end

  # Two libraries export the same symbol; the ordinal, not the name, decides.
  def duplicate_symbol_resolver
    resolver(
      Image.new("app", :executable => true,
                :dependents => ["libfoo.dylib", "libbar.dylib"]),
      Image.new("libfoo.dylib", :exports => %w[_compute _foo_version]),
      Image.new("libbar.dylib", :exports => %w[_compute _bar_version])
    )
  end

  def test_ordinal_selects_among_duplicate_exports
    r = duplicate_symbol_resolver

    first = r.bind(:from => "app", :ordinal => 1, :symbol => "_compute")
    assert first.bound?
    assert_equal "libfoo.dylib", first.image
    assert_equal ["libfoo.dylib"], first.path

    second = r.bind(:from => "app", :ordinal => 2, :symbol => "_compute")
    assert second.bound?
    assert_equal "libbar.dylib", second.image
  end

  def test_flat_lookup_takes_first_match_in_load_order
    r = duplicate_symbol_resolver

    flat = r.flat_lookup("_compute")
    assert flat.bound?
    assert_equal "libfoo.dylib", flat.image

    via_ordinal = r.bind(:from => "app", :ordinal => 0xFF, :symbol => "_compute")
    assert via_ordinal.bound?
    assert_equal "libfoo.dylib", via_ordinal.image
  end

  def test_flat_lookup_prefers_main_executable
    r = resolver(
      Image.new("libfoo.dylib", :exports => %w[_compute]),
      Image.new("app", :executable => true, :exports => %w[_compute],
                :dependents => ["libfoo.dylib"])
    )

    assert_equal "app", r.flat_lookup("_compute").image
  end

  # A client binds a symbol its direct dependency merely re-exports.
  def reexport_resolver
    resolver(
      Image.new("app", :executable => true, :dependents => ["libkit.dylib"]),
      Image.new("libkit.dylib", :exports => %w[_kit_open],
                :dependents => ["libcore.dylib"], :reexports => ["libcore.dylib"]),
      Image.new("libcore.dylib", :exports => %w[_core_init])
    )
  end

  def test_indirect_reexport_is_traced
    r = reexport_resolver

    result = r.bind(:from => "app", :ordinal => 1, :symbol => "_core_init")
    assert result.bound?
    assert_equal "libcore.dylib", result.image
    assert_equal ["libkit.dylib", "libcore.dylib"], result.path
  end

  def test_non_reexported_dependent_is_not_searched
    r = resolver(
      Image.new("app", :executable => true, :dependents => ["libkit.dylib"]),
      Image.new("libkit.dylib", :dependents => ["libcore.dylib"]),
      Image.new("libcore.dylib", :exports => %w[_core_init])
    )

    result = r.bind(:from => "app", :ordinal => 1, :symbol => "_core_init")
    refute result.bound?
    assert_equal :undefined, result.reason
  end

  # Weak imports tolerate missing definitions; strong imports do not.
  def weak_resolver
    resolver(
      Image.new("app", :executable => true, :dependents => ["libfeature.dylib"]),
      Image.new("libfeature.dylib", :exports => %w[_feature_required])
    )
  end

  def test_weak_undefined_binds_to_null
    result = weak_resolver.bind(:from => "app", :ordinal => 1,
                                :symbol => "_feature_optional", :weak => true)

    refute result.bound?
    assert_equal :weak_undefined, result.reason
    assert result.tolerated?
  end

  def test_strong_undefined_is_an_error
    result = weak_resolver.bind(:from => "app", :ordinal => 1,
                                :symbol => "_feature_optional")

    refute result.bound?
    assert_equal :undefined, result.reason
    refute result.tolerated?
  end

  # Mutual re-exports must not hang the search and must be reported.
  def circular_resolver
    resolver(
      Image.new("app", :executable => true, :dependents => ["libping.dylib"]),
      Image.new("libping.dylib", :reexports => ["libpong.dylib"]),
      Image.new("libpong.dylib", :exports => %w[_pong], :reexports => ["libping.dylib"])
    )
  end

  def test_circular_reexport_is_reported_when_undefined
    result = circular_resolver.bind(:from => "app", :ordinal => 1, :symbol => "_missing")

    refute result.bound?
    assert_equal :circular_reexport, result.reason
  end

  def test_circular_reexport_still_resolves_defined_symbols
    result = circular_resolver.bind(:from => "app", :ordinal => 1, :symbol => "_pong")

    assert result.bound?
    assert_equal "libpong.dylib", result.image
    assert_equal ["libping.dylib", "libpong.dylib"], result.path
  end

  def test_self_ordinal
    r = resolver(
      Image.new("libself.dylib", :exports => %w[_internal],
                :dependents => ["libother.dylib"]),
      Image.new("libother.dylib", :exports => %w[_internal])
    )

    result = r.bind(:from => "libself.dylib", :ordinal => 0, :symbol => "_internal")
    assert result.bound?
    assert_equal "libself.dylib", result.image
  end

  def test_executable_ordinal
    r = resolver(
      Image.new("app", :executable => true, :exports => %w[_app_delegate],
                :dependents => ["libplugin.dylib"]),
      Image.new("libplugin.dylib")
    )

    result = r.bind(:from => "libplugin.dylib", :ordinal => 0xFE, :symbol => "_app_delegate")
    assert result.bound?
    assert_equal "app", result.image
  end

  def test_executable_ordinal_without_main_executable
    r = resolver(Image.new("libplugin.dylib"))

    result = r.bind(:from => "libplugin.dylib", :ordinal => 0xFE, :symbol => "_app_delegate")
    refute result.bound?
    assert_equal :no_main_executable, result.reason
  end

  def test_ordinal_out_of_range
    result = weak_resolver.bind(:from => "app", :ordinal => 5, :symbol => "_x")

    refute result.bound?
    assert_equal :ordinal_out_of_range, result.reason
  end

  def test_invalid_ordinal
    result = weak_resolver.bind(:from => "app", :ordinal => 0x100, :symbol => "_x")

    refute result.bound?
    assert_equal :invalid_ordinal, result.reason
  end

  def test_unknown_importing_image
    result = weak_resolver.bind(:from => "libghost.dylib", :ordinal => 1, :symbol => "_x")

    refute result.bound?
    assert_equal :unknown_image, result.reason
  end

  def test_duplicate_image_names_are_rejected
    assert_raises(ArgumentError) do
      resolver(Image.new("liba.dylib"), Image.new("liba.dylib"))
    end
  end

  def test_result_summaries
    r = reexport_resolver

    bound = r.bind(:from => "app", :ordinal => 1, :symbol => "_core_init")
    assert_includes bound.to_s, "libkit.dylib -> libcore.dylib"

    unbound = r.bind(:from => "app", :ordinal => 1, :symbol => "_nope")
    assert_includes unbound.to_s, "unresolved"
    refute unbound.tolerated?
  end
end
