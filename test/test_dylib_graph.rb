# frozen_string_literal: true

require_relative "helpers"

class DylibGraphTest < Minitest::Test
  CPU_TYPES = {
    :x86_64 => 0x01000007,
    :arm64 => 0x0100000c,
  }.freeze

  CPU_SUBTYPES = {
    :x86_64 => 3, # CPU_SUBTYPE_X86_64_ALL
    :arm64 => 0, # CPU_SUBTYPE_ARM64_ALL
  }.freeze

  MH_EXECUTE = 0x2
  MH_DYLIB = 0x6

  LOAD_COMMANDS = {
    :strong => 0x0c, # LC_LOAD_DYLIB
    :weak => 0x80000018, # LC_LOAD_WEAK_DYLIB
    :reexport => 0x8000001f, # LC_REEXPORT_DYLIB
  }.freeze

  LC_ID_DYLIB = 0x0d
  LC_RPATH = 0x8000001c

  def dylib_command(cmd, name)
    payload = "#{name}\x00"
    cmdsize = (24 + payload.bytesize + 7) & ~7
    [cmd, cmdsize, 24, 0, 0, 0].pack("V6") + payload.ljust(cmdsize - 24, "\x00")
  end

  def rpath_command(path)
    payload = "#{path}\x00"
    cmdsize = (12 + payload.bytesize + 7) & ~7
    [LC_RPATH, cmdsize, 12].pack("V3") + payload.ljust(cmdsize - 12, "\x00")
  end

  # Builds a minimal 64-bit little-endian Mach-O image.
  def macho(arch: :x86_64, filetype: MH_DYLIB, id: nil, loads: [], rpaths: [])
    commands = []
    commands << dylib_command(LC_ID_DYLIB, id) if id
    loads.each { |(kind, name)| commands << dylib_command(LOAD_COMMANDS.fetch(kind), name) }
    rpaths.each { |path| commands << rpath_command(path) }
    header = [0xfeedfacf, CPU_TYPES.fetch(arch), CPU_SUBTYPES.fetch(arch), filetype,
              commands.size, commands.sum(&:bytesize), 0, 0].pack("V8")
    header + commands.join
  end

  # Builds a fat Mach-O from [arch, image] pairs.
  def fat_macho(slices)
    offset = 8 + (slices.size * 20)
    archs = []
    slices.each do |(arch, data)|
      archs << [CPU_TYPES.fetch(arch), CPU_SUBTYPES.fetch(arch), offset, data.bytesize, 0].pack("N5")
      offset += data.bytesize
    end
    [0xcafebabe, slices.size].pack("N2") + archs.join + slices.map(&:last).join
  end

  def resolve(main, files, arch: nil)
    MachO::DylibGraph.resolve(main, arch: arch) { |path| files[path] }
  end

  def test_requires_a_fetch_callback
    assert_raises(ArgumentError) { MachO::DylibGraph.resolve("/main") }
  end

  def test_missing_main_executable_raises
    error = assert_raises(ArgumentError) { resolve("/nope", {}) }
    assert_match "no such file", error.message
  end

  def test_executable_path_resolution
    files = {
      "/app/bin/tool" => macho(:filetype => MH_EXECUTE,
                               :loads => [[:strong, "@executable_path/../lib/liba.dylib"]]),
      "/app/lib/liba.dylib" => macho(:id => "liba"),
    }

    graph = resolve("/app/bin/tool", files)

    assert_equal ["/app/bin/tool", "/app/lib/liba.dylib"], graph.nodes.map(&:path)
    edge = graph.root.edges.first
    assert_equal :strong, edge.kind
    refute_predicate edge, :optional?
    refute_predicate edge, :missing?
    assert_equal "/app/lib/liba.dylib", edge.target.path
    assert_equal "liba", edge.target.install_name
  end

  def test_loader_path_is_expanded_per_loader
    # The same install name, @loader_path/libfoo.dylib, must resolve
    # differently for each loader; a global string replacement would
    # collapse these two edges onto a single file.
    files = {
      "/app/main" => macho(:filetype => MH_EXECUTE,
                           :loads => [[:strong, "/one/libmid.dylib"], [:strong, "/two/libmid.dylib"]]),
      "/one/libmid.dylib" => macho(:id => "mid-one",
                                   :loads => [[:strong, "@loader_path/libfoo.dylib"]]),
      "/two/libmid.dylib" => macho(:id => "mid-two",
                                   :loads => [[:strong, "@loader_path/libfoo.dylib"]]),
      "/one/libfoo.dylib" => macho(:id => "foo-one"),
      "/two/libfoo.dylib" => macho(:id => "foo-two"),
    }

    graph = resolve("/app/main", files)
    one, two = graph.root.edges.map(&:target)

    assert_equal "/one/libfoo.dylib", one.edges.first.target.path
    assert_equal "/two/libfoo.dylib", two.edges.first.target.path
    assert_equal "foo-one", one.edges.first.target.install_name
    assert_equal "foo-two", two.edges.first.target.install_name
    assert_equal 5, graph.nodes.size
  end

  def test_rpath_resolution_and_aggregation
    # libb resolves through liba's own rpath; libc resolves through the main
    # executable's rpath, which stays active down the whole load chain.
    files = {
      "/app/main" => macho(:filetype => MH_EXECUTE,
                           :loads => [[:strong, "@rpath/liba.dylib"]],
                           :rpaths => ["/mainlibs"]),
      "/mainlibs/liba.dylib" => macho(:id => "liba",
                                      :loads => [[:strong, "@rpath/libb.dylib"]],
                                      :rpaths => ["@loader_path/deps"]),
      "/mainlibs/deps/libb.dylib" => macho(:id => "libb",
                                           :loads => [[:strong, "@rpath/libc.dylib"]]),
      "/mainlibs/libc.dylib" => macho(:id => "libc"),
    }

    graph = resolve("/app/main", files)

    assert_equal ["/app/main", "/mainlibs/liba.dylib", "/mainlibs/deps/libb.dylib",
                  "/mainlibs/libc.dylib",], graph.nodes.map(&:path)
    assert_empty graph.missing
  end

  def test_missing_weak_dylib_remains_an_optional_edge
    files = {
      "/app/main" => macho(:filetype => MH_EXECUTE,
                           :loads => [[:weak, "@executable_path/libnope.dylib"],
                                      [:strong, "@executable_path/libok.dylib"],]),
      "/app/libok.dylib" => macho(:id => "libok"),
    }

    graph = resolve("/app/main", files)
    weak_edge, strong_edge = graph.root.edges

    assert_predicate weak_edge, :optional?
    assert_predicate weak_edge, :missing?
    assert_nil weak_edge.target
    assert_equal ["/app/libnope.dylib"], weak_edge.attempted_paths
    refute_predicate strong_edge, :missing?
    assert_equal [weak_edge], graph.missing
    assert_equal 2, graph.nodes.size
  end

  def test_missing_strong_dylib_reports_attempted_paths
    files = {
      "/app/main" => macho(:filetype => MH_EXECUTE,
                           :loads => [[:strong, "@rpath/libgone.dylib"]],
                           :rpaths => ["/a", "/b"]),
    }

    graph = resolve("/app/main", files)
    edge = graph.root.edges.first

    refute_predicate edge, :optional?
    assert_predicate edge, :missing?
    assert_equal ["/a/libgone.dylib", "/b/libgone.dylib"], edge.attempted_paths
    assert_equal [edge], graph.missing
  end

  def test_reexport_dylib_is_loaded_as_a_strong_dependency
    files = {
      "/app/main" => macho(:filetype => MH_EXECUTE,
                           :loads => [[:reexport, "/lib/libre.dylib"]]),
      "/lib/libre.dylib" => macho(:id => "libre",
                                  :loads => [[:strong, "@loader_path/libdeep.dylib"]]),
      "/lib/libdeep.dylib" => macho(:id => "libdeep"),
    }

    graph = resolve("/app/main", files)
    edge = graph.root.edges.first

    assert_equal :reexport, edge.kind
    refute_predicate edge, :optional?
    assert_equal "/lib/libre.dylib", edge.target.path
    assert_equal ["/app/main", "/lib/libre.dylib", "/lib/libdeep.dylib"], graph.nodes.map(&:path)
    assert_empty graph.missing
  end

  def test_cycles_converge_on_resolved_image_identity
    files = {
      "/app/main" => macho(:filetype => MH_EXECUTE, :loads => [[:strong, "/lib/liba.dylib"]]),
      "/lib/liba.dylib" => macho(:id => "liba", :loads => [[:strong, "/lib/libb.dylib"]]),
      "/lib/libb.dylib" => macho(:id => "libb", :loads => [[:strong, "/lib/liba.dylib"]]),
    }

    graph = resolve("/app/main", files)
    liba = graph.root.edges.first.target
    libb = liba.edges.first.target

    assert_equal 3, graph.nodes.size
    assert_same liba, libb.edges.first.target
    assert_empty graph.missing
  end

  def test_fat_slice_selection_uses_requested_arch
    files = {
      "/main" => macho(:arch => :arm64, :filetype => MH_EXECUTE,
                       :loads => [[:strong, "/lib/libfat.dylib"]]),
      "/lib/libfat.dylib" => fat_macho([
        [:x86_64, macho(:arch => :x86_64, :id => "slice-x86_64")],
        [:arm64, macho(:arch => :arm64, :id => "slice-arm64")],
      ]),
    }

    graph = resolve("/main", files, :arch => :arm64)

    assert_equal :arm64, graph.arch
    assert_equal "slice-arm64", graph.root.edges.first.target.install_name
    assert_empty graph.missing
  end

  def test_fat_main_defaults_to_host_slice
    host = MachO::DylibGraph::HOST_CPU_TYPES[RbConfig::CONFIG["host_cpu"]]
    skip "no host mapping for #{RbConfig::CONFIG["host_cpu"]}" unless host

    files = {
      "/main" => fat_macho([
        [:x86_64, macho(:arch => :x86_64, :filetype => MH_EXECUTE,
                        :loads => [[:strong, "/lib/libx.dylib"]])],
        [:arm64, macho(:arch => :arm64, :filetype => MH_EXECUTE,
                       :loads => [[:strong, "/lib/liba.dylib"]])],
      ]),
      "/lib/libx.dylib" => macho(:arch => :x86_64, :id => "libx"),
      "/lib/liba.dylib" => macho(:arch => :arm64, :id => "liba"),
    }

    graph = resolve("/main", files)

    assert_equal host, graph.arch
    expected = host == :arm64 ? "/lib/liba.dylib" : "/lib/libx.dylib"
    assert_equal expected, graph.root.edges.first.target.path
  end

  def test_incompatible_thin_dylib_is_unresolved
    files = {
      "/main" => macho(:arch => :arm64, :filetype => MH_EXECUTE,
                       :loads => [[:strong, "/lib/libwrong.dylib"]]),
      "/lib/libwrong.dylib" => macho(:arch => :x86_64, :id => "wrong-arch"),
    }

    graph = resolve("/main", files, :arch => :arm64)
    edge = graph.root.edges.first

    assert_predicate edge, :missing?
    assert_equal ["/lib/libwrong.dylib"], edge.attempted_paths
  end

  def test_main_without_compatible_slice_raises
    files = {
      "/main" => macho(:arch => :x86_64, :filetype => MH_EXECUTE),
    }

    assert_raises(ArgumentError) { resolve("/main", files, :arch => :arm64) }
  end

  def test_resolution_is_read_only_over_the_file_tree
    files = {
      "/app/main" => macho(:filetype => MH_EXECUTE,
                           :loads => [[:strong, "@loader_path/lib/liba.dylib"]]),
      "/app/lib/liba.dylib" => macho(:id => "liba"),
    }
    files.each_value(&:freeze)
    files.freeze

    graph = resolve("/app/main", files)

    assert_equal 2, graph.nodes.size
    assert_equal ["/app/lib/liba.dylib", "/app/main"], files.keys.sort
    assert files.values.all?(&:frozen?)
  end
end
