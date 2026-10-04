# frozen_string_literal: true

require_relative "helpers"

class DependencyGraphTest < Minitest::Test
  include Helpers

  MH_EXECUTE = 0x2
  MH_DYLIB = 0x6

  CPU_TYPE_X86_64 = 0x01000007
  CPU_TYPE_ARM64 = 0x0100000c
  CPU_SUBTYPE_X86_64_ALL = 3
  CPU_SUBTYPE_ARM64_ALL = 0

  COMMANDS = {
    :LC_ID_DYLIB => MachO::LoadCommands::LOAD_COMMAND_CONSTANTS[:LC_ID_DYLIB],
    :LC_LOAD_DYLIB => MachO::LoadCommands::LOAD_COMMAND_CONSTANTS[:LC_LOAD_DYLIB],
    :LC_LOAD_WEAK_DYLIB => MachO::LoadCommands::LOAD_COMMAND_CONSTANTS[:LC_LOAD_WEAK_DYLIB],
    :LC_REEXPORT_DYLIB => MachO::LoadCommands::LOAD_COMMAND_CONSTANTS[:LC_REEXPORT_DYLIB],
    :LC_RPATH => MachO::LoadCommands::LOAD_COMMAND_CONSTANTS[:LC_RPATH],
  }.freeze

  def test_loads_graph_through_loader_executable_and_rpath_rules
    files = {
      "/app/bin/main" => macho("main", MH_EXECUTE, CPU_TYPE_ARM64, [
        [:LC_LOAD_DYLIB, "@executable_path/../lib/libdirect.dylib"],
        [:LC_LOAD_DYLIB, "@rpath/librouted.dylib"],
        [:LC_RPATH, "@executable_path/../lib"],
      ]),
      "/app/lib/libdirect.dylib" => macho("direct", MH_DYLIB, CPU_TYPE_ARM64, [
        [:LC_ID_DYLIB, "/app/lib/libdirect.dylib"],
        [:LC_REEXPORT_DYLIB, "@loader_path/libreexport.dylib"],
      ]),
      "/app/lib/libreexport.dylib" => macho("reexport", MH_DYLIB, CPU_TYPE_ARM64, [
        [:LC_ID_DYLIB, "/app/lib/libreexport.dylib"],
        [:LC_LOAD_DYLIB, "@rpath/librouted.dylib"],
        [:LC_RPATH, "/app/lib"],
      ]),
      "/app/lib/librouted.dylib" => macho("routed", MH_DYLIB, CPU_TYPE_ARM64, [
        [:LC_ID_DYLIB, "/app/lib/librouted.dylib"],
      ]),
    }
    reads = read_tracker(files)

    graph = MachO.dependency_graph("/app/bin/main", reads)

    paths = graph.image_list.map(&:path)
    assert_includes paths, "/app/lib/libdirect.dylib"
    assert_includes paths, "/app/lib/libreexport.dylib"
    assert_includes paths, "/app/lib/librouted.dylib"

    edge = graph.edges.find { |candidate| candidate.install_name == "@loader_path/libreexport.dylib" }
    assert_equal "/app/lib/libreexport.dylib", graph.images.fetch(edge.target).path
    assert_equal :LC_REEXPORT_DYLIB, edge.load_command
    assert edge.reexport
  end

  def test_loader_path_is_resolved_per_loader
    files = {
      "/a/main" => macho("main", MH_EXECUTE, CPU_TYPE_ARM64, [
        [:LC_LOAD_DYLIB, "@loader_path/libx.dylib"],
      ]),
      "/a/libx.dylib" => macho("a-libx", MH_DYLIB, CPU_TYPE_ARM64, [
        [:LC_ID_DYLIB, "/a/libx.dylib"],
        [:LC_LOAD_DYLIB, "@loader_path/liby.dylib"],
      ]),
      "/a/liby.dylib" => macho("a-liby", MH_DYLIB, CPU_TYPE_ARM64, [
        [:LC_ID_DYLIB, "/a/liby.dylib"],
        [:LC_LOAD_DYLIB, "@loader_path/libshared.dylib"],
      ]),
      "/a/libshared.dylib" => macho("a-shared", MH_DYLIB, CPU_TYPE_ARM64, [
        [:LC_ID_DYLIB, "/a/libshared.dylib"],
      ]),
      "/b/main" => macho("other-main", MH_EXECUTE, CPU_TYPE_ARM64, []),
      "/b/libx.dylib" => macho("b-libx", MH_DYLIB, CPU_TYPE_ARM64, [
        [:LC_ID_DYLIB, "/b/libx.dylib"],
      ]),
      "/b/liby.dylib" => macho("b-liby", MH_DYLIB, CPU_TYPE_ARM64, [
        [:LC_ID_DYLIB, "/b/liby.dylib"],
        [:LC_LOAD_DYLIB, "@loader_path/libshared.dylib"],
      ]),
      "/b/libshared.dylib" => macho("b-shared", MH_DYLIB, CPU_TYPE_ARM64, [
        [:LC_ID_DYLIB, "/b/libshared.dylib"],
      ]),
    }

    graph = MachO.dependency_graph("/a/main", &read_tracker(files))

    assert_includes graph.image_list.map(&:path), "/a/libshared.dylib"
    refute_includes graph.image_list.map(&:path), "/b/libshared.dylib"
    refute_includes graph.image_list.map(&:path), "/b/liby.dylib"
  end

  def test_cycles_converge_by_resolved_image_identity
    files = {
      "/bin/main" => macho("main", MH_EXECUTE, CPU_TYPE_ARM64, [
        [:LC_LOAD_DYLIB, "@loader_path/liba.dylib"],
      ]),
      "/bin/liba.dylib" => macho("liba", MH_DYLIB, CPU_TYPE_ARM64, [
        [:LC_ID_DYLIB, "/liba.dylib"],
        [:LC_LOAD_DYLIB, "@loader_path/libb.dylib"],
      ]),
      "/bin/libb.dylib" => macho("libb", MH_DYLIB, CPU_TYPE_ARM64, [
        [:LC_ID_DYLIB, "/libb.dylib"],
        [:LC_LOAD_DYLIB, "@loader_path/liba.dylib"],
      ]),
    }

    graph = MachO.dependency_graph("/bin/main", &read_tracker(files))

    back_edge = graph.edges.find { |edge| edge.source.first == "/bin/libb.dylib" }
    refute_nil back_edge
    assert_equal "/bin/liba.dylib", back_edge.target.first
    assert_equal 3, graph.image_list.count { |image| !image.missing? }
  end

  def test_missing_weak_dylib_is_optional_but_missing_strong_dylib_raises_paths
    files = {
      "/main" => macho("main", MH_EXECUTE, CPU_TYPE_ARM64, [
        [:LC_LOAD_WEAK_DYLIB, "@rpath/libmissing.dylib"],
        [:LC_RPATH, "@loader_path/one"],
        [:LC_RPATH, "/two"],
      ]),
    }

    graph = MachO.dependency_graph("/main", &read_tracker(files))
    edge = graph.missing_edges.first

    assert edge.weak
    assert edge.missing
    assert_equal ["/one/libmissing.dylib", "/two/libmissing.dylib"], edge.tried_paths

    files["/main"] = macho("main", MH_EXECUTE, CPU_TYPE_ARM64, [
      [:LC_LOAD_DYLIB, "@rpath/libmissing.dylib"],
      [:LC_RPATH, "@loader_path/one"],
      [:LC_RPATH, "/two"],
    ])

    error = assert_raises MachO::DylibNotFoundError do
      MachO.dependency_graph("/main", &read_tracker(files))
    end

    assert_equal "@rpath/libmissing.dylib", error.install_name
    assert_equal ["/one/libmissing.dylib", "/two/libmissing.dylib"], error.tried_paths
  end

  def test_selects_compatible_fat_slice_and_skips_incompatible_candidates
    arm64 = MachO::MachOFile.new_from_bin(macho("arm64", MH_DYLIB, CPU_TYPE_ARM64, [
      [:LC_ID_DYLIB, "@rpath/libfat.dylib"],
    ]))
    x86_64 = MachO::MachOFile.new_from_bin(macho("x86_64", MH_DYLIB, CPU_TYPE_X86_64, [
      [:LC_ID_DYLIB, "@rpath/libfat.dylib"],
    ]))
    main = MachO::MachOFile.new_from_bin(macho("main", MH_EXECUTE, CPU_TYPE_X86_64, [
      [:LC_LOAD_DYLIB, "@loader_path/libfat.dylib"],
    ]))

    files = {
      "/bin/main" => MachO::FatFile.new_from_machos(arm64, main).serialize,
      "/bin/libfat.dylib" => MachO::FatFile.new_from_machos(arm64, x86_64).serialize,
    }

    graph = MachO.dependency_graph("/bin/main", read_tracker(files), :arch => :x86_64)

    assert_equal [CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL], graph.root.arch
    assert graph.images.values.one? { |image| image.path == "/bin/libfat.dylib" }
    assert_equal [CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL],
                 graph.images.values.find { |image| image.path == "/bin/libfat.dylib" }.arch
  end

  def test_nested_rpath_uses_loader_specific_rpaths
    files = {
      "/app/main" => macho("main", MH_EXECUTE, CPU_TYPE_ARM64, [
        [:LC_LOAD_DYLIB, "@loader_path/Local.framework/Local"],
      ]),
      "/app/Local.framework/Local" => macho("local", MH_DYLIB, CPU_TYPE_ARM64, [
        [:LC_ID_DYLIB, "@rpath/Local.framework/Local"],
        [:LC_LOAD_DYLIB, "@rpath/Dependency.framework/Dependency"],
        [:LC_RPATH, "@loader_path/.."],
      ]),
      "/app/Dependency.framework/Dependency" => macho("dependency", MH_DYLIB, CPU_TYPE_ARM64, [
        [:LC_ID_DYLIB, "@rpath/Dependency.framework/Dependency"],
      ]),
    }

    graph = MachO.dependency_graph("/app/main", &read_tracker(files))

    assert_includes graph.image_list.map(&:path), "/app/Dependency.framework/Dependency"
  end

  def test_incompatible_fat_candidate_continues_to_next_path
    arm64 = MachO::MachOFile.new_from_bin(macho("arm64", MH_DYLIB, CPU_TYPE_ARM64, [
      [:LC_ID_DYLIB, "libarm-only.dylib"],
    ]))
    x86_64 = MachO::MachOFile.new_from_bin(macho("x86_64", MH_DYLIB, CPU_TYPE_X86_64, [
      [:LC_ID_DYLIB, "libx86.dylib"],
    ]))
    main = MachO::MachOFile.new_from_bin(macho("main", MH_EXECUTE, CPU_TYPE_X86_64, [
      [:LC_LOAD_DYLIB, "@rpath/libfat.dylib"],
      [:LC_RPATH, "/arm-only"],
      [:LC_RPATH, "/x86"],
    ]))

    files = {
      "/main" => main.serialize,
      "/arm-only/libfat.dylib" => MachO::FatFile.new_from_machos(arm64).serialize,
      "/x86/libfat.dylib" => MachO::FatFile.new_from_machos(x86_64).serialize,
    }

    graph = MachO.dependency_graph("/main", read_tracker(files), :arch => :x86_64)

    assert_equal "/x86/libfat.dylib", graph.edges.first.target.first
  end

  def test_graph_reads_only_from_callback
    files = {
      "/virtual/main" => macho("main", MH_EXECUTE, CPU_TYPE_ARM64, []),
    }
    reader = lambda { |path| files.fetch(path) }
    real_reads = []
    trace = TracePoint.new(:call) do |event|
      if event.self == ::File || event.self == ::IO
        real_reads << [event.defined_class, event.method_id]
      end
    end

    trace.enable { MachO.dependency_graph("/virtual/main", reader) }

    assert_empty real_reads
  end

  private

  def read_tracker(files)
    reads = []
    lambda do |path|
      reads << path
      files[path]
    end
  end

  def macho(_name, filetype, cputype, commands)
    serialized_commands = commands.map { |name, path| serialize_command(COMMANDS.fetch(name), path) }
    sizeofcmds = serialized_commands.sum(&:bytesize)
    header = [
      0xfeedfacf,
      cputype,
      cputype == CPU_TYPE_ARM64 ? CPU_SUBTYPE_ARM64_ALL : CPU_SUBTYPE_X86_64_ALL,
      filetype,
      commands.size,
      sizeofcmds,
      0,
      0,
    ].pack("L<8")

    header + serialized_commands.join
  end

  def serialize_command(type, path)
    case type
    when COMMANDS[:LC_ID_DYLIB], COMMANDS[:LC_LOAD_DYLIB],
         COMMANDS[:LC_LOAD_WEAK_DYLIB], COMMANDS[:LC_REEXPORT_DYLIB]
      dylib_command(type, path)
    when COMMANDS[:LC_RPATH]
      string_command(type, path, 12)
    else
      raise ArgumentError, "unsupported command: #{type}"
    end
  end

  def dylib_command(type, path)
    cmdsize = 24 + path.bytesize + 1
    cmdsize = align(cmdsize, 8)
    [type, cmdsize, 24, 0, 0, 0].pack("L<6") + cstring(path, cmdsize - 24)
  end

  def string_command(type, path, offset)
    cmdsize = align(offset + path.bytesize + 1, 8)
    [type, cmdsize, offset].pack("L<3") + cstring(path, cmdsize - offset)
  end

  def cstring(string, length)
    string.b + "\x00".b * (length - string.bytesize)
  end

  def align(value, alignment)
    (value + alignment - 1) / alignment * alignment
  end
end
