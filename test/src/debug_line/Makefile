# Regenerate the DWARF line number fixture used by test/test_debug_line.rb.
# Unlike test/bin/yaml2obj, this fixture is built with plain Ruby and does
# not require yaml2obj, a compiler, or dwarfdump.

FIXTURE = ../../bin/dwarf/debug-line.macho
GENERATOR = make_debug_line_fixture.rb

.PHONY: all
all: $(FIXTURE)

$(FIXTURE): $(GENERATOR)
	ruby $(GENERATOR)

.PHONY: clean
clean:
	rm -f $(FIXTURE)
