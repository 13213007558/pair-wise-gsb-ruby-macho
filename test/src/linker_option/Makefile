# Regenerates the relocatable-object fixtures used by the LC_LINKER_OPTION
# grow-header tests. Each object has a __text and a __data section with an
# external relocation against _ext, and no header padding.

.PHONY: all clean
all: reloc-x86_64.o reloc-arm64.o fat-reloc.o

reloc-x86_64.o: x86_64.s
	clang -target x86_64-apple-macos11 -c $< -o $@

reloc-arm64.o: arm64.s
	clang -target arm64-apple-macos11 -c $< -o $@

fat-reloc.o: reloc-x86_64.o reloc-arm64.o
	lipo -create $^ -output $@

clean:
	rm -f reloc-x86_64.o reloc-arm64.o fat-reloc.o
