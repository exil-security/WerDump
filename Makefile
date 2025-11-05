BOFNAME := WerDump
BOFNAME_RESUME := WerResume
CCX64 := x86_64-w64-mingw32-gcc
#CCX86 := i686-w64-mingw32-gcc

#COMINCLUDE := -I ./BOF/include
CFLAGSBOF := -s -Os -c
CFLAGS := -s -Os

bof:
	$(CCX64) $(CFLAGSBOF) -o bin/WerDump.x64.o src/WerDump.c
#	$(CCX86) $(CFLAGSBOF) -o bin/WerDump.x86.o src/WerDump.c

install: bof
	mkdir -p -m 700 ~/.sliver-client/extensions/werdump/
	cp extension.json ~/.sliver-client/extensions/werdump/
	cp bin/WerDump.*.o ~/.sliver-client/extensions/werdump/
	