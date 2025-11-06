BOFNAME := WerDump
BOFNAME_RESUME := WerResume
CCX64 := x86_64-w64-mingw32-gcc

CFLAGSBOF := -s -Os -c
CFLAGS := -s -Os

bof:
	$(CCX64) $(CFLAGSBOF) -o bin/WerDump.x64.o src/WerDump.c

install: bof
	mkdir -p -m 700 ~/.sliver-client/extensions/werdump/
	cp extension.json ~/.sliver-client/extensions/werdump/
	cp bin/WerDump.x64.o ~/.sliver-client/extensions/werdump/

exe:
	$(CCX64) $(CFLAGS) -o bin/WerDump.exe src/standalone/WerDump.c