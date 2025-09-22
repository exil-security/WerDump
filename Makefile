BOFNAME := WerDump
BOFNAME_RESUME := WerResume
# CCX64 := x86_64-w64-mingw32-gcc
# CCX86 := i686-w64-mingw32-gcc
CCX64 := /opt/shared/C2/Havoc/data/x86_64-w64-mingw32-cross/bin/x86_64-w64-mingw32-gcc
# CCX86 := /opt/shared/C2/Operators/Havoc/data/i686-w64-mingw32-cross/bin/i686-w64-mingw32-gcc

CC=x86_64-w64-mingw32-clang

#COMINCLUDE := -I ./BOF/include
CFLAGSBOF := -s -Os -c
CFLAGS := -s -Os

all: WerResumeBof WerDumpBof

WerResumeBof:
	$(CCX64) $(CFLAGSBOF) -o ./dst/$(BOFNAME_RESUME).o ./src/WerResume.c -DBOF

WerDumpBof:
	$(CCX64) $(CFLAGSBOF) -o ./dst/$(BOFNAME).o ./src/WerDump.c -DBOF
