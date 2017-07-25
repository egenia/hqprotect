@echo off

SET PROJECTNAME=prot
SET MASMBINPATH=\MASM32\BIN

D:\MASM32\BIN\Ml.exe /c /coff /Zp1 %PROJECTNAME%.asm
D:\MASM32\BIN\Link.exe /SUBSYSTEM:WINDOWS /MERGE:.idata=.text /MERGE:.data=.text /MERGE:.rdata=.text /SECTION:.text,EWR /IGNORE:4078 %PROJECTNAME%.obj

del *.obj
