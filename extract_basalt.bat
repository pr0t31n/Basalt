@echo off
REM Basalt Zip Extractor for Windows Server 2012
REM Uses VBScript Shell.Application (bypasses PowerShell CLM)
REM
REM Usage: Place this bat next to Basalt_v1.0.3_win_amd64.zip and run it.
REM        It will extract to a "Basalt" folder in the same directory.

setlocal

set "HERE=%~dp0"
set "ZIPFILE=%HERE%Basalt_v1.0.3_win_amd64.zip"
set "DEST=%HERE%Basalt"

if not exist "%ZIPFILE%" (
    echo ERROR: Cannot find %ZIPFILE%
    echo Place this bat file next to the zip and run again.
    pause
    exit /b 1
)

if exist "%DEST%" (
    echo WARNING: %DEST% already exists.
    echo Delete or rename it first.
    pause
    exit /b 1
)

mkdir "%DEST%"

echo Extracting Basalt...

REM Create a temporary VBScript to extract the zip
set "VBS=%TEMP%\extract_basalt_%RANDOM%.vbs"

> "%VBS%" echo Set objShell = CreateObject("Shell.Application")
>> "%VBS%" echo Set objSource = objShell.NameSpace("%ZIPFILE%")
>> "%VBS%" echo Set objTarget = objShell.NameSpace("%DEST%")
>> "%VBS%" echo If objSource Is Nothing Then
>> "%VBS%" echo     WScript.Echo "ERROR: Cannot open zip file."
>> "%VBS%" echo     WScript.Quit 1
>> "%VBS%" echo End If
>> "%VBS%" echo If objTarget Is Nothing Then
>> "%VBS%" echo     WScript.Echo "ERROR: Cannot access destination folder."
>> "%VBS%" echo     WScript.Quit 1
>> "%VBS%" echo End If
>> "%VBS%" echo intOptions = 256
>> "%VBS%" echo objTarget.CopyHere objSource.Items, intOptions
>> "%VBS%" echo WScript.Echo "Extraction complete."

cscript //nologo "%VBS%"
set "EXITCODE=%ERRORLEVEL%"

del "%VBS%" 2>nul

if %EXITCODE% neq 0 (
    echo.
    echo Extraction failed. Try extracting the zip manually with 7-Zip
    echo or copy the files individually.
    pause
    exit /b 1
)

echo.
echo Basalt extracted to: %DEST%
echo.
echo To run:  %DEST%\basalt.bat --help
echo.
pause
endlocal
