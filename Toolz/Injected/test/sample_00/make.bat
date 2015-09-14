@SET OBJNAME=sample_00.obj

@WHERE ml64
@IF %ERRORLEVEL% NEQ 0 (@SET MLBIN=ml & @SET NOUT=sample_00_32.exe) ELSE (@SET MLBIN=ml64 & @SET NOUT=sample_00_64.exe)

@if exist OBJNAME del OBJNAME
@if exist NOUT del NOUT

@%MLBIN% sample_00.asm /c
@if errorlevel 1 goto errml

@link sample_00.obj kernel32.lib user32.lib gdi32.lib psapi.lib shell32.lib /DYNAMICBASE:NO /subsystem:windows /entry:start /OUT:%NOUT%
@if errorlevel 1 goto errlink

:errml
:errlink
@if exist %OBJNAME% del %OBJNAME%