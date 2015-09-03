@SET OBJNAME=injector.obj

@WHERE ml64
@IF %ERRORLEVEL% NEQ 0 (@SET NOUT=injector_32.exe) ELSE (@SET NOUT=injector_64.exe)

@if exist OBJNAME del OBJNAME
@if exist NOUT del NOUT

@cl.exe injector.c /W3 /GF /GS- /GA /MT /nologo /c /TC
@if errorlevel 1 goto errml

@link %OBJNAME% /release /subsystem:console /OSVERSION:5.1 /OUT:%NOUT% /MANIFEST:NO /merge:.rdata=.text /DYNAMICBASE:NO
@if errorlevel 1 goto errlink

:errml
:errlink
@if exist %OBJNAME% del %OBJNAME%