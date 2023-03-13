program test_enabled;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

{$APPTYPE CONSOLE}

{$R *.res}

uses
  SysUtils,
  libc_win,
  zlog4d in 'zlog4d.pas';


function main():integer;
var
  rc : integer;
  zc : Pzlog_category;
begin
  debug_log := 'debug.log';
  error_log := 'error.log';
  rc := zlog_init('test_enabled.conf');
  if rc > 0 then begin
    Writeln('init failed');
    Exit(-1);
  end;
  zc := zlog_get_category('my_cat');
  if nil = zc then begin
    Writeln('get cat fail');
    zlog_fini();
    Exit(-2);
  end;
  if zlog_trace_enabled(zc) then  begin
    { do something heavy to collect data }
    zlog_trace(zc, 'hello, zlog - trace', []);
  end;
  if zlog_debug_enabled(zc) then  begin
    { do something heavy to collect data }
    zlog_debug(zc, 'hello, zlog - debug', []);
  end;
  if zlog_info_enabled(zc) then  begin
    { do something heavy to collect data }
    zlog_info(zc, 'hello, zlog - info', []);
  end;
  zlog_fini();
  Result := 0;
end;



begin
  try
    main{ TODO -oUser -cConsole Main : Insert code here }
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
