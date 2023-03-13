program test_default;

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
begin
  debug_log := 'debug.log';
  error_log := 'error.log';
  rc := dzlog_init('test_default.conf', 'my_cat');
  if rc > 0 then begin
    Writeln('init failed');
    Exit(-1);
  end;
  dzlog_info('hello, zlog');
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
