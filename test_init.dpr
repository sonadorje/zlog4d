program test_init;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

{$APPTYPE CONSOLE}

{$R *.res}

uses
  SysUtils,
  libc_win,
  zlog4d in 'zlog4d.pas';

function main:integer;
var
  rc : integer;
  zc : Pzlog_category;
begin

  debug_log := 'debug.log';
  error_log := 'error.log';
  rc := zlog_init('test_init.conf');
  if rc > 0 then begin
    Write('init fail');
    Exit(-2);
  end;
  zc := zlog_get_category('my_cat');
  if nil =zc then begin
    Writeln('zlog_get_category fail');
    zlog_fini();
    Exit(-1);
  end;
  zlog_info(zc, 'before update');
  sleep(100);
  rc := zlog_reload('test_init.2.conf');
  if rc > 0 then begin
    Writeln('update fail');
  end;
  zlog_info(zc, 'after update');
  zlog_profile();
  zlog_fini();
  sleep(100);
  zlog_init('test_init.conf');
  zc := zlog_get_category('my_cat');
  if nil =zc then begin
    Writeln('zlog_get_category fail');
    zlog_fini();
    Exit(-1);
  end;
  zlog_info(zc, 'init again');
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
