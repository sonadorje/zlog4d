program test_category;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

{$APPTYPE CONSOLE}

{$R *.res}

uses
  SysUtils, zlog4d,
  libc4d;

function main():integer;
var
  rc : integer;
  zc : Pzlog_category;
begin
  debug_log := 'debug.log';
  error_log := 'error.log';
  rc := zlog_init('test_category.conf');
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
  zlog_debug(zc, 'hello, zlog - debug', []);
  zc := zlog_get_category('my-cat');
  if nil =zc then begin
    Writeln('get cat fail');
    zlog_fini();
    Exit(-2);
  end;
  zlog_info(zc, 'hello, zlog - info', []);
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
