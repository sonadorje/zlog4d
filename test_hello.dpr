program test_hello;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

{$APPTYPE CONSOLE}

{$R *.res}

uses
  SysUtils,
  libc4d,
  zlog4d in 'zlog4d.pas';

function main:integer;
var
  rc : integer;
  zc : Pzlog_category;
begin
  debug_log := 'debug.log';
  error_log := 'error.log';

  rc := zlog_init('test_hello.conf');
  if rc > 0 then begin
    Writeln('init failed');
    Exit(-1);
  end;
  zc := zlog_get_category('my_cat');
  if nil =zc then
  begin
    Writeln('get cat fail');
    zlog_fini();
    Exit(-2);
  end;
  __FUNCTION__ := 'main';
  zlog_info(zc, 'hello, zlog!');
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
