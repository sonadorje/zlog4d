program test_sscanf;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

{$APPTYPE CONSOLE}

{$R *.res}

uses
  SysUtils,
  pthreads.win,
  pthreads.core,
  glob in 'glob.pas',
  libc4d in 'libc4d.pas';

function main:integer;
var
    str        : array[0..127] of AnsiChar;
    s          : PAnsiChar;
    szfilename : array[0..31] of AnsiChar;
    i,v          : integer;
begin
  {sscanf('123334abcd123', '%[0-9]*', [str]);
  writeln(format('str=%s',[str]));
  sscanf('123456abcdedfBCDEF', '%[^A-Z]', [str]);
  writeln(format('str=%s',[str]));
  sscanf('123456abcdedfBCDEF', '%[1-9]', [str]);
  writeln(format('str=%s',[str]));
  }
  s := 'DEBUG=20';
  szfilename := '';
  //i := sscanf(s, '%*[^=]', [szfilename]);
  // szfilename=nil,因为没保存

  i := sscanf(s, '%[^=]=%d', [szfilename, @v]);
  // szfilename=1.0.0.1001
  writeln(format('%d',[v]));
end;





begin
  try
    main{ TODO -oUser -cConsole Main : Insert code here }
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
