program test_buf;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

{$APPTYPE CONSOLE}

{$R *.res}

uses
  SysUtils,zlog4d,
  libc4d;

function main():integer;
var
  a_buf : Pzlog_buf;
  aa : PTChar;
  i, j : integer;
begin
  debug_log := 'debug.log';
  error_log := 'error.log';
  a_buf := zlog_buf_new(10, 20, 'ABC');
  if nil =a_buf then begin
    zc_error('zlog_buf_new fail', []);
    Exit(-1);
  end;
  aa := '123456789';
  zlog_buf_append(a_buf, aa, Length(aa));
  zc_error('a_buf.start[%s]', [a_buf.start]);
  fwrite(a_buf.start, zlog_buf_len(a_buf), 1, stdout);
  zc_error('------------', []);
  aa := '0';
  zlog_buf_append(a_buf, aa, Length(aa));
  zc_error('a_buf.start[%s]', [a_buf.start]);
  zc_error('------------', []);
  aa := '12345';
  zlog_buf_append(a_buf, aa, Length(aa));
  zc_error('a_buf.start[%s]', [a_buf.start]);
  zc_error('------------', []);
  aa := '6789';
  zlog_buf_append(a_buf, aa, Length(aa));
  zc_error('a_buf.start[%s]', [a_buf.start]);
  zc_error('------------', []);
  aa := '0';
  zlog_buf_append(a_buf, aa, Length(aa));
  zc_error('a_buf.start[%s]', [a_buf.start]);
  zc_error('------------', []);
  aa := '22345';
  zlog_buf_append(a_buf, aa, Length(aa));
  zc_error('a_buf.start[%s]', [a_buf.start]);
  zc_error('------------', []);
  aa := 'abc';
  for i := 0 to 5 do
  begin
    for j := 0 to 5 do
    begin
      zlog_buf_restart(a_buf);
      zc_error('left[1],max[%d],min[%d]', [i, j]);
      zlog_buf_adjust_append(a_buf, aa, Length(aa), 1, 0, i, j);
      zc_error('a_buf.start[%s]', [a_buf.start]);
      zc_error('-----', []);
      zlog_buf_restart(a_buf);
      zc_error('left[0],max[%d],min[%d]', [i, j]);
      zlog_buf_adjust_append(a_buf, aa, Length(aa), 0, 0, i, j);
      zc_error('a_buf.start[%s]', [a_buf.start]);
      zc_error('------------', []);
    end;
  end;
  aa := '1234567890';
  zc_error('left[0],max[%d],min[%d]', [15, 5]);
  zlog_buf_adjust_append(a_buf, aa, Length(aa), 0, 0, 15, 5);
  zc_error('a_buf.start[%s]', [a_buf.start]);
  zc_error('------------', []);
  aa := '1234567890';
  zlog_buf_restart(a_buf);
  zc_error('left[0],max[%d],min[%d]', [25, 5]);
  zlog_buf_adjust_append(a_buf, aa, Length(aa), 1, 0, 25, 5);
  zc_error('a_buf.start[%s]', [a_buf.start]);
  zc_error('------------', []);
  zlog_buf_restart(a_buf);
  zc_error('left[0],max[%d],min[%d]', [19, 5]);
  zlog_buf_adjust_append(a_buf, aa, Length(aa), 0, 0, 19, 5);
  zc_error('a_buf.start[%s]', [a_buf.start]);
  zc_error('------------', []);
  zlog_buf_restart(a_buf);
  zc_error('left[0],max[%d],min[%d]', [20, 5]);
  zlog_buf_adjust_append(a_buf, aa, Length(aa), 0, 0, 20, 5);
  zc_error('a_buf.start[%s]', [a_buf.start]);
  zc_error('------------', []);
  zlog_buf_del(a_buf);
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
