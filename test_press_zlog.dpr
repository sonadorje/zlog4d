program test_press_zlog;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

{$APPTYPE CONSOLE}

{$R *.res}

uses
  SysUtils,
  libc_win,
  pthreads.win, pthreads.core,
  zlog4d in 'zlog4d.pas',
  glob in 'glob.pas';

var
    zc         : Pzlog_category;
    loop_count : long;

function work( ptr : Pointer):Pointer;
var
  j : long;
begin
  j := loop_count;
  while PostDec(j) > 0 do  begin
    zlog_info(zc, ['loglog']);
  end;
  Result := 0;
end;


function test( process_count, thread_count : long):integer;
var
  i : long;
  pid : pid_t;
  j : long;
  tid : array of pthread_t;
begin
  SetLength(tid, thread_count);
  for i := 0 to process_count-1 do
  begin
    pid := fork();
    if pid < 0 then begin
      Writeln('fork fail');
    end
    else if(pid = 0) then
    begin
      for j := 0 to thread_count-1 do begin
        pthread_create(@tid[j], nil, work, nil);
      end;
      for j := 0 to thread_count-1 do begin
        pthread_join(tid[j], nil);
      end;
      Exit(0);
    end;
  end;
  for i := 0 to process_count-1 do
  begin
    pid := wait(nil);
  end;
  Result := 0;
end;


function main( argc : integer):integer;
var
  rc : integer;
begin
   debug_log := 'debug.log';
  error_log := 'error.log';
  if ParamCount <> 4 then begin
    fprint_f(stderr, 'test nprocess nthreads nloop\n');
    exit(1);
  end;
  rc := zlog_init('test_press_zlog.conf');
  if rc then begin
    Writeln('init failed');
    Exit(2);
  end;
  zc := zlog_get_category('my_cat');
  if 0>=zc then begin
    Writeln('get cat failed');
    zlog_fini();
    Exit(3);
  end;
  loop_count := atol(ParamStr(3));
  test(atol(ParamStr(1)), atol(ParamStr(2)));
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
