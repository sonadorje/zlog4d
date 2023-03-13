program test_bitmap;

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
  aa : array[0..31] of Byte;
  i, j : integer;
begin
  debug_log := 'debug.log';
  error_log := 'error.log';
  if ParamCount <> 3 -1 then begin
    Writeln('useage: test_bitmap i j');
    exit(1);
  end;
  dzlog_init(nil, 'AA');
  i := StrToInt(ParamStr(1));
  j := StrToInt(ParamStr(2));
  memset(@aa, $00, sizeof(aa));
  { 32 byte, 256 bit
   * [11111..1100...00]
   *          i
   }
  aa[i div 8]  := aa[i div 8]  or (not ($FF shl (8 - i mod 8)));
  memset(PByte(@aa) + i div 8 + 1, $FF, sizeof(aa) - i div 8 - 1);
  hdzlog_info(@aa, sizeof(aa));
  dzlog_info('%0x', [aa[j div 8]]);
  dzlog_info('%0x', [aa[j div 8]  shr  6]);
  { see j of bits fits }
  dzlog_info('%0x', [not ((aa[j div 8]  shr  (7 - j mod 8)) and $01) ]);
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
