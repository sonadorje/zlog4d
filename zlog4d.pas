unit zlog4d;

{$DEFINE  USELIBC4D}
interface
uses {$IFDEF USELIBC4D}libc4d{$ELSE} libc_win{$ENDIF}, SysUtils, DateUtils, Windows,
     Math, pthreads.mutex,
     pthreads.rwlock, {$IFNDEF FPC}Net.Winsock2, {$ELSE} Winsock2,{$ENDIF}
     pthreads.win, pthreads.core;
{$POINTERMATH ON}
const
 	__ZC_DEBUG = 0;
	__ZC_WARN  = 1;
	__ZC_ERROR = 2;
  ZLOG_LEVEL_TRACE = 30;
  MAXLEN_PATH = 1024;
  fail_goto = -1;
  ZLOG_VERSION:PTChar = '1.2.12';
  STDIN_FILENO  = (0);
  STDOUT_FILENO = (1);
  STDERR_FILENO = (2);
  ZLOG_LEVEL_DEBUG = 20;
	ZLOG_LEVEL_INFO = 40;
	ZLOG_LEVEL_NOTICE = 60;
	ZLOG_LEVEL_WARN = 80;
	ZLOG_LEVEL_ERROR = 100;
	ZLOG_LEVEL_FATAL = 120;
  ROLLING = 1;     (* aa.02->aa.03, aa.01->aa.02, aa->aa.01 *)
  SEQUENCE = 2;    (* aa->aa.03 *)
  MAXLEN_CFG_LINE = (MAXLEN_PATH * 4);
  MAXLINES_NO     = 128;
  NO_CFG = 0;
	FILE_CFG = 1;
	IN_MEMORY_CFG = 2;
  ARRAY_LIST_DEFAULT_SIZE = 32;
  FILE_NEWLINE:TChar = #10;
  FILE_NEWLINE_LEN = 1;
  ZLOG_HEX_HEAD  = #10'             0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F    0123456789ABCDEF';
  ZLOG_MAX_UINT32_VALUE = uint32($ffffffff);
  ZLOG_MAX_INT32_VALUE  = uint32($7fffffff);
  ZLOG_DEFAULT_TIME_FMT = '%Y-%m-%d %H:%M:%S';
  ZLOG_INT32_LEN = sizeof('-2147483648') - 1;
  ZLOG_INT64_LEN = sizeof('-9223372036854775808') - 1;
  ZLOG_CONF_DEFAULT_FORMAT             = 'default = "%D %V [%p:%F:%L] %m%n"';
  ZLOG_CONF_DEFAULT_RULE               = '*.*    >stdout';
  ZLOG_CONF_DEFAULT_BUF_SIZE_MIN       = 1024;
  ZLOG_CONF_DEFAULT_BUF_SIZE_MAX       = (2 * 1024 * 1024);
  ZLOG_CONF_DEFAULT_FILE_PERMS         = 0600;
  ZLOG_CONF_DEFAULT_RELOAD_CONF_PERIOD = 0;
  ZLOG_CONF_DEFAULT_FSYNC_PERIOD       = 0;
  ZLOG_CONF_BACKUP_ROTATE_LOCK_FILE    = '/tmp/zlog.lock';

  LOG_EMERG   = 0	(* system is unusable *);
  LOG_ALERT   = 1	(* action must be taken immediately *);
  LOG_CRIT    = 2	(* critical conditions *);
  LOG_ERR     = 3	(* error conditions *);
  LOG_WARNING = 4	(* warning conditions *);
  LOG_NOTICE  = 5	(* normal but significant condition *);
  LOG_INFO    = 6	(* informational *);
  LOG_DEBUG   = 7	(* debug-level messages *);
  LOG_PRIMASK = $07	(* mask to extract priority part (internal) *);

  UNIXEM_GLOB_NOSPACE = (1)         (*!< (Error result code:) An attempt to allocate memory failed, or if errno was 0 UNIXEM_GLOB_LIMIT was specified in the flags and ARG_MAX patterns were matched. *);
  UNIXEM_GLOB_ABORTED = (2)         (*!< (Error result code:) The scan was stopped because an error was encountered and either UNIXEM_GLOB_ERR was set or ( *errfunc)() returned non-zero. *);
  UNIXEM_GLOB_NOMATCH = (3)         (*!< (Error result code:) The pattern does not match any existing pathname, and UNIXEM_GLOB_NOCHECK was not set int flags. *);
  UNIXEM_GLOB_NOSYS   = (4)         (*!< (Error result code:) . *);
  UNIXEM_GLOB_ABEND   = UNIXEM_GLOB_ABORTED (*!< (Error result code:) . *);

  UNIXEM_GLOB_ERR      = $00000001     (*!< Return on read errors. *);
  UNIXEM_GLOB_MARK     = $00000002     (*!< Append a slash to each name. *);
  UNIXEM_GLOB_NOSORT   = $00000004     (*!< Don't sort the names. *);
  UNIXEM_GLOB_DOOFFS   = $00000008     (*!< Insert PGLOB->gl_offs NULLs. Supported from version 1.6 of UNIXem. *);
  UNIXEM_GLOB_NOCHECK  = $00000010     (*!< If nothing matches, return the pattern. Supported from version 1.6 of UNIXem. *);
  UNIXEM_GLOB_APPEND   = $00000020     (*!< Append to results of a previous call. Not currently supported in this implementation. *);
  UNIXEM_GLOB_NOESCAPE = $00000040     (*!< Backslashes don't quote metacharacters. Has no effect in this implementation, since escaping is not supported. *);

  UNIXEM_GLOB_PERIOD      = $00000080     (*!< Leading `.' can be matched by metachars. Supported from version 1.6 of UNIXem. *);
  UNIXEM_GLOB_MAGCHAR     = $00000100     (*!< Set in gl_flags if any metachars seen. Supported from version 1.6 of UNIXem. *);
  UNIXEM_GLOB_NOMAGIC     = $00000800     (*!< If no magic chars, return the pattern. Supported from version 1.6 of UNIXem. *);
  UNIXEM_GLOB_TILDE       = $00001000     (*!< Expand ~user and ~ to home directories. Partially supported from version 1.6 of UNIXem: leading ~ is expanded to %HOMEDRIVE%%HOMEPATH%. *);
  UNIXEM_GLOB_ONLYDIR     = $00002000     (*!< Match only directories. This implementation guarantees to only return directories when this flag is specified. *);
  UNIXEM_GLOB_TILDE_CHECK = $00004000     (*!< Like UNIXEM_GLOB_TILDE but return an UNIXEM_GLOB_NOMATCH even if UNIXEM_GLOB_NOCHECK specified. Supported from version 1.6 of UNIXem. *);
  UNIXEM_GLOB_ONLYFILE    = $00008000     (*!< Match only files. Supported from version 1.6 of UNIXem. *);
  UNIXEM_GLOB_NODOTSDIRS  = $00010000     (*!< Elide "." and ".." directories from wildcard searches. Supported from version 1.6 of UNIXem. *);
  UNIXEM_GLOB_LIMIT       = $00020000     (*!< Limits the search to the number specified by the caller in gl_matchc. Supported from version 1.6 of UNIXem. *);

  GLOB_NOSPACE     = (UNIXEM_GLOB_NOSPACE)  (*!< (Error result code:) An attempt to allocate memory failed, or if errno was 0 GLOB_LIMIT was specified in the flags and ARG_MAX patterns were matched. *);
  GLOB_ABORTED     = (UNIXEM_GLOB_ABORTED)  (*!< (Error result code:) The scan was stopped because an error was encountered and either GLOB_ERR was set or ( *errfunc)() returned non-zero. *);
  GLOB_NOMATCH     = (UNIXEM_GLOB_NOMATCH)  (*!< (Error result code:) The pattern does not match any existing pathname, and GLOB_NOCHECK was not set int flags. *);
  GLOB_NOSYS       = (UNIXEM_GLOB_NOSYS)   (*!< (Error result code:) . *);
  GLOB_ABEND       = (UNIXEM_GLOB_ABEND)   (*!< (Error result code:) . *);
  GLOB_ERR         = (UNIXEM_GLOB_ERR)    (*!< Return on read errors. *);
  GLOB_MARK        = (UNIXEM_GLOB_MARK)   (*!< Append a slash to each name. *);
  GLOB_NOSORT      = (UNIXEM_GLOB_NOSORT)  (*!< Don't sort the names. *);
  GLOB_DOOFFS      = (UNIXEM_GLOB_DOOFFS)  (*!< Insert PGLOB->gl_offs NULLs. Supported from version 1.6 of UNIXem. *);
  GLOB_NOCHECK     = (UNIXEM_GLOB_NOCHECK)  (*!< If nothing matches, return the pattern. Supported from version 1.6 of UNIXem. *);
  GLOB_APPEND      = (UNIXEM_GLOB_APPEND)  (*!< Append to results of a previous call. Not currently supported in this implementation. *);
  GLOB_NOESCAPE    = (UNIXEM_GLOB_NOESCAPE) (*!< Backslashes don't quote metacharacters. Has no effect in this implementation, since escaping is not supported. *);
  GLOB_PERIOD      = (UNIXEM_GLOB_PERIOD)  (*!< Leading `.' can be matched by metachars. Supported from version 1.6 of UNIXem. *);
  GLOB_MAGCHAR     = (UNIXEM_GLOB_MAGCHAR)  (*!< Set in gl_flags if any metachars seen. Supported from version 1.6 of UNIXem. *);
  GLOB_NOMAGIC     = (UNIXEM_GLOB_NOMAGIC)    (*!< If no magic chars, return the pattern. Supported from version 1.6 of UNIXem. *);
  GLOB_TILDE       = (UNIXEM_GLOB_TILDE)     (*!< Expand ~user and ~ to home directories. Partially supported from version 1.6 of UNIXem: leading ~ is expanded to %HOMEDRIVE%%HOMEPATH%. *);
  GLOB_ONLYDIR     = (UNIXEM_GLOB_ONLYDIR)    (*!< Match only directories. This implementation guarantees to only return directories when this flag is specified. *);
  GLOB_TILDE_CHECK = (UNIXEM_GLOB_TILDE_CHECK)  (*!< Like GLOB_TILDE but return an GLOB_NOMATCH even if GLOB_NOCHECK specified. Supported from version 1.6 of UNIXem. *);
  GLOB_ONLYFILE    = (UNIXEM_GLOB_ONLYFILE)   (*!< Match only files. Supported from version 1.6 of UNIXem. *);
  GLOB_NODOTSDIRS  = (UNIXEM_GLOB_NODOTSDIRS)  (*!< Elide "." and ".." directories from wildcard searches. Supported from version 1.6 of UNIXem. *);
  GLOB_LIMIT       = (UNIXEM_GLOB_LIMIT)     (*!< Limits the search to the number specified by the caller in gl_matchc. Supported from version 1.6 of UNIXem. *);
  __MAX_PATH__ = 260;

type
long = LongInt;
Tzc_arraylist_del_fn = procedure (data: Pointer);
Tzc_arraylist = record
  _array : PPointer;
  len, size : integer;
  del : Tzc_arraylist_del_fn;
end;
Pzc_arraylist = ^Tzc_arraylist;
PPzc_arraylist = ^Pzc_arraylist;

zlog_category_s = record
  name                : array[0..(MAXLEN_PATH + 1)-1] of TChar;
  name_len            : size_t;
  level_bitmap,
  level_bitmap_backup : array[0..31] of Byte;

  fit_rules,
  fit_rules_backup    : Pzc_arraylist;
end;
Tzlog_category = zlog_category_s;
Pzlog_category = ^Tzlog_category;

Pzc_hashtable_entry = ^Tzc_hashtable_entry;
zc_hashtable_entry_s = record
  hash_key : uint32;
  key,
  value    : Pointer;
  prev,
  next     : Pzc_hashtable_entry;
end;
Tzc_hashtable_entry = zc_hashtable_entry_s;
PPzc_hashtable_entry = ^Pzc_hashtable_entry;

Tzc_hashtable_hash_fn = function(const key: Pointer): Uint32;
Tzc_hashtable_equal_fn = function (const key1, key2: Pointer ): int;
Tzc_hashtable_del_fn = procedure (kv: Pointer);

zc_hashtable_s = record
    nelem     : size_t;
    tab       : PPzc_hashtable_entry;
    tab_size  : size_t;
    hash      : Tzc_hashtable_hash_fn;
    equal     : Tzc_hashtable_equal_fn;
    key_del,
    value_del : Tzc_hashtable_del_fn;
end;
Tzc_hashtable = zc_hashtable_s;
Pzc_hashtable = ^Tzc_hashtable;

zlog_mdc_s = record
	tab: Pzc_hashtable;
end;
Tzlog_mdc = zlog_mdc_s;
Pzlog_mdc = ^Tzlog_mdc;
va_list = array of TVarRec;

Tzlog_event_cmd = (
    ZLOG_FMT = 0,
    ZLOG_HEX = 1);

zlog_time_cache_s = record
  str : array[0..(MAXLEN_CFG_LINE + 1)-1] of TChar;
  len : size_t;
  sec : time_t;
end;
Tzlog_time_cache = zlog_time_cache_s;
Pzlog_time_cache = ^Tzlog_time_cache;

Tzlog_event = record
    category_name     : PTChar;
    category_name_len : size_t;
    host_name         : array[0..(256 + 1)-1] of TChar;
    host_name_len     : size_t;
    _file             : PTChar;
    file_len          : size_t;
    func              : PTChar;
    func_len          : size_t;
    line              : long;
    level             : integer;
    hex_buf           : Pointer;
    hex_buf_len       : size_t;
    str_format        : PTChar;
    str_args          : array of TVarRec;
    generate_cmd      : Tzlog_event_cmd;
    time_stamp        : Ttimeval;
    time_utc_sec      : time_t;
    time_utc          : Ttm;
    time_local_sec    : time_t;
    time_local        : Ttm;
    time_caches       : Pzlog_time_cache;
    time_cache_count  : integer;

    pid,
    last_pid          : pid_t;
    pid_str           : array[0..(30 + 1)-1] of TChar;
    pid_str_len       : size_t;
    tid               : pthread_t;
    tid_str           : array[0..(30 + 1)-1] of TChar;
    tid_str_len       : size_t;
    tid_hex_str       : array[0..(30 + 1)-1] of TChar;
    tid_hex_str_len   : size_t;
//{$if defined(__linux__) or  defined(__APPLE__)}
    ktid              : pid_t;
    ktid_str          : array[0..30] of TChar;
    ktid_str_len      : size_t;
//{$ENDIF}
end;
Pzlog_event = ^Tzlog_event;


zlog_buf_s = record
  start,
  tail,
  _end,
  end_plus_1       : PTChar;
  size_min,
  size_max,
  size_real        : size_t;
  truncate_str     : array[0..(MAXLEN_PATH + 1)-1] of TChar;
  truncate_str_len : size_t;
end;
Tzlog_buf = zlog_buf_s;
Pzlog_buf = ^Tzlog_buf;

Tzlog_thread = record
  init_version     : integer;
  mdc              : Pzlog_mdc;
  event            : Pzlog_event;
  pre_path_buf,
  path_buf,
  archive_path_buf,
  pre_msg_buf,
  msg_buf          : Pzlog_buf;
end;
Pzlog_thread = ^Tzlog_thread;

HANDLE = Pointer;
TLOCK_FD = HANDLE;
zlog_rotater_s = record
  lock_mutex    : pthread_mutex_t;
  lock_file     : PTChar;
  lock_fd       : TLOCK_FD;
  base_path,
  archive_path  : PTChar;
  glob_path     : array[0..(MAXLEN_PATH + 1)-1] of TChar;
  num_start_len,
  num_end_len   : size_t;
  num_width,
  mv_type,
  max_count     : integer;
  files         : Pzc_arraylist;
end;
Tzlog_rotater = zlog_rotater_s;
Pzlog_rotater = ^Tzlog_rotater;


zlog_format_s = record
  name,
  pattern       : array[0..(MAXLEN_CFG_LINE + 1)-1] of TChar;
  pattern_specs : Pzc_arraylist;
end;
Tzlog_format = zlog_format_s;
Pzlog_format = ^Tzlog_format;

zlog_conf_s = record
    conf_file               : array[0..(MAXLEN_PATH + 1)-1] of TChar;
    cfg_ptr             : array[0..(MAXLEN_CFG_LINE*MAXLINES_NO)-1] of TChar;
    mtime               : array[0..20] of TChar;
    strict_init         : integer;
    buf_size_min,
    buf_size_max        : size_t;
    rotate_lock_file    : array[0..(MAXLEN_CFG_LINE + 1)-1] of TChar;
    rotater             : Pzlog_rotater;
    default_format_line : array[0..(MAXLEN_CFG_LINE + 1)-1] of TChar;
    default_format      : Pzlog_format;
    file_perms          : uint32;
    fsync_period,
    reload_conf_period  : size_t;
    levels,
    formats,
    rules               : Pzc_arraylist;
    time_cache_count    : integer;
end;
Tzlog_conf = zlog_conf_s;
Pzlog_conf = ^Tzlog_conf;


zlog_level_s = record
  int_level     : integer;
  str_uppercase,
  str_lowercase : array[0..(MAXLEN_PATH + 1)-1] of TChar;
  str_len       : size_t;
  syslog_level  : integer;
end;
Tzlog_level = zlog_level_s;
Pzlog_level = ^Tzlog_level;
Pzlog_rule = ^Tzlog_rule;
Tzlog_rule_output_fn = function (a_rule: Pzlog_rule; a_thread: Pzlog_thread): int;


zlog_msg_s = record
  buf : PTChar;
  len : size_t;
  path : PTChar;
end;
Tzlog_msg = zlog_msg_s;
Pzlog_msg = ^Tzlog_msg;
Tzlog_record_fn = function(msg: Pzlog_msg): int;


zlog_rule_s = record
  category          : array[0..(MAXLEN_CFG_LINE + 1)-1] of TChar;
  compare_AnsiChar  : TChar;
  level             : integer;
  level_bitmap      : array[0..31] of Byte;
  file_perms        : uint32;
  file_open_flags   : integer;
  file_path         : array[0..(MAXLEN_PATH + 1)-1] of TChar;
  dynamic_specs     : Pzc_arraylist;
  static_fd         : integer;
  static_dev        : dev_t;
  static_ino        : ino_t;
  archive_max_size  : long;
  archive_max_count : integer;
  archive_path      : array[0..(MAXLEN_PATH + 1)-1] of TChar;
  archive_specs     : Pzc_arraylist;
  pipe_fp           : PFILE;
  pipe_fd           : integer;
  fsync_period,
  fsync_count       : size_t;
  levels            : Pzc_arraylist;
  syslog_facility   : integer;
  _format            : Pzlog_format;
  output            : Tzlog_rule_output_fn;
  record_name,
  record_path       : array[0..(MAXLEN_PATH + 1)-1] of TChar;
  record_func       : Tzlog_record_fn;
end;
Tzlog_rule = zlog_rule_s;
Pzlog_spec = ^Tzlog_spec;
Tzlog_spec_write_fn = function ( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
Tzlog_spec_gen_fn = function ( a_spec : Pzlog_spec; a_thread : Pzlog_thread):integer;

zlog_spec_s = record
  str              : PTChar;
  len              : integer;
  time_fmt         : array[0..(MAXLEN_CFG_LINE + 1)-1] of TChar;
  time_cache_index : integer;
  mdc_key          : array[0..(MAXLEN_PATH + 1)-1] of TChar;
  print_fmt        : array[0..(MAXLEN_CFG_LINE + 1)-1] of TChar;
  left_adjust,
  left_fill_zeros  : integer;
  max_width,
  min_width        : size_t;
  write_buf        : Tzlog_spec_write_fn;
  gen_msg,
  gen_path,
  gen_archive_path : Tzlog_spec_gen_fn;
end;
Tzlog_spec = zlog_spec_s;
Tzlog_spec_time_fn = function(const calendar:Ptime_t; localtime:Ptm): Ptm;

zlog_mdc_kv_s = record
  key,
  value     : array[0..(MAXLEN_PATH + 1)-1] of TChar;
  value_len : size_t;
end;
Tzlog_mdc_kv = zlog_mdc_kv_s;
Pzlog_mdc_kv = ^Tzlog_mdc_kv;


zlog_file_s = record
  index : integer;
  path : array[0..MAXLEN_PATH] of TChar;
end;
Tzlog_file = zlog_file_s;
Pzlog_file = ^Tzlog_file;

zlog_record_s = record
  name : array[0..(MAXLEN_PATH + 1)-1] of TChar;
  output : Tzlog_record_fn;
end;

Tzlog_record = zlog_record_s;
Pzlog_record = ^Tzlog_record;
unixem_glob_s = record
  gl_pathc,
  gl_matchc,
  gl_offs,
  gl_flags      : integer;
  gl_pathv: PPTChar;
end;
Tglob = unixem_glob_s;
Tunixem_glob = unixem_glob_s;
Punixem_glob = ^Tunixem_glob;
Terrfunc = function(const str: PTChar; err: Integer):integer;
Tzc_arraylist_cmp_fn = function(data1, data2: Pointer): int;


function zlog_init(const config : PTChar):integer;
function zc_profile_inner(flag : integer;const _file :String; line : long; fmt : PTChar; args : array of const):integer;
procedure zc_time( time_str : PTChar; time_str_size : size_t);
function zc_error(fmt: PTChar; args: array of const): Integer;
function zc_debug(fmt: PTChar; args: array of const): Integer;
function zc_warn(fmt: PTChar; args: array of const): Integer;
function zlog_init_inner(const config : PTChar):integer;
procedure zlog_thread_del( a_thread : Pzlog_thread);
procedure zlog_mdc_del( a_mdc : Pzlog_mdc);
procedure zc_hashtable_del( a_table : Pzc_hashtable);
procedure zlog_event_del( a_event : Pzlog_event);

const
  INVALID_LOCK_FD =  HANDLE(LONG_PTR(-1));

var
  __FILE__, __FUNCTION__: __Text;
  __LINE__: int = 0;
  zlog_env_is_init: int = 0;
  zlog_env_init_version: int = 0;
  zlog_env_conf: Pzlog_conf;
  zlog_env_categories : Pzc_hashtable;
  zlog_env_records: Pzc_hashtable;
  debug_log: PTChar = nil;
  error_log: PTChar = nil;
  init_flag: size_t = 0;
  zlog_env_reload_conf_count: size_t;
  zlog_thread_key: pthread_key_t ;
  zlog_default_category: Pzlog_category;
  zlog_env_lock:  pthread_rwlock_t = PTHREAD_RWLOCK_INITIALIZER;
  hex : PTChar = '0123456789abcdef';

procedure zlog_buf_del( a_buf : Pzlog_buf);
procedure zlog_clean_rest_thread;
function zlog_conf_new(const config : PTChar):Pzlog_conf;
function zlog_level_list_new:Pzc_arraylist;
function zc_arraylist_new( del : Tzc_arraylist_del_fn):Pzc_arraylist;
procedure zlog_level_del( a_level : Pzlog_level);
function zlog_level_list_set_default( levels : Pzc_arraylist):integer;
function zlog_level_list_set( levels : Pzc_arraylist; line : PTChar):integer;
function zlog_level_new( line : PTChar):Pzlog_level;
 function syslog_level_atoi( str : PTChar):integer;
function zc_arraylist_set( a_list : Pzc_arraylist; idx : integer; data : Pointer):integer;
function zc_arraylist_expand_inner( a_list : Pzc_arraylist; _max : integer):integer;
procedure zc_arraylist_del( a_list : Pzc_arraylist);
procedure zlog_format_del( a_format : Pzlog_format);
function zc_assert(expr: Boolean; rv: Integer): Integer;
procedure zlog_rule_del( a_rule : Pzlog_rule);
function zlog_conf_build_with_file( a_conf : Pzlog_conf):integer;
function zlog_conf_parse_line( a_conf : Pzlog_conf; line : PTChar; section : PInteger):integer;
function zlog_rotater_new( lock_file : PTChar):Pzlog_rotater;
procedure zlog_rotater_del( a_rotater : Pzlog_rotater);
function unlock_file( fd : TLOCK_FD):Boolean;
function zlog_format_new( line : PTChar; time_cache_count : PInteger):Pzlog_format;
function zc_str_replace_env( str : PTChar; str_size : size_t):integer;
procedure zlog_spec_del( a_spec : Pointer);
function zlog_spec_new( pattern_start : PTChar; pattern_next : PPTChar; time_cache_count : PInteger):Pzlog_spec;
function zlog_spec_gen_msg_reformat( a_spec : Pzlog_spec; a_thread : Pzlog_thread):integer;
procedure zlog_buf_restart(a_buf: Pzlog_buf);
function zlog_buf_len(a_buf: Pzlog_buf): int;
function zlog_buf_adjust_append(a_buf : Pzlog_buf;const str : PTChar; str_len : size_t; left_adjust, zero_pad : integer; in_width, out_width : size_t):integer;
function zlog_buf_resize( a_buf : Pzlog_buf; increment : size_t):integer;
procedure zlog_buf_truncate( a_buf : Pzlog_buf);
function zlog_spec_gen_path_reformat( a_spec : Pzlog_spec; a_thread : Pzlog_thread):integer;
function zlog_buf_str(a_buf: Pzlog_buf): PTChar;
function zlog_spec_gen_archive_path_reformat( a_spec : Pzlog_spec; a_thread : Pzlog_thread):integer;
function zlog_spec_parse_print_fmt( a_spec : Pzlog_spec):integer;
function zlog_spec_gen_msg_direct( a_spec : Pzlog_spec; a_thread : Pzlog_thread):integer;
function zlog_spec_gen_path_direct( a_spec : Pzlog_spec; a_thread : Pzlog_thread):integer;
function zlog_spec_gen_archive_path_direct( a_spec : Pzlog_spec; a_thread : Pzlog_thread):integer;
function zlog_spec_write_time_UTC( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
function zlog_spec_write_time_local( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
function zlog_spec_write_time_internal( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf; use_utc : byte):integer;
function zlog_buf_append(a_buf : Pzlog_buf;const str : PTChar; str_len : size_t):integer;
function zlog_spec_write_mdc( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
function zlog_mdc_get_kv(a_mdc : Pzlog_mdc;const key : PTChar):Pzlog_mdc_kv;
function zc_hashtable_get(a_table : Pzc_hashtable;const a_key : Pointer):Pointer;
function zlog_spec_write_ms( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
function zlog_buf_printf_dec32( a_buf : Pzlog_buf; ui32 : uint32; width : integer):integer;
function zlog_spec_write_us( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
function zlog_spec_write_category( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
function zlog_spec_write_srcfile( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
function zlog_spec_write_srcfile_neat( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
function zlog_spec_write_srcline( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
function zlog_spec_write_srcfunc( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
function zlog_buf_printf_dec64( a_buf : Pzlog_buf; ui64 : uint64; width : integer):integer;
function zlog_spec_write_hostname( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
function zlog_spec_write_ktid( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
function zlog_spec_write_usrmsg( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
function zlog_buf_vprintf(a_buf : Pzlog_buf;const format : PTChar; args : array of const):integer;
 function zlog_buf_printf_hex( a_buf : Pzlog_buf; ui32 : uint32; width : integer):integer;
function zlog_spec_write_newline( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
function zlog_spec_write_cr( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
function zlog_spec_write_pid( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
function zlog_spec_write_level_lowercase( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
function zlog_level_list_get( levels : Pzc_arraylist; l : integer):Pzlog_level;
function zc_arraylist_get(a_list: Pzc_arraylist; i : integer): Pointer;
function zlog_spec_write_level_uppercase( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
function zlog_spec_write_tid_hex( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
function zlog_spec_write_tid_long( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
function zlog_spec_write_percent( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
function zlog_spec_write_str( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
procedure zlog_spec_profile( a_spec : Pzlog_spec; flag : integer);
function zc_profile(flag : integer; fmt : PTChar; args : array of const): Int;
function zc_arraylist_add( a_list : Pzc_arraylist; data : Pointer):integer;
procedure zlog_format_profile( a_format : Pzlog_format; flag : integer);
function zc_parse_byte_size( astring : PTChar):size_t;
function zlog_format_has_name(a_format: Pzlog_format; fname: PTChar): Boolean;
function zlog_rule_new( line : PTChar; levels : Pzc_arraylist; default_format : Pzlog_format; formats : Pzc_arraylist; file_perms : uint32; fsync_period : size_t; time_cache_count : PInteger):Pzlog_rule;
function zlog_level_list_atoi( levels : Pzc_arraylist; str : PTChar):integer;
function zlog_rule_parse_path( path_start, path_str : PTChar; path_size : size_t; path_specs : PPzc_arraylist; time_cache_count : PInteger):integer;
function zlog_rule_output_static_file_single( a_rule : Pzlog_rule; a_thread : Pzlog_thread):integer;
function zlog_format_gen_msg( a_format : Pzlog_format; a_thread : Pzlog_thread):integer;
function zlog_spec_gen_msg(a_spec: Pzlog_spec; a_thread: Pzlog_thread): int;
function fsync( fd : integer):integer;
function zlog_rule_output_dynamic_file_single( a_rule : Pzlog_rule; a_thread : Pzlog_thread):integer;
function zlog_rule_output_dynamic_file_rotate( a_rule : Pzlog_rule; a_thread : Pzlog_thread):integer;
function zlog_rotater_rotate( a_rotater : Pzlog_rotater; base_path : PTChar; msg_len : size_t; archive_path : PTChar; archive_max_size : long; archive_max_count : integer):integer;
function zlog_rotater_trylock( a_rotater : Pzlog_rotater):integer;
function lock_file( path : PTChar): TLOCK_FD;
function zlog_rotater_lsmv( a_rotater : Pzlog_rotater; base_path, archive_path : PTChar; archive_max_count : integer):integer;
function zlog_rotater_parse_archive_path( a_rotater : Pzlog_rotater):integer;
function zlog_rotater_add_archive_files( a_rotater : Pzlog_rotater):integer;
procedure zlog_file_del( a_file : Pzlog_file);
function zlog_file_cmp( a_file_1, a_file_2 : Pzlog_file):integer;
function zlog_file_check_new(a_rotater : Pzlog_rotater;const path : PTChar):Pzlog_file;
function zc_arraylist_sortadd( a_list : Pzc_arraylist; cmp : Tzc_arraylist_cmp_fn; data : Pointer):integer;
function zc_arraylist_insert_inner( a_list : Pzc_arraylist; idx : integer; data : Pointer):integer;
function zlog_rotater_roll_files( a_rotater : Pzlog_rotater):integer;
function zlog_rotater_seq_files( a_rotater : Pzlog_rotater):integer;
procedure zlog_rotater_clean( a_rotater : Pzlog_rotater);
function zlog_rotater_unlock( a_rotater : Pzlog_rotater):integer;
function zlog_rule_gen_archive_path( a_rule : Pzlog_rule; a_thread : Pzlog_thread):PTChar;
procedure zlog_buf_seal(a_buf: Pzlog_buf);
function zlog_spec_gen_archive_path(a_spec: Pzlog_spec; a_thread: Pzlog_thread): int;
function zlog_rule_output_static_file_rotate( a_rule : Pzlog_rule; a_thread : Pzlog_thread):integer;
function zlog_rule_output_pipe( a_rule : Pzlog_rule; a_thread : Pzlog_thread):integer;
function syslog_facility_atoi( facility : PTChar):integer;
function zlog_rule_output_stdout( a_rule : Pzlog_rule; a_thread : Pzlog_thread):integer;
function zlog_rule_output_stderr( a_rule : Pzlog_rule; a_thread : Pzlog_thread):integer;
function zlog_rule_output_static_record( a_rule : Pzlog_rule; a_thread : Pzlog_thread):integer;
function zlog_rule_output_dynamic_record( a_rule : Pzlog_rule; a_thread : Pzlog_thread):integer;
function zlog_conf_build_with_in_memory( a_conf : Pzlog_conf):integer;
function zlog_conf_build_without_file( a_conf : Pzlog_conf):integer;
procedure zlog_conf_profile( a_conf : Pzlog_conf; flag : integer);
procedure zlog_rotater_profile( a_rotater : Pzlog_rotater; flag : integer);
procedure zlog_level_list_profile( levels : Pzc_arraylist; flag : integer);
procedure zlog_level_profile( a_level : Pzlog_level; flag : integer);
procedure zlog_rule_profile( a_rule : Pzlog_rule; flag : integer);
procedure zlog_conf_del( a_conf : Pzlog_conf);
procedure zlog_level_list_del( levels : Pzc_arraylist);
function zlog_category_table_new:Pzc_hashtable;
function zc_hashtable_new( a_size : size_t; hash : Tzc_hashtable_hash_fn; equal : Tzc_hashtable_equal_fn; key_del, value_del : Tzc_hashtable_del_fn):Pzc_hashtable;
function zc_hashtable_str_hash(const str : Pointer):uint32;
function zc_hashtable_str_equal(const key1, key2 : Pointer):integer;
procedure zlog_category_del( a_category : Pointer);
procedure zlog_category_table_profile( categories : Pzc_hashtable; flag : integer);
function zc_hashtable_begin( a_table : Pzc_hashtable):Pzc_hashtable_entry;
procedure zlog_category_profile( a_category : Pzlog_category; flag : integer);
function zc_hashtable_next( a_table : Pzc_hashtable; a_entry : Pzc_hashtable_entry):Pzc_hashtable_entry;
function zlog_record_table_new:Pzc_hashtable;
procedure zlog_record_del(a_record : Pointer);
procedure zlog_record_table_profile( records : Pzc_hashtable; flag : integer);
procedure zlog_record_profile( a_record : Pzlog_record; flag : integer);
procedure zlog_fini_inner;
procedure zlog_category_table_del( categories : Pzc_hashtable);
procedure zlog_record_table_del( records : Pzc_hashtable);
function zlog_get_category(const cname : PTChar):Pzlog_category;
function zlog_category_table_fetch_category(categories : Pzc_hashtable;const category_name : PTChar; rules : Pzc_arraylist):Pzlog_category;
function zlog_category_new(const name : PTChar; rules : Pzc_arraylist):Pzlog_category;
function zlog_category_obtain_rules( a_category : Pzlog_category; rules : Pzc_arraylist):integer;
function zlog_rule_match_category( a_rule : Pzlog_rule; category : PTChar):integer;
procedure zlog_cateogry_overlap_bitmap( a_category : Pzlog_category; a_rule : Pzlog_rule);
function zlog_rule_is_wastebin( a_rule : Pzlog_rule):integer;
function zc_hashtable_put( a_table : Pzc_hashtable; a_key, a_value : Pointer):integer;
function zc_hashtable_rehash( a_table : Pzc_hashtable):integer;
procedure zlog_fini;
function zlog_category_needless_level(a_category: Pzlog_category;const lv: Integer): Boolean;
procedure zlog(category : Pzlog_category; &file :String; filelen : size_t;const func :String; funclen : size_t; line : long;const level : integer; format : PTChar; args : array of const);
function zlog_thread_new( init_version : integer; buf_size_min, buf_size_max : size_t; time_cache_count : integer):Pzlog_thread;
function zlog_mdc_new:Pzlog_mdc;
procedure zlog_mdc_kv_del( a_mdc_kv : Pointer);
function zlog_event_new( time_cache_count : integer):Pzlog_event;
function zlog_buf_new(buf_size_min, buf_size_max : size_t;const truncate_str : PTChar):Pzlog_buf;
function zlog_thread_rebuild_msg_buf( a_thread : Pzlog_thread; buf_size_min, buf_size_max : size_t):integer;
function zlog_thread_rebuild_event( a_thread : Pzlog_thread; time_cache_count : integer):integer;
procedure zlog_event_set_fmt(a_event : Pzlog_event; category_name : PTChar; category_name_len : size_t;const &file :String; file_len : size_t;const func :String; func_len : size_t; line : long; level : integer;const str_format : PTChar; str_args : array of const);
function zlog_reload({const} config : PTChar):integer;
function zlog_rule_set_record( a_rule : Pzlog_rule; records : Pzc_hashtable):integer;
function zlog_category_table_update_rules( categories : Pzc_hashtable; new_rules : Pzc_arraylist):integer;
function zlog_category_update_rules( a_category : Pzlog_category; new_rules : Pzc_arraylist):integer;
procedure zlog_category_table_commit_rules( categories : Pzc_hashtable);
procedure zlog_category_commit_rules( a_category : Pzlog_category);
procedure zlog_category_table_rollback_rules( categories : Pzc_hashtable);
procedure zlog_category_rollback_rules( a_category : Pzlog_category);
function zlog_category_output( a_category : Pzlog_category; a_thread : Pzlog_thread):integer;
function zlog_rule_output( a_rule : Pzlog_rule; a_thread : Pzlog_thread):integer;
procedure zlog_info(cat: Pzlog_category; fmt: PTChar; args: array of const) ;
function zlog_fetch_thread(var a_thread : Pzlog_thread):integer;
function __DATE__: __TEXT;
function __TIME__: __TEXT;
procedure zlog_profile;
function dzlog_init(const config, cname : PTChar):integer;
procedure dzlog_info(fmt: PTChar; args: array of const);
procedure dzlog(const &file :String; filelen : size_t;const func :String; funclen : size_t; line : long; level : integer;const format : PTChar; args: array of const);
function unixem_glob(const pattern : PTChar; flags : integer; errfunc : Terrfunc; pglob : Punixem_glob):integer;
procedure unixem_globfree( pglob : Punixem_glob);
function unixem_strrpbrk_(const str, strCharSet : PansiChar):PansiChar;
function __write(Handle: THandle; const Buffer: PTCHar; Count: LongWord): Integer;
function zlog_trace_enabled(cat: Pzlog_category): Boolean;
function zlog_level_enabled(category : Pzlog_category;const level : integer):Boolean;
procedure zlog_trace(cat: Pzlog_category; fmt: PTChar; args: array of const) ;
function zlog_debug_enabled(zc: Pzlog_category): Boolean;
procedure zlog_debug(cat: Pzlog_category; fmt: PTChar; args: array of const) ;
function zlog_info_enabled(zc: Pzlog_category): Boolean;

procedure hdzlog(const &file :__TEXT; filelen : size_t;const func :__TEXT; funclen : size_t; line : long; level : integer;const buf : Pointer; buflen : size_t);
procedure hdzlog_info(buf: PTCHAR; buf_len: int);
procedure zlog_event_set_hex(a_event : Pzlog_event; category_name : PTChar; category_name_len : size_t;const &file :__TEXT; file_len : size_t;const func :__TEXT; func_len : size_t; line : long; level : integer;const hex_buf : Pointer; hex_buf_len : size_t);

implementation


procedure zlog_event_set_hex(a_event : Pzlog_event; category_name : PTChar; category_name_len : size_t;const &file :__TEXT; file_len : size_t;const func :__TEXT; func_len : size_t; line : long; level : integer;const hex_buf : Pointer; hex_buf_len : size_t);
begin
  {
   * category_name point to zlog_category_output's category.name
   }
  a_event.category_name := category_name;
  a_event.category_name_len := category_name_len;
  a_event._file := PTChar(&file);
  a_event.file_len := file_len;
  a_event.func := PTChar(func);
  a_event.func_len := func_len;
  a_event.line := line;
  a_event.level := level;
  a_event.generate_cmd := ZLOG_HEX;
  a_event.hex_buf := hex_buf;
  a_event.hex_buf_len := hex_buf_len;
  { pid should fetch eveytime, as no one knows,
   * when does user fork his process
   * so clean here, and fetch at spec.c
   }
  a_event.pid := pid_t(0);
  { in a event's life cycle, time will be get when spec need,
   * and keep unchange though all event's life cycle
   }
  a_event.time_stamp.tv_sec := 0;

end;



procedure hdzlog(const &file :__TEXT; filelen : size_t;const func :__TEXT; funclen : size_t; line : long; level : integer;const buf : Pointer; buflen : size_t);
var
  a_thread : Pzlog_thread;
label _exit, _reload;
begin
  if zlog_category_needless_level(zlog_default_category, level) then
     exit;
  pthread_rwlock_rdlock(@zlog_env_lock);
  if 0>=zlog_env_is_init then
  begin
    zc_error('never call zlog_init() or dzlog_init() before', []);
    goto _exit;
  end;
  { that's the differnce, must judge default_category in lock }
  if nil =zlog_default_category then
  begin
    zc_error('zlog_default_category is null,'+
      'dzlog_init() or dzlog_set_cateogry() is not called above', []);
    goto _exit;
  end;
  if 0 = zlog_fetch_thread(a_thread) then
     goto _exit;
  zlog_event_set_hex(a_thread.event,
                    zlog_default_category.name, zlog_default_category.name_len,
                    &file, filelen, func, funclen, line, level,
                    buf, buflen);
  if zlog_category_output(zlog_default_category, a_thread) > 0 then
  begin
    zc_error('zlog_output fail, srcfile[%s], srcline[%ld]', [&file, line]);
    goto _exit;
  end;
  if (zlog_env_conf.reload_conf_period > 0)  and
     (PreInc(zlog_env_reload_conf_count) > zlog_env_conf.reload_conf_period)  then
  begin
    { under the protection of lock read env conf }
    goto _reload;
  end;
_exit:
  pthread_rwlock_unlock(@zlog_env_lock);
  exit;
_reload:
  pthread_rwlock_unlock(@zlog_env_lock);
  { will be wrlock, so after unlock }
  if zlog_reload(PTChar(-1)) > 0 then
  begin
    zc_error('reach reload-conf-period but zlog_reload fail, zlog-chk-conf [file] see detail', []);
  end;

end;


function zlog_info_enabled(zc: Pzlog_category): Boolean;
begin
   Result := zlog_level_enabled(zc, ZLOG_LEVEL_INFO)
end;

function zlog_debug_enabled(zc: Pzlog_category): Boolean;
begin
  Result := zlog_level_enabled(zc, ZLOG_LEVEL_DEBUG)
end;

function zlog_level_enabled(category : Pzlog_category;const level : integer):Boolean;
begin
  Result := (category <> nil)  and  (zlog_category_needless_level(category, level) = False);
end;


function zlog_trace_enabled(cat: Pzlog_category): Boolean;
begin
   Result := zlog_level_enabled(cat, ZLOG_LEVEL_TRACE)
end;

function unixem_strrpbrk_(const str, strCharSet : PansiChar):PansiChar;
var
  part, pch, p : PTChar;
begin
    part := nil;
    pch := strCharSet;
    while pch^ <> #0 do
    begin
        p := strrchr(str, pch^);
        if nil <> p then
        begin
            if nil = part then
            begin
                part := p;
            end
            else
            begin
                if part < p then begin
                    part := p;
                end;
            end;
        end;
        Inc(pch);
    end;
    Result := part;
end;



function unixem_glob(const pattern : PTChar; flags : integer; errfunc : Terrfunc; pglob : Punixem_glob):integer;
var
  szRelative       : array[0..__MAX_PATH__] of TChar;
  file_part        : PTChar;
  find_data        : WIN32_FIND_DATAA;
  hFind            : THANDLE;
  buffer           : PTChar;
  szPattern2,
  szPattern3       : array[0..__MAX_PATH__] of TChar;
  effectivePattern,
  next_str,
  leafMost         : PTChar;
  bMagic,
  bNoMagic,
  bMagic0          : int;
  maxMatches       : size_t;
  dw               : DWORD;
  cbCurr           : integer;
  cbAlloc,
  cMatches         : size_t;
  cch              : integer;
  new_cbAlloc      : size_t;
  new_buffer       : PTChar;
  cbPointers       : size_t;
  pp,
  _begin,
  _end             : PPTChar;
begin
    effectivePattern := pattern;
    bMagic := int(nil <> strpbrk(pattern, '?*'));
    bNoMagic := 0;
    maxMatches := not size_t(0);
    assert(nil <> pglob);
    if flags and UNIXEM_GLOB_NOMAGIC > 0 then
        bNoMagic := not bMagic;

    if flags and UNIXEM_GLOB_LIMIT > 0 then
        maxMatches := size_t(pglob.gl_matchc);

    if flags and UNIXEM_GLOB_TILDE > 0 then
    begin
        { Check that begins with '~/' }
        if( '~' = pattern[0])  and
            (   (#0 = pattern[1])  or
                ('/' = pattern[1])  or
                ('\' = pattern[1])) then
        begin
            lstrcpyA(@szPattern2[0], '%HOMEDRIVE%%HOMEPATH%');
            dw := ExpandEnvironmentStringsA(@szPattern2[0], @szPattern3[0], Sizeof(szPattern3) - 1);
            if 0 <> dw then
            begin
                lstrcpynA(PTChar(@szPattern3[0]) + dw - 1, @pattern[1], int(SizeOf(szPattern3) - dw));
                szPattern3[Sizeof(szPattern3) - 1] := #0;
                effectivePattern := szPattern3;
            end;
        end;
    end;
    file_part := unixem_strrpbrk_(effectivePattern, '9247');
    if nil <> file_part then
    begin
        leafMost := PreInc(file_part);
        lstrcpyA(szRelative, effectivePattern);
        szRelative[file_part - effectivePattern] := #0;
    end
    else
    begin
        szRelative[0] := #0;
        leafMost := effectivePattern;
    end;
    bMagic0 := int(leafMost = strpbrk(leafMost, '?*'));
    hFind := FindFirstFileA(effectivePattern, &find_data);
    buffer := nil;
    pglob.gl_pathc := 0;
    pglob.gl_pathv := nil;
    if 0 = (flags and UNIXEM_GLOB_DOOFFS) then
    begin
        pglob.gl_offs := 0;
    end;
    if hFind = INVALID_HANDLE_VALUE then
    begin
        { If this was a pattern search, and the
         * directory exists, then we return 0
         * matches, rather than UNIXEM_GLOB_NOMATCH
         }
        if( bMagic > 0)  and (  nil <> file_part) then
        begin
            result := 0;
        end
        else
        begin
            if Assigned(errfunc) then begin
                errfunc(effectivePattern, int(GetLastError));
            end;
            result := UNIXEM_GLOB_NOMATCH;
        end;
    end
    else
    begin
        cbCurr := 0;
        cbAlloc := 0;
        cMatches := 0;
        result := 0;
        repeat
            if (bMagic0 > 0)  and  (0 = (flags and UNIXEM_GLOB_PERIOD)) then
            begin
                if '.' = find_data.cFileName[0] then
                begin
                    continue;
                end;
            end;
            if find_data.dwFileAttributes and FILE_ATTRIBUTE_DIRECTORY > 0 then
            begin
{$IF UNIXEM_GLOB_ONLYFILE > 0}
                if flags and UNIXEM_GLOB_ONLYFILE > 0 then
                begin
                    continue;
                end;
{$endif} { UNIXEM_GLOB_ONLYPFILE }
                if (bMagic0 > 0)  and  (UNIXEM_GLOB_NODOTSDIRS = (flags and UNIXEM_GLOB_NODOTSDIRS)) then
                begin
                    { Pattern must begin with '.' to match either dots directory }
                    if (0 = lstrcmpA('.', find_data.cFileName))  or
                       (0 = lstrcmpA('..', find_data.cFileName))  then
                    begin
                        continue;
                    end;
                end;
                if flags and UNIXEM_GLOB_MARK > 0 then
                begin
{$IF false}
                    if find_data.cFileName[0] >= 'A'  and  find_data.cFileName[0] <= 'M' then
{$endif} { 0 }
                    lstrcatA(find_data.cFileName, '/');
                end;
            end
            else
            begin
                if flags and UNIXEM_GLOB_ONLYDIR > 0 then
                begin
                    { Skip all further actions, and get the next entry }
{$IF false}
                    if find_data.cFileName[0] >= 'A'  and  find_data.cFileName[0] <= 'M' then
{$endif} { 0 }
                    continue;
                end;
            end;
            cch := lstrlenA(find_data.cFileName);
            if nil <> file_part then begin
                cch  := cch + (int(file_part - effectivePattern));
            end;
            new_cbAlloc := size_t(cbCurr) + cch + 1;
            if new_cbAlloc > cbAlloc then
            begin
                new_cbAlloc  := new_cbAlloc  * 2;
                new_cbAlloc := (new_cbAlloc + 31) and not (31);
                new_buffer := ReallocMemory(buffer, new_cbAlloc);
                if new_buffer = nil then begin
                    result := UNIXEM_GLOB_NOSPACE;
                    freeMem(buffer);
                    buffer := nil;
                    break;
                end;
                buffer := new_buffer;
                cbAlloc := new_cbAlloc;
            end;
            lstrcpynA(buffer + cbCurr, szRelative, 1 + int(file_part - effectivePattern));
            lstrcatA(buffer + cbCurr, find_data.cFileName);
            cbCurr  := cbCurr + (cch + 1);
            Inc(cMatches);
        until not( (FindNextFileA(hFind, find_data))  and  (cMatches <> maxMatches) ) ;
        FindClose(hFind);
        if result = 0 then
        begin
            { Now expand the buffer, to fit in all the pointers. }
            cbPointers := (1 + cMatches + pglob.gl_offs) * sizeof(PTChar);
            new_buffer  := ReallocMemory(buffer, cbAlloc + cbPointers);
            if new_buffer = nil then begin
                result := UNIXEM_GLOB_NOSPACE;
                freeMem(buffer);
            end
            else
            begin

                buffer := new_buffer;
                move(new_buffer^, (new_buffer + cbPointers)^,  cbAlloc);
                { Handle the offsets. }
                _begin := PPTChar(new_buffer);
                _end := _begin + pglob.gl_offs;
                while _begin <> _end do
                begin
                    _begin^ := nil;
                    Inc(_begin);
                end;
                { Sort, or no sort. }
                pp := PPTChar(new_buffer) + pglob.gl_offs;
                _begin := pp;
                _end := _begin + cMatches;
                if flags and UNIXEM_GLOB_NOSORT > 0 then
                begin
                    { The way we need in order to test the removal of dots in the findfile_sequence. }
                    _end^ := nil;
                    _begin := pp;
                    next_str := buffer + cbPointers;
                    while _begin <> _end do
                    begin
                        (_end - 1)^ := next_str;
                        { Find the next string. }
                        next_str  := next_str + (1 + lstrlenA(next_str));
                        Dec(_end);
                    end;
                end
                else
                begin
                    { The normal way. }
                    _begin := pp;
                    next_str := buffer + cbPointers;
                    while _begin <> _end do
                    begin
                        _begin^ := next_str;
                        { Find the next string. }
                        next_str  := next_str + (1 + lstrlenA(next_str));
                        Inc(_begin);
                    end;
                    _begin^ := nil;
                end;
                { Return results to caller. }
                pglob.gl_pathc := int(cMatches);
                pglob.gl_matchc := int(cMatches);
                pglob.gl_flags := 0;
                if bMagic > 0 then begin
                    pglob.gl_flags  := pglob.gl_flags  or UNIXEM_GLOB_MAGCHAR;
                end;
                pglob.gl_pathv := PPTChar(new_buffer);
            end;
        end;
        if 0 = cMatches then begin
            result := UNIXEM_GLOB_NOMATCH;
        end;
    end;
end;


procedure unixem_globfree( pglob : Punixem_glob);
begin
    if pglob <> nil then begin
        freeMem(pglob.gl_pathv);
        pglob.gl_pathc := 0;
        pglob.gl_pathv := nil;
    end;
end;

procedure hdzlog_info(buf: PTCHAR; buf_len: int);
begin
	hdzlog(__FILE__, Length(__FILE__)-1, __function__, length(__function__)-1, __LINE__,
	ZLOG_LEVEL_INFO, buf, buf_len)
end;

procedure dzlog(const &file :String; filelen : size_t;const func :String; funclen : size_t; line : long; level : integer;const format : PTChar; args: array of const);
var
    a_thread : Pzlog_thread;
    label _reload, _exit;
begin
  pthread_rwlock_rdlock(@zlog_env_lock);
  if 0>=zlog_env_is_init then begin
    zc_error('never call zlog_init() or dzlog_init() before', []);
    goto _exit;
  end;
  { that's the differnce, must judge default_category in lock }
  if nil =zlog_default_category then begin
    zc_error('zlog_default_category is null,'+
      'dzlog_init() or dzlog_set_cateogry() is not called above', []);
    goto _exit;
  end;
  if zlog_category_needless_level(zlog_default_category, level) then
     goto _exit;
  if 0 >= zlog_fetch_thread(a_thread) then
     goto _exit;
  //va_start(args, format);
  zlog_event_set_fmt(a_thread.event,
                    zlog_default_category.name, zlog_default_category.name_len,
                    &file, filelen, func, funclen, line, level,
                    format, args);
  if zlog_category_output(zlog_default_category, a_thread) > 0 then
  begin
     zc_error('zlog_output fail, srcfile[%s], srcline[%ld]', [&file, line]);
     goto _exit;
  end;

  if (zlog_env_conf.reload_conf_period > 0) and
     (PreInc(zlog_env_reload_conf_count) > zlog_env_conf.reload_conf_period)  then
  begin
    { under the protection of lock read env conf }
    goto _reload;
  end;

_exit:
  pthread_rwlock_unlock(@zlog_env_lock);
  exit;
_reload:
  pthread_rwlock_unlock(@zlog_env_lock);
  { will be wrlock, so after unlock }
  if zlog_reload(PTChar(-1)) > 0 then begin
    zc_error('reach reload-conf-period but zlog_reload fail, zlog-chk-conf [file] see detail', []);
  end;

end;


procedure dzlog_info(fmt: PTChar; args: array of const);
begin
  Assert(false);
  __function__ := 'dzlog_info';
	dzlog(__FILE__, sizeof(__FILE__)-1, __function__, sizeof(__function__)-1, __LINE__,
	      ZLOG_LEVEL_INFO, fmt, args)
end;

function dzlog_init(const config, cname : PTChar):integer;
var
  rc : integer;
  label _err;
begin
  Assert(false);
  rc := 0;
  zc_debug('------dzlog_init start------', []);
  zc_debug('------compile time[%s %s], version[%s]------',
              [__DATE__, __TIME__, ZLOG_VERSION]);
  rc := pthread_rwlock_wrlock(@zlog_env_lock);
  if rc > 0 then begin
    zc_error('pthread_rwlock_wrlock fail, rc[%d]', [rc]);
    Exit(-1);
  end;
  if zlog_env_is_init > 0 then begin
    zc_error('already init, use zlog_reload pls', []);
    goto _err;
  end;
  if zlog_init_inner(config) > 0 then
  begin
    zc_error('zlog_init_inner[%s] fail', [config]);
    goto _err;
  end;
  zlog_default_category := zlog_category_table_fetch_category(
    zlog_env_categories,
    cname,
    zlog_env_conf.rules);
  if nil =zlog_default_category then begin
    zc_error('zlog_category_table_fetch_category[%s] fail', [cname]);
    goto _err;
  end;
  zlog_env_is_init := 1;
  PostInc(zlog_env_init_version);
  zc_debug('------dzlog_init success end------', []);
  rc := pthread_rwlock_unlock(@zlog_env_lock);
  if rc > 0 then begin
    zc_error('pthread_rwlock_unlock fail, rc=[%d]', [rc]);
    Exit(-1);
  end;
  Exit(0);
_err:
  zc_error('------dzlog_init fail end------', []);
  rc := pthread_rwlock_unlock(@zlog_env_lock);
  if rc > 0 then begin
    zc_error('pthread_rwlock_unlock fail, rc=[%d]', [rc]);
    Exit(-1);
  end;
  Result := -1;
end;



procedure zlog_profile;
var
  rc : integer;
begin
  rc := 0;
  rc := pthread_rwlock_rdlock(@zlog_env_lock);
  if rc > 0 then begin
    zc_error('pthread_rwlock_wrlock fail, rc[%d]', [rc]);
    exit;
  end;
  zc_warn('------zlog_profile start------ ', []);
  zc_warn('is init:[%d]', [zlog_env_is_init]);
  zc_warn('init version:[%d]', [zlog_env_init_version]);
  zlog_conf_profile(zlog_env_conf, __ZC_WARN);
  zlog_record_table_profile(zlog_env_records, __ZC_WARN);
  zlog_category_table_profile(zlog_env_categories, __ZC_WARN);
  if zlog_default_category <> nil then
  begin
    zc_warn('-default_category-', []);
    zlog_category_profile(zlog_default_category, __ZC_WARN);
  end;
  zc_warn('----zlog_profile----end---- ', []);
  rc := pthread_rwlock_unlock(@zlog_env_lock);
  if rc > 0 then begin
    zc_error('pthread_rwlock_unlock fail, rc=[%d]', [rc]);
    exit;
  end;

end;

function zlog_fetch_thread(var a_thread : Pzlog_thread):integer;
var
  rd : integer;
begin
  rd := 0;
  a_thread := pthread_getspecific(zlog_thread_key);
  if nil = a_thread then
  begin
    a_thread := zlog_thread_new(zlog_env_init_version,
                                zlog_env_conf.buf_size_min,
                                zlog_env_conf.buf_size_max,
                                zlog_env_conf.time_cache_count);
    if nil = a_thread then
    begin
      zc_error('zlog_thread_new fail', []);
      exit( fail_goto);
    end;
    rd := pthread_setspecific(zlog_thread_key, a_thread);
    if rd > 0 then begin
      zlog_thread_del(a_thread);
      zc_error('pthread_setspecific fail, rd[%d]', [rd]);
      exit( fail_goto);
    end;
  end;
  if a_thread.init_version <> zlog_env_init_version then
  begin
    { as mdc is still here, so can not easily del and new }
    rd := zlog_thread_rebuild_msg_buf(a_thread,
                                      zlog_env_conf.buf_size_min,
                                      zlog_env_conf.buf_size_max);
    if rd > 0 then begin
      zc_error('zlog_thread_resize_msg_buf fail, rd[%d]', [rd]);
      exit( fail_goto);
    end;
    rd := zlog_thread_rebuild_event(a_thread, zlog_env_conf.time_cache_count);
    if rd > 0 then begin
      zc_error('zlog_thread_resize_msg_buf fail, rd[%d]', [rd]);
      exit( fail_goto);
    end;
    a_thread.init_version := zlog_env_init_version;
  end;
  exit(rd);
end;

function zlog_rule_output( a_rule : Pzlog_rule; a_thread : Pzlog_thread):integer;
begin
  case a_rule.compare_AnsiChar  of
  '*' :
    Exit(a_rule.output(a_rule, a_thread));
    //break;
  '.' :
  begin
    if a_thread.event.level >= a_rule.level then begin
      Exit(a_rule.output(a_rule, a_thread));
    end
    else begin
      Exit(0);
    end;
  end;
  '=' :
  begin
    if a_thread.event.level = a_rule.level then
      Exit(a_rule.output(a_rule, a_thread))
    else
      Exit(0);
  end;

  '!' :
  begin
    if a_thread.event.level <> a_rule.level then
      Exit(a_rule.output(a_rule, a_thread))
    else
      Exit(0);
  end;

  end;
  Result := 0;
end;

function zlog_category_output( a_category : Pzlog_category; a_thread : Pzlog_thread):integer;
var
  i, rc : integer;
   a_rule : Pzlog_rule;
begin
  rc := 0;
  { go through all match rules to output }
  //zc_arraylist_foreach(a_category.fit_rules, i, a_rule)
   //a_rule := a_category.fit_rules._array[0];
  for i := 0 to a_category.fit_rules.len -1 do
  begin
    a_rule := a_category.fit_rules._array[i];
    rc := zlog_rule_output(a_rule, a_thread);
  end;
  Result := rc;
end;



procedure zlog_category_rollback_rules( a_category : Pzlog_category);
begin
  assert(a_category <> nil);
  if nil =a_category.fit_rules_backup then begin
    zc_warn('a_category.fit_rules_backup in nil, never update before', []);
    exit;
  end;
  if a_category.fit_rules <> nil then
  begin
    { update success, rm new and backup }
    zc_arraylist_del(a_category.fit_rules);
    a_category.fit_rules := a_category.fit_rules_backup;
    a_category.fit_rules_backup := nil;
  end
  else begin
    { update fail, just backup }
    a_category.fit_rules := a_category.fit_rules_backup;
    a_category.fit_rules_backup := nil;
  end;
  memcpy(@a_category.level_bitmap, @a_category.level_bitmap_backup,
      sizeof(a_category.level_bitmap));
  memset(@a_category.level_bitmap_backup, $00,
      sizeof(a_category.level_bitmap_backup));
   { always success }
end;



procedure zlog_category_table_rollback_rules( categories : Pzc_hashtable);
var
    a_entry    : Pzc_hashtable_entry;
    a_category : Pzlog_category;
begin
  assert(categories <> nil);
  //zc_hashtable_foreach(categories, a_entry)
  a_entry := zc_hashtable_begin(categories);
  while a_entry <> nil do
  begin
    a_category := Pzlog_category(a_entry.value);
    zlog_category_rollback_rules(a_category);
    a_entry := zc_hashtable_next(categories, a_entry)
  end;

end;



procedure zlog_category_commit_rules( a_category : Pzlog_category);
begin
  assert(a_category <> nil);
  if nil =a_category.fit_rules_backup then begin
    zc_warn('a_category.fit_rules_backup is nil, never update before', []);
    Exit;
  end;
  zc_arraylist_del(a_category.fit_rules_backup);
  a_category.fit_rules_backup := nil;
  memset(@a_category.level_bitmap_backup, $00,
      sizeof(a_category.level_bitmap_backup));

end;



procedure zlog_category_table_commit_rules( categories : Pzc_hashtable);
var
    a_entry    : Pzc_hashtable_entry;
    a_category : Pzlog_category;
begin
  assert(categories <> nil);
  //zc_hashtable_foreach(categories, a_entry)
  a_entry := zc_hashtable_begin(categories);
  while a_entry <> nil do
  begin
    a_category := Pzlog_category(a_entry.value);
    zlog_category_commit_rules(a_category);
    a_entry := zc_hashtable_next(categories, a_entry)
  end;

end;



function zlog_category_update_rules( a_category : Pzlog_category; new_rules : Pzc_arraylist):integer;
begin
  zc_assert(a_category <> nil, -1);
  zc_assert(new_rules <> nil, -1);
  { 1st, mv fit_rules fit_rules_backup }
  if a_category.fit_rules_backup <> nil then
     zc_arraylist_del(a_category.fit_rules_backup);
  a_category.fit_rules_backup := a_category.fit_rules;
  a_category.fit_rules := nil;
  memcpy(@a_category.level_bitmap_backup, @a_category.level_bitmap,
      sizeof(a_category.level_bitmap));
  { 2nd, obtain new_rules to fit_rules }
  if zlog_category_obtain_rules(a_category, new_rules) > 0 then
  begin
    zc_error('zlog_category_obtain_rules fail', []);
    a_category.fit_rules := nil;
    Exit(-1);
  end;
  { keep the fit_rules_backup not change, return }
  Result := 0;
end;



function zlog_category_table_update_rules( categories : Pzc_hashtable; new_rules : Pzc_arraylist):integer;
var
    a_entry    : Pzc_hashtable_entry;
    a_category : Pzlog_category;
begin
  zc_assert(categories <> nil, -1);
  //zc_hashtable_foreach(categories, a_entry)
  a_entry := zc_hashtable_begin(categories);
  while a_entry <> nil do
  begin
    a_category := Pzlog_category(a_entry.value);
    if zlog_category_update_rules(a_category, new_rules) > 0 then
    begin
      zc_error('zlog_category_update_rules fail, try rollback', []);
      Exit(-1);
    end;
    a_entry := zc_hashtable_next(categories, a_entry);
  end;
  Result := 0;
end;



function zlog_rule_set_record( a_rule : Pzlog_rule; records : Pzc_hashtable):integer;
var
  a_record : Pzlog_record;
begin
  if (@a_rule.output <> @zlog_rule_output_static_record)
   and   (@a_rule.output <> @zlog_rule_output_dynamic_record) then begin
    Exit( 0); { fliter, may go through not record rule }
  end;
  a_record := zc_hashtable_get(records, @a_rule.record_name);
  if a_record <> nil then begin
    a_rule.record_func := a_record.output;
  end;
  Result := 0;
end;



function zlog_reload({const} config : PTChar):integer;
var
  rc,
  i        : integer;
  new_conf : Pzlog_conf;
  a_rule   : Pzlog_rule;
  c_up     : integer;
  label _quit, _err;
begin
  rc := 0;
  i := 0;
  new_conf := nil;
  c_up := 0;
  zc_debug('------zlog_reload start------', []);
  rc := pthread_rwlock_wrlock(@zlog_env_lock);
  if rc > 0 then begin
    zc_error('pthread_rwlock_wrlock fail, rc[%d]', [rc]);
    Exit(-1);
  end;
  if 0>=zlog_env_is_init then begin
    zc_error('never call zlog_init() or dzlog_init() before', []);
    goto _quit;
  end;
  { use last conf file }
  if config = nil then
     config := @zlog_env_conf.conf_file;
  { reach reload period }
  if config = PTChar(-1) then
  begin
    { test again, avoid other threads already reloaded }
    if zlog_env_reload_conf_count > zlog_env_conf.reload_conf_period then  begin
      config := zlog_env_conf.conf_file;
    end
    else
    begin
      { do nothing, already done }
      goto _quit;
    end;
  end;
  { reset counter, whether automaticlly or mannually }
  zlog_env_reload_conf_count := 0;
  new_conf := zlog_conf_new(config);
  if nil =new_conf then begin
    zc_error('zlog_conf_new fail', []);
    goto _err;
  end;
  //zc_arraylist_foreach(new_conf.rules, i, a_rule)
  // a_rule := new_conf.rules._array[0];
  for i := 0 to new_conf.rules.len - 1 do
  begin
    a_rule := new_conf.rules._array[i];
    zlog_rule_set_record(a_rule, zlog_env_records);
  end;

  if zlog_category_table_update_rules(zlog_env_categories, new_conf.rules ) > 0 then
  begin
    c_up := 0;
    zc_error('zlog_category_table_update fail', []);
    goto _err;
  end
  else begin
    c_up := 1;
  end;
  Inc(zlog_env_init_version);
  if c_up > 0 then
     zlog_category_table_commit_rules(zlog_env_categories);
  zlog_conf_del(zlog_env_conf);
  zlog_env_conf := new_conf;
  zc_debug('------(zlog_reload) success, total init verison[%d] ------', [zlog_env_init_version]);
  rc := pthread_rwlock_unlock(@zlog_env_lock);
  if rc > 0 then begin
    zc_error('pthread_rwlock_unlock fail, rc=[%d]', [rc]);
    Exit(-1);
  end;
  Exit(0);
_err:
  { fail, roll back everything }
  zc_warn('zlog_reload fail, use old conf file, still working', []);
  if new_conf  <> nil then
     zlog_conf_del(new_conf);
  if c_up > 0 then
     zlog_category_table_rollback_rules(zlog_env_categories);
  zc_error('------(zlog_reload) fail, total init version[%d] ------', [zlog_env_init_version]);
  rc := pthread_rwlock_unlock(@zlog_env_lock);
  if rc > 0 then begin
    zc_error('pthread_rwlock_unlock fail, rc=[%d]', [rc]);
    Exit(-1);
  end;
  Exit(-1);
_quit:
  zc_debug('------(zlog_reload) do PostDec(nothing)----', []);
  rc := pthread_rwlock_unlock(@zlog_env_lock);
  if rc > 0 then begin
    zc_error('pthread_rwlock_unlock fail, rc=[%d]', [rc]);
    Exit(-1);
  end;
  Result := 0;
end;



procedure zlog_event_set_fmt(a_event : Pzlog_event; category_name : PTChar; category_name_len : size_t;const &file : String; file_len : size_t;const func :String; func_len : size_t; line : long; level : integer;const str_format : PTChar; str_args : array of const);
var
  i: Integer;
  s: AnsiString;
begin
  {
   * category_name point to zlog_category_output's category.name
   }
  s := &file;
  a_event.category_name     := category_name;
  a_event.category_name_len := category_name_len;
  a_event._file             := PTChar(s);
  a_event.file_len          := file_len;
  s := func;
  a_event.func              := PTChar(s);
  a_event.func_len          := func_len;
  a_event.line              := line;
  a_event.level             := level;
  a_event.generate_cmd      := ZLOG_FMT;
  a_event.str_format        := str_format;
  SetLength(a_event.str_args, Length(str_args));
  for i := 0 to High( str_args ) do
      a_event.str_args[i] := str_args[i];
  { pid should fetch eveytime, as no one knows,
   * when does user fork his process
   * so clean here, and fetch at spec.c
   }
  a_event.pid := pid_t(0);
  { in a event's life cycle, time will be get when spec need,
   * and keep unchange though all event's life cycle
   * zlog_spec_write_time gettimeofday
   }
  a_event.time_stamp.tv_sec := 0;

end;



function zlog_thread_rebuild_event( a_thread : Pzlog_thread; time_cache_count : integer):integer;
var
  event_new : Pzlog_event;
  label _err;
begin
  event_new := nil;
  zc_assert(a_thread <> nil, -1);
  event_new := zlog_event_new(time_cache_count);
  if nil =event_new then begin
    zc_error('zlog_event_new fail', []);
    goto _err;
  end;
  zlog_event_del(a_thread.event);
  a_thread.event := event_new;
  Exit(0);
_err:
  if event_new <> nil then
     zlog_event_del(event_new);
  Result := -1;
end;



function zlog_thread_rebuild_msg_buf( a_thread : Pzlog_thread; buf_size_min, buf_size_max : size_t):integer;
var
  pre_msg_buf_new,
  msg_buf_new     : Pzlog_buf;
  label _err;
begin
  pre_msg_buf_new := nil;
  msg_buf_new := nil;
  zc_assert(a_thread <> nil, -1);
  if (a_thread.msg_buf.size_min = buf_size_min)  and  (a_thread.msg_buf.size_max = buf_size_max) then  begin
    zc_debug('buf size not changed, no need rebuild', []);
    Exit(0);
  end;
  pre_msg_buf_new := zlog_buf_new(buf_size_min, buf_size_max, '...'#10);
  if nil =pre_msg_buf_new then
  begin
    zc_error('zlog_buf_new fail', []);
    goto _err;
  end;
  msg_buf_new := zlog_buf_new(buf_size_min, buf_size_max, '...'#10);
  if nil =msg_buf_new then begin
    zc_error('zlog_buf_new fail', []);
    goto _err;
  end;
  zlog_buf_del(a_thread.pre_msg_buf);
  a_thread.pre_msg_buf := pre_msg_buf_new;
  zlog_buf_del(a_thread.msg_buf);
  a_thread.msg_buf := msg_buf_new;
  Exit(0);
_err:
  if pre_msg_buf_new <> nil then
     zlog_buf_del(pre_msg_buf_new);
  if msg_buf_new <> nil then
     zlog_buf_del(msg_buf_new);
  Result := -1;
end;

function zlog_buf_new(buf_size_min, buf_size_max : size_t;const truncate_str : PTChar):Pzlog_buf;
var
  a_buf : Pzlog_buf;
  label _err;
begin
  if buf_size_min = 0 then begin
    zc_error('buf_size_min = 0, not allowed', []);
    Exit(nil);
  end;
  if (buf_size_max <> 0)  and  (buf_size_max < buf_size_min) then
  begin
    zc_error('buf_size_max[%lu] < buf_size_min[%lu]  and  buf_size_max <> 0',
              [ulong(buf_size_max), ulong(buf_size_min)]);
    Exit(nil);
  end;
  a_buf := calloc(1, sizeof( a_buf^));
  if nil =a_buf then begin
    zc_error('calloc fail, errno[%d]', [errno]);
    Exit(nil);
  end;
  if truncate_str <> nil then
  begin
    if StrLen(truncate_str) > Sizeof(a_buf.truncate_str) - 1 then  begin
      zc_error('truncate_str[%s] overflow', [truncate_str]);
      goto _err;
    end
    else
    begin
       Move(truncate_str^, a_buf.truncate_str, StrLen(truncate_str));
    end;
    a_buf.truncate_str_len := Length(truncate_str);
  end;
  a_buf.size_min := buf_size_min;
  a_buf.size_max := buf_size_max;
  a_buf.size_real := a_buf.size_min;
  a_buf.start := calloc(1, a_buf.size_real);
  if nil =a_buf.start then begin
    zc_error('calloc fail, errno[%d]', [errno]);
    goto _err;
  end;
  a_buf.tail := a_buf.start;
  a_buf.end_plus_1 := a_buf.start + a_buf.size_real;
  a_buf._end := a_buf.end_plus_1 - 1;
  //zlog_buf_profile(a_buf, ZC_DEBUG);
  Exit(a_buf);
_err:
  zlog_buf_del(a_buf);
  Result := nil;
end;

function zlog_event_new( time_cache_count : integer):Pzlog_event;
var
  a_event : Pzlog_event;
  tid64 : uint64;
  label _err;
begin
  a_event := calloc(1, sizeof(Tzlog_event));
  if nil =a_event then begin
    zc_error('calloc fail, errno[%d]', [errno]);
    Exit(nil);
  end;
  a_event.time_caches := calloc(time_cache_count, sizeof(Tzlog_time_cache));
  if nil = a_event.time_caches then begin
    zc_error('calloc fail, errno[%d]', [errno]);
    FreeMem(a_event);
    Exit(nil);
  end;
  a_event.time_cache_count := time_cache_count;
  {
   * at the zlog_init we gethostname,
   * u don't always change your hostname, eh?
   }
  if gethostname(a_event.host_name, sizeof(a_event.host_name) - 1) > 0  then
  begin
    zc_error('gethostname fail, errno[%d]', [errno]);
    goto _err;
  end;
  a_event.host_name_len := Length(a_event.host_name);
  { tid is bound to a_event
   * as in whole lifecycle event persists
   * even fork to oth pid, tid not change
   }
  a_event.tid := pthread_self();
  a_event.tid_str_len := sprintf(a_event.tid_str, '%lu', [intptr(a_event.tid.p)]);
  a_event.tid_hex_str_len := sprintf(a_event.tid_hex_str, '%x', [intptr(a_event.tid.p)]);
{$IFDEF __linux__}
  a_event.ktid := syscall(SYS_gettid);
{$elif defined(__APPLE__}}
    pthread_threadid_np(nil, &tid64);
    a_event.tid := (pthread_t)tid64;
{$ENDIF}
{$IF defined(__linux__)  or  defined(__APPLE__)}
  a_event.ktid_str_len := sprintf(a_event.ktid_str, '%u', (Uint32)a_event.ktid);
{$ENDIF}
  //zlog_event_profile(a_event, ZC_DEBUG);
  Exit(a_event);
_err:
  zlog_event_del(a_event);
  Result := nil;
end;

procedure zlog_mdc_kv_del( a_mdc_kv : Pointer);
begin
  zc_debug('zlog_mdc_kv_del[%p]', [Pzlog_mdc_kv(a_mdc_kv)]);
  freeMem(a_mdc_kv);
end;

function zlog_mdc_new:Pzlog_mdc;
var
  a_mdc : Pzlog_mdc;
  label _err;
begin
  a_mdc := calloc(1, sizeof(Tzlog_mdc));
  if nil =a_mdc then begin
    zc_error('calloc fail, errno[%d]', [errno]);
    Exit(nil);
  end;
  a_mdc.tab := zc_hashtable_new(20,
            zc_hashtable_str_hash,
            zc_hashtable_str_equal, nil,
             zlog_mdc_kv_del);
  if nil =a_mdc.tab then begin
    zc_error('zc_hashtable_new fail', []);
    goto _err;
  end;
  //zlog_mdc_profile(a_mdc, ZC_DEBUG);
  Exit(a_mdc);
_err:
  zlog_mdc_del(a_mdc);
  Result := nil;
end;



function zlog_thread_new( init_version : integer; buf_size_min, buf_size_max : size_t; time_cache_count : integer):Pzlog_thread;
var
  a_thread : Pzlog_thread;
  label _err;
begin
  a_thread := calloc(1, sizeof(Tzlog_thread));
  if nil =a_thread then begin
    zc_error('calloc fail, errno[%d]', [errno]);
    Exit(nil);
  end;
  a_thread.init_version := init_version;
  a_thread.mdc := zlog_mdc_new();
  if nil =a_thread.mdc then begin
    zc_error('zlog_mdc_new fail', []);
    goto _err;
  end;
  a_thread.event := zlog_event_new(time_cache_count);
  if nil =a_thread.event then begin
    zc_error('zlog_event_new fail', []);
    goto _err;
  end;
  a_thread.pre_path_buf := zlog_buf_new(MAXLEN_PATH + 1, MAXLEN_PATH + 1, nil);
  if nil =a_thread.pre_path_buf then
  begin
    zc_error('zlog_buf_new fail', []);
    goto _err;
  end;
  a_thread.path_buf := zlog_buf_new(MAXLEN_PATH + 1, MAXLEN_PATH + 1, nil);
  if nil =a_thread.path_buf then begin
    zc_error('zlog_buf_new fail', []);
    goto _err;
  end;
  a_thread.archive_path_buf := zlog_buf_new(MAXLEN_PATH + 1, MAXLEN_PATH + 1, nil);
  if nil =a_thread.archive_path_buf then begin
    zc_error('zlog_buf_new fail', []);
    goto _err;
  end;
  a_thread.pre_msg_buf := zlog_buf_new(buf_size_min, buf_size_max, '...'#10);
  if nil =a_thread.pre_msg_buf then begin
    zc_error('zlog_buf_new fail', []);
    goto _err;
  end;
  a_thread.msg_buf := zlog_buf_new(buf_size_min, buf_size_max, '...'#10);
  if nil =a_thread.msg_buf then begin
    zc_error('zlog_buf_new fail', []);
    goto _err;
  end;
  //zlog_thread_profile(a_thread, ZC_DEBUG);
  Exit(a_thread);
_err:
  zlog_thread_del(a_thread);
  Result := nil;
end;


function zlog_category_needless_level(a_category: Pzlog_category;const lv: Integer): Boolean;
begin
   Result := (a_category <> nil) and (0 >= ((a_category.level_bitmap[lv div 8] shr (7 - lv mod 8)) and $01))
end;

procedure zlog(category : Pzlog_category; &file : String; filelen : size_t;const func :String; funclen : size_t; line : long;const level : integer; format : PTChar; args : array of const);
var
    a_thread : Pzlog_thread;
    label _exit, _reload;
begin
  Assert(false);
  a_thread := nil;
  if (category <> nil)  and  (zlog_category_needless_level(category, level)) then
     exit;
  pthread_rwlock_rdlock(@zlog_env_lock);
  if 0 >= zlog_env_is_init then begin
    zc_error('never call zlog_init() or dzlog_init() before', []);
    goto _exit;
  end;
  if -1 = zlog_fetch_thread(a_thread) then
     goto _exit;

  zlog_event_set_fmt(a_thread.event, category.name, category.name_len,
                      &file, filelen, func, funclen, line, level,
                      format, args);
  if zlog_category_output(category, a_thread) > 0 then
  begin
    zc_error('zlog_output fail, srcfile[%s], srcline[%ld]', [&file, line]);
    //va_end(args);
    goto _exit;
  end;
  //va_end(args);
  if (zlog_env_conf.reload_conf_period > 0)  and
     (PreInc(zlog_env_reload_conf_count) > zlog_env_conf.reload_conf_period ) then
  begin
    { under the protection of lock read env conf }
    goto _reload;
  end;

_exit:
  pthread_rwlock_unlock(@zlog_env_lock);
  exit;

_reload:
  pthread_rwlock_unlock(@zlog_env_lock);
  { will be wrlock, so after unlock }
  if zlog_reload(PTChar(-1)) > 0 then
  begin
    zc_error('reach reload-conf-period but zlog_reload fail, zlog-chk-conf [file] see detail', []);
  end;

end;

procedure zlog_debug(cat: Pzlog_category; fmt: PTChar; args: array of const) ;
begin
  Assert(false);
	zlog(cat, __FILE__, length(__FILE__), __FUNCTION__, Length(__FUNCTION__), __LINE__,
          	ZLOG_LEVEL_DEBUG, fmt, args)
end;

procedure zlog_trace(cat: Pzlog_category; fmt: PTChar; args: array of const) ;
begin
  Assert(false);
	zlog(cat, __FILE__, length(__FILE__), __FUNCTION__, Length(__FUNCTION__), __LINE__,
          	ZLOG_LEVEL_TRACE, fmt, args)
end;

procedure zlog_info(cat: Pzlog_category; fmt: PTChar; args: array of const) ;
begin
  Assert(false);
	zlog(cat, __FILE__, length(__FILE__), __FUNCTION__, Length(__FUNCTION__), __LINE__,
          	ZLOG_LEVEL_INFO, fmt, args)
end;

procedure zlog_fini;
var
  rc : integer;
  label _exit;
begin
  Assert(false);
  rc := 0;
  zc_debug('------zlog_fini----start----', []);
  rc := pthread_rwlock_wrlock(@zlog_env_lock);
  if rc > 0 then begin
    zc_error('pthread_rwlock_wrlock fail, rc[%d]', [rc]);
    exit;
  end;
  if 0 >=zlog_env_is_init then begin
    zc_error('before finish, must zlog_init() or dzlog_init() first', []);
    goto _exit;
  end;
  zlog_fini_inner();
  zlog_env_is_init := 0;

_exit:
  zc_debug('------zlog_fini----end----', []);
  rc := pthread_rwlock_unlock(@zlog_env_lock);
  if rc > 0 then begin
    zc_error('pthread_rwlock_unlock fail, rc=[%d]', [rc]);
    exit;
  end;

end;



function zc_hashtable_rehash( a_table : Pzc_hashtable):integer;
var
  i,j,
  tab_size : size_t;
  tab      : PPzc_hashtable_entry;
  p, q        : Pzc_hashtable_entry;
begin
  tab_size := 2 * a_table.tab_size;
  tab := calloc(tab_size, sizeof( tab^));
  if nil =tab then begin
    zc_error('calloc fail, errno[%d]', [errno]);
    Exit(-1);
  end;
  for i := 0 to a_table.tab_size-1 do
  begin
    p := (a_table.tab)[i];
    while p <> nil do
    begin
      q := p.next;
      p.next := nil;
      p.prev := nil;
      j := p.hash_key mod tab_size;
      if tab[j] <> nil then begin
        tab[j].prev := p;
        p.next := tab[j];
      end;
      tab[j] := p;
      p := q;
    end;
  end;
  freeMem(a_table.tab);
  a_table.tab := tab;
  a_table.tab_size := tab_size;
  Result := 0;
end;


function zc_hashtable_put( a_table : Pzc_hashtable; a_key, a_value : Pointer):integer;
var
  rc : integer;
  i : uint32;
  p : Pzc_hashtable_entry;
begin
  rc := 0;
  p := nil;
  i := a_table.hash(a_key) mod a_table.tab_size;
  p := (a_table.tab)[i];
  while p <> nil do
  begin
    if a_table.equal(a_key, p.key) > 0 then
      break;
    p := p.next;
  end;
  if p <> nil then
  begin
    if Assigned(a_table.key_del) then  begin
      a_table.key_del(p.key);
    end;
    if Assigned(a_table.value_del) then begin
      a_table.value_del(p.value);
    end;
    p.key := a_key;
    p.value := a_value;
    Exit(0);
  end
  else
  begin
    if a_table.nelem > a_table.tab_size * 1.3 then
    begin
      rc := zc_hashtable_rehash(a_table);
      if rc > 0 then begin
        zc_error('rehash fail', []);
        Exit(-1);
      end;
    end;
    p := calloc(1, sizeof( p^));
    if nil =p then begin
      zc_error('calloc fail, errno[%d]', [errno]);
      Exit(-1);
    end;
    p.hash_key := a_table.hash(a_key);
    p.key := a_key;
    p.value := a_value;
    p.next := nil;
    p.prev := nil;
    i := p.hash_key mod a_table.tab_size;
    if a_table.tab[i] <> nil then
    begin
      (a_table.tab)[i].prev := p;
      p.next := (a_table.tab)[i];
    end;
    (a_table.tab)[i] := p;
    Inc(a_table.nelem);
  end;
  Result := 0;
end;



function zlog_rule_is_wastebin( a_rule : Pzlog_rule):integer;
begin
  zc_assert(a_rule <> nil, -1);
  if STRCOMP(a_rule.category, '!') = 0 then  begin
    Exit(1);
  end;
  Result := 0;
end;



procedure zlog_cateogry_overlap_bitmap( a_category : Pzlog_category; a_rule : Pzlog_rule);
var
  i : integer;
begin
  for i := 0 to sizeof(a_rule.level_bitmap)-1 do
  begin
    a_category.level_bitmap[i]  := a_category.level_bitmap[i]  or (a_rule.level_bitmap[i]);
  end;
end;



function zlog_rule_match_category( a_rule : Pzlog_rule; category : PTChar):integer;
var
  len : size_t;
begin
  zc_assert(a_rule <> nil, -1);
  zc_assert(category <> nil, -1);
  if STRCOMP(a_rule.category, '*') = 0 then
  begin
    { '*' match anything, so go on }
    Exit(1);
  end
  else if (STRCOMP(a_rule.category,  category) = 0) then
  begin
    { accurate compare }
    Exit(1);
  end
  else
  begin
    { aa_ match aa_xx and aa, but not match aa1_xx }
    len := Length(a_rule.category);
    if a_rule.category[len - 1] = '_' then
    begin
      if Length(category) = len - 1 then  begin
         Dec(len);
      end;
      if STRNCMP(a_rule.category, category, len) = 0 then
      begin
        Exit(1);
      end;
    end;
  end;
  Result := 0;
end;



function zlog_category_obtain_rules( a_category : Pzlog_category; rules : Pzc_arraylist):integer;
var
  i, count,
  fit           : integer;
  a_rule,
  wastebin_rule : Pzlog_rule;
  label _err;
begin
  count := 0;
  fit := 0;
  wastebin_rule := nil;
  { before set, clean last fit rules first }
  if a_category.fit_rules <> nil then
     zc_arraylist_del(a_category.fit_rules);
  memset(@a_category.level_bitmap, $00, sizeof(a_category.level_bitmap));
  a_category.fit_rules := zc_arraylist_new(nil);
  if nil =(a_category.fit_rules) then
  begin
    zc_error('zc_arraylist_new fail', []);
    Exit(-1);
  end;
  { get match rules from all rules }
  //zc_arraylist_foreach(rules, i, a_rule)
  // a_rule := rules._array[0];
  for i := 0 to rules.len -1 do
  begin
    a_rule := rules._array[i] ;
    fit := zlog_rule_match_category(a_rule, a_category.name);
    if fit > 0 then
    begin
      if zc_arraylist_add(a_category.fit_rules, a_rule) > 0 then  begin
        zc_error('zc_arrylist_add fail', []);
        goto _err;
      end;
      zlog_cateogry_overlap_bitmap(a_category, a_rule);
      Inc(count);
    end;
    if zlog_rule_is_wastebin(a_rule) > 0 then
      wastebin_rule := a_rule;
  end;

  if count = 0 then
  begin
    if wastebin_rule <> nil then
    begin
      zc_debug('category[%s], no match rules, use wastebin_rule', [a_category.name]);
      if zc_arraylist_add(a_category.fit_rules, wastebin_rule ) > 0 then
      begin
        zc_error('zc_arrylist_add fail', []);
        goto _err;
      end;
      zlog_cateogry_overlap_bitmap(a_category, wastebin_rule);
      Inc(count);
    end
    else begin
      zc_debug('category[%s], no match rules and no wastebin_rule', [a_category.name]);
    end;
  end;
  Exit(0);
_err:
  zc_arraylist_del(a_category.fit_rules);
  a_category.fit_rules := nil;
  Result := -1;
end;



function zlog_category_new(const name : PTChar; rules : Pzc_arraylist):Pzlog_category;
var
    len        : size_t;
    a_category : Pzlog_category;
    label _err;
begin
  assert(name <> nil);
  assert(rules <> nil);
  len := Length(name);
  if len > sizeof(a_category.name) - 1  then
  begin
    zc_error('name[%s] too long', [name]);
    Exit(nil);
  end;
  a_category := calloc(1, sizeof(Tzlog_category));
  if nil =a_category then begin
    zc_error('calloc fail, errno[%d]', [errno]);
    Exit(nil);
  end;
  Move(name^, a_category.name, StrLen(name));
  a_category.name_len := len;
  if zlog_category_obtain_rules(a_category, rules) > 0 then
  begin
    zc_error('zlog_category_fit_rules fail', []);
    goto _err;
  end;
  zlog_category_profile(a_category, __ZC_DEBUG);
  Exit(a_category);
_err:
  zlog_category_del(a_category);
  Result := nil;
end;

function zlog_category_table_fetch_category(categories : Pzc_hashtable;const category_name : PTChar; rules : Pzc_arraylist):Pzlog_category;
var
  a_category : Pzlog_category;
  label _err;
begin
  assert(categories <> nil);
  { 1st find category in global category map }
  a_category := zc_hashtable_get(categories, category_name);
  if a_category <> nil then Exit(a_category);
  { else not found, create one }
  a_category := zlog_category_new(category_name, rules);
  if nil =a_category then begin
    zc_error('zc_category_new fail', []);
    Exit(nil);
  end;
  if zc_hashtable_put(categories, @a_category.name, a_category) > 0 then
  begin
    zc_error('zc_hashtable_put fail', []);
    goto _err;
  end;
  Exit(a_category);

_err:
  zlog_category_del(a_category);
  Result := nil;
end;

function zlog_get_category(const cname : PTChar):Pzlog_category;
var
  rc         : integer;
  a_category : Pzlog_category;
  label _err;
begin
  Assert(false);
  rc := 0;
  a_category := nil;
  assert(cname <> nil);
  zc_debug('------zlog_get_category[%s]----start----', [cname]);
  rc := pthread_rwlock_wrlock(@zlog_env_lock);
  if rc > 0 then begin
    zc_error('pthread_rwlock_wrlock fail, rc[%d]', [rc]);
    Exit(nil);
  end;
  if 0 >= zlog_env_is_init then begin
    zc_error('never call zlog_init() or dzlog_init() before', []);
    a_category := nil;
    goto _err;
  end;
  a_category := zlog_category_table_fetch_category(zlog_env_categories, cname, zlog_env_conf.rules);
  if nil = a_category then begin
    zc_error('zlog_category_table_fetch_category[%s] fail', [cname]);
    goto _err;
  end;
  zc_debug('------(zlog_get_category)[%s] success, --(end)---- ', [cname]);
  rc := pthread_rwlock_unlock(@zlog_env_lock);
  if rc > 0 then begin
    zc_error('pthread_rwlock_unlock fail, rc=[%d]', [rc]);
    Exit(nil);
  end;
  Exit(a_category);
_err:
  zc_error('------(zlog_get_category)[%s] fail, --(end)---- ', [cname]);
  rc := pthread_rwlock_unlock(@zlog_env_lock);
  if rc > 0 then begin
    zc_error('pthread_rwlock_unlock fail, rc=[%d]', [rc]);
    Exit(nil);
  end;
  Result := nil;
end;



procedure zlog_record_table_del( records : Pzc_hashtable);
begin
  assert(records <> nil);
  zc_hashtable_del(records);
  zc_debug('zlog_record_table_del[%p]', [records]);

end;




procedure zlog_category_table_del( categories : Pzc_hashtable);
begin
  assert(categories <> nil);
  zc_hashtable_del(categories);
  zc_debug('zlog_category_table_del[%p]', [categories]);

end;



procedure zlog_fini_inner;
begin
  { pthread_key_delete(zlog_thread_key); }
  { never use pthread_key_delete,
   * it will cause other thread can not release zlog_thread_t
   * after one thread call pthread_key_delete
   * also key not init will cause a core dump
   }
  if zlog_env_categories <> nil then
     zlog_category_table_del(zlog_env_categories);
  zlog_env_categories := nil;
  zlog_default_category := nil;
  if zlog_env_records <> nil then
     zlog_record_table_del(zlog_env_records);
  zlog_env_records := nil;
  if zlog_env_conf <> nil then
     zlog_conf_del(zlog_env_conf);
  zlog_env_conf := nil;

end;



procedure zlog_record_profile( a_record : Pzlog_record; flag : integer);
begin
  assert(a_record <> nil);
  zc_profile(flag, '--(record):[%p][%s:%p]--', [a_record, @a_record.name,  @a_record.output]);

end;



procedure zlog_record_table_profile( records : Pzc_hashtable; flag : integer);
var
    a_entry  : Pzc_hashtable_entry;
    a_record : Pzlog_record;
begin
  assert(records <> nil);
  zc_profile(flag, '---record_table[%p]---', [records]);
  //zc_hashtable_foreach(records, a_entry)
  a_entry := zc_hashtable_begin(records);
  while a_entry <> nil do
  begin
    a_record := Pzlog_record(a_entry.value);
    zlog_record_profile(a_record, flag);
    a_entry := zc_hashtable_next(records, a_entry)
  end;

end;



procedure zlog_record_del(a_record : Pointer);
begin
  assert(a_record <> nil);
  zc_debug('zlog_record_del[%p]', [a_record]);
  freeMem(a_record);

end;



function zlog_record_table_new:Pzc_hashtable;
var
  records : Pzc_hashtable;
begin
  records := zc_hashtable_new(20,
        zc_hashtable_str_hash,
        zc_hashtable_str_equal,
       nil,  zlog_record_del);
  if nil =records then begin
    zc_error('zc_hashtable_new fail', []);
    Exit(nil);
  end
  else
  begin
    zlog_record_table_profile(records, Int(__ZC_DEBUG));
    Exit(records);
  end;
end;



function zc_hashtable_next( a_table : Pzc_hashtable; a_entry : Pzc_hashtable_entry):Pzc_hashtable_entry;
var
  i, j : size_t;
begin
  if a_entry.next <> nil then
     Exit(a_entry.next);
  i := a_entry.hash_key mod a_table.tab_size;
  for j := i + 1 to a_table.tab_size-1 do
  begin
    if a_table.tab[j] <> nil then
    begin
      Exit((a_table.tab)[j]);
    end;
  end;
  Result := nil;
end;



procedure zlog_category_profile( a_category : Pzlog_category; flag : integer);
var
  i : integer;
  a_rule : Pzlog_rule;
begin
  assert(a_category <> nil);
  zc_profile(flag, '---category[%p][%s][%p]---',
      [a_category,
      @a_category.name,
      a_category.fit_rules]);
  if a_category.fit_rules <> nil then
  begin
    //zc_arraylist_foreach(a_category.fit_rules, i, a_rule)

    //a_rule := a_category.fit_rules._array[0];
    for i := 0 to a_category.fit_rules.len - 1 do
    begin
      a_rule := a_category.fit_rules._array[i];
      zlog_rule_profile(a_rule, flag);
    end;
  end;

end;



function zc_hashtable_begin( a_table : Pzc_hashtable):Pzc_hashtable_entry;
var
  i : size_t;
  p : Pzc_hashtable_entry;
begin
  for i := 0 to a_table.tab_size-1 do
  begin
    p := (a_table.tab)[i];
    while p <> nil do
    begin
      if p <> nil then Exit(p);
      p := p.next;
    end;
  end;
  Result := nil;
end;



procedure zlog_category_table_profile( categories : Pzc_hashtable; flag : integer);
var
    a_entry    : Pzc_hashtable_entry;
    a_category : Pzlog_category;
begin
  assert(categories <> nil);
  zc_profile(flag, '---category_table[%p]---', [categories]);
  //zc_hashtable_foreach(categories, a_entry)
  a_entry := zc_hashtable_begin(categories);
  while a_entry <> nil do
  begin
    a_category := Pzlog_category( a_entry.value);
    zlog_category_profile(a_category, flag);
    a_entry := zc_hashtable_next(categories, a_entry);
  end;

end;



procedure zlog_category_del( a_category : Pointer);
begin
  assert(a_category <> nil);
  if Pzlog_category(a_category).fit_rules <> nil then
     zc_arraylist_del(Pzlog_category(a_category).fit_rules);
  zc_debug('zlog_category_del[%p]', [a_category]);
  freeMem(a_category);

end;



function zc_hashtable_str_equal(const key1, key2 : Pointer):integer;
begin
  Result := Int(STRCOMP(PTChar(key1), PTChar(key2)) = 0);
end;



function zc_hashtable_str_hash(const str : Pointer):uint32;
var
  h : uint32;
  p : PTChar;
begin
{$Q-}
  h := 5381;
  p := str;
  while p^ <> #0 do
    h := ((h shl 5) + h) + Byte( PostInc(p)^); { hash * 33 + c }
  Result := h;
{$Q+}
end;



function zc_hashtable_new( a_size : size_t; hash : Tzc_hashtable_hash_fn; equal : Tzc_hashtable_equal_fn; key_del, value_del : Tzc_hashtable_del_fn):Pzc_hashtable;
var
  a_table : Pzc_hashtable;
begin
  a_table := calloc(1, sizeof( a_table^));
  if nil =a_table then begin
    zc_error('calloc fail, errno[%d]', [errno]);
    Exit(nil);
  end;
  a_table.tab := calloc(a_size, sizeof( (a_table.tab)^));
  if nil =a_table.tab then begin
    zc_error('calloc fail, errno[%d]', [errno]);
    freeMem(a_table);
    Exit(nil);
  end;
  a_table.tab_size := a_size;
  a_table.nelem := 0;
  a_table.hash := hash;
  a_table.equal := equal;
  { these two could be nil }
  a_table.key_del := key_del;
  a_table.value_del := value_del;
  Result := a_table;
end;



function zlog_category_table_new:Pzc_hashtable;
var
  categories : Pzc_hashtable;
begin
  categories := zc_hashtable_new(20,
        zc_hashtable_str_hash,
       zc_hashtable_str_equal,
       nil, zlog_category_del);
  if nil =categories then
  begin
    zc_error('zc_hashtable_new fail', []);
    Exit(nil);
  end
  else
  begin
    zlog_category_table_profile(categories, Int(__ZC_DEBUG));
    Exit(categories);
  end;
end;


procedure zlog_level_list_del( levels : Pzc_arraylist);
begin
  assert(levels <> nil);
  zc_arraylist_del(levels);
  zc_debug('zc_level_list_del[%p]', [levels]);

end;

procedure zlog_conf_del( a_conf : Pzlog_conf);
begin
  assert(a_conf <> nil);
  if a_conf.rotater <> nil then zlog_rotater_del(a_conf.rotater);
  if a_conf.levels <> nil then zlog_level_list_del(a_conf.levels);
  if a_conf.default_format <> nil then zlog_format_del(a_conf.default_format);
  if a_conf.formats <> nil then zc_arraylist_del(a_conf.formats);
  if a_conf.rules <> nil then zc_arraylist_del(a_conf.rules);
  freeMem(a_conf);
  zc_debug('zlog_conf_del[%p]', []);

end;

procedure zlog_rule_profile( a_rule : Pzlog_rule; flag : integer);
var
  i : integer;
  a_spec : Pzlog_spec;
begin
  assert(a_rule <> nil);
  zc_profile(flag, '---rule:[%p][%s%c%d]-[%d,%d][%s,%p,%d:%ld*%d~%s][%d][%d][%s:%s:%p];[%p]---',
            [a_rule, //%p
            @a_rule.category,
            a_rule.compare_AnsiChar ,
            a_rule.level,
            a_rule.file_perms,
            a_rule.file_open_flags,
            @a_rule.file_path,
            a_rule.dynamic_specs, //%p
            a_rule.static_fd,
            a_rule.archive_max_size,
            a_rule.archive_max_count,
            @a_rule.archive_path,
            a_rule.pipe_fd,
            a_rule.syslog_facility,
            @a_rule.record_name,
            @a_rule.record_path,
            Addr(a_rule.record_func),//%p
            a_rule._format]); //%p
  if a_rule.dynamic_specs <> nil then
  begin
    a_spec := a_rule.dynamic_specs._array[0];
    for i := 0 to a_rule.dynamic_specs.len -1 do
    begin
      zlog_spec_profile(a_spec, flag);
      a_spec := a_rule.dynamic_specs._array[i] ;
    end;
  end;

end;


procedure zlog_level_profile( a_level : Pzlog_level; flag : integer);
begin
  assert(a_level <> nil);
  zc_profile(flag, '---level[%p][%d,%s,%s,%d,%d]---',
    [a_level,
    a_level.int_level,
    a_level.str_uppercase,
    a_level.str_lowercase,
    int( a_level.str_len),
    a_level.syslog_level]);

end;



procedure zlog_level_list_profile( levels : Pzc_arraylist; flag : integer);
var
  i : integer;
  a_level : Pzlog_level;
begin
  assert(levels <> nil);
  zc_profile(flag, '---level_list[%p]---', [levels]);
  //zc_arraylist_foreach(levels, i, a_level)
  i := 0; a_level := levels._array[0];
  while (i < levels.len) do
  begin
    { skip empty slots }
    if a_level <> nil then
       zlog_level_profile(a_level, flag);
    Inc(i) ;
    a_level := levels._array[i];

  end;

end;



procedure zlog_rotater_profile( a_rotater : Pzlog_rotater; flag : integer);
var
  i : integer;
  a_file : Pzlog_file;
begin
  assert(a_rotater <> nil);
  zc_profile(flag, '---rotater[%p][%p,%s,%d][%s,%s,%s,%ld,%ld,%d,%d,%d]--',
    [a_rotater,
    @(a_rotater.lock_mutex),
    a_rotater.lock_file,
    UIntptr(a_rotater.lock_fd),
    a_rotater.base_path,
    a_rotater.archive_path,
    a_rotater.glob_path,
    long(a_rotater.num_start_len),
    long(a_rotater.num_end_len),
    a_rotater.num_width,
    a_rotater.mv_type,
    a_rotater.max_count]
    );
  if a_rotater.files <> nil then
  begin
    i := 0;
    a_file := a_rotater.files._array[0];
    while (i < a_rotater.files.len) do
    begin
      zc_profile(flag, '[%s,%d].', [a_file.path, a_file.index]);
      Inc(i);
      a_file := a_rotater.files._array[i];

    end;
  end;

end;



procedure zlog_conf_profile( a_conf : Pzlog_conf; flag : integer);
var
    i        : integer;
    a_rule   : Pzlog_rule;
    a_format : Pzlog_format;
begin
  assert(a_conf <> nil);
  zc_profile(flag, '---conf[%p]---', [a_conf]);
  zc_profile(flag, '---global---', []);
  zc_profile(flag, '---file[%s],mtime[%s]---', [a_conf.conf_file, a_conf.mtime]);
  zc_profile(flag, '---in-memory conf[%s]---', [a_conf.cfg_ptr]);
  zc_profile(flag, '---strict init[%d]---', [a_conf.strict_init]);
  zc_profile(flag, '---buffer min[%ld]---', [a_conf.buf_size_min]);
  zc_profile(flag, '---buffer max[%ld]---', [a_conf.buf_size_max]);
  if a_conf.default_format <> nil then
  begin
    zc_profile(flag, '---default_format---', []);
    zlog_format_profile(a_conf.default_format, flag);
  end;
  zc_profile(flag, '---file perms[0%o]---', [a_conf.file_perms]);
  zc_profile(flag, '---reload conf period[%ld]---', [a_conf.reload_conf_period]);
  zc_profile(flag, '---fsync period[%ld]---', [a_conf.fsync_period]);
  zc_profile(flag, '---rotate lock file[%s]---', [a_conf.rotate_lock_file]);
  if a_conf.rotater <> nil then
     zlog_rotater_profile(a_conf.rotater, flag);
  if a_conf.levels <> nil then
     zlog_level_list_profile(a_conf.levels, flag);
  if a_conf.formats <> nil then
  begin
    zc_profile(flag, '---format list[%p]---', [a_conf.formats]);
    // a_format := a_conf.formats._array[0];
    for i := 0 to a_conf.formats.len - 1 do
    begin
      a_format := a_conf.formats._array[i] ;
      zlog_format_profile(a_format, flag);
    end;
  end;
  if a_conf.rules <> nil then
  begin
    zc_profile(flag, '---rule_list[%p]---', [a_conf.rules]);
    //a_rule := a_conf.rules._array[0];
    for i := 0 to a_conf.rules.len -1 do
    begin
      a_rule := a_conf.rules._array[i];
      zlog_rule_profile(a_rule, flag);
    end;
  end;

end;



function zlog_conf_build_without_file( a_conf : Pzlog_conf):integer;
var
  default_rule : Pzlog_rule;
begin
  a_conf.default_format := zlog_format_new(a_conf.default_format_line, @(a_conf.time_cache_count));
  if nil =a_conf.default_format then begin
    zc_error('zlog_format_new fail', []);
    Exit(-1);
  end;
  a_conf.rotater := zlog_rotater_new(a_conf.rotate_lock_file);
  if nil =a_conf.rotater then begin
    zc_error('zlog_rotater_new fail', []);
    Exit(-1);
  end;
  default_rule := zlog_rule_new(
      ZLOG_CONF_DEFAULT_RULE,
      a_conf.levels,
      a_conf.default_format,
      a_conf.formats,
      a_conf.file_perms,
      a_conf.fsync_period,
      @(a_conf.time_cache_count));
  if nil =default_rule then
  begin
    zc_error('zlog_rule_new fail', []);
    Exit(-1);
  end;
  { add default rule }
  if zc_arraylist_add(a_conf.rules, default_rule) > 0 then
  begin
    zlog_rule_del(default_rule);
    zc_error('zc_arraylist_add fail', []);
    Exit(-1);
  end;
  Result := 0;
end;



function zlog_conf_build_with_in_memory( a_conf : Pzlog_conf):integer;
var
  rc : integer;
  line : array[0..(MAXLEN_CFG_LINE + 1)-1] of TChar;
  pline : PTChar;
  section : integer;
begin
  rc := 0;
  pline := nil;
  section := 0;
  pline := line;
  memset(@line, $00, sizeof(line));
  pline := strtok(@a_conf.cfg_ptr, #10);
  while pline <> nil do
  begin
    rc := zlog_conf_parse_line(a_conf, pline, @section);
    if rc < 0 then begin
      zc_error('parse in-memory configurations[%s] line [%s] fail', [a_conf.cfg_ptr, pline]);
      break;
    end
    else
    if (rc > 0) then
    begin
      zc_error('parse in-memory configurations[%s] line [%s] fail', [a_conf.cfg_ptr, pline]);
      zc_warn('as strict init is set to false, ignore and go on', []);
      rc := 0;
      continue;
    end;
    pline := strtok(nil, #10);
  end;
  Result := rc;
end;



function zlog_rule_output_dynamic_record( a_rule : Pzlog_rule; a_thread : Pzlog_thread):integer;
var
  msg : Tzlog_msg;
  i: int;
  a_spec: Pzlog_spec;
begin
  if not Assigned(a_rule.record_func) then
  begin
    zc_error('user defined record funcion for [%s] not set, no output',
             [a_rule.record_name]);
    Exit(-1);
  end;
  //zlog_rule_gen_path(a_rule, a_thread);
  a_thread.path_buf.tail := a_thread.path_buf.start;
  i := 0; a_spec := a_rule.dynamic_specs._array[0];
  while (i < a_rule.dynamic_specs.len)  do
  begin
     if (a_spec.gen_path(a_spec, a_thread)> 0) then
     begin
       zc_error('zlog_spec_gen_path fail', []);
       Exit(-1);
     end;
     Inc(i);
     a_spec := a_rule.dynamic_specs._array[i];

  end;
  a_thread.path_buf^.tail := #0;
  if zlog_format_gen_msg(a_rule._format, a_thread) > 0 then
  begin
    zc_error('zlog_format_gen_msg fail', []);
    Exit(-1);
  end;
  zlog_buf_seal(a_thread.msg_buf);
  msg.buf := zlog_buf_str(a_thread.msg_buf);
  msg.len := zlog_buf_len(a_thread.msg_buf);
  msg.path := zlog_buf_str(a_thread.path_buf);
  if a_rule.record_func(@msg) > 0 then
  begin
    zc_error('a_rule.record fail', []);
    Exit(-1);
  end;
  Result := 0;
end;



function zlog_rule_output_static_record( a_rule : Pzlog_rule; a_thread : Pzlog_thread):integer;
var
  msg : Tzlog_msg;
begin
  if not Assigned(a_rule.record_func) then begin
    zc_error('user defined record funcion for [%s] not set, no output',
             [a_rule.record_name]);
    Exit(-1);
  end;
  if zlog_format_gen_msg(a_rule._format, a_thread) > 0 then
  begin
    zc_error('zlog_format_gen_msg fail', []);
    Exit(-1);
  end;
  zlog_buf_seal(a_thread.msg_buf);
  msg.buf := zlog_buf_str(a_thread.msg_buf);
  msg.len := zlog_buf_len(a_thread.msg_buf);
  msg.path := a_rule.record_path;
  if a_rule.record_func(@msg) > 0 then
  begin
    zc_error('a_rule.record fail', []);
    Exit(-1);
  end;
  Result := 0;
end;



function zlog_rule_output_stdout( a_rule : Pzlog_rule; a_thread : Pzlog_thread):integer;
begin
  if zlog_format_gen_msg(a_rule._format, a_thread) > 0 then
  begin
    zc_error('zlog_format_gen_msg fail', []);
    Exit(-1);
  end;
  if printf(zlog_buf_str(a_thread.msg_buf) , []) < 0  then
  begin
    zc_error('zlog_rule_output_stdout: write fail, errno[%d]', [errno]);
    Exit(-1);
  end;

  Result := 0;
end;

function __write(Handle: THandle; const Buffer: PTCHar; Count: LongWord): Integer;
var
  buf: PTChar;
begin
   if Handle = STDERR_FILENO  then
   begin
      buf := AllocMem(Count * SizeOf(TChar)) ;
      Move(Buffer^, buf^, count);
      Writeln(ErrOutput, buf);
      Result := Length(Buf);
      CloseFile(ErrOutput);
      FreeMem(Buf);
   end;
end;

function zlog_rule_output_stderr( a_rule : Pzlog_rule; a_thread : Pzlog_thread):integer;
begin
  if zlog_format_gen_msg(a_rule._format, a_thread) > 0 then
  begin
    zc_error('zlog_format_gen_msg fail', []);
    Exit(-1);
  end;
  if __write(STDERR_FILENO, zlog_buf_str(a_thread.msg_buf) , zlog_buf_len(a_thread.msg_buf)) < 0  then
  begin
    zc_error('zlog_rule_output_stderr: write fail, errno[%d]', [errno]);
    Exit(-1);
  end;
  Result := 0;
end;



function syslog_facility_atoi( facility : PTChar):integer;
begin
{$IFNDEF MSWINDOWS}
  { guess no unix system will choose -187
   * as its syslog facility, so it is a safe return value
   }
  zc_assert(facility, -187);
  if STRICMP(facility, =, 'LOG_LOCAL0') then Exit(LOG_LOCAL0);
  if STRICMP(facility, =, 'LOG_LOCAL1') then Exit(LOG_LOCAL1);
  if STRICMP(facility, =, 'LOG_LOCAL2') then Exit(LOG_LOCAL2);
  if STRICMP(facility, =, 'LOG_LOCAL3') then Exit(LOG_LOCAL3);
  if STRICMP(facility, =, 'LOG_LOCAL4') then Exit(LOG_LOCAL4);
  if STRICMP(facility, =, 'LOG_LOCAL5') then Exit(LOG_LOCAL5);
  if STRICMP(facility, =, 'LOG_LOCAL6') then Exit(LOG_LOCAL6);
  if STRICMP(facility, =, 'LOG_LOCAL7') then Exit(LOG_LOCAL7);
  if STRICMP(facility, =, 'LOG_USER') then Exit(LOG_USER);
  if STRICMP(facility, =, 'LOG_AUTHPRIV') then Exit(LOG_AUTHPRIV);
  if STRICMP(facility, =, 'LOG_CRON') then Exit(LOG_CRON);
  if STRICMP(facility, =, 'LOG_DAEMON') then Exit(LOG_DAEMON);
  if STRICMP(facility, =, 'LOG_FTP') then Exit(LOG_FTP);
  if STRICMP(facility, =, 'LOG_KERN') then Exit(LOG_KERN);
  if STRICMP(facility, =, 'LOG_LPR') then Exit(LOG_LPR);
  if STRICMP(facility, =, 'LOG_MAIL') then Exit(LOG_MAIL);
  if STRICMP(facility, =, 'LOG_NEWS') then Exit(LOG_NEWS);
  if STRICMP(facility, =, 'LOG_SYSLOG') then Exit(LOG_SYSLOG);
    Exit(LOG_AUTHPRIV);
{$ENDIF}
  zc_error('wrong syslog facility[%s], must in LOG_LOCAL[0-7] or LOG_USER', [facility]);
  Result := -187;
end;



function zlog_rule_output_pipe( a_rule : Pzlog_rule; a_thread : Pzlog_thread):integer;
begin
  if zlog_format_gen_msg(a_rule._format, a_thread) > 0 then
  begin
    zc_error('zlog_format_gen_msg fail', []);
    Exit(-1);
  end;
  if FileWrite(a_rule.pipe_fd, zlog_buf_str(a_thread.msg_buf)^ ,
      zlog_buf_len(a_thread.msg_buf)) < 0  then
  begin
    zc_error('zlog_rule_output_pipe: write fail, errno[%d]', [errno]);
    Exit(-1);
  end;
  Result := 0;
end;


function zlog_rule_output_static_file_rotate( a_rule : Pzlog_rule; a_thread : Pzlog_thread):integer;
var
  len : size_t;
  info : Tzlog_stat;
  fd : integer;
begin
  if zlog_format_gen_msg(a_rule._format, a_thread) > 0 then
  begin
    zc_error('zlog_format_gen_msg fail', []);
    Exit(-1);
  end;
  fd := Fileopen(a_rule.file_path, a_rule.file_open_flags or O_WRITE);
  if fd < 0 then begin
    zc_error('open file[%s] fail, errno[%d]', [a_rule.file_path, errno]);
    Exit(-1);
  end;
  len := zlog_buf_len(a_thread.msg_buf);
  if filewrite(fd, zlog_buf_str(a_thread.msg_buf)^ , len) < 0 then
  begin
    zc_error('zlog_rule_output_static_file_rotate: write fail, errno[%d]', [errno]);
    CloseHandle(fd);
    Exit(-1);
  end;
  if (a_rule.fsync_period > 0)  and  (PreInc(a_rule.fsync_count) >= a_rule.fsync_period) then
  begin
    a_rule.fsync_count := 0;
    if fsync(fd ) > 0 then
       zc_error('fsync[%d] fail, errno[%d]', [fd, errno]);
  end;
  if not CloseHandle(fd) then begin
    zc_error('close fail, maybe cause by write, errno[%d]', [errno]);
    Exit(-1);
  end;
  if len > a_rule.archive_max_size then
  begin
    zc_debug('one msgs len[%ld] > archive_max_size[%ld], no rotate',
              [long(len), long(a_rule.archive_max_size)]);
    Exit(0);
  end;
  if stat(a_rule.file_path, @info) > 0 then
  begin
    zc_warn('stat [%s] fail, errno[%d], maybe in rotating', [a_rule.file_path, errno]);
    Exit(0);
  end;
  { file not so big, return }
  if info.st_size + len < a_rule.archive_max_size then Exit(0);
  if zlog_rotater_rotate(zlog_env_conf.rotater,
                          a_rule.file_path, len,
                          zlog_rule_gen_archive_path(a_rule, a_thread),
                          a_rule.archive_max_size, a_rule.archive_max_count) > 0 then
  begin
    zc_error('zlog_rotater_rotate fail', []);
    Exit(-1);
  end;
 { success or no rotation do nothing }
  Result := 0;
end;

procedure zlog_buf_seal(a_buf: Pzlog_buf);
begin
  a_buf^.tail := #0
end;

function zlog_spec_gen_archive_path(a_spec: Pzlog_spec; a_thread: Pzlog_thread): int;
begin
	  Result := a_spec.gen_archive_path(a_spec, a_thread)
end;

function zlog_rule_gen_archive_path( a_rule : Pzlog_rule; a_thread : Pzlog_thread):PTChar;
var
  i : integer;
  a_spec : Pzlog_spec;
begin
  if nil =a_rule.archive_specs then
     Exit(a_rule.archive_path);
  zlog_buf_restart(a_thread.archive_path_buf);
  //zc_arraylist_foreach(a_rule.archive_specs, i, a_spec)
  i := 0;
  a_spec := a_rule.archive_specs._array[0];
  while (i < a_rule.archive_specs.len) do
  begin
    if zlog_spec_gen_archive_path(a_spec, a_thread) > 0 then
    begin
      zc_error('zlog_spec_gen_path fail', []);
      Exit(nil);
    end;
    Inc(i);
    a_spec := a_rule.archive_specs._array[i];

  end;
  zlog_buf_seal(a_thread.archive_path_buf);
  Result := zlog_buf_str(a_thread.archive_path_buf);
end;



function zlog_rotater_unlock( a_rotater : Pzlog_rotater):integer;
var
  rc : integer;
begin
  rc := 0;
  if not unlock_file(a_rotater.lock_fd) then  begin
    rc := -1;
  end
  else
  begin
        a_rotater.lock_fd := HANDLE(LONG_PTR(-1));
  end;
  if pthread_mutex_unlock(a_rotater.lock_mutex) > 0 then
  begin
    rc := -1;
    zc_error('pthread_mutext_unlock fail, errno[%d]', [errno]);
  end;
  Result := rc;
end;



procedure zlog_rotater_clean( a_rotater : Pzlog_rotater);
begin
  a_rotater.base_path := Pointer (0);
  a_rotater.archive_path := Pointer (0);
  a_rotater.max_count := 0;
  a_rotater.mv_type := 0;
  a_rotater.num_width := 0;
  a_rotater.num_start_len := 0;
  a_rotater.num_end_len := 0;
  memset(@a_rotater.glob_path, $00, sizeof(a_rotater.glob_path));
  if a_rotater.files <> nil then
     zc_arraylist_del(a_rotater.files);
  a_rotater.files := Pointer (0);
end;


function zlog_rotater_seq_files( a_rotater : Pzlog_rotater):integer;
var
  rc,
  nwrite,
  i,j : integer;
  a_file   : Pzlog_file;
  new_path : array[0..(MAXLEN_PATH + 1)-1] of TChar;
begin
  rc := 0;
  nwrite := 0;
  i := 0;
  a_file := a_rotater.files._array[0];
  while (i < a_rotater.files.len) do
  begin
    if (a_rotater.max_count > 0) and  (i < a_rotater.files.len - a_rotater.max_count) then
    begin
      { unlink aa.0 aa.1 .. aa.(n-c) }
      rc := _unlink(a_file.path);
      if rc > 0 then begin
        zc_error('unlink[%s] fail, errno[%d]', [a_file.path , errno]);
        Exit(-1);
      end;
      continue;
    end;
    Inc(i);
    a_file := a_rotater.files._array[i];

  end;
  if a_rotater.files.len > 0 then
  begin  { list is not empty }
    a_file := zc_arraylist_get(a_rotater.files, a_rotater.files.len-1);
    if nil =a_file then begin
      zc_error('zc_arraylist_get fail', []);
      Exit(-1);
    end;
    j := max(a_rotater.files.len-1, a_file.index) + 1;
  end
  else begin
    j := 0;
  end;
  { do the base_path mv  }
  memset(@new_path, $00, sizeof(new_path));
  nwrite := snprintf(new_path, sizeof(new_path), '%.*s%0*d%s',
                    [int( a_rotater.num_start_len), a_rotater.glob_path,
                    a_rotater.num_width, j,
                    PTChar(@a_rotater.glob_path) + a_rotater.num_end_len]);
  if (nwrite < 0)  or  (nwrite >= sizeof(new_path)) then
  begin
    zc_error('nwirte[%d], overflow or errno[%d]', [nwrite, errno]);
    Exit(-1);
  end;
  if rename(a_rotater.base_path, new_path) > 0 then
  begin
    zc_error('rename[%s].[%s] fail, errno[%d]', [a_rotater.base_path, new_path, errno]);
    Exit(-1);
  end;
  Result := 0;
end;



function zlog_rotater_roll_files( a_rotater : Pzlog_rotater):integer;
var
  i,
  rc,
  nwrite   : integer;
  new_path : array[0..(MAXLEN_PATH + 1)-1] of TChar;
  a_file   : Pzlog_file;
begin
  rc := 0;
  { now in the list, aa.0 aa.1 aa.2 aa.02... }
  for i := a_rotater.files.len - 1 downto 0 do
  begin
    a_file := zc_arraylist_get(a_rotater.files, i);
    if nil =a_file then begin
      zc_error('zc_arraylist_get fail', []);
      Exit(-1);
    end;
    if (a_rotater.max_count > 0)  and  (i >= a_rotater.max_count - 1) then
    begin
      { remove file.3 >= 3}
      rc := _unlink(a_file.path);
      if rc > 0 then begin
        zc_error('unlink[%s] fail, errno[%d]', [a_file.path , errno]);
        Exit(-1);
      end;
      continue;
    end;
    { begin rename aa.01.log . aa.02.log , using i, as index in list maybe repeat }
    memset(@new_path, $00, sizeof(new_path));
    nwrite := snprintf(new_path, sizeof(new_path), '%.*s%0*d%s',
                     [int( a_rotater.num_start_len), a_rotater.glob_path,
                      a_rotater.num_width, i + 1,
                      PTChar(@a_rotater.glob_path) + a_rotater.num_end_len]);
    if (nwrite < 0)  or  (nwrite >= sizeof(new_path)) then
    begin
      zc_error('nwirte[%d], overflow or errno[%d]', [nwrite, errno]);
      Exit(-1);
    end;
    if rename(a_file.path, new_path) > 0 then
    begin
      zc_error('rename[%s].[%s] fail, errno[%d]', [a_file.path, new_path, errno]);
      Exit(-1);
    end;
  end;
  { do the base_path mv  }
  memset(@new_path, $00, sizeof(new_path));
  nwrite := snprintf(new_path, sizeof(new_path), '%.*s%0*d%s',
                     [int(a_rotater.num_start_len), a_rotater.glob_path,
                      a_rotater.num_width, 0,
                      PTChar(@a_rotater.glob_path) + a_rotater.num_end_len]);
  if (nwrite < 0)  or  (nwrite >= sizeof(new_path)) then
  begin
    zc_error('nwirte[%d], overflow or errno[%d]', [nwrite, errno]);
    Exit(-1);
  end;
  if rename(a_rotater.base_path, new_path) > 0 then
  begin
    zc_error('rename[%s].[%s] fail, errno[%d]', [a_rotater.base_path, new_path, errno]);
    Exit(-1);
  end;
  Result := 0;
end;

function zc_arraylist_insert_inner( a_list : Pzc_arraylist; idx : integer; data : Pointer):integer;
begin
  if a_list._array[idx] = nil then
  begin
    a_list._array[idx] := data;
    Exit(0);
  end;
  if a_list.len > a_list.size - 1 then
  begin
    if zc_arraylist_expand_inner(a_list, 0) > 0 then
    begin
      zc_error('expand_internal fail', []);
      Exit(-1);
    end;
  end;
  move( (a_list._array + idx)^, (a_list._array + idx + 1)^,  (a_list.len - idx) * sizeof(Pointer ));
  a_list._array[idx] := data;
  Inc(a_list.len);
  Result := 0;
end;


function zc_arraylist_sortadd( a_list : Pzc_arraylist; cmp : Tzc_arraylist_cmp_fn; data : Pointer):integer;
var
  i : integer;
begin
  for i := 0 to a_list.len-1 do
  begin
    if cmp(a_list._array[i], data) > 0 then
      break;
  end;
  if i = a_list.len then
     Exit(zc_arraylist_add(a_list, data))
  else
    Result := zc_arraylist_insert_inner(a_list, i, data);
end;



function zlog_file_check_new(a_rotater : Pzlog_rotater;const path : PTChar):Pzlog_file;
var
  nwrite, nread : integer;
  a_file : Pzlog_file;
label _err;
begin
  { base_path will not be in list }
  if STRCOMP(a_rotater.base_path, path) = 0 then begin
    Exit(nil);
  end;
  { omit dirs }
  if (path[Length(path) - 1] = '/') then  begin
    Exit(nil);
  end;
  a_file := calloc(1, sizeof(Tzlog_file));
  if nil =a_file then begin
    zc_error('calloc fail, errno[%d]', [errno]);
    Exit(nil);
  end;
  nwrite := snprintf(a_file.path, sizeof(a_file.path), '%s', [path]);
  if (nwrite < 0)  or  (nwrite >= sizeof(a_file.path)) then
  begin
    zc_error('snprintf fail or overflow, nwrite=[%d], errno[%d]', [nwrite, errno]);
    goto _err;
  end;
  nread := 0;
  sscanf(PTChar(@a_file.path) + a_rotater.num_start_len, '%d%n', [@a_file.index, @nread]);
  if a_rotater.num_width <> 0 then begin
    if nread < a_rotater.num_width then  begin
      zc_warn('aa.1.log is not expect, need aa.01.log', []);
      goto _err;
    end;
  end;
 { else all file is ok }
  Exit(a_file);
_err:
  freeMem(a_file);
  Result := nil;
end;



function zlog_file_cmp( a_file_1, a_file_2 : Pzlog_file):integer;
begin
  Result := int(a_file_1.index > a_file_2.index);
end;



procedure zlog_file_del( a_file : Pzlog_file);
begin
  zc_debug('del onefile[%p]', [a_file]);
  zc_debug('a_file.path[%s]', [a_file.path]);
  freeMem(a_file);
end;

function zlog_rotater_add_archive_files( a_rotater : Pzlog_rotater):integer;
var
    rc       : integer;
    glob_buf : Tglob;
    pathc    : size_t;
    pathv    : PPTChar;
    a_file   : Pzlog_file;
label _exit, _err;
begin
  rc := 0;
  a_rotater.files := zc_arraylist_new(@zlog_file_del);
  if nil =a_rotater.files then begin
    zc_error('zc_arraylist_new fail', []);
    Exit(-1);
  end;
  { scan file which is aa.*.log and aa }
  rc := unixem_glob(a_rotater.glob_path, GLOB_ERR or GLOB_MARK or GLOB_NOSORT, nil, @glob_buf);
  if rc = GLOB_NOMATCH then begin
    goto _exit;
  end
  else if (rc > 0 ) then
  begin
    zc_error('glob err, rc=[%d], errno[%d]', [rc, errno]);
    Exit(-1);
  end;
  pathv := glob_buf.gl_pathv;
  pathc := glob_buf.gl_pathc;
  { check and find match aa.[0-9]*.log, depend on num_width }
  while PostDec(pathc) > 0 do
  begin
    a_file := zlog_file_check_new(a_rotater, pathv^);
    if nil =a_file then begin
      zc_warn('not the expect pattern file', []);
      continue;
    end;
    { file in list aa.00, aa.01, aa.02... }
    rc := zc_arraylist_sortadd(a_rotater.files, @zlog_file_cmp, a_file);
    if rc > 0 then begin
      zc_error('zc_arraylist_sortadd fail', []);
      goto _err;
    end;
    Inc(pathv);
  end;

_exit:
  unixem_globfree(@glob_buf);
  Exit(0);

_err:
  unixem_globfree(@glob_buf);
  Result := -1;
end;

function zlog_rotater_parse_archive_path( a_rotater : Pzlog_rotater):integer;
var
  nwrite, nread : integer;
  p : PTChar;
  len : size_t;
begin
  { no archive path is set }
  if a_rotater.archive_path[0] = #0 then
  begin
    nwrite := snprintf(a_rotater.glob_path, sizeof(a_rotater.glob_path),
                      '%s.*', [a_rotater.base_path]);
    if (nwrite < 0)  or  (nwrite > sizeof(a_rotater.glob_path)) then
    begin
      zc_error('nwirte[%d], overflow or errno[%d]', [nwrite, errno]);
      Exit(-1);
    end;
    a_rotater.mv_type := ROLLING;
    a_rotater.num_width := 0;
    a_rotater.num_start_len := Length(a_rotater.base_path) + 1;
    a_rotater.num_end_len := Length(a_rotater.base_path) + 2;
    Exit(0);
  end
  else begin
    { find the 1st # }
    p := strchr(a_rotater.archive_path, '#');
    if nil =p then begin
      zc_error('no # in archive_path[%s]', [a_rotater.archive_path]);
      Exit(-1);
    end;
    nread := 0;
    sscanf(p, '#%d%n', [@a_rotater.num_width, @nread]);
    if nread = 0 then nread := 1;
    if (p+nread)^ = 'r' then
    begin
      a_rotater.mv_type := ROLLING;
    end
    else
    if (p+nread)^ = 's' then
    begin
      a_rotater.mv_type := SEQUENCE;
    end
    else
    begin
      zc_error('#r or #s not found', []);
      Exit(-1);
    end;
    { copy and substitue #i to * in glob_path}
    len := p - a_rotater.archive_path;
    if len > sizeof(a_rotater.glob_path) - 1  then
    begin
      zc_error('sizeof glob_path not enough,len[%ld]', [long(len)]);
      Exit(-1);
    end;
    memcpy(@a_rotater.glob_path, a_rotater.archive_path, len);
    nwrite := snprintf(PTChar(@a_rotater.glob_path) + len, sizeof(a_rotater.glob_path) - len,
        '*%s', [p + nread + 1]);
    if (nwrite < 0)  or  (nwrite > sizeof(a_rotater.glob_path) - len)  then
    begin
      zc_error('nwirte[%d], overflow or errno[%d]', [nwrite, errno]);
      Exit(-1);
    end;
    a_rotater.num_start_len := len;
    a_rotater.num_end_len := len + 1;
  end;
  Result := 0;
end;


function zlog_rotater_lsmv( a_rotater : Pzlog_rotater; base_path, archive_path : PTChar; archive_max_count : integer):integer;
var
  rc : integer;
  label _err;
begin
  rc := 0;
  a_rotater.base_path := base_path;
  a_rotater.archive_path := archive_path;
  a_rotater.max_count := archive_max_count;
  rc := zlog_rotater_parse_archive_path(a_rotater);
  if rc > 0 then begin
    zc_error('zlog_rotater_parse_archive_path fail', []);
    goto _err;
  end;
  rc := zlog_rotater_add_archive_files(a_rotater);
  if rc > 0 then begin
    zc_error('zlog_rotater_add_archive_files fail', []);
    goto _err;
  end;
  if a_rotater.mv_type = ROLLING then
  begin
    rc := zlog_rotater_roll_files(a_rotater);
    if rc > 0 then
    begin
      zc_error('zlog_rotater_roll_files fail', []);
      goto _err;
    end;
  end
  else
  if (a_rotater.mv_type = SEQUENCE) then
  begin
    rc := zlog_rotater_seq_files(a_rotater);
    if rc > 0 then begin
      zc_error('zlog_rotater_seq_files fail', []);
      goto _err;
    end;
  end;
  zlog_rotater_clean(a_rotater);
  Exit(0);

_err:
  zlog_rotater_clean(a_rotater);
  Result := -1;
end;


function lock_file( path : PTChar): TLOCK_FD;
var
  fd : TLOCK_FD;
  err : DWORD;
begin
    if (nil =path)  or  (Length(path) <= 0)  then
    begin
        Exit(INVALID_LOCK_FD);
    end;
{$IFDEF MSWINDOWS }
    fd := Handle(CreateFileA(path, GENERIC_READ or GENERIC_WRITE, 0, nil, OPEN_ALWAYS,
                      FILE_ATTRIBUTE_NORMAL, 0));
    if fd = INVALID_LOCK_FD then begin
        err := GetLastError();
    zc_error('lock file error : %d ', [err]);
    end;
{$ELSE}
    fd := open(path, O_RDWR or O_CREAT or O_EXCL, S_IRWXU or S_IRWXG or S_IRWXO);
    if fd = INVALID_LOCK_FD then begin
    zc_error('lock file error : %s ', [strerror(errno)]);
    end;
{$ENDIF}
    Result := fd;
end;



function zlog_rotater_trylock( a_rotater : Pzlog_rotater):integer;
var
  rc : integer;
begin
  rc := pthread_mutex_trylock(a_rotater.lock_mutex);
  if rc = EBUSY then begin
    zc_warn('pthread_mutex_trylock fail, as lock_mutex is locked by other threads', []);
    Exit(-1);
  end
 else if (rc <> 0) then
 begin
    zc_error('pthread_mutex_trylock fail, rc[%d]', [rc]);
    Exit(-1);
  end;
  a_rotater.lock_fd := lock_file(a_rotater.lock_file);
  if a_rotater.lock_fd = INVALID_LOCK_FD then begin
    Exit(-1);
  end;
  Result := 0;
end;

function zlog_rotater_rotate( a_rotater : Pzlog_rotater; base_path : PTChar; msg_len : size_t; archive_path : PTChar; archive_max_size : long; archive_max_count : integer):integer;
var
  rc : integer;
  info : Tzlog_stat;
label _exit;
begin
  rc := 0;
  zc_assert(base_path <> nil, -1);
  if zlog_rotater_trylock(a_rotater) > 0 then
  begin
    zc_warn('zlog_rotater_trylock fail, maybe lock by other process or threads', []);
    Exit(0);
  end;
  if stat(base_path, @info) > 0 then begin
    rc := -1;
    zc_error('stat [%s] fail, errno[%d]', [base_path, errno]);
    goto _exit;
  end;
  if info.st_size + msg_len <= archive_max_size then
  begin
    { file not so big,
     * may alread rotate by oth process or thread,
     * return }
    rc := 0;
    goto _exit;
  end;
  { begin list and move files }
  rc := zlog_rotater_lsmv(a_rotater, base_path, archive_path, archive_max_count);
  if rc > 0 then begin
    zc_error('zlog_rotater_lsmv [%s] fail, return', [base_path]);
    rc := -1;
  end;
 { else if (rc = 0) }
  //zc_debug('zlog_rotater_file_ls_mv success');
_exit:
  { unlock file }
  if zlog_rotater_unlock(a_rotater) > 0 then
  begin
    zc_error('zlog_rotater_unlock fail', []);
  end;
  Result := rc;
end;



function zlog_rule_output_dynamic_file_rotate( a_rule : Pzlog_rule; a_thread : Pzlog_thread):integer;
var
  fd, i : integer;
  path : PTChar;
  len : size_t;
  info : Tzlog_stat;
  a_spec: Pzlog_spec;
begin
  //zlog_rule_gen_path(a_rule, a_thread);
  a_thread.path_buf.tail := a_thread.path_buf.start;

  i := 0;
  a_spec := a_rule.dynamic_specs._array[0];
  while (i < a_rule.dynamic_specs.len)   do
  begin
     if a_spec.gen_path(a_spec, a_thread) > 0 then
     begin
        zc_profile_inner(Int(__ZC_ERROR), __FILE__, __LINE__, 'zlog_spec_gen_path fail', []);
        Exit(-1);
     end;
     a_thread.path_buf^.tail := #0;
     Inc(i);
     a_spec := a_rule.dynamic_specs._array[i];

  end;

  if zlog_format_gen_msg(a_rule._format, a_thread) > 0 then
  begin
    zc_error('zlog_format_output fail', []);
    Exit(-1);
  end;
  path := zlog_buf_str(a_thread.path_buf);
  fd := FileOpen(path, a_rule.file_open_flags or O_WRITE);
  if fd < 0 then begin
    zc_error('open file[%s] fail, errno[%d]', [zlog_buf_str(a_thread.path_buf), errno]);
    Exit(-1);
  end;
  len := zlog_buf_len(a_thread.msg_buf);
  if filewrite(fd, zlog_buf_str(a_thread.msg_buf)^ , len) < 0  then
  begin
    zc_error('zlog_rule_output_dynamic_file_rotate: write fail, errno[%d]', [errno]);
    CloseHandle(fd);
    Exit(-1);
  end;
  if (a_rule.fsync_period > 0)  and  (PreInc(a_rule.fsync_count) >= a_rule.fsync_period)  then
  begin
    a_rule.fsync_count := 0;
    if fsync(fd) > 0 then
       zc_error('fsync[%d] fail, errno[%d]', [fd, errno]);
  end;
  if CloseHandle(fd) = False  then
  begin
    zc_error('write fail, maybe cause by write, errno[%d]', [errno]);
    Exit(-1);
  end;
  if len > a_rule.archive_max_size then
  begin
    zc_debug('one msg''s len[%ld] > archive_max_size[%ld], no rotate',
       [long(len), long( a_rule.archive_max_size)]);
    Exit(0);
  end;
  if stat(path, @info) > 0 then
  begin
    zc_warn('stat [%s] fail, errno[%d], maybe in rotating', [path, errno]);
    Exit(0);
  end;
  { file not so big, return }
  if info.st_size + len < a_rule.archive_max_size then Exit(0);
  if zlog_rotater_rotate(zlog_env_conf.rotater,
                        path, len, zlog_rule_gen_archive_path(a_rule, a_thread),
                        a_rule.archive_max_size, a_rule.archive_max_count)  > 0 then
  begin
    zc_error('zlog_rotater_rotate fail', []);
    Exit(-1);
  end; { success or no rotation do nothing }
  Result := 0;
end;



function zlog_rule_output_dynamic_file_single( a_rule : Pzlog_rule; a_thread : Pzlog_thread):integer;
var
  fd, i: integer;
  a_spec: Pzlog_spec;
begin
  //zlog_rule_gen_path(a_rule, a_thread);
    a_thread.path_buf.tail := a_thread.path_buf.start;

    i := 0;
    a_spec := a_rule.dynamic_specs._array[0];
    while (i < a_rule.dynamic_specs.len)   do
    begin
       if a_spec.gen_path(a_spec, a_thread) > 0 then
       begin
          zc_profile_inner(Int(__ZC_ERROR), __FILE__, __LINE__, 'zlog_spec_gen_path fail', []);
          Exit(-1);
       end;
       a_thread.path_buf^.tail := #0;
       Inc(i);
       a_spec := a_rule.dynamic_specs._array[i];

    end;

    if zlog_format_gen_msg(a_rule._format, a_thread) > 0 then
    begin
      zc_error('zlog_format_output fail', []);
      Exit(-1);
    end;
  fd := Fileopen(zlog_buf_str(a_thread.path_buf), a_rule.file_open_flags or O_WRITE);
  if fd < 0 then begin
    zc_error('open file[%s] fail, errno[%d]', [zlog_buf_str(a_thread.path_buf), errno]);
    Exit(-1);
  end;
  if filewrite(fd, zlog_buf_str(a_thread.msg_buf)^ , zlog_buf_len(a_thread.msg_buf)) < 0 then
  begin
    zc_error('zlog_rule_output_dynamic_file_single: write fail, errno[%d]', [errno]);
    CloseHandle(fd);
    Exit(-1);
  end;
  if (a_rule.fsync_period > 0) and  (PreInc(a_rule.fsync_count) >= a_rule.fsync_period) then
  begin
    a_rule.fsync_count := 0;
    if fsync(fd) > 0 then
       zc_error('fsync[%d] fail, errno[%d]', [fd, errno]);
  end;
  if CloseHandle(fd) = False  then
  begin
    zc_error('close fail, maybe cause by write, errno[%d]', [errno]);
    Exit(-1);
  end;
  Result := 0;
end;

function fsync( fd : integer):integer;
var
  h : THANDLE;
  err : DWORD;
begin
    h := THANDLE( _get_osfhandle (fd));
    if h = INVALID_HANDLE_VALUE then begin
        errno := EBADF;
        Exit(-1);
    end;
    if not FlushFileBuffers (h) then
    begin
        { Translate some Windows errors into rough approximations of Unix
         * errors.  MSDN is useless as usual - in this case it doesn't
         * document the full range of errors.
         }
        err := GetLastError ();
        case err of
          { eg. Trying to fsync a tty. }
          ERROR_INVALID_HANDLE:
              errno := EINVAL;
              //break;
          else
              errno := EIO;
        end;
        Exit(-1);
    end;
    Result := 0;
end;

function zlog_spec_gen_msg(a_spec: Pzlog_spec; a_thread: Pzlog_thread): int;
begin
  Result :=	a_spec.gen_msg(a_spec, a_thread)
end;

function zlog_format_gen_msg( a_format : Pzlog_format; a_thread : Pzlog_thread):integer;
var
  i : integer;
  a_spec : Pzlog_spec;
begin
  zlog_buf_restart(a_thread.msg_buf);
  //zc_arraylist_foreach(a_format.pattern_specs, i, a_spec) begin
  for i := 0 to a_format.pattern_specs.len - 1 do
  begin
    a_spec := a_format.pattern_specs._array[i];
    if zlog_spec_gen_msg(a_spec, a_thread) = 0  then
       continue
    else
      Exit(-1);
  end;
  Result := 0;
end;


function zlog_rule_output_static_file_single( a_rule : Pzlog_rule; a_thread : Pzlog_thread):integer;
var
  stb             : Tstat;
  do_file_reload: Boolean;
  redo_inode_stat : integer;
begin
  do_file_reload := Boolean(0);
  redo_inode_stat := 0;
  if zlog_format_gen_msg(a_rule._format, a_thread) > 0 then begin
    zc_error('zlog_format_gen_msg fail', []);
    Exit(-1);
  end;
  { check if the output file was changed by an external tool by comparing the inode to our saved off one }
  if stat(a_rule.file_path, @stb) > 0 then
  begin
    if errno <> ENOENT then  begin
      zc_error('stat fail on [%s], errno[%d]', [a_rule.file_path, errno]);
      Exit(-1);
    end
    else begin
      do_file_reload := Boolean(1);
      redo_inode_stat := 1; { we'll have to restat the newly created file to get the inode info }
    end;
  end
  else
  begin
    do_file_reload := (stb.st_ino <> a_rule.static_ino)  or  (stb.st_dev <> a_rule.static_dev);
  end;
  if do_file_reload then begin
    CloseHandle(a_rule.static_fd);
    a_rule.static_fd := Fileopen(a_rule.file_path, O_WRITE);
    if a_rule.static_fd < 0 then begin
      zc_error('open file[%s] fail, errno[%d]', [a_rule.file_path, errno]);
      Exit(-1);
    end;
    { save off the new dev/inode info from the stat call we already did }
    if redo_inode_stat > 0 then
    begin
      if stat(a_rule.file_path, @stb) > 0 then  begin
        zc_error('stat fail on new file[%s], errno[%d]', [a_rule.file_path, errno]);
        Exit(-1);
      end;
    end;
    a_rule.static_dev := stb.st_dev;
    a_rule.static_ino := stb.st_ino;
  end;
  if filewrite(a_rule.static_fd,
      zlog_buf_str(a_thread.msg_buf)^,
      zlog_buf_len(a_thread.msg_buf)) < 0 then
  begin
    zc_error('zlog_rule_output_static_file_single: write fail, errno[%d]', [errno]);
    Exit(-1);
  end;
  { not so thread safe here, as multiple thread may PreInc(fsync_count) at the same time }
  if (a_rule.fsync_period > 0)  and  (PreInc(a_rule.fsync_count) >= a_rule.fsync_period) then
  begin
    a_rule.fsync_count := 0;
    if fsync(a_rule.static_fd) > 0 then begin
      zc_error('fsync[%d] fail, errno[%d]', [a_rule.static_fd, errno]);
    end;
  end;
  Result := 0;
end;

function zlog_rule_parse_path( path_start, path_str : PTChar; path_size : size_t; path_specs : PPzc_arraylist; time_cache_count : PInteger):integer;
var

  p, q : PTChar;
  len : size_t;
  a_spec : Pzlog_spec;
  specs : Pzc_arraylist;
label _err;
begin
  p := path_start + 1;
  q := strrchr(p, '"');
  if nil =q then begin
    zc_error('matching " not found in conf line[%s]', [path_start]);
    Exit(-1);
  end;
  len := q - p;
  if len > path_size - 1 then begin
    zc_error('file_path too long %ld > %ld', [len, path_size - 1]);
    Exit(-1);
  end;
  memcpy(path_str, p, len);
  { replace any environment variables like %E(HOME) }
  if zc_str_replace_env(path_str, path_size) > 0 then
  begin
    zc_error('zc_str_replace_env fail', []);
    Exit(-1);
  end;
  if strchr(path_str, '%') = nil  then begin
    {  , no need create specs }
    Exit(0);
  end;
  specs := zc_arraylist_new(@zlog_spec_del);
  if nil =path_specs then begin
    zc_error('zc_arraylist_new fail', []);
    Exit(-1);
  end;
  p := path_str;
  while p^ <> #0 do
  begin
    a_spec := zlog_spec_new(p, @q, time_cache_count);
    if nil =a_spec then begin
      zc_error('zlog_spec_new fail', []);
      goto _err;
    end;
    if zc_arraylist_add(specs, a_spec) > 0 then begin
      zc_error('zc_arraylist_add fail', []);
      goto _err;
    end;
    p := q;
  end;
  path_specs^ := specs;
  Exit(0);
_err:
  if specs <> nil then zc_arraylist_del(specs);
  if a_spec <> nil then zlog_spec_del(a_spec);
  Result := -1;
end;

function zlog_format_has_name(a_format: Pzlog_format; fname: PTChar): Boolean;
begin
  Result :=	STRCOMP(a_format.name, fname) = 0;
end;

function zlog_level_list_atoi( levels : Pzc_arraylist; str : PTChar):integer;
var
  i : integer;
  a_level : Pzlog_level;
begin
  if (str = nil)  or  (str^ = #0) then
  begin
    zc_error('str is [%s], cant find level', [str]);
    Exit(-1);
  end;
  //zc_arraylist_foreach(levels, i, a_level) begin
  for i := 0 to levels.len - 1 do
  begin
    a_level := levels._array[i];
    if (a_level <> nil)  and  (strcasecmp(str, a_level.str_uppercase) = 0) then
       Exit(i);
  end;
  zc_error('str[%s] can not found in level list', [str]);
  Result := -1;
end;



function zlog_rule_new( line : PTChar; levels : Pzc_arraylist; default_format : Pzlog_format; formats : Pzc_arraylist; file_perms : uint32; fsync_period : size_t; time_cache_count : PInteger):Pzlog_rule;
var
  rc,
  nscan,
  nread            : integer;
  a_rule           : Pzlog_rule;
  selector,
  category,
  level            : array[0..(MAXLEN_CFG_LINE + 1)-1] of TChar;
  action           : PTChar;
  output,
  format_name,
  file_path,
  archive_max_size : array[0..(MAXLEN_CFG_LINE + 1)-1] of TChar;
  file_limit,
  p,  q                : PTChar;
  len              : size_t;
  i, idx, find_flag        : integer;
  a_format         : Pzlog_format;
  stb              : Tstat;
  a_spec           : Pzlog_spec;
  label _err, _fall;
begin
{$R-}
  rc := 0;
  nscan := 0;
  nread := 0;
  assert(line <> nil);
  assert(default_format <> nil);
  assert(formats <> nil);
  a_rule := calloc(1, sizeof(Tzlog_rule));
  if nil =a_rule then begin
    zc_error('calloc fail, errno[%d]', [errno]);
    Exit(nil);
  end;
  a_rule.file_perms := file_perms;
  a_rule.fsync_period := fsync_period;
  { line         [f.INFO '%H/log/aa.log', 20MB * 12; MyTemplate]
   * selector     [f.INFO]
   * *action      ['%H/log/aa.log', 20MB * 12; MyTemplate]
   }
  memset(@selector, $00, sizeof(selector));
  nscan := sscanf(line, '%s %n', [selector, @nread]);
  if nscan <> 1 then begin
    zc_error('sscanf [%s] fail, selector', [line]);
    goto _err;
  end;
  action := line + nread;
  {
   * selector     [f.INFO]
   * category     [f]
   * level        [.INFO]
   }
  memset(@category, $00, sizeof(category));
  memset(@level, $00, sizeof(level));
  nscan := sscanf(selector, ' %[^.].%s', [@category, @level]);
  if nscan <> 2 then begin
    zc_error('sscanf [%s] fail, category or level is null', [selector]);
    goto _err;
  end;
  { check and set category }
  p := category;
  while p^ <> #0 do
  begin
    if (not isalnum(p^))  and  ( p^ <> '_')  and  ( p^ <> '-')  and  ( p^ <> '*')  and  ( p^ <> '!') then
    begin
      zc_error('category name[%s] AnsiChar acter is not in [a-Z][0-9][_!*-]', [category]);
      goto _err;
    end;
    Inc(p);
  end;
  { as one line can't be longer than MAXLEN_CFG_LINE, same as category }
  Move(category, a_rule.category, sizeof(category));
  { check and set level }
  case level[0] of
      '=':
      begin
        { aa.=debug }
        a_rule.compare_AnsiChar := '=';
        p := level + 1;
      end;
      '!':
      begin
        { aa.!debug }
        a_rule.compare_AnsiChar := '!';
        p := level + 1;
      end;
      '*':
      begin
        { aa.* }
        a_rule.compare_AnsiChar := '*';
        p := level;
      end;
      else
      begin
        { aa.debug }
        a_rule.compare_AnsiChar := '.';
        p := level;
      end;
  end;
  a_rule.level := zlog_level_list_atoi(levels, p);
  { level_bit is a bitmap represents which level can be output
   * 32bytes, [0-255] levels, see level.c
   * which bit field is 1 means allow output and 0 not
   }
  case a_rule.compare_AnsiChar  of
    '=':
    begin
      memset(@a_rule.level_bitmap, $00, sizeof(a_rule.level_bitmap));
      a_rule.level_bitmap[a_rule.level div 8]  := a_rule.level_bitmap[a_rule.level div 8]  or ((1 shl (7 - a_rule.level mod 8)));
    end;
    '!':
    begin
      memset(@a_rule.level_bitmap, $FF, sizeof(a_rule.level_bitmap));
      a_rule.level_bitmap[a_rule.level div 8] := a_rule.level_bitmap[a_rule.level div 8] and not(1 shl (7 - a_rule.level mod 8));
    end;
    '*':
      memset(@a_rule.level_bitmap, $FF, sizeof(a_rule.level_bitmap));
      //break;
    '.':
    begin
      memset(@a_rule.level_bitmap, $00, sizeof(a_rule.level_bitmap));
      idx := a_rule.level div 8;
      a_rule.level_bitmap[idx]  := a_rule.level_bitmap[idx]  or
                                  not ($FF shl (8 - a_rule.level mod 8));
      memset(PByte(@a_rule.level_bitmap) + idx + 1, $FF,
             sizeof(a_rule.level_bitmap) -  idx - 1);
    end;
  end;
  { action               ['%H/log/aa.log', 20MB * 12 ; MyTemplate]
   * output               ['%H/log/aa.log', 20MB * 12]
   * format               [MyTemplate]
   }
  memset(@output, $00, sizeof(output));
  memset(@format_name, $00, sizeof(format_name));
  nscan := sscanf(action, ' %[^;];%s', [output, format_name]);
  if nscan < 1 then begin
    zc_error('sscanf [%s] fail', [action]);
    goto _err;
  end;
  { check and get format }
  if STRCOMP(format_name, '') = 0 then
  begin
    zc_debug('no format specified, use default', []);
    a_rule._format := default_format;
  end
  else
  begin
    find_flag := 0;
    //zc_arraylist_foreach(formats, i, a_format) begin
    i := 0;
    a_format := formats._array[0];
    while (i < formats.len) do
    begin
      if zlog_format_has_name(a_format, format_name)  then
      begin
        a_rule._format := a_format;
        find_flag := 1;
        break;
      end;
      Inc(i);
      a_format := formats._array[i];

    end;
    if 0>=find_flag then begin
      zc_error('in conf file can not find format[%s], pls check', [format_name]);
      goto _err;
    end;
  end;
  { output               [-'%E(HOME)/log/aa.log' , 20MB*12]  [>syslog , LOG_LOCAL0 ]
   * file_path            [-'%E(HOME)/log/aa.log' ]           [>syslog ]
   * *file_limit          [20MB * 12 ~ 'aa.#i.log' ]          [LOG_LOCAL0]
   }
  memset(@file_path, $00, sizeof(file_path));
  nscan := sscanf(output, ' %[^,],', [file_path]);
  if nscan < 1 then begin
    zc_error('sscanf [%s] fail', [action]);
    goto _err;
  end;
  file_limit := strchr(output, ',');
  if file_limit <> nil then
  begin
    Inc(file_limit); { skip the , }
    while isspace(file_limit^)  do
      Inc(file_limit);

  end;
  p := nil;
  case file_path[0] of
  '-' :
  begin
    { sync file each time write log }
    if file_path[1] <> '"' then begin
      zc_error(' - must set before a file output', []);
      goto _err;
    end;
    { no need to fsync, as file is opened by O_SYNC, write immediately }
    a_rule.fsync_period := 0;
    p := file_path + 1;
    goto _fall;
{$IFNDEF MSWINDOWS}
    a_rule.file_open_flags := O_SYNC;
    { fall through }
{$ENDIF}
  end;
  '"' :
  begin
_fall:
    if nil =p then p := file_path;
    rc := zlog_rule_parse_path(p, a_rule.file_path, sizeof(a_rule.file_path),
        @a_rule.dynamic_specs, time_cache_count);
    if rc > 0 then begin
      zc_error('zlog_rule_parse_path fail', []);
      goto _err;
    end;
    if file_limit <> nil then begin
      memset(@archive_max_size, $00, sizeof(archive_max_size));
      nscan := sscanf(file_limit, ' %[0-9MmKkBb] * %d ~',
          [archive_max_size, @a_rule.archive_max_count]);
      if nscan > 0 then
        a_rule.archive_max_size := zc_parse_byte_size(archive_max_size);

      p := strchr(file_limit, '"');
      if p <> nil then begin { archive file path exist }
        rc := zlog_rule_parse_path(p,
          a_rule.archive_path, sizeof(a_rule.file_path),
          @(a_rule.archive_specs), time_cache_count);
        if rc > 0 then begin
          zc_error('zlog_rule_parse_path fail', []);
          goto _err;
        end;
        p := strchr(a_rule.archive_path, '#');
        if (p = nil)  or  ((strchr(p, 'r') = nil)  and  (strchr(p, 's') = nil)) then  begin
          zc_error('archive_path must contain #r or #s', []);
          goto _err;
        end;
      end;
    end;
    { try to figure out if the log file path is dynamic or   }
    if a_rule.dynamic_specs <> nil then
    begin
      if a_rule.archive_max_size <= 0 then
        a_rule.output := zlog_rule_output_dynamic_file_single
      else
        a_rule.output := zlog_rule_output_dynamic_file_rotate;

    end
    else
    begin
      if a_rule.archive_max_size <= 0 then
         a_rule.output := zlog_rule_output_static_file_single
      else begin
        { as rotate, so need to reopen everytime }
         a_rule.output := zlog_rule_output_static_file_rotate;
      end;
      a_rule.static_fd := Fileopen(a_rule.file_path, O_WRITE);
      if a_rule.static_fd < 0 then
      begin
        zc_error('open file[%s] fail, errno[%d]', [a_rule.file_path, errno]);
        goto _err;
      end;
      { save off the inode information for checking for a changed file later on }
      if fstat(a_rule.static_fd, @stb) > 0 then  begin
        zc_error('stat [%s] fail, errno[%d], failing to open  _fd', [a_rule.file_path, errno]);
        goto _err;
      end;
      if a_rule.archive_max_size > 0 then
      begin
        CloseHandle(a_rule.static_fd);
        a_rule.static_fd := -1;
      end;
      a_rule.static_dev := stb.st_dev;
      a_rule.static_ino := stb.st_ino;
    end;
  end;
  '|' :
  begin
    a_rule.pipe_fp := fopen(output + 1, 'w');
    if nil =a_rule.pipe_fp then begin
      zc_error('popen fail, errno[%d]', [errno]);
      goto _err;
    end;
    a_rule.pipe_fd := fileno(a_rule.pipe_fp);
    if a_rule.pipe_fd < 0  then
    begin
      zc_error('fileno fail, errno[%d]', [errno]);
      goto _err;
    end;
    a_rule.output := zlog_rule_output_pipe;
  end;
  '>' :
  begin
    if STRNCMP(file_path + 1, 'syslog', 6) = 0 then
    begin
      a_rule.syslog_facility := syslog_facility_atoi(file_limit);
{$IFDEF MSWINDOWS }
            zc_error('syslog not support under windows!', []);
{$ELSE} if a_rule.syslog_facility = -187 then {
        zc_error('-187 get');
        goto_err;
      }
      a_rule.output := zlog_rule_output_syslog;
      openlog(nil, LOG_NDELAY or LOG_NOWAIT or LOG_PID, LOG_USER);
{$ENDIF}
    end
    else
    if STRNCMP(file_path + 1, 'stdout', 6) = 0 then
      a_rule.output := zlog_rule_output_stdout
    else
    if STRNCMP(file_path + 1, 'stderr', 6) = 0 then
      a_rule.output := zlog_rule_output_stderr
    else begin
      zc_error('[%s]the string after is not syslog, stdout or stderr', [output]);
      goto _err;
    end;
  end;
  '$' :
  begin
    sscanf(file_path + 1, '%s', [a_rule.record_name]);
    if file_limit <> nil then
    begin
      { record path exists }
      p := strchr(file_limit, '"');
      if nil =p then begin
        zc_error('record_path not start with \", [%s]', [file_limit]);
        goto _err;
      end;
      Inc(p); { skip 1st " }
      q := strrchr(p, '"');
      if nil =q then begin
        zc_error('matching \" not found in conf line[%s]', [p]);
        goto _err;
      end;
      len := q - p;
      if len > sizeof(a_rule.record_path) - 1  then
      begin
        zc_error('record_path too long %ld > %ld', [len, sizeof(a_rule.record_path) - 1]);
        goto _err;
      end;
      memcpy(@a_rule.record_path, p, len);
    end;
    { replace any environment variables like %E(HOME) }
    rc := zc_str_replace_env(a_rule.record_path, sizeof(a_rule.record_path));
    if rc > 0 then
    begin
      zc_error('zc_str_replace_env fail', []);
      goto _err;
    end;
    { try to figure out if the log file path is dynamic or   }
    if strchr(a_rule.record_path, '%') = nil  then
       a_rule.output := zlog_rule_output_static_record
    else
    begin
      a_rule.output := zlog_rule_output_dynamic_record;
      a_rule.dynamic_specs := zc_arraylist_new(@zlog_spec_del);
      if nil =(a_rule.dynamic_specs) then
      begin
        zc_error('zc_arraylist_new fail', []);
        goto _err;
      end;
      p := a_rule.record_path;
      while p^ <> #0 do
      begin
        a_spec := zlog_spec_new(p, @q, time_cache_count);
        if nil =a_spec then begin
          zc_error('zlog_spec_new fail', []);
          goto _err;
        end;
        rc := zc_arraylist_add(a_rule.dynamic_specs, a_spec);
        if rc > 0 then begin
          zlog_spec_del(a_spec);
          zc_error('zc_arraylist_add fail', []);
          goto _err;
        end;
        p := q;
      end;
    end;
  end;
  else
  begin
    zc_error('the 1st AnsiChar [%c] of file_path[%s] is wrong',
           [file_path[0], file_path]);
    goto _err;
  end;
  end;
  Exit(a_rule);

_err:
  zlog_rule_del(a_rule);
  Result := nil;
{$R+}
end;



function zc_parse_byte_size( astring : PTChar):size_t;
var
  p, q : PTChar;
  sz : size_t;
  res : long;
  c, m : integer;
begin
  { Parse size in bytes depending on the suffix.   Valid suffixes are KB, MB and GB }
  zc_assert(astring <> nil, 0);
  { clear space }
  p := astring; q := astring;
  while p^ <> #0 do
  begin
    if isspace( p^) then  begin
      continue;
    end
    else begin
      q^ := p^;
      PostInc(q);
    end;
    Inc(p);
  end;
  q^ := #0;
  sz := Length(astring);
  res := strtol(astring, PPTChar (nil), 10);
  if res <= 0 then Exit(0);
  if (astring[sz - 1] = 'B')  or  (astring[sz - 1] = 'b') then begin
    c := Ord(astring[sz - 2]);
    m := 1024;
  end
  else begin
    c := Ord(astring[sz - 1]);
    m := 1000;
  end;
  case TChar(c) of
  'K',
  'k':
    res  := res  * m;
    //break;
  'M',
  'm':
    res  := res  * (m * m);
    //break;
  'G',
  'g':
    res  := res  * (m * m * m);
    //break;
  else
    if not isdigit(TChar(c)) then begin
      zc_error('Wrong suffix parsing " "size in bytes for string [%s], ignoring suffix',
         [astring]);
    end;
    //break;
  end;
  Result := (res);
end;




procedure zlog_format_profile( a_format : Pzlog_format; flag : integer);
var
  i : integer;
  a_spec : Pzlog_spec;
begin
  assert(a_format <> nil);
  zc_profile(flag, '---format[%p][%s = %s(%p)]---',
            [a_format,
            a_format.name,
            a_format.pattern,
            a_format.pattern_specs]);
{$IF false}
  zc_arraylist_foreach(a_format.pattern_specs, i, a_spec) begin
    zlog_spec_profile(a_spec, flag);
  end;
{$ENDIF}

end;

function zc_arraylist_add( a_list : Pzc_arraylist; data : Pointer):integer;
begin
  Result := zc_arraylist_set(a_list, a_list.len, data);
end;

function zc_profile(flag : integer; fmt : PTChar; args : array of const): Int;
begin
	  Result :=	zc_profile_inner(flag, __FILE__, __LINE__, fmt, args)
end;

procedure zlog_spec_profile( a_spec : Pzlog_spec; flag : integer);
begin
  assert(a_spec <> nil);
  zc_profile(flag, '----spec[%p][%.*s][%s|%d][%s,%ld,%ld,%s][%s]----',
    [a_spec,
    a_spec.len, a_spec.str,
    a_spec.time_fmt,
    a_spec.time_cache_index,
    a_spec.print_fmt, long(a_spec.max_width), long(a_spec.min_width),
    get_result(a_spec.left_fill_zeros > 0, 'true' , 'false'),
    a_spec.mdc_key]);

end;



function zlog_spec_write_str( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
begin
  Result := zlog_buf_append(a_buf, a_spec.str, a_spec.len);
end;



function zlog_spec_write_percent( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
begin
  Result := zlog_buf_append(a_buf, '%', 1);
end;



function zlog_spec_write_tid_long( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
begin
  { don't need to get tid again, as tmap_new_thread fetched it already }
  { and fork not change tid }
  Result := zlog_buf_append(a_buf, a_thread.event.tid_str, a_thread.event.tid_str_len);
end;



function zlog_spec_write_tid_hex( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
begin
  { don't need to get tid again, as tmap_new_thread fetched it already }
  { and fork not change tid }
  Result := zlog_buf_append(a_buf, a_thread.event.tid_hex_str, a_thread.event.tid_hex_str_len);
end;



function zlog_spec_write_level_uppercase( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
var
  a_level : Pzlog_level;
begin
  a_level := zlog_level_list_get(zlog_env_conf.levels, a_thread.event.level);
  Result := zlog_buf_append(a_buf, a_level.str_uppercase, a_level.str_len);
end;

function zc_arraylist_get(a_list: Pzc_arraylist; i : integer): Pointer;
begin
	 if (i >= a_list.len) then
      Result := nil
   else
      Result := a_list._array[i];
end;


function zlog_level_list_get( levels : Pzc_arraylist; l : integer):Pzlog_level;
var
  a_level : Pzlog_level;
begin
{$IF false}
  if (l <= 0)  or  (l > 254) then  begin
    { illegal input from zlog() }
    zc_error('l[%d] not in (0,254), set to UNKOWN', [l]);
    l := 254;
  end;
{$ENDIF}
  a_level := zc_arraylist_get(levels, l);
  if a_level <> nil then begin
    Exit(a_level);
  end
  else begin
    { empty slot }
    zc_error('l[%d] not in (0,254), or has no level defined,'+
      'see configure file define, set to UNKOWN', [l]);
    Exit(zc_arraylist_get(levels, 254));
  end;
end;



function zlog_spec_write_level_lowercase( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
var
  a_level : Pzlog_level;
begin
  a_level := zlog_level_list_get(zlog_env_conf.levels, a_thread.event.level);
  Result := zlog_buf_append(a_buf, a_level.str_lowercase, a_level.str_len);
end;



function zlog_spec_write_pid( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
begin
  { 1st in event lifecycle }
  if 0>=a_thread.event.pid then
  begin
    a_thread.event.pid := getpid();
    { compare with previous event }
    if a_thread.event.pid <> a_thread.event.last_pid then begin
      a_thread.event.last_pid := a_thread.event.pid;
      a_thread.event.pid_str_len := sprintf(a_thread.event.pid_str, '%u', [a_thread.event.pid]);
    end;
  end;
  Result := zlog_buf_append(a_buf, a_thread.event.pid_str, a_thread.event.pid_str_len);
end;



function zlog_spec_write_cr( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
begin
  Result := zlog_buf_append(a_buf, #13, 1);
end;

function zlog_spec_write_newline( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
begin
  Result := zlog_buf_append(a_buf, #10, FILE_NEWLINE_LEN);
end;



function zlog_buf_printf_hex( a_buf : Pzlog_buf; ui32 : uint32; width : integer):integer;
var
  p        : PByte;
  q        : PTChar;
  tmp      : array[0..(ZLOG_INT32_LEN + 1)-1] of Byte;
  num_len,
  zero_len,
  out_len  : size_t;
  rc       : integer;
  len_left : size_t;
  function get_ui32: UInt32;
  begin
     ui32 := ui32 shr 4;
     Exit(ui32);
  end;
begin
  if nil =a_buf.start then begin
    zc_error('pre-use of zlog_buf_resize fail, so can not convert', []);
    Exit(-1);
  end;
  p := PByte(@tmp) + ZLOG_INT32_LEN;
  repeat
    { the '(uint32_t)' cast disables the BCC's warning }
    PreDec(p)^ := Ord(hex[uint32(ui32 and $f)]);
  until not (get_ui32 > 0);

{$if false}
	} else { /* is_hex == 2 */
		do {
			/* the "(uint32_t)" cast disables the BCC's warning */
			*--p = HEX[(uint32_t) (ui64 & 0xf)];
		} while (ui64 >>= 4);
	}
{$endif}
  { zero or space padding }
  num_len := (PByte(@tmp) + ZLOG_INT32_LEN) - p;
  if width > num_len then
  begin
    zero_len := width - num_len;
    out_len := width;
  end
  else begin
    zero_len := 0;
    out_len := num_len;
  end;
  q := a_buf.tail + out_len;
  if q > a_buf._end then
  begin
    //zc_debug('size_left not enough, resize');
    rc := zlog_buf_resize(a_buf, out_len - (a_buf._end - a_buf.tail));
    if rc > 0 then
    begin
      zc_error('conf limit to %ld, can not extend, so output', [a_buf.size_max]);
      len_left := a_buf._end - a_buf.tail;
      if len_left <= zero_len then begin
        zero_len := len_left;
        num_len := 0;
      end
      else if (len_left > zero_len) then begin
        { zero_len not changed }
        num_len := len_left - zero_len;
      end;
      if zero_len > 0 then
         memset(a_buf.tail, Ord('0'), zero_len);
      memcpy(a_buf.tail + zero_len, p, num_len);
      a_buf.tail  := a_buf.tail + len_left;
      //(a_buf.tail) = #0;
      zlog_buf_truncate(a_buf);
      Exit(1);
    end
    else if (rc < 0) then
    begin
      zc_error('zlog_buf_resize fail', []);
      Exit(-1);
    end
    else begin
      //zc_debug('zlog_buf_resize succ, to[%ld]', a_buf.size_real);
      q := a_buf.tail + out_len; { re-calculate p}
    end;
  end;
  if zero_len > 0 then
     memset(a_buf.tail, Ord('0'), zero_len);
  memcpy(a_buf.tail + zero_len, p, num_len);
  a_buf.tail := q;
  //(a_buf.tail) = #0;
  Result := 0;
end;

function zlog_buf_vprintf(a_buf : Pzlog_buf;const format : PTChar; args : array of const):integer;
var
  ap        : va_list;
  size_left : size_t;
  nwrite,
  rc        : integer;
begin
  if nil =a_buf.start then begin
    zc_error('pre-use of zlog_buf_resize fail, so can not convert', []);
    Exit(-1);
  end;
  //va_copy(ap, args);
  size_left := a_buf.end_plus_1 - a_buf.tail;
  nwrite := vsnprintf(a_buf.tail, size_left, format, args);
  if (nwrite >= 0)  and  (nwrite < size_left) then begin
    a_buf.tail  := a_buf.tail + nwrite;
    Exit(0);
  end
  else if (nwrite < 0) then
  begin
    zc_error('vsnprintf fail, errno[%d]', [errno]);
    zc_error('nwrite[%d], size_left[%ld], format[%s]', [nwrite, size_left, format]);
    Exit(-1);
  end
  else if (nwrite >= size_left) then
  begin
    //zc_debug('nwrite[%d]>=size_left[%ld],format[%s],resize', nwrite, size_left, format);
    rc := zlog_buf_resize(a_buf, nwrite - size_left + 1);
    if rc > 0 then
    begin
      zc_error('conf limit to %ld, can not extend, so truncate', [a_buf.size_max]);
      //va_copy(ap, args);
      size_left := a_buf.end_plus_1 - a_buf.tail;
      vsnprintf(a_buf.tail, size_left, format, args);
      a_buf.tail  := a_buf.tail + (size_left - 1);
      zlog_buf_truncate(a_buf);
      Exit(1);
    end
    else if (rc < 0) then
    begin
      zc_error('zlog_buf_resize fail', []);
      Exit(-1);
    end
    else
    begin
      //zc_debug('zlog_buf_resize succ, to[%ld]', a_buf.size_real);
      //va_copy(ap, args);
      size_left := a_buf.end_plus_1 - a_buf.tail;
      nwrite := vsnprintf(a_buf.tail, size_left, format, args);
      if nwrite < 0 then begin
        zc_error('vsnprintf fail, errno[%d]', [errno]);
        zc_error('nwrite[%d], size_left[%ld], format[%s]', [nwrite, size_left, format]);
        Exit(-1);
      end
      else begin
        a_buf.tail  := a_buf.tail + nwrite;
        Exit(0);
      end;
    end;
  end;
  Result := 0;
end;



function zlog_spec_write_usrmsg( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
var
  rc          : integer;
  line_offset,
  byte_offset : long;
  c           : Byte;
label _zlog_hex_exit;
begin
  if a_thread.event.generate_cmd = ZLOG_FMT then
  begin
    if a_thread.event.str_format <> nil then
    begin
      Exit(zlog_buf_vprintf(a_buf,
              a_thread.event.str_format,
              a_thread.event.str_args));
    end
    else
    begin
      Exit(zlog_buf_append(a_buf, 'format=(null)', sizeof('format=(null)')-1));
    end;
  end
  else
  if (a_thread.event.generate_cmd = ZLOG_HEX) then
  begin
    { thread buf start = null or len <= 0 }
    if a_thread.event.hex_buf = nil then begin
      rc := zlog_buf_append(a_buf, 'buf=(null)', sizeof('buf=(null)')-1);
      goto _zlog_hex_exit;
    end;
    rc := zlog_buf_append(a_buf, ZLOG_HEX_HEAD, sizeof(ZLOG_HEX_HEAD)-1);
    if rc > 0 then begin
      goto _zlog_hex_exit;
    end;
    line_offset := 0;
    //byte_offset = 0;
    while true do
    begin
      rc := zlog_buf_append(a_buf, #10, 1);
      if rc > 0 then goto _zlog_hex_exit;
      rc := zlog_buf_printf_dec64(a_buf, line_offset + 1, 10);
      if rc > 0 then goto _zlog_hex_exit;
      rc := zlog_buf_append(a_buf, '   ', 3);
      if rc > 0 then goto _zlog_hex_exit;
      for byte_offset := 0 to 15 do
      begin
        if line_offset * 16 + byte_offset < a_thread.event.hex_buf_len then
        begin
          c := (PByte(a_thread.event.hex_buf) + line_offset * 16 + byte_offset)^;
          rc := zlog_buf_printf_hex(a_buf, c, 2);
          if rc > 0 then goto _zlog_hex_exit;
          rc := zlog_buf_append(a_buf, ' ', 1);
          if rc > 0 then goto _zlog_hex_exit;
        end
        else
        begin
          rc := zlog_buf_append(a_buf, '   ', 3);
          if rc > 0 then goto _zlog_hex_exit;
        end;
      end;
      rc := zlog_buf_append(a_buf, '  ', 2);
      if rc > 0 then goto _zlog_hex_exit;
      for byte_offset := 0 to 15 do
      begin
        if line_offset * 16 + byte_offset < a_thread.event.hex_buf_len then
        begin
          c := (PByte(a_thread.event.hex_buf) + line_offset * 16 + byte_offset)^;
          if (c >= 32)  and  (c <= 126) then
          begin
            rc := zlog_buf_append(a_buf,PTChar(@c), 1);
            if rc > 0 then goto _zlog_hex_exit;
          end
          else begin
            rc := zlog_buf_append(a_buf, '.', 1);
            if rc > 0 then goto _zlog_hex_exit;
          end;
        end
        else begin
          rc := zlog_buf_append(a_buf, ' ', 1);
          if rc > 0 then goto _zlog_hex_exit;
        end;
      end;
      if line_offset * 16 + byte_offset >= a_thread.event.hex_buf_len then begin
        break;
      end;
      Inc(line_offset);
    end;
_zlog_hex_exit:
    if rc < 0 then begin
      zc_error('write hex msg fail', []);
      Exit(-1);
    end
    else if (rc > 0) then
    begin
      zc_error('write hex msg, buf is full', []);
      Exit(1);
    end;
    Exit(0);
  end;
  Result := 0;
end;



function zlog_spec_write_ktid( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
begin
  { don't need to get ktid again, as tmap_new_thread fetched it already }
  { and fork not change tid }
  Result := zlog_buf_append(a_buf, a_thread.event.ktid_str, a_thread.event.ktid_str_len);
end;



function zlog_spec_write_hostname( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
begin
  Result := zlog_buf_append(a_buf, a_thread.event.host_name, a_thread.event.host_name_len);
end;

function zlog_buf_printf_dec64( a_buf : Pzlog_buf; ui64 : uint64; width : integer):integer;
var
  p        : PByte;
  q        : PTChar;
  tmp      : array[0..(ZLOG_INT64_LEN + 1)-1] of Byte;
  num_len,
  zero_len,
  out_len  : size_t;
  ui32     : uint32;
  rc       : integer;
  len_left : size_t;
  function get_ui32: UInt32;
  begin
    ui32 := ui32 div (10);
    Exit(ui32)
  end;
  function get_ui64: UInt64;
  begin
    ui64 := ui64 div (10);
    Exit(ui64)
  end;
begin
  if nil =a_buf.start then begin
    zc_error('pre-use of zlog_buf_resize fail, so can''t convert', []);
    Exit(-1);
  end;
  p := PByte(@tmp) + ZLOG_INT64_LEN;
  if ui64 <= ZLOG_MAX_UINT32_VALUE then
  begin
    {
    * To divide 64-bit numbers and to find remainders
    * on the x86 platform gcc and icc call the libc functions
    * [u]divdi3() and [u]moddi3(), they call another function
    * in its turn.  On FreeBSD it is the qdivrem() function,
    * its source code is about 170 lines of the code.
    * The glibc counterpart is about 150 lines of the code.
    *
    * For 32-bit numbers and some divisors gcc and icc use
    * a inlined multiplication and shifts.  For example,
    * unsigned 'i32 / 10' is compiled to
    *
    *     (i32 * $CCCCCCCD)  shr  35
    }
    ui32 := uint32(ui64);
    repeat
      PreDec(p)^ := Byte(ui32 mod 10 + Ord('0'));
    until not (get_ui32 > 0);
  end
  else
  begin
    repeat
      PreDec(p)^ := Byte(ui64 mod 10 + Ord('0'));
    until not (get_ui64 > 0);
  end;
  { zero or space padding }
  num_len := (PByte(@tmp) + ZLOG_INT64_LEN) - p;
  if width > num_len then begin
    zero_len := width - num_len;
    out_len := width;
  end
  else
  begin
    zero_len := 0;
    out_len := num_len;
  end;
  q := a_buf.tail + out_len;
  if q > a_buf._end then
  begin
    //zc_debug('size_left not enough, resize');
    rc := zlog_buf_resize(a_buf, out_len - (a_buf._end - a_buf.tail));
    if rc > 0 then begin
      zc_error('conf limit to %ld, can''t extend, so output', [a_buf.size_max]);
      len_left := a_buf._end - a_buf.tail;
      if len_left <= zero_len then
      begin
        zero_len := len_left;
        num_len := 0;
      end
      else if (len_left > zero_len) then
      begin
        { zero_len not changed }
        num_len := len_left - zero_len;
      end;
      if zero_len > 0 then
         memset(a_buf.tail, Ord('0'), zero_len);
      memcpy(a_buf.tail + zero_len, p, num_len);
      a_buf.tail  := a_buf.tail + len_left;
      //(a_buf.tail) = #0;
      zlog_buf_truncate(a_buf);
      Exit(1);
    end
    else if (rc < 0) then
    begin
      zc_error('zlog_buf_resize fail', []);
      Exit(-1);
    end
    else begin
      //zc_debug('zlog_buf_resize succ, to[%ld]', a_buf.size_real);
      q := a_buf.tail + out_len; { re-calculate p}
    end;
  end;
  if zero_len > 0 then
     memset(a_buf.tail, Ord('0'), zero_len);
  memcpy(a_buf.tail + zero_len, p, num_len);
  a_buf.tail := q;
  //(a_buf.tail) = #0;
  Result := 0;
end;


function zlog_spec_write_srcfile( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
begin
  if '' = a_thread.event._file then begin
    Exit(zlog_buf_append(a_buf, '(file=null)', sizeof('(file=null)') - 1));
  end
 else begin
    Exit(zlog_buf_append(a_buf, a_thread.event._file, a_thread.event.file_len));
  end;
end;


function zlog_spec_write_srcfile_neat( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
var
  p : PTChar;
begin
  p := strrchr(a_thread.event._file, '/' );
  if p <> nil then
  begin
    Exit(zlog_buf_append(a_buf, p + 1,
                         a_thread.event._file + a_thread.event.file_len - p - 1));
  end
  else
  begin
    if nil =a_thread.event._file then begin
      Exit(zlog_buf_append(a_buf, '(file=null)', sizeof('(file=null)') - 1));
    end
    else begin
      Exit(zlog_buf_append(a_buf, a_thread.event._file, a_thread.event.file_len));
    end;
  end;
end;


function zlog_spec_write_srcline( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
begin
  Result := zlog_buf_printf_dec64(a_buf, a_thread.event.line, 0);
end;


function zlog_spec_write_srcfunc( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
begin
  if nil =a_thread.event._file then begin
    Exit(zlog_buf_append(a_buf, '(func=null)', sizeof('(func=null)') - 1));
  end
  else begin
    Exit(zlog_buf_append(a_buf, a_thread.event.func, a_thread.event.func_len));
  end;
end;



function zlog_spec_write_category( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
begin
  Result := zlog_buf_append(a_buf, a_thread.event.category_name, a_thread.event.category_name_len);
end;



function zlog_spec_write_us( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
begin
  if 0>=a_thread.event.time_stamp.tv_sec then begin
    gettimeofday(@a_thread.event.time_stamp, nil);
  end;
  Result := zlog_buf_printf_dec32(a_buf, a_thread.event.time_stamp.tv_usec, 6);
end;



function zlog_buf_printf_dec32( a_buf : Pzlog_buf; ui32 : uint32; width : integer):integer;
var
  p        : PByte;
  q        : PTChar;
  tmp      : array[0..(ZLOG_INT32_LEN + 1)-1] of Byte;

  num_len,
  zero_len,
  out_len  : size_t;
  rc       : integer;
  len_left : size_t;
  function get_ui32: UInt32;
  begin
    ui32 := ui32 div (10);
    Exit(ui32)
  end;
begin
  if nil =a_buf.start then begin
    zc_error('pre-use of zlog_buf_resize fail, so can''t convert', []);
    Exit(-1);
  end;
  p := PByte(@tmp) + ZLOG_INT32_LEN;
  repeat
    PreDec(p)^ := Byte(ui32 mod 10 + Ord('0'));
  until not (get_ui32 > 0);
  { zero or space padding }
  num_len := (PByte(@tmp) + ZLOG_INT32_LEN) - p;
  if width > num_len then begin
    zero_len := width - num_len;
    out_len := width;
  end
  else
  begin
    zero_len := 0;
    out_len := num_len;
  end;
  q := a_buf.tail + out_len;
  if q > a_buf._end then
  begin
    //zc_debug('size_left not enough, resize');
    rc := zlog_buf_resize(a_buf, out_len - (a_buf._end - a_buf.tail));
    if rc > 0 then begin
      zc_error('conf limit to %ld, can''t extend, so output', [a_buf.size_max]);
      len_left := a_buf._end - a_buf.tail;
      if len_left <= zero_len then begin
        zero_len := len_left;
        num_len := 0;
      end
      else if (len_left > zero_len) then begin
        { zero_len not changed }
        num_len := len_left - zero_len;
      end;
      if zero_len > 0 then
         memset(a_buf.tail, Ord('0'), zero_len);
      memcpy(a_buf.tail + zero_len, p, num_len);
      a_buf.tail  := a_buf.tail + len_left;
      //(a_buf.tail) = #0;
      zlog_buf_truncate(a_buf);
      Exit(1);
    end
    else if (rc < 0) then
    begin
      zc_error('zlog_buf_resize fail', []);
      Exit(-1);
    end
    else begin
      //zc_debug('zlog_buf_resize succ, to[%ld]', a_buf.size_real);
      q := a_buf.tail + out_len; { re-calculate p}
    end;
  end;
  if zero_len > 0 then
     memset(a_buf.tail, Ord('0'), zero_len);
  memcpy(a_buf.tail + zero_len, p, num_len);
  a_buf.tail := q;
  //(a_buf.tail) = #0;
  Result := 0;
end;



function zlog_spec_write_ms( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
begin
  if 0>=a_thread.event.time_stamp.tv_sec then begin
    gettimeofday(@a_thread.event.time_stamp, nil);
  end;
  Result := zlog_buf_printf_dec32(a_buf, (a_thread.event.time_stamp.tv_usec div 1000), 3);
end;



function zc_hashtable_get(a_table : Pzc_hashtable;const a_key : Pointer):Pointer;
var
  i : uint32;
  p : Pzc_hashtable_entry;
begin
  i := a_table.hash(a_key) mod a_table.tab_size;
  p := a_table.tab[i];
  while p <> nil do
  begin
    if a_table.equal(a_key, p.key) > 0 then
      Exit(p.value);
    p := p.next;
  end;
  Result := nil;
end;




function zlog_mdc_get_kv(a_mdc : Pzlog_mdc;const key : PTChar):Pzlog_mdc_kv;
var
  a_mdc_kv : Pzlog_mdc_kv;
begin
  a_mdc_kv := zc_hashtable_get(a_mdc.tab, key);
  if nil =a_mdc_kv then begin
    zc_error('zc_hashtable_get fail', []);
    Exit(nil);
  end
 else begin
    Exit(a_mdc_kv);
  end;
end;

function zlog_spec_write_mdc( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
var
  a_mdc_kv : Pzlog_mdc_kv;
begin
  a_mdc_kv := zlog_mdc_get_kv(a_thread.mdc, a_spec.mdc_key);
  if nil =a_mdc_kv then begin
    zc_error('zlog_mdc_get_kv key[%s] fail', [a_spec.mdc_key]);
    Exit(0);
  end;
  Result := zlog_buf_append(a_buf, a_mdc_kv.value, a_mdc_kv.value_len);
end;



function zlog_buf_append(a_buf : Pzlog_buf;const str : PTChar; str_len : size_t):integer;
var
    p        : PTChar;
    rc       : integer;
    len_left : size_t;
begin
{$IF false}
  if str_len <= 0  or  str = nil then begin
    Exit(0);
  end;
  if 0>=a_buf.start then begin
    zc_error('pre-use of zlog_buf_resize fail, so can't convert');
    Exit(-1);
  }
{$ENDIF}
  //visual stdio里面a_buf.tail为""时+strlen，结果还是""，delphi里为乱码
  p := a_buf.tail  + str_len;
  if p  > a_buf._end then
  begin
    //zc_debug('size_left not enough, resize');
    rc := zlog_buf_resize(a_buf, str_len - (a_buf._end - a_buf.tail));
    if rc > 0 then
    begin
      zc_error('conf limit to %ld, can''t extend, so output', [a_buf.size_max]);
      len_left := a_buf._end - a_buf.tail;
      memcpy(a_buf.tail, str, len_left);
      a_buf.tail  := a_buf.tail + len_left;
      //(a_buf.tail) = #0;
      zlog_buf_truncate(a_buf);
      Exit(1);
    end
    else if (rc < 0) then
    begin
      zc_error('zlog_buf_resize fail', []);
      Exit(-1);
    end
    else begin
      //zc_debug('zlog_buf_resize succ, to[%ld]', a_buf.size_real);
      p := a_buf.tail + str_len; { re-calculate p}
    end;
  end;
  memcpy(a_buf.tail, str, str_len);

  a_buf.tail := p;
  // *(a_buf.tail) = #0;
  Result := 0;
end;



function zlog_spec_write_time_internal( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf; use_utc : byte):integer;
var
    a_cache                     : Pzlog_time_cache;
    now_sec                     : time_t;
    time                        : Ptm;
    time_sec                    : Ptime_t;
    time_stamp_convert_function : Tzlog_spec_time_fn;
    outstr: PTChar;
begin
  a_cache := a_thread.event.time_caches + a_spec.time_cache_index;
  now_sec := a_thread.event.time_stamp.tv_sec;
  //typedef Ptm ( *zlog_spec_time_fn) (const time_t*, Ptm );
  if use_utc  > 0 then
  begin
    time := @(a_thread.event.time_utc);
    time_sec := @(a_thread.event.time_utc_sec);
    time_stamp_convert_function := gmtime_r;
  end
  else
  begin
    time := @(a_thread.event.time_local);
    time_sec := @(a_thread.event.time_local_sec);
    time_stamp_convert_function := gmtime_r;
  end;
  { the event meet the 1st time_spec in his life cycle }
  if 0>=now_sec then begin
    gettimeofday(@a_thread.event.time_stamp, nil);
    now_sec := a_thread.event.time_stamp.tv_sec;
  end;
  { When this event's last cached time_local is not now }
  if time_sec^ <> now_sec then begin
    time_stamp_convert_function(@now_sec, time);
    time_sec^ := now_sec;
  end;
  { When this spec's last cache time string is not now }
  outstr := @a_cache.str;
  if a_cache.sec <> now_sec then
  begin
    a_cache.len := strftime(outstr, sizeof(a_cache.str), a_spec.time_fmt, time);
    a_cache.sec := now_sec;
  end;
  Result := zlog_buf_append(a_buf, a_cache.str, a_cache.len);
end;


function zlog_spec_write_time_UTC( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
begin
  Result := zlog_spec_write_time_internal(a_spec, a_thread, a_buf, 1);
end;


function zlog_spec_write_time_local( a_spec : Pzlog_spec; a_thread : Pzlog_thread; a_buf : Pzlog_buf):integer;
begin
  Result := zlog_spec_write_time_internal(a_spec, a_thread, a_buf, 0);
end;

function zlog_spec_gen_archive_path_direct( a_spec : Pzlog_spec; a_thread : Pzlog_thread):integer;
begin
  { no need to reprint %1.2d here }
  Result := a_spec.write_buf(a_spec, a_thread, a_thread.archive_path_buf);
end;



function zlog_spec_gen_path_direct( a_spec : Pzlog_spec; a_thread : Pzlog_thread):integer;
begin
  { no need to reprint %1.2d here }
  Result := a_spec.write_buf(a_spec, a_thread, a_thread.path_buf);
end;



function zlog_spec_gen_msg_direct( a_spec : Pzlog_spec; a_thread : Pzlog_thread):integer;
begin
  { no need to reprint %1.2d here }
  Result := a_spec.write_buf(a_spec, a_thread, a_thread.msg_buf);
end;



function zlog_spec_parse_print_fmt( a_spec : Pzlog_spec):integer;
var
  p, q : PTChar;
  i, j : long;
begin
  { -12.35 12 .35 }
  p := a_spec.print_fmt;
  if p^ = '-' then
  begin
    a_spec.left_adjust := 1;
    Inc(p);
  end
  else
  begin
    if p^ = '0' then begin
      a_spec.left_fill_zeros := 1;
    end;
    a_spec.left_adjust := 0;
  end;
  i := 0;
  j := 0;
  sscanf(p, '%ld.', [@i]);
  q := strchr(p, '.');
  if q <> nil then
     sscanf(q, '.%ld', [@j]);
  a_spec.min_width := size_t(i);
  a_spec.max_width := size_t(j);
  Result := 0;
end;



function zlog_spec_gen_archive_path_reformat( a_spec : Pzlog_spec; a_thread : Pzlog_thread):integer;
var
  rc : integer;
begin
  zlog_buf_restart(a_thread.pre_path_buf);
  rc := a_spec.write_buf(a_spec, a_thread, a_thread.pre_path_buf);
  if rc < 0 then
  begin
    zc_error('a_spec.gen_buf fail', []);
    Exit(-1);
  end
  else if (rc > 0) then begin
    { buf is full, try printf }
  end;
  Result := zlog_buf_adjust_append(a_thread.archive_path_buf,
    zlog_buf_str(a_thread.pre_path_buf), zlog_buf_len(a_thread.pre_path_buf),
    a_spec.left_adjust, a_spec.left_fill_zeros, a_spec.min_width, a_spec.max_width);
end;



function zlog_spec_gen_path_reformat( a_spec : Pzlog_spec; a_thread : Pzlog_thread):integer;
var
  rc : integer;
begin
  zlog_buf_restart(a_thread.pre_path_buf);
  rc := a_spec.write_buf(a_spec, a_thread, a_thread.pre_path_buf);
  if rc < 0 then begin
    zc_error('a_spec.gen_buf fail', []);
    Exit(-1);
  end
  else if (rc > 0) then begin
    { buf is full, try printf }
  end;
  Result := zlog_buf_adjust_append(a_thread.path_buf,
    zlog_buf_str(a_thread.pre_path_buf), zlog_buf_len(a_thread.pre_path_buf),
    a_spec.left_adjust, a_spec.left_fill_zeros, a_spec.min_width, a_spec.max_width);
end;



procedure zlog_buf_truncate( a_buf : Pzlog_buf);
var
  p : PTChar;
  len : size_t;
begin
  if a_buf.truncate_str[0] = #0 then
     exit;
  p := (a_buf.tail - a_buf.truncate_str_len);
  if p < a_buf.start then
     p := a_buf.start;
  len := a_buf.tail - p;
  memcpy(p, @a_buf.truncate_str, len);

end;



function zlog_buf_resize( a_buf : Pzlog_buf; increment : size_t):integer;
var
  rc       : integer;
  new_size,
  len      : size_t;
  p        : PTChar;
begin
  rc := 0;
  new_size := 0;
  len := 0;
  p := nil;
  if (a_buf.size_max <> 0)  and  (a_buf.size_real >= a_buf.size_max) then
  begin
    zc_error('a_buf.size_real[%ld] >= a_buf.size_max[%ld]',
              [a_buf.size_real, a_buf.size_max]);
    Exit(1);
  end;
  if a_buf.size_max = 0 then begin
    { unlimit }
    new_size := a_buf.size_real + round(1.5 * increment);
  end
  else begin
    { limited  }
    if a_buf.size_real + increment <= a_buf.size_max then begin
      new_size := a_buf.size_real + increment;
    end
    else begin
      new_size := a_buf.size_max;
      rc := 1;
    end;
  end;
  len := a_buf.tail - a_buf.start;
  p := ReallocMemory(a_buf.start, new_size);
  if nil =p then
  begin
    zc_error('realloc fail, errno[%d]', [errno]);
    freeMem(a_buf.start);
    a_buf.start := nil;
    a_buf.tail := nil;
    a_buf._end := nil;
    a_buf.end_plus_1 := nil;
    Exit(-1);
  end
  else
  begin
    a_buf.start := p;
    a_buf.tail := p + len;
    a_buf.size_real := new_size;
    a_buf.end_plus_1 := a_buf.start + new_size;
    a_buf._end := a_buf.end_plus_1 - 1;
  end;
  Result := rc;
end;



function zlog_buf_adjust_append(a_buf : Pzlog_buf;const str : PTChar; str_len : size_t; left_adjust, zero_pad : integer; in_width, out_width : size_t):integer;
var
  append_len,
  source_len,
  space_len  : size_t;
  rc         : integer;
begin
  append_len := 0;
  source_len := 0;
  space_len := 0;
{$IF false}
  if str_len <= 0  or  str = nil then begin
    Exit(0);
  end;
{$ENDIF}
  if nil =a_buf.start then
  begin
    zc_error('pre-use of zlog_buf_resize fail, so can''t convert', []);
    Exit(-1);
  end;
  { calculate how many AnsiChar acter will be got from str }
  if (out_width = 0)  or  (str_len < out_width) then
    source_len := str_len
  else
    source_len := out_width;

  { calculate how many AnsiChar acter will be output }
  if (in_width = 0)  or  (source_len >= in_width)  then begin
    append_len := source_len;
    space_len := 0;
  end
  else begin
    append_len := in_width;
    space_len := in_width - source_len;
  end;
  {  |---PreDec(PostDec)(append_len)---------| }
  {  |-PostDec(source_len)-|-space_len-|  left_adjust }
  {  |-PostDec(space_len)-|-source_len-|  right_adjust }
  {  |-(size_real-1)---|           size not enough }
  if append_len > a_buf._end - a_buf.tail then
  begin
    rc := 0;
    //zc_debug('size_left not enough, resize');
    rc := zlog_buf_resize(a_buf, append_len - (a_buf._end -a_buf.tail));
    if rc > 0 then
    begin
      zc_error('conf limit to %ld, can''t extend, so output', [a_buf.size_max]);
      append_len := (a_buf._end - a_buf.tail);
      if left_adjust > 0 then
      begin
        if source_len < append_len then
        begin
          space_len := append_len - source_len;
        end
        else
        begin
          source_len := append_len;
          space_len := 0;
        end;
        if space_len > 0 then
           memset(a_buf.tail + source_len, Ord(' '), space_len);
        memcpy(a_buf.tail, str, source_len);
      end
      else
      begin
        if space_len < append_len then
        begin
          source_len := append_len - space_len;
        end
        else
        begin
          space_len := append_len;
          source_len := 0;
        end;
        if space_len > 0 then
        begin
          if zero_pad > 0 then  begin
            memset(a_buf.tail, Ord('0'), space_len);
          end
          else begin
            memset(a_buf.tail, Ord(' '), space_len);
          end;
        end;
        memcpy(a_buf.tail + space_len, str, source_len);
      end;
      a_buf.tail  := a_buf.tail + append_len;
      //(a_buf.tail) = #0;
      zlog_buf_truncate(a_buf);
      Exit(1);
    end
    else if (rc < 0) then
    begin
      zc_error('zlog_buf_resize fail', []);
      Exit(-1);
    end
    else begin
      //zc_debug('zlog_buf_resize succ, to[%ld]', a_buf.size_real);
    end;
  end;
  if left_adjust > 0 then
  begin
    if space_len > 0 then
       memset(a_buf.tail + source_len, Ord(' '), space_len) ;
    memcpy(a_buf.tail, str, source_len);
  end
  else
  begin
    if space_len > 0 then begin
      if zero_pad > 0 then  begin
        memset(a_buf.tail, Ord('0'), space_len);
      end
      else begin
        memset(a_buf.tail, Ord(' '), space_len);
      end;
    end;
    memcpy(a_buf.tail + space_len, str, source_len);
  end;
  a_buf.tail  := a_buf.tail + append_len;
  //(a_buf.tail) = #0;
  Result := 0;
end;

procedure zlog_buf_restart(a_buf: Pzlog_buf);
begin
	a_buf.tail := a_buf.start;
end;

function zlog_buf_len(a_buf: Pzlog_buf): int;
begin
   Result := (a_buf.tail - a_buf.start)
end;

function zlog_buf_str(a_buf: Pzlog_buf): PTChar;
begin
  Result :=  (a_buf.start)
end;



function zlog_spec_gen_msg_reformat( a_spec : Pzlog_spec; a_thread : Pzlog_thread):integer;
var
  rc : integer;
begin
  zlog_buf_restart(a_thread.pre_msg_buf);
  rc := a_spec.write_buf(a_spec, a_thread, a_thread.pre_msg_buf);
  if rc < 0 then
  begin
    zc_error('a_spec.gen_buf fail', []);
    Exit(-1);
  end
  else
  if (rc > 0) then begin
    { buf is full, try printf }
  end;
  Result := zlog_buf_adjust_append(a_thread.msg_buf,
    zlog_buf_str(a_thread.pre_msg_buf), zlog_buf_len(a_thread.pre_msg_buf),
    a_spec.left_adjust, a_spec.left_fill_zeros, a_spec.min_width, a_spec.max_width);
end;



function zlog_spec_new( pattern_start : PTChar; pattern_next : PPTChar; time_cache_count : PInteger):Pzlog_spec;
var
  p : PTChar;
  nscan, nread : integer;
  a_spec : Pzlog_spec;
  use_utc : short;
label _err, _break;
begin
  nscan := 0;
  nread := 0;
  assert(pattern_start <> nil);
  assert(pattern_next <> nil);
  a_spec := calloc(1, sizeof(Tzlog_spec));
  if nil =a_spec then begin
    zc_error('calloc fail, errno[%d]', [errno]);
    Exit(nil);
  end;
  a_spec.str := pattern_start;
  p := pattern_start;
  case  p^ of
  '%':
  begin
    { a string begin with %: %12.35d(%F %X) }
    { process width and precision AnsiChar  in %-12.35P }
    nread := 0;
    nscan := sscanf(p, '%%%[.0-9-]%n', [a_spec.print_fmt, @nread]);
    if nscan = 1 then
    begin
      a_spec.gen_msg := zlog_spec_gen_msg_reformat;
      a_spec.gen_path := zlog_spec_gen_path_reformat;
      a_spec.gen_archive_path := zlog_spec_gen_archive_path_reformat;
      if zlog_spec_parse_print_fmt(a_spec) > 0 then
      begin
        zc_error('zlog_spec_parse_print_fmt fail', []);
        goto _err;
      end;
    end
    else
    begin
      nread := 1; (* skip the % char *)
      a_spec.gen_msg := zlog_spec_gen_msg_direct;
      a_spec.gen_path := zlog_spec_gen_path_direct;
      a_spec.gen_archive_path := zlog_spec_gen_archive_path_direct;
    end;
    p  := p + nread;
    if (p^ = 'd')  or  (p^ = 'g') then
    begin
      use_utc := Int('g');
      p^ := 'g';
      if (p+1)^ <> '('  then
      begin
        { without '(' , use default }
        a_spec.time_fmt := ZLOG_DEFAULT_TIME_FMT;
        Inc(p);
      end
      else if (STRNCMP(p, 'd()', 3) = 0) then
      begin
        { with () but without detail time format,
         * keep a_spec.time_fmt='' }
        a_spec.time_fmt := ZLOG_DEFAULT_TIME_FMT;
        p  := p + 3;
      end
      else
      begin
        nread := 0;
        nscan := sscanf(p, 'd(%[^)])%n', [a_spec.time_fmt, @nread]);
        if nscan <> 1 then begin
          nread := 0;
        end;
        p  := p + nread;
        if (p - 1)^  <> ')' then
        begin
          zc_error('in string[%s] can''t find match '')''', [a_spec.str]);
          goto _err;
        end;
      end;
      a_spec.time_cache_index := time_cache_count^;
      Inc( time_cache_count^);
      if use_utc > 0 then begin
        a_spec.write_buf := zlog_spec_write_time_UTC;
      end
      else begin
        a_spec.write_buf := zlog_spec_write_time_local;
      end;
      pattern_next^ := p;
      a_spec.len := p - a_spec.str;
      goto _break;
    end;
    if p^ = 'M' then
    begin
      nread := 0;
      nscan := sscanf(p, 'M(%[^)])%n', [a_spec.mdc_key, @nread]);
      if nscan <> 1 then
      begin
        nread := 0;
        if STRNCMP(p, 'M()', 3) = 0 then begin
          nread := 3;
        end;
      end;
      p  := p + nread;
      if (p - 1)^ <> ')'  then begin
        zc_error('in string[%s] can''t find match '')''', [a_spec.str]);
        goto _err;
      end;
      pattern_next^ := p;
      a_spec.len := p - a_spec.str;
      a_spec.write_buf := zlog_spec_write_mdc;
      goto _break;
    end;
    if STRNCMP(p, 'ms', 2) = 0 then
    begin
      p  := p + 2;
      pattern_next^ := p;
      a_spec.len := p - a_spec.str;
      a_spec.write_buf := zlog_spec_write_ms;
      goto _break;
    end
    else if STRNCMP(p, 'us', 2) = 0 then
    begin
      p  := p + 2;
      pattern_next^ := p;
      a_spec.len := p - a_spec.str;
      a_spec.write_buf := zlog_spec_write_us;
      goto _break;
    end;
    pattern_next^ := p + 1;
    a_spec.len := p - a_spec.str + 1;
    case  p^ of
        'c':
          a_spec.write_buf := zlog_spec_write_category;
          //break;
        'D':
        begin
          a_spec.time_fmt := ZLOG_DEFAULT_TIME_FMT;
          a_spec.time_cache_index := time_cache_count^;
          Inc(time_cache_count^);
          a_spec.write_buf := zlog_spec_write_time_local;
        end;
        'F':
          a_spec.write_buf := zlog_spec_write_srcfile;
          //break;
        'f':
          a_spec.write_buf := zlog_spec_write_srcfile_neat;
          //break;
        'G':
        begin
          a_spec.time_fmt := ZLOG_DEFAULT_TIME_FMT;
          a_spec.time_cache_index := time_cache_count^;
          Inc(time_cache_count^);
          a_spec.write_buf := zlog_spec_write_time_UTC;
        end;
        'H':
          a_spec.write_buf := zlog_spec_write_hostname;
          //break;
        'k':
          a_spec.write_buf := zlog_spec_write_ktid;
          //break;
        'L':
          a_spec.write_buf := zlog_spec_write_srcline;
          //break;
        'm':
          a_spec.write_buf := zlog_spec_write_usrmsg;
          //break;
        'n':
          a_spec.write_buf := zlog_spec_write_newline;
          //break;
        'r':
          a_spec.write_buf := zlog_spec_write_cr;
          //break;
        'p':
          a_spec.write_buf := zlog_spec_write_pid;
          //break;
        'U':
          a_spec.write_buf := zlog_spec_write_srcfunc;
          //break;
        'v':
          a_spec.write_buf := zlog_spec_write_level_lowercase;
          //break;
        'V':
          a_spec.write_buf := zlog_spec_write_level_uppercase;
          //break;
        't':
          a_spec.write_buf := zlog_spec_write_tid_hex;
          //break;
        'T':
          a_spec.write_buf := zlog_spec_write_tid_long;
          //break;
        '%':
          a_spec.write_buf := zlog_spec_write_percent;
          //break;
        else
        begin
          zc_error('str[%s] in wrong format, p[%c]', [a_spec.str, p^]);
          goto _err;
        end;
    end;
  end
  else
  begin
    { a const string: /home/bb }
    pattern_next^ := strchr(p, '%');
    if pattern_next^ <> nil then
      a_spec.len := pattern_next^ - p

    else
    begin
      a_spec.len := Length(p);
      pattern_next^ := p + a_spec.len;
    end;
    a_spec.write_buf := zlog_spec_write_str;
    a_spec.gen_msg := zlog_spec_gen_msg_direct;
    a_spec.gen_path := zlog_spec_gen_path_direct;
    a_spec.gen_archive_path := zlog_spec_gen_archive_path_direct;
  end;
  end;

_break:
  zlog_spec_profile(a_spec, Int(__ZC_DEBUG));
  Exit( a_spec);
_err:
	zlog_spec_del(a_spec);
	Result := nil;
end;



procedure zlog_spec_del( a_spec : Pointer);
begin
  assert(a_spec <> nil);
  zc_debug('zlog_spec_del[%p]', [Pzlog_spec(a_spec)]);
  freeMem(a_spec);
end;



function zc_str_replace_env( str : PTChar; str_size : size_t):integer;
var
  p, q     : PTChar;
  fmt,
  env_key,
  env_value     : array[0..(MAXLEN_CFG_LINE + 1)-1] of TChar;
  str_len,
  env_value_len,
  nscan,
  nread         : integer;
begin
  str_len := Length(str);
  q := str;
  while Boolean(1) do
  begin
    p := strchr(q, '%');
    if nil =p then
    begin
      { can't find more % }
      break;
    end;
    memset(@fmt, $00, sizeof(fmt));
    memset(@env_key, $00, sizeof(env_key));
    memset(@env_value, $00, sizeof(env_value));
    nread := 0;
    nscan := sscanf(p + 1, '%[.0-9-]%n', [fmt + 1, @nread]);
    if nscan = 1 then
    begin
      fmt[0] := '%';
      fmt[nread + 1] := 's';
    end
    else
    begin
      nread := 0;
      fmt := '%s';
    end;
    q := p + 1 + nread;
    nscan := sscanf(q, 'E(%[^)])%n', [env_key, @nread]);
    if nscan = 0 then begin
      continue;
    end;
    q  := q + nread;
    if (q - 1)^ <> ')'  then begin
      zc_error('in string[%s] can''t find match )', [p]);
      Exit(-1);
    end;
    env_value_len := snprintf(env_value, sizeof(env_value), fmt, [getenv(env_key)]);
    if (env_value_len < 0)  or  (env_value_len >= sizeof(env_value)) then
    begin
      zc_error('snprintf fail, errno[%d], evn_value_len[%d]',
                [errno, env_value_len]);
      Exit(-1);
    end;
    str_len := str_len - (q - p) + env_value_len;
    if str_len > str_size - 1 then begin
      zc_error('repalce env_value[%s] cause overlap', [env_value]);
      Exit(-1);
    end;
    //memmove(p + env_value_len, q, Length(q) + 1);
    move( q^, (p + env_value_len)^, Length(q) + 1);
    memcpy(p, @env_value, env_value_len);
  end ;
  Result := 0;
end;


function zlog_format_new( line : PTChar; time_cache_count : PInteger):Pzlog_format;
var
  nscan    : integer;
  a_format : Pzlog_format;
  nread    : integer;
  p_start,
  p_end,
  p,  q        : PTChar;
  a_spec   : Pzlog_spec;
label _err;
begin
  nscan := 0;
  a_format := nil;
  nread := 0;
  assert(line<> nil);
  a_format := calloc(1, sizeof(Tzlog_format));
  if nil =a_format then begin
    zc_error('calloc fail, errno[%d]', [errno]);
    Exit(nil);
  end;
  { line         default = '%d(%F %X.%l) %-6V (%c:%F:%L) - %m%n'
   * name         default
   * pattern      %d(%F %X.%l) %-6V (%c:%F:%L) - %m%n
   }
  memset(@a_format.name, $00, sizeof(a_format.name));
  nread := 0;
  nscan := sscanf(line, ' %[^= ] = %n', [a_format.name, @nread]);
  if nscan <> 1 then begin
    zc_error('format[%s], syntax wrong', [line]);
    goto _err;
  end;
  if (line + nread)^  <> '"' then
  begin
    zc_error('the 1st AnsiChar  of pattern is not ", line+nread[%s]', [line+nread]);
    goto _err;
  end;

  p := a_format.name;
  while p^ <> #0 do
  begin
    if (not isalnum(p^))  and  ( p^ <> '_') then
    begin
      zc_error('a_format.name[%s] AnsiChar acter is not in [a-Z][0-9][_]', [a_format.name]);
      goto _err;
    end;
    Inc(p);
  end;
  p_start := line + nread + 1;
  p_end := strrchr(p_start, '"');
  if nil =p_end then
  begin
    zc_error('there is no " at end of pattern, line[%s]', [line]);
    goto _err;
  end;
  if p_end - p_start > sizeof(a_format.pattern) - 1  then
  begin
    zc_error('pattern is too long', []);
    goto _err;
  end;
  memset(@a_format.pattern, $00, sizeof(a_format.pattern));
  memcpy(@a_format.pattern, p_start, p_end - p_start);
  if zc_str_replace_env(a_format.pattern, sizeof(a_format.pattern)) > 0 then
  begin
    zc_error('zc_str_replace_env fail', []);
    goto _err;
  end;
  a_format.pattern_specs := zc_arraylist_new(zlog_spec_del);
  if nil =(a_format.pattern_specs) then
  begin
    zc_error('zc_arraylist_new fail', []);
    goto _err;
  end;

  p := a_format.pattern;
  while p^ <> #0 do
  begin
    a_spec := zlog_spec_new(p, @q, time_cache_count);
    if nil = a_spec then begin
      zc_error('zlog_spec_new fail', []);
      goto _err;
    end;
    if zc_arraylist_add(a_format.pattern_specs, a_spec) > 0 then
    begin
      zlog_spec_del(a_spec);
      zc_error('zc_arraylist_add fail', []);
      goto _err;
    end;
    p := q;
  end;
  zlog_format_profile(a_format, Int(__ZC_DEBUG));
  Exit(a_format);
_err:
  zlog_format_del(a_format);
  Result := nil;
end;



function unlock_file( fd : TLOCK_FD):Boolean;
var
  ret : Boolean;
  err : DWORD;
begin
    if fd = INVALID_LOCK_FD then begin
        Exit(true);
    end;
{$IFDEF MSWINDOWS }
    ret := CloseHandle(intptr(fd));
    if ret = false then begin
        err := GetLastError();
    zc_error('unlock file error : %d ', [err]);
    end;
{$ELSE}
    ret := close(fd) = 0;
    if ret = false then begin
    zc_error('unlock file error : %s ', [strerror(errno)]);
    end;
{$ENDIF}
    Result := ret;
end;

procedure zlog_rotater_del( a_rotater : Pzlog_rotater);
begin
  assert(a_rotater <> nil);
  if a_rotater.lock_fd <> INVALID_LOCK_FD then
  begin
    if not unlock_file(a_rotater.lock_fd) then
    begin
      zc_error('close fail, errno[%d]', [errno]);
    end;
        a_rotater.lock_fd := INVALID_LOCK_FD;
  end;
  if pthread_mutex_destroy(a_rotater.lock_mutex) > 0 then
  begin
    zc_error('pthread_mutex_destroy fail, errno[%d]', [errno]);
  end;
  zc_debug('zlog_rotater_del[%p]', [a_rotater]);
  freeMem(a_rotater);

end;



function zlog_rotater_new( lock_file : PTChar):Pzlog_rotater;
var
  a_rotater : Pzlog_rotater;
begin
  assert(lock_file <> nil);
  a_rotater := calloc(1, sizeof(Tzlog_rotater));
  if nil =a_rotater then begin
    zc_error('calloc fail, errno[%d]', [errno]);
    Exit(nil);
  end;
  if pthread_mutex_init(a_rotater.lock_mutex , nil) > 0 then
  begin
    zc_error('pthread_mutex_init fail, errno[%d]', [errno]);
    freeMem(a_rotater);
    Exit(nil);
  end;
  a_rotater.lock_fd := INVALID_LOCK_FD;
  a_rotater.lock_file := lock_file;
  //zlog_rotater_profile(a_rotater, ZC_DEBUG);
  Exit(a_rotater);
  zlog_rotater_del(a_rotater);
  Result := nil;
end;


function zlog_conf_parse_line( a_conf : Pzlog_conf; line : PTChar; section : PInteger):integer;
var
  nscan,
  nread        : integer;
  name,
  word_1,
  word_2,
  word_3,
  value        : array[0..MAXLEN_CFG_LINE] of TChar;
  a_format     : Pzlog_format;
  a_rule       : Pzlog_rule;
  last_section : integer;

begin
  name := '';
  a_format := nil;
  a_rule := nil;
  if Length(line) > MAXLEN_CFG_LINE  then
  begin
    zc_error ('line_len[%ld] > MAXLEN_CFG_LINE[%ld], may cause overflow',
               [Length(line), MAXLEN_CFG_LINE]);
    Exit(-1);
  end;
  { get and set outer section flag, so it is a closure? haha }
  if line[0] = '[' then
  begin
    last_section := section^;
    nscan := sscanf(line, '[ %[^] '#9']', [name]);
    if STRCOMP(name, 'global') = 0 then
    begin
      section^ := 1;
    end
    else
    if STRCOMP(name, 'levels') = 0 then
    begin
      section^ := 2;
    end
    else
    if STRCOMP(name, 'formats') = 0 then
    begin
        section^ := 3;
    end
    else
    if (STRCOMP(name, 'rules')) = 0 then
    begin
        section^ := 4;
    end
    else
    begin
        zc_error('wrong section name[%s]', [name]);
        Exit(-1);
      end;
    { check the sequence of section, must increase }
    if last_section >= section^ then
    begin
      zc_error('wrong sequence of section, must follow global.levels.formats.rules', []);
      Exit(-1);
    end;
    if section^ = 4 then
    begin
      if (a_conf.reload_conf_period <> 0) and
         (a_conf.fsync_period >= a_conf.reload_conf_period) then
      begin
        { as all rule will be rebuilt when conf is reload,
         * so fsync_period > reload_conf_period will never
         * cause rule to fsync it's file.
         * fsync_period will be meaningless and down speed,
         * so make it zero.
         }
        zc_warn('fsync_period[%ld] >= reload_conf_period[%ld],'+
          'set fsync_period to zero', []);
        a_conf.fsync_period := 0;
      end;
      { now build rotater and default_format
       * from the unchanging global setting,
       * for zlog_rule_new() }
      a_conf.rotater := zlog_rotater_new(a_conf.rotate_lock_file);
      if nil =a_conf.rotater then
      begin
        zc_error('zlog_rotater_new fail', []);
        Exit(-1);
      end;
      a_conf.default_format := zlog_format_new(a_conf.default_format_line,
              @a_conf.time_cache_count);
      if nil =a_conf.default_format then
      begin
        zc_error('zlog_format_new fail', []);
        Exit(-1);
      end;
    end;
    Exit(0);
  end;
  { process detail }
  case  section^ of
  1:
  begin
    memset(@name, $00, sizeof(name));
    memset(@value, $00, sizeof(value));
    nscan := sscanf(line, ' %[^=]= %s ', [name, value]);
    if nscan <> 2 then begin
      zc_error('sscanf [%s] fail, name or value is null', [line]);
      Exit(-1);
    end;
    memset(@word_1, $00, sizeof(word_1));
    memset(@word_2, $00, sizeof(word_2));
    memset(@word_3, $00, sizeof(word_3));
    nread := 0;
    nscan := sscanf(name, '%s%n%s%s', [word_1, @nread, word_2, word_3]);
    if (strcmp(@word_1, 'strict') = 0)  and  (strcmp(@word_2, 'init') = 0) then
    begin
      { if environment variable ZLOG_STRICT_INIT is set
       * then always make it strict
       }
      if (strcasecmp(value, 'false') = 0)  and  (nil =getenv('ZLOG_STRICT_INIT')) then  begin
        a_conf.strict_init := 0;
      end
      else begin
        a_conf.strict_init := 1;
      end;
    end
    else
    if (STRCOMP(word_1, 'buffer') = 0)  and  (STRCOMP(word_2, 'min') = 0) then begin
      a_conf.buf_size_min := zc_parse_byte_size(value);
    end
    else
    if (STRCOMP(word_1, 'buffer') = 0)  and  (STRCOMP(word_2, 'max') = 0) then
    begin
      a_conf.buf_size_max := zc_parse_byte_size(value);
    end
    else if (STRCOMP(word_1, 'file') = 0)  and  (STRCOMP(word_2, 'perms') = 0) then
    begin
       sscanf(value, '%o', [@a_conf.file_perms]);
    end
    else
    if (STRCOMP(word_1, 'rotate') = 0)  and
       (STRCOMP(word_2, 'lock') = 0)  and  (STRCOMP(word_3, 'file') = 0) then
    begin
      { may overwrite the inner default value, or last value }
      if STRCOMP(value, 'self') = 0 then  begin
        Move(a_conf.conf_file, a_conf.rotate_lock_file, SizeOf(a_conf.conf_file));
      end
      else begin
        Move(value, a_conf.rotate_lock_file, 4096) ;
      end;
    end
    else
    if (STRCOMP(word_1, 'default') = 0)  and  (STRCOMP(word_2, 'format') = 0 ) then begin
      { so the input now is [format = 'xxyy'], fit format's style }
      Move((line + nread)^, a_conf.default_format_line, 4096);
    end
    else
    if (STRCOMP(word_1, 'reload') = 0)  and
       (STRCOMP(word_2, 'conf') = 0)  and  (STRCOMP(word_3, 'period') = 0) then begin
      a_conf.reload_conf_period := zc_parse_byte_size(value);
    end
    else
    if (STRCOMP(word_1, 'fsync') = 0)  and  (STRCOMP(word_2, 'period') = 0) then begin
          a_conf.fsync_period := zc_parse_byte_size(value);
    end
    else
    begin
          zc_error('name[%s] is not any one of global options', [name]);
          if a_conf.strict_init > 0 then Exit(-1);
    end;
  end;
  2:
  begin
    if zlog_level_list_set(a_conf.levels, line ) > 0 then begin
      zc_error('zlog_level_list_set fail', []);
      if a_conf.strict_init > 0 then Exit(-1);
    end;
  end;
  3:
  begin
    a_format := zlog_format_new(line, @a_conf.time_cache_count);
    if nil =a_format then begin
      zc_error('zlog_format_new fail [%s]', [line]);
      if a_conf.strict_init > 0 then Exit(-1);
    end;
    if zc_arraylist_add(a_conf.formats, a_format) > 0 then
    begin
      zlog_format_del(a_format);
      zc_error('zc_arraylist_add fail', []);
      Exit(-1);
    end;
  end;
  4:
  begin
      a_rule := zlog_rule_new(line,
                              a_conf.levels,
                              a_conf.default_format,
                              a_conf.formats,
                              a_conf.file_perms,
                              a_conf.fsync_period,
                              @a_conf.time_cache_count);
    if nil = a_rule then
    begin
      zc_error('zlog_rule_new fail [%s]', [line]);
      if a_conf.strict_init > 0 then
         Exit(-1);
    end;
    if zc_arraylist_add(a_conf.rules, a_rule) > 0 then
    begin
      zlog_rule_del(a_rule);
      zc_error('zc_arraylist_add fail', []);
      Exit(-1);
    end;
  end;
  else
  begin
    zc_error('not in any section', []);
    Exit(-1);
  end;
  end;
  Result := 0;
end;

function zlog_conf_build_with_file( a_conf : Pzlog_conf):integer;
var
  rc           : integer;
  a_stat       : Tzlog_stat;
  local_time   : Ttm;
  fp           : PFILE;
  line         : array[0..MAXLEN_CFG_LINE] of TChar;
  line_len     : size_t;
  pline,
  p, outp      : PTChar;
  line_no, i,
  in_quotation,
  section      : integer;
label _exit;
begin
  rc := 0;
  fp := nil;
  pline := nil;
  p := nil;
  line_no := 0;
  i := 0;
  in_quotation := 0;
  section := 0;
  if stat(a_conf.conf_file, @a_stat) > 0 then
  begin
    zc_error('lstat conf file[%s] fail, errno[%d]', [a_conf.conf_file,  errno]);
    Exit(-1);
  end;
  a_stat.st_mtime := DateTimeToUnix(Now);
  gmtime_r(@a_stat.st_mtime, @local_time);
  strftime(a_conf.mtime, sizeof(a_conf.mtime), '%Y-%m-%d %H:%M:%S', @local_time);
  fp := fopen(a_conf.conf_file, 'r');
  if fp = nil then  begin
    zc_error('open configure file[%s] fail', [a_conf.conf_file]);
    Exit(-1);
  end;
  { Now process the file.
   }
  pline := line;
  memset(@line, $00, sizeof(line));
  while fgets(pline, sizeof(line) - (pline - line), fp) <> nil do
  begin
    Inc(line_no);
    line_len := Length(pline);
    if 0 = line_len then
      continue;

    if pline[line_len - 1] = #10 then
      pline[line_len - 1] := #0;

    { check for end-of-section, comments, strip off trailing
     * spaces and newline AnsiChar acter.
     }
    p := pline;
    while (p^ <> #0)  and  (isspace(p^)) do
        Inc(p);
    if (p^ = #0)  or  (p^ = '#') then
       continue;
    i := 0;
    while p[i] <> #0 do
    begin
      pline[i] := p[i];
      Inc(i);
    end;
    pline[i] := #0;
    p := pline + Length(pline) - 1;
    while isspace(p^) do
      Dec(p);
      {EMPTY}

    if p^ = '\' then
    begin
      if (p - line) > MAXLEN_CFG_LINE - 30 then
      begin
        { Oops the buffer is full - what now? }
        pline := line;
      end
      else
      begin
        Dec(p);
        while (p >= line)  and  (isspace(p^)) do
          Dec(p); {EMPTY}

        Inc(p);
        p^ := #0;
        pline := p;
        continue;
      end;
    end
    else
      pline := line;

    PreInc(p)^ := #0;
    { clean the tail comments start from # and not in quotation }
    in_quotation := 0;
    p := @line;
    while p^ <> #0 do
    begin
      if p^ = '"' then
      begin
        in_quotation  := in_quotation xor 1;
        Inc(p);
        continue;
      end;
      if (p^ = '#')  and  (0 >= in_quotation) then
      begin
        p^ := #0;
        break;
      end;
      Inc(p);
    end;
    { we now have the complete line,
     * and are positioned at the first non-whitespace
     * AnsiChar acter. So let's process it
     }
    rc := zlog_conf_parse_line(a_conf, line, @section);
    if rc < 0 then
    begin
      zc_error('parse configure file[%s]line_no[%ld] fail', [a_conf.conf_file, line_no]);
      zc_error('line[%s]', [line]);
      goto _exit;
    end
    else if (rc > 0) then
    begin
      zc_warn('parse configure file[%s]line_no[%ld] fail', [a_conf.conf_file, line_no]);
      zc_warn('line[%s]', [line]);
      zc_warn('as strict init is set to false, ignore and go on', []);
      rc := 0;
      continue;
    end;
  end;
_exit:
  fclose(fp);
  Result := rc;
end;


procedure zlog_rule_del( a_rule : Pzlog_rule);
begin
  assert(a_rule <> nil);
  if a_rule.dynamic_specs <> nil then
  begin
    zc_arraylist_del(a_rule.dynamic_specs);
    a_rule.dynamic_specs := nil;
  end;
  if a_rule.static_fd > 0 then
  begin
    if closeHandle(a_rule.static_fd) then  begin
      zc_error('close fail, maybe cause by write, errno[%d]', [errno]);
    end;
  end;
{$IFNDEF MSWINDOWS}
  if a_rule.pipe_fp then begin
    if pclose(a_rule.pipe_fp) = -1 then  begin
      zc_error('pclose fail, errno[%d]', errno);
    end;
  end;
{$ENDIF}
  if a_rule.archive_specs <> nil then
  begin
    zc_arraylist_del(a_rule.archive_specs);
    a_rule.archive_specs := nil;
  end;
  zc_debug('zlog_rule_del[%p]', [a_rule]);
  freeMem(a_rule);

end;

procedure zlog_format_del( a_format : Pzlog_format);
begin
  assert(a_format <> nil);
  if a_format.pattern_specs <> nil then begin
    zc_arraylist_del(a_format.pattern_specs);
  end;
  zc_debug('zlog_format_del[%p]', [a_format]);
  freeMem(a_format);

end;



procedure zc_arraylist_del( a_list : Pzc_arraylist);
var
  i : integer;
begin
  if nil =a_list then exit;
  if Assigned(a_list.del) then
  begin
    for i := 0 to a_list.len-1 do begin
      if a_list._array[i] <> nil then
        a_list.del(a_list._array[i]);
    end;
  end;
  if a_list._array <> nil then
     freeMem(a_list._array);
  freeMem(a_list);

end;




function zc_arraylist_expand_inner( a_list : Pzc_arraylist; _max : integer):integer;
var
  tmp       : Pointer;
  new_size,
  diff_size : integer;
begin
  new_size := max(a_list.size * 2, _max);
  reallocmem(a_list._array, new_size * sizeof(Pointer ));
  {if 0>=tmp then begin
    zc_error('realloc fail, errno[%d]', errno);
    Exit(-1);
  end;}
  //a_list.array := (PPointer )tmp;
  diff_size := new_size - a_list.size;
  if diff_size > 0 then
     memset(a_list._array + a_list.size, $00, diff_size * sizeof(Pointer ));
  a_list.size := new_size;
  Result := 0;
end;

function zc_arraylist_set( a_list : Pzc_arraylist; idx : integer; data : Pointer):integer;
begin
  if idx > a_list.size - 1 then
  begin
    if zc_arraylist_expand_inner(a_list, idx) > 0 then
     begin
      zc_error('expand_internal fail', []);
      Exit(-1);
    end;
  end;
  if (a_list._array[idx] <> nil) and  (Assigned(a_list.del)) then
      a_list.del(a_list._array[idx]);
  a_list._array[idx] := data;
  if a_list.len <= idx then
     a_list.len := idx + 1;
  Result := 0;
end;


function zc_assert(expr: Boolean; rv: Integer): Integer;
begin
	if not (expr) then
  begin
		zc_error('expr is null or 0', []);
		Result := rv;
	end;
end;

function syslog_level_atoi( str : PTChar):integer;
begin
  { guess no unix system will choose -187
   * as its syslog level, so it is a safe return value
   }
  zc_assert(str <> nil, -187);
  if strcasecmp(str,'LOG_EMERG' ) = 0 then
    Exit(LOG_EMERG);
  if strcasecmp(str, 'LOG_ALERT' ) = 0 then
    Exit(LOG_ALERT);
  if strcasecmp(str, 'LOG_CRIT' ) = 0 then
    Exit(LOG_CRIT);
  if strcasecmp(str, 'LOG_ERR' ) = 0 then
    Exit(LOG_ERR);
  if strcasecmp(str, 'LOG_WARNING' ) = 0 then
    Exit(LOG_WARNING);
  if strcasecmp(str, 'LOG_NOTICE' ) = 0 then
    Exit(LOG_NOTICE);
  if strcasecmp(str, 'LOG_INFO' ) = 0 then
    Exit(LOG_INFO);
  if strcasecmp(str, 'LOG_DEBUG' ) = 0 then
    Exit(LOG_DEBUG);
  zc_error('wrong syslog level[%s]', [str]);
  Result := -187;
end;

function zlog_level_new( line : PTChar):Pzlog_level;
var
  a_level : Pzlog_level;
  i, nscan : integer;
  str : array[0..(MAXLEN_CFG_LINE + 1)-1] of TChar;
  l : integer;
  sl : array[0..(MAXLEN_CFG_LINE + 1)-1] of TChar;
label _err;
begin
  a_level := nil;
  l := 0;
  //zc_assert(line, nil);
  memset(@str, $00, sizeof(str));
  memset(@sl, $00, sizeof(sl));
  nscan := sscanf(line, ' %[^= '#9'] = %d ,%s', [str, @l, sl]);
  if nscan < 2 then begin
    zc_error('level[%s], syntax wrong', [line]);
    Exit(nil);
  end;
  { check level and str }
  if (l < 0)  or  (l > 255) then  begin
    zc_error('l[%d] not in [0,255], wrong', [l]);
    Exit(nil);
  end;
  if str[0] = #0 then begin
    zc_error('str[0] = 0', []);
    Exit(nil);
  end;
  a_level := calloc(1, sizeof(Tzlog_level));
  if nil =a_level then begin
    zc_error('calloc fail, errno[%d]', [errno]);
    Exit(nil);
  end;
  a_level.int_level := l;
  { fill syslog level }
  if sl[0] = #0 then begin
    a_level.syslog_level := LOG_DEBUG;
  end
 else
 begin
    a_level.syslog_level := syslog_level_atoi(sl);
    if a_level.syslog_level = -187 then begin
      zc_error('syslog_level_atoi fail', []);
      goto _err;
    end;
  end;
  { strncpy and toupper(str)  }
  i := 0;
  while (i < sizeof(a_level.str_uppercase) - 1)  and  (str[i] <> #0) do
  begin
    a_level.str_uppercase[i] := toupper(str[i]);
    a_level.str_lowercase[i] := tolower(str[i]);
    Inc(i);
  end;
  if str[i] <> #0 then begin
    { overflow }
    zc_error('not enough space for str, str[%s] > %d', [str, i]);
    goto _err;
  end
 else begin
    a_level.str_uppercase[i] := #0;
    a_level.str_lowercase[i] := #0;
  end;
  a_level.str_len := i;
  //zlog_level_profile(a_level, ZC_DEBUG);
  Exit(a_level);

_err:
  zc_error('line[%s]', [line]);
  zlog_level_del(a_level);
  Result := nil;
end;


function zlog_level_list_set( levels : Pzc_arraylist; line : PTChar):integer;
var
  a_level : Pzlog_level;
label _err;
begin
  a_level := zlog_level_new(line);
  if nil =a_level then begin
    zc_error('zlog_level_new fail', []);
    Exit(-1);
  end;
  if zc_arraylist_set(levels, a_level.int_level, a_level) > 0 then
  begin
    zc_error('zc_arraylist_set fail', []);
    goto _err;
  end;
  Exit(0);

_err:
  zc_error('line[%s]', [line]);
  zlog_level_del(a_level);
  Result := -1;
end;


function zlog_level_list_set_default( levels : Pzc_arraylist):integer;
begin
  Result := zlog_level_list_set(levels, '* = 0, LOG_INFO')
             or  zlog_level_list_set(levels, 'DEBUG = 20, LOG_DEBUG')
             or  zlog_level_list_set(levels, 'INFO = 40, LOG_INFO')
             or  zlog_level_list_set(levels, 'NOTICE = 60, LOG_NOTICE')
             or  zlog_level_list_set(levels, 'WARN = 80, LOG_WARNING')
             or  zlog_level_list_set(levels, 'ERROR = 100, LOG_ERR')
             or  zlog_level_list_set(levels, 'FATAL = 120, LOG_ALERT')
             or  zlog_level_list_set(levels, 'UNKNOWN = 254, LOG_ERR')
             or  zlog_level_list_set(levels, '! = 255, LOG_INFO');
end;



procedure zlog_level_del( a_level : Pzlog_level);
begin
  assert(a_level <> nil);
  zc_debug('zlog_level_del[%p]', [a_level]);
    freeMem(a_level);
end;


function zc_arraylist_new( del : Tzc_arraylist_del_fn):Pzc_arraylist;
var
  a_list : Pzc_arraylist;
begin
  a_list := Pzc_arraylist (calloc(1, sizeof(Tzc_arraylist)));
  if nil =a_list then begin
    zc_error('calloc fail, errno[%d]', [errno]);
    Exit(nil);
  end;
  a_list.size := ARRAY_LIST_DEFAULT_SIZE;
  a_list.len := 0;
  { this could be nil }
  a_list.del := del;
  a_list._array := PPointer (calloc(a_list.size, sizeof(Pointer )));
  if nil =a_list._array then begin
    zc_error('calloc fail, errno[%d]', [errno]);
    freeMem(a_list);
    Exit(nil);
  end;
  Result := a_list;
end;


function zlog_level_list_new:Pzc_arraylist;
var
  levels : Pzc_arraylist;
  label _err;

begin
  levels := zc_arraylist_new(@zlog_level_del);
  if nil =levels then
    zc_error('zc_arraylist_new fail', []);

  if zlog_level_list_set_default(levels) > 0 then
  begin
    zc_error('zlog_level_set_default fail', []);
    goto _err;
  end;

  //zlog_level_list_profile(levels, ZC_DEBUG);
  Exit(levels);
_err:
  zc_arraylist_del(levels);
  Exit(nil);
end;

function zlog_conf_new(const config : PTChar):Pzlog_conf;
var
  nwrite,
  cfg_source : integer;
  a_conf     : Pzlog_conf;
  label  _err;
begin
  nwrite := 0;
  cfg_source := 0;
  a_conf := nil;
  a_conf := calloc(1, sizeof(Tzlog_conf));
  if nil = a_conf then begin
    zc_error('calloc fail, errno[%d]', [errno]);
  end;
  // Find content of pointer. If it starts with '[' then content are configurations.
  if (config <> nil) and  (config[0] <> #0)  and  (config[0] <> '[') then
  begin
    nwrite := snprintf(a_conf.conf_file, sizeof(a_conf.conf_file), '%s', [config]);
    cfg_source := FILE_CFG;
  end
  else if (getenv('ZLOG_CONF_PATH') <> nil) then
  begin
    nwrite := snprintf(a_conf.conf_file, sizeof(a_conf.conf_file), '%s', [getenv('ZLOG_CONF_PATH')]);
    cfg_source := FILE_CFG;
  end
 else if (config <> nil)  and  (config[0] = '[') then
 begin
    memset(@a_conf.conf_file, $00, sizeof(a_conf.conf_file));
    nwrite := snprintf(a_conf.cfg_ptr, sizeof(a_conf.cfg_ptr), '%s', [config]);
    cfg_source := IN_MEMORY_CFG;
    if (nwrite < 0)  or  (nwrite >= sizeof(a_conf.conf_file)) then
    begin
      zc_error('not enough space for configurations, nwrite=[%d], errno[%d]', [nwrite, errno]);
      goto _err;
    end;
  end
  else begin
    memset(@a_conf.conf_file, $00, sizeof(a_conf.conf_file));
    cfg_source := NO_CFG;
  end;
  if (nwrite < 0)  or  ( (nwrite >= sizeof(a_conf.conf_file))  and  (cfg_source = FILE_CFG)) then
  begin
    zc_error('not enough space for path name, nwrite=[%d], errno[%d]', [nwrite, errno]);
    goto _err;
  end;
  { set default configuration start }
  a_conf.strict_init := 1;
  a_conf.buf_size_min := ZLOG_CONF_DEFAULT_BUF_SIZE_MIN;
  a_conf.buf_size_max := ZLOG_CONF_DEFAULT_BUF_SIZE_MAX;
  if cfg_source = FILE_CFG then begin
    { configure file as default lock file }
    move(a_conf.conf_file, a_conf.rotate_lock_file, 1025);
  end
  else
    a_conf.rotate_lock_file := ZLOG_CONF_BACKUP_ROTATE_LOCK_FILE;

  a_conf.default_format_line := ZLOG_CONF_DEFAULT_FORMAT;
  a_conf.file_perms := ZLOG_CONF_DEFAULT_FILE_PERMS;
  a_conf.reload_conf_period := ZLOG_CONF_DEFAULT_RELOAD_CONF_PERIOD;
  a_conf.fsync_period := ZLOG_CONF_DEFAULT_FSYNC_PERIOD;
  { set default configuration end }
  a_conf.levels := zlog_level_list_new();
  if nil = a_conf.levels then begin
    zc_error('zlog_level_list_new fail', []);
    goto _err;
  end;
  a_conf.formats := zc_arraylist_new(@zlog_format_del);
  if nil = a_conf.formats then begin
    zc_error('zc_arraylist_new fail', []);
    goto _err;
  end;
  a_conf.rules := zc_arraylist_new(@zlog_rule_del);
  if nil = a_conf.rules then begin
    zc_error('init rule_list fail', []);
    goto _err;
  end;

  case cfg_source of
      FILE_CFG:
      begin
        if zlog_conf_build_with_file(a_conf) > 0 then
        begin
          zc_error('zlog_conf_build_with_file fail', []);
          goto _err;
        end;
      end;
      IN_MEMORY_CFG:
      begin
        if zlog_conf_build_with_in_memory(a_conf) > 0 then
        begin
          zc_error('zlog_conf_build_with_in_memory fail', []);
          goto _err;
        end;
      end;
      else
      begin
        if zlog_conf_build_without_file(a_conf) > 0 then
        begin
          zc_error('zlog_conf_build_without_file fail', []);
          goto _err;
        end;
      end;
  end;
  zlog_conf_profile(a_conf, __ZC_DEBUG);
  Exit(a_conf);

_err:
  zlog_conf_del(a_conf);
  Exit(nil)
end;

procedure zlog_clean_rest_thread;
var
  a_thread : Pzlog_thread;
begin
  a_thread := pthread_getspecific(zlog_thread_key);
  if nil =a_thread then exit;
  zlog_thread_del(a_thread);
  exit;
end;



procedure zlog_buf_del( a_buf : Pzlog_buf);
begin
  //zc_assert(a_buf,);
  if a_buf.start <> nil then
     freemem(a_buf.start);
  zc_debug('zlog_buf_del[%p]', [a_buf]);
    freemem(a_buf);
  exit;
end;




procedure zlog_event_del( a_event : Pzlog_event);
begin
  assert(a_event <> nil);
  if a_event.time_caches <> nil then
     freemem(a_event.time_caches);
  zc_debug('zlog_event_del[%p]', [a_event]);
    freemem(a_event);
  exit;
end;



procedure zc_hashtable_del( a_table : Pzc_hashtable);
var
  i : size_t;
  p, q : Pzc_hashtable_entry;
begin
  if nil =a_table then begin
    zc_error('a_table[%p] is nil, just do nothing', [a_table]);
    exit;
  end;
  for i := 0 to a_table.tab_size-1 do
  begin
    p := a_table.tab[i];
    while p <> nil do
    begin
      q := p.next;
      if Assigned(a_table.key_del) then begin
        a_table.key_del(p.key);
      end;
      if Assigned(a_table.value_del) then begin
        a_table.value_del(p.value);
      end;

      FreeMem(p); p := q;
    end;
  end;
  if a_table.tab <> nil then
     freemem(a_table.tab);
  freemem(a_table);
  exit;
end;


procedure zlog_mdc_del( a_mdc : Pzlog_mdc);
begin
  assert(a_mdc <> nil);
  if a_mdc.tab <> nil then
     zc_hashtable_del(a_mdc.tab);
  zc_debug('zlog_mdc_del[%p]', [a_mdc]);
  freemem(a_mdc);
  exit;
end;

procedure zlog_thread_del( a_thread : Pzlog_thread);
begin
  assert(a_thread <> nil);
  if a_thread.mdc <> nil then zlog_mdc_del(a_thread.mdc);
  if a_thread.event <> nil then zlog_event_del(a_thread.event);
  if a_thread.pre_path_buf <> nil then zlog_buf_del(a_thread.pre_path_buf);
  if a_thread.path_buf <> nil then zlog_buf_del(a_thread.path_buf);
  if a_thread.archive_path_buf <> nil then zlog_buf_del(a_thread.archive_path_buf);
  if a_thread.pre_msg_buf <> nil then zlog_buf_del(a_thread.pre_msg_buf);
  if a_thread.msg_buf <> nil then zlog_buf_del(a_thread.msg_buf);
  zc_debug('zlog_thread_del[%p]', [a_thread]);
  SetLength(a_thread.event.str_args, 0);
  freemem(a_thread);

end;


function zlog_init_inner(const config : PTChar):integer;
var
  rc : integer;
  label  _err;
begin
  rc := 0;
  { the 1st time in the whole process do init }
  if zlog_env_init_version = 0 then
  begin
    { clean up is done by OS when a thread call pthread_exit }
    rc := pthread_key_create(zlog_thread_key, @zlog_thread_del);
    if rc > 0 then begin
      zc_error('pthread_key_create fail, rc[%d]', [rc]);
      goto _err;
    end;
    { if some thread do not call pthread_exit, like main thread
     * atexit will clean it
     }
    addexitProc(zlog_clean_rest_thread);

    {if rc > 0 then begin
      zc_error('atexit fail, rc[%d]', [rc]);
      goto _err;
    end;}
    Inc(zlog_env_init_version);
  end;
 { else maybe after zlog_fini() and need not create pthread_key }
  zlog_env_conf := zlog_conf_new(config);
  if nil =zlog_env_conf then
  begin
    zc_error('zlog_conf_new[%s] fail', [config]);
    goto _err;
  end;
  zlog_env_categories := zlog_category_table_new();
  if nil =zlog_env_categories then
  begin
    zc_error('zlog_category_table_new fail', []);
    goto _err;
  end;
  zlog_env_records := zlog_record_table_new();
  if nil =zlog_env_records then begin
    zc_error('zlog_record_table_new fail', []);
    goto _err;
  end;
  Exit(0);
_err:
  zlog_fini_inner();
  Result := -1;
end;

function __TIME__: __TEXT;
begin
   Result := DateTimeToStr(Time);
end;

function __DATE__: __TEXT;
begin
   Result := DateTimeToStr(Now);
end;

procedure zc_time( time_str : PTChar; time_str_size : size_t);
var
    tt         : time_t;
    local_time : Ptm;
    s: Ansistring;
begin
{$IFDEF MSWINDOWS }
  s := FormatDateTime('mm-dd hh:nn:ss', Now);
  Move(s[1], time_str^, time_str_size);
{$ELSE}
  localtime_r(&tt, &local_time);
  strftime(time_str, time_str_size, '%m-%d %H:%M:%S', &local_time);
{$ENDIF}
  exit;
end;

function zc_profile_inner(flag : integer;const _file :String; line : long; fmt : PTChar; args : array of const):integer;
var
  time_str : array[0..20] of TChar;
  fp       : PFILE;
  fname: AnsiString;
begin
  fp := nil;
  fname := _file;
  if 0>=init_flag then begin
    init_flag := 1;
    //debug_log := getenv('ZLOG_PROFILE_DEBUG');
    //error_log := getenv('ZLOG_PROFILE_ERROR');
  end;
  case flag of
      __ZC_DEBUG:
      begin
        if debug_log = nil then
           Exit(0);
        fp := fopen(debug_log, 'a');
        if nil = fp then Exit(-1);
        FillChar(time_str, SizeOf(time_str), 0);
        zc_time(time_str, sizeof(time_str));
        fprintf(fp, '%s DEBUG (pid:%d %s Line:%d) ',[@time_str, getpid(), PTChar(fname), line]);
      end;
      __ZC_WARN:
      begin
        if error_log = nil then Exit(0);
        fp := fopen(error_log, 'a');
        if nil =fp then Exit(-1);
        zc_time(time_str, sizeof(time_str));
        memset(fp.buffer, Length(fp.buffer), 0);
        fprintf(fp, '%s WARN  (%d:%s:%d) ',[time_str, getpid(), PTChar(fname), line]);
      end;
      __ZC_ERROR:
      begin
        if error_log = nil then Exit(0);
        fp := fopen(error_log, 'a');
        if nil =fp then Exit(-1);
        zc_time(time_str, sizeof(time_str));
        FillChar(fp.buffer^, Length(fp.buffer), 0);
        fprintf(fp, '%s ERROR (%d:%s:%d) ',[time_str, getpid(), PTChar(fname), line]);
      end;
  end;
  { writing file twice(time and msg) is not atomic
   * may cause cross
   * but avoid log size limit }

  vfprintf(fp, fmt, args);
  fprintf(fp, #10, []);
  fclose(fp);
  Exit(0);
end;

function zc_warn(fmt: PTChar; args: array of const): Integer;
begin
		Result := zc_profile_inner(Int(__ZC_WARN), __FILE__, __LINE__, fmt, args)
end;

function zc_debug(fmt: PTChar; args: array of const): Integer;
begin
		Result := zc_profile_inner(Int(__ZC_DEBUG), __FILE__, __LINE__, fmt, args)
end;

function zc_error(fmt: PTChar; args: array of const): Integer;
begin
		Result := zc_profile_inner(Int(__ZC_ERROR), __FILE__, __LINE__, fmt, args)
end;

function zlog_init(const config : PTChar):integer;
var
  rc : integer;
  label _err;
begin
  Assert(false);
  zc_debug('------zlog_init start----', []);
  zc_debug('------compile time[%s], version[%s]------', [PTChar(__DATE__), ZLOG_VERSION]);
  rc := pthread_rwlock_wrlock(@zlog_env_lock);
  if rc > 0 then begin
    zc_error('pthread_rwlock_wrlock fail, rc[%d]', [rc]);
    Exit(-1);
  end;
  if zlog_env_is_init > 0 then
  begin
    zc_error('already init, use zlog_reload pls', []);
    goto _err;
  end;
  if zlog_init_inner(config) > 0 then begin
    zc_error('zlog_init_inner[%s] fail', [config]);
    goto _err;
  end;
  zlog_env_is_init := 1;
  Inc(zlog_env_init_version);
  zc_debug('------zlog_init success----end----', []);
  rc := pthread_rwlock_unlock(@zlog_env_lock);
  if rc > 0 then begin
    zc_error('pthread_rwlock_unlock fail, rc=[%d]', [rc]);
    Exit(-1);
  end;
  Exit(0);

_err:
  zc_error('------zlog_init fail----end----', []);
  rc := pthread_rwlock_unlock(@zlog_env_lock);
  if rc > 0 then begin
    zc_error('pthread_rwlock_unlock fail, rc=[%d]', [rc]);
    Exit(-1);
  end;
  Result := -1;
end;

procedure AssertErrorHandler(const Message, Filename: string;  LineNumber: Integer; ErrorAddr: Pointer);
var
  S: String;
begin
  S := Format('%s (%s, line %d, address $%x, thread id: %d)',
              [Message, Filename, LineNumber, Pred(Integer(ErrorAddr)), GetCurrentThreadId]);
  OutputDebugString(PChar(S));
  __FILE__ := PTChar(Filename);
  __LINE__ := LineNumber;
end;

procedure AssertErrorNoHandler(const Message, Filename: string; LineNumber: Integer; ErrorAddr: Pointer);
begin
   __FILE__ := ExtractFileName(Filename);
   __LINE__ := LineNumber;
end;

initialization

  if FindCmdLineSwitch('Debug', ['/', '-'], True) then
    AssertErrorProc := @AssertErrorHandler
  else
    AssertErrorProc := @AssertErrorNoHandler

end.
