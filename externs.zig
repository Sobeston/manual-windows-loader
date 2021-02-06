const std = @import("std");
usingnamespace std.os.windows;

pub extern "kernel32" fn VirtualAllocEx(
    hProcess: HANDLE,
    lpAddress: ?LPVOID,
    dwSize: SIZE_T,
    flAllocationTypew: DWORD,
    flProtect: DWORD,
) callconv(WINAPI) ?LPVOID;

pub extern "kernel32" fn VirtualFreeEx(
    hProcess: HANDLE,
    lpAddress: LPVOID,
    dwSize: SIZE_T,
    dwFreeType: DWORD,
) callconv(WINAPI) BOOL;

pub extern "kernel32" fn OpenProcess(
    dwDesiredAccess: DWORD,
    bInheritHandle: BOOL,
    dwProcessId: DWORD,
) callconv(WINAPI) ?HANDLE;

pub extern "kernel32" fn WriteProcessMemory(
    hProcess: HANDLE,
    lpBaseAddress: LPVOID,
    lpBuffer: LPCVOID,
    nSize: SIZE_T,
    lpNumberOfBytesWritten: ?*SIZE_T,
) callconv(WINAPI) BOOL;

pub extern "kernel32" fn GetModuleHandleA(
    lpModuleName: LPCSTR,
) callconv(WINAPI) ?HMODULE;

pub extern "kernel32" fn CreateRemoteThread(
    hProcess: HANDLE,
    lpThreadAttributes: ?LPSECURITY_ATTRIBUTES,
    dwStackSize: SIZE_T,
    lpStartAddress: LPTHREAD_START_ROUTINE,
    lpParameter: LPVOID,
    dwCreationFlags: DWORD,
    lpThreadId: ?LPDWORD,
) callconv(WINAPI) ?HANDLE;

pub extern "kernel32" fn LoadLibraryA(
    lib_file_name: [*:0]const u8,
) callconv(WINAPI) HMODULE;

pub const HARDERROR_RESPONSE_OPTION = extern enum(c_ulong) {
    OptionAbortRetryIgnore,
    OptionOk,
    OptionOkCancel,
    OptionRetryCancel,
    OptionYesNo,
    OptionYesNoCancel,
    OptionShutdownSystem,
    OptionOkNoWait,
    OptionCancelTryContinue,
    _,
};

pub const HARDERROR_RESPONSE = extern enum(c_ulong) {
    ResponseReturnToCaller,
    ResponseNotHandled,
    ResponseAbort,
    ResponseCancel,
    ResponseIgnore,
    ResponseNo,
    ResponseOk,
    ResponseRetry,
    ResponseYes,
    ResponseTryAgain,
    ResponseContinue,
    _,
};

pub extern "ntdll" fn NtRaiseHardError(
    error_status: NTSTATUS,
    number_of_parameters: ULONG,
    unicode_string_parameter_mask: ULONG,
    parameters: [*]usize,
    response_option: HARDERROR_RESPONSE_OPTION,
    response: ?*HARDERROR_RESPONSE,
) callconv(WINAPI) NTSTATUS;

pub extern "ntdll" fn LdrLoadDll(
    DllPath: ?[*:0]const u16,
    DllCharacteristics: ?*ULONG,
    DllName: *const UNICODE_STRING,
    DllHandle: *c_void,
) callconv(WINAPI) NTSTATUS;

pub extern "kernel32" fn VirtualProtect(
    lpAddress: *const c_void,
    dwSize: usize,
    flNewProtect: u32,
    lpflOldProtect: *u32,
) callconv(WINAPI) BOOL;

pub const IMAGE_DOS_HEADER = extern struct {
    magic: [2]u8,
    cblp: WORD,
    cp: WORD,
    crlc: WORD,
    cparhdr: WORD,
    minalloc: WORD,
    maxalloc: WORD,
    ss: WORD,
    sp: WORD,
    csum: WORD,
    ip: WORD,
    cs: WORD,
    lfarlc: WORD,
    ovno: WORD,
    res: [8]u8,
    oemid: WORD,
    oeminfo: WORD,
    res2: [20]u8,
    lfanew: LONG,
};

pub const IMAGE_FILE_HEADER = extern struct {
    magic: [4]u8,
    machine: std.coff.MachineType,
    number_of_sections: WORD,
    time_date_stamp: DWORD,
    pointer_to_symbol_table: DWORD,
    number_of_symbols: DWORD,
    size_of_optional_header: WORD,
    characteristics: WORD,
};

pub const IMAGE_DATA_DIRECTORY = extern struct {
    rva: DWORD,
    size: DWORD,
};

pub const PE_MAGIC = extern enum(u16) {
    PE_ROM_IMAGE = 0x0107,
    PE_32BIT = 0x010B,
    PE_64BIT = 0x020B,
};

pub const PE_SUBSYSTEM = extern enum(u16) {
    UNKNOWN = 0x0,
    NATIVE = 0x1,
    WINDOWS_GUI = 0x2,
    WINDOWS_CUI = 0x3,
    OS2_CUI = 0x5,
    POSIX_CUI = 0x7,
    NATIVE_WINDOWS = 0x8,
    WINDOWS_CE_GUI = 0x9,
    EFI_APPLICATION = 0xa,
    EFI_BOOT_SERVICE_DRIVER = 0xb,
    EFI_RUNTIME_DRIVER = 0xc,
    EFI_ROM = 0xd,
    XBOX = 0xe,
    WINDOWS_BOOT_APPLICATION = 0x10,
};

pub const PE_DLL_CHARACTERISTICS = struct {
    pub const _0001 = 0x1;
    pub const _0002 = 0x2;
    pub const _0004 = 0x4;
    pub const _0008 = 0x8;
    pub const HIGH_ENTROPY_VA = 0x20;
    pub const DYNAMIC_BASE = 0x40;
    pub const FORCE_INTEGRITY = 0x80;
    pub const NX_COMPAT = 0x100;
    pub const NO_ISOLATION = 0x200;
    pub const NO_SEH = 0x400;
    pub const NO_BIND = 0x800;
    pub const APPCONTAINER = 0x1000;
    pub const WDM_DRIVER = 0x2000;
    pub const GUARD_CF = 0x4000;
    pub const TERMINAL_SERVER_AWARE = 0x8000;
};

pub const IMAGE_OPTIONAL_HEADER = extern struct {
    magic: PE_MAGIC,
    major_linker_version: UCHAR,
    minor_linker_version: UCHAR,
    size_of_code: ULONG,
    size_of_initialized_data: ULONG,
    size_of_uninitialized_data: ULONG,
    address_of_entry_point: ULONG,
    base_of_code: ULONG,
    image_base: usize,
    section_alignment: ULONG,
    file_alignment: ULONG,
    major_operating_system_version: USHORT,
    minor_operating_system_version: USHORT,
    major_image_version: USHORT,
    minor_image_version: USHORT,
    major_subsystem_version: USHORT,
    minor_subsystem_version: USHORT,
    win32_version_value: ULONG,
    size_of_image: ULONG,
    size_of_headers: ULONG,
    check_sum: ULONG,
    subsystem: PE_SUBSYSTEM,
    dll_characteristics: u16,
    size_of_stack_reserve: usize,
    size_of_stack_commit: usize,
    size_of_heap_reserve: usize,
    size_of_heap_commit: usize,
    loader_flags: ULONG,
    number_of_rva_and_sizes: ULONG,
    export_table_entry: IMAGE_DATA_DIRECTORY,
    import_table_entry: IMAGE_DATA_DIRECTORY,
    resource_table_entry: IMAGE_DATA_DIRECTORY,
    exception_table_entry: IMAGE_DATA_DIRECTORY,
    certificate_table_entry: IMAGE_DATA_DIRECTORY,
    base_relocation_table_entry: IMAGE_DATA_DIRECTORY,
    debug_entry: IMAGE_DATA_DIRECTORY,
    architecture_entry: IMAGE_DATA_DIRECTORY,
    global_ptr_entry: IMAGE_DATA_DIRECTORY,
    tls_table_entry: IMAGE_DATA_DIRECTORY,
    load_config_table_entry: IMAGE_DATA_DIRECTORY,
    bound_import_entry: IMAGE_DATA_DIRECTORY,
    iat_entry: IMAGE_DATA_DIRECTORY,
    delay_import_descriptor_entry: IMAGE_DATA_DIRECTORY,
    clr_runtime_header_entry: IMAGE_DATA_DIRECTORY,
    reserved_entry: IMAGE_DATA_DIRECTORY,
};

///valid for x86-64, TODO: check for 32 bit
pub const EXPORT_DIRECTORY_TABLE = extern struct {
    exportFlags: u32,
    timeDateStamp: u32,
    majorVersion: u16,
    minorVersion: u16,
    nameRva: u32,
    ordinalBase: u32,
    addressTableEntries: u32,
    numberOfNamePointers: u32,
    exportAddressTableRva: u32,
    namePointerRva: u32,
    ordinalTableRva: u32,
};

const Entry = enum {
    export_,
    import,
    resource,
    exception,
    certificate,
    baseRelocation,
    debug,
    architecture,
    global_ptr,
    tls_table,
    load_config,
    bound_import,
    delay_import,
    clr_runtime,
    reserved,
};

pub const IMAGE_SECTION_HEADER = extern struct {
    name: [8]UCHAR,
    virtual_size: ULONG,
    virtual_address: ULONG,
    size_of_raw_data: ULONG,
    pointer_to_raw_data: ULONG,
    pointer_to_relocations: ULONG,
    pointer_to_linenumbers: ULONG,
    number_of_relocations: USHORT,
    number_of_linenumbers: USHORT,
    characteristics: ULONG,
};

pub const IMAGE_NT_HEADERS = extern struct {
    signature: DWORD,
    file_header: IMAGE_FILE_HEADER,
    optional_header: IMAGE_OPTIONAL_HEADER,
};

pub const IMAGE_EXPORT_DIRECTORY = extern struct {
    characteristics: ULONG,
    time_date_stamp: ULONG,
    major_version: USHORT,
    minor_version: USHORT,
    name: ULONG,
    base: ULONG,
    number_of_functions: ULONG,
    number_of_names: ULONG,
    address_of_functions: ULONG,
    address_of_names: ULONG,
    address_of_name_ordinals: ULONG,
};

pub const PE_SECTION_FLAGS = extern enum(u32) {
    RESERVED_0001 = 0x1,
    RESERVED_0002 = 0x2,
    RESERVED_0004 = 0x4,
    TYPE_NO_PAD = 0x8,
    RESERVED_0010 = 0x10,
    CNT_CODE = 0x20,
    CNT_INITIALIZED_DATA = 0x40,
    CNT_UNINITIALIZED_DATA = 0x80,
    LNK_OTHER = 0x100,
    LNK_INFO = 0x200,
    RESERVED_0400 = 0x400,
    LNK_REMOVE = 0x800,
    LNK_COMDAT = 0x1000,
    GPREL = 0x8000,
    MEM_PURGEABLE = 0x10000,
    MEM_16BIT = 0x20000,
    MEM_LOCKED = 0x40000,
    MEM_PRELOAD = 0x80000,
    LNK_NRELOC_OVFL = 0x1000000,
    MEM_DISCARDABLE = 0x2000000,
    MEM_NOT_CACHED = 0x4000000,
    MEM_NOT_PAGED = 0x8000000,
    MEM_SHARED = 0x10000000,
    MEM_EXECUTE = 0x20000000,
    MEM_READ = 0x40000000,
    MEM_WRITE = 0x80000000,
};

pub const SectionFlags = packed struct {
    reserved_0001: bool,
    reserved_0002: bool,
    reserved_0004: bool,
    type_no_pad: bool,
    reserved_0010: bool,
    cnt_code: bool,
    cnt_initialized_data: bool,
    cnt_uninitialized_data: bool,
    lnk_other: bool,
    lnk_info: bool,
    reserved_0400: bool,
    lnk_remove: bool,
    lnk_comdat: bool,
    pad_0: bool,
    pad_1: bool,
    gprel: bool,
    mem_purgeable: bool,
    mem_16_bit: bool,
    mem_locked: bool,
    mem_preload: bool,
    pad_2: bool,
    pad_3: bool,
    pad_4: bool,
    pad_5: bool,
    lnk_nreloc_ovfl: bool,
    mem_discardable: bool,
    mem_not_cached: bool,
    mem_not_paged: bool,
    mem_shared: bool,
    mem_execute: bool,
    mem_read: bool,
    mem_write: bool,
};

pub const Import_Directory_Table = extern struct {
    import_lookup_table_rva: u32,
    time_date_stamp: u32,
    forwarder_chain: u32,
    name_rva: u32,
    import_address_table_rva: u32,
};

pub const RelocationBlock = packed struct {
    rva: u32,
    size: u32,
};

pub const RelocationPatch = packed struct {
    offset: u12,
    reloc_type: enum(u4) {
        absolute,
        addr64,
        addr32,
        addr32_nb,
        rel32,
        rel32_1,
        rel32_2,
        rel32_3,
        rel32_4,
        rel32_5,
        section,
        secrel,
        secrel7,
        token,
        srel32,
        pair,
        // sspan32, wtf is this? why does this not fit in u4?
    },
};

comptime {
    if (@bitSizeOf(RelocationPatch) != 16 or @sizeOf(RelocationPatch) != 2) {
        @compileError("wrong size!");
    }
}
