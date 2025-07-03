use std::arch::asm;
use std::ffi::OsString;
use std::collections::HashSet;
use std::os::windows::ffi::OsStringExt;
use windows_sys::Win32::Foundation::{BOOLEAN, HANDLE, UNICODE_STRING};
use std::ffi::{c_ulong, c_void};
use std::ptr;
use windows_sys::Win32::System::Diagnostics::Debug::{
    IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_NT_HEADERS64, IMAGE_NT_OPTIONAL_HDR_MAGIC,
};
use windows_sys::Win32::System::SystemServices::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY,
};
use windows_sys::Win32::System::Threading::{PEB, TEB};
use windows_sys::Win32::System::Kernel::LIST_ENTRY;
#[cfg(target_arch = "x86_64")]
pub(crate) fn current_peb() -> *mut PEB {
    unsafe {
        let mut addr;
        // the PEB is stored in the GS register on x64
        asm!("mov {}, gs:[0x60];", out(reg) addr);
        addr
    }
}
#[repr(C)]
pub(crate) struct PebLdrData {
    length: c_ulong,
    initialized: BOOLEAN,
    ss_handle: HANDLE,
    in_load_order_module_list: LIST_ENTRY, // linked lists of modules
    in_memory_order_module_list: LIST_ENTRY,
    in_initialization_order_module_list: LIST_ENTRY,
}

#[repr(C)]
pub(crate) struct LdrDataTableEntry {
    in_load_order_links: LIST_ENTRY,
    in_memory_order_module_list: LIST_ENTRY,
    in_initialization_order_module_list: LIST_ENTRY,
    dll_base: *mut c_void,
    entry_point: *mut c_void,
    size_of_image: c_ulong,
    full_dll_name: UNICODE_STRING,
    base_dll_name: UNICODE_STRING,
}

pub unsafe fn peb_walker(target_dll_name: &str, target_func: &str) -> Option<*const u8> {
    let peb = *current_peb();
    let ldr = peb.Ldr;

    if ldr.is_null() {
        println!("PEB.Ldr is null");
        return None;
    }

    // Make list_head mutable
    let list_head = &mut (*ldr).InMemoryOrderModuleList as *mut LIST_ENTRY;
    let mut current_entry = (*list_head).Flink;  // current_entry starts from Flink

    let mut visited: HashSet<*mut LIST_ENTRY> = HashSet::new();  // Track visited entries

    while !current_entry.is_null() && current_entry != list_head {
        if visited.contains(&current_entry) {
            println!("Detected loop, breaking");
            break;
        }
        visited.insert(current_entry);

        // LdrDataTableEntry is embedded in the structure at offset -0x10 from the LIST_ENTRY
        let entry = (current_entry as *const u8).offset(-(std::mem::size_of::<LIST_ENTRY>() as isize)) as *const LdrDataTableEntry;

        if entry.is_null() {
            current_entry = (*current_entry).Flink;
            continue;
        }

        let base_dll_name = &(*entry).base_dll_name;

        if !base_dll_name.Buffer.is_null() {
            let length = (base_dll_name.Length / 2) as usize; // Length is in bytes; /2 for wchar
            let wide_slice = std::slice::from_raw_parts(base_dll_name.Buffer, length);
            let module_name = OsString::from_wide(wide_slice).to_string_lossy().to_string();

            println!("MODULE NAME IS '{}'", module_name);

            if module_name.trim().eq_ignore_ascii_case(target_dll_name) {
                println!("Target found: {}", module_name);
                let base = (*entry).dll_base as *const u8;
                println!("Module base address: 0x{:X}", base as usize);
                return pe_file_parser(entry, target_func);
            }
        }

        current_entry = (*current_entry).Flink; // Move to next entry
    }

    println!("Target module '{}' not found", target_dll_name);
    None
}
unsafe fn pe_file_parser(module_base: *const LdrDataTableEntry, name: &str)->Option<*const u8> {
    println!("Module base address: {:p}", module_base);

    let base = unsafe { (*module_base).dll_base } as *const u8;

    let dos_header = base as *const IMAGE_DOS_HEADER;
    if (unsafe { *dos_header }).e_magic != IMAGE_DOS_SIGNATURE {
        println!("Invalid DOS signature");
        return None;
    }

    let nt_headers_offset = (unsafe { *dos_header }).e_lfanew as usize;
    let nt_headers = unsafe { base.add(nt_headers_offset) } as *const IMAGE_NT_HEADERS64;

    if (unsafe { *nt_headers }).Signature != 0x00004550 {
        println!("Invalid PE file signature");
        return None;
    }

    let export_directory_rva = (unsafe { *nt_headers }).OptionalHeader.DataDirectory[0].VirtualAddress;
    if export_directory_rva == 0 {
        println!("No export directory.");
        return None;
    }

    let export_directory = unsafe { base.add(export_directory_rva as usize) } as *const IMAGE_EXPORT_DIRECTORY;

    let names_rva = (unsafe { *export_directory }).AddressOfNames;
    let functions_rva = (unsafe { *export_directory }).AddressOfFunctions;
    let ordinals_rva = (unsafe { *export_directory }).AddressOfNameOrdinals;
    let number_of_names = (unsafe { *export_directory }).NumberOfNames as usize;

    let names_ptr = unsafe { base.add(names_rva as usize) } as *const u32;
    let ordinals_ptr = unsafe { base.add(ordinals_rva as usize) } as *const u16;
    let addr_funcptr = unsafe { base.add(functions_rva as usize) } as *const u32;

   for i in 0..number_of_names {
        let name_rva = unsafe { *names_ptr.add(i) };
        let name_ptr = unsafe { base.add(name_rva as usize) } as *const u8;

        let mut length = 0;
        while unsafe { *name_ptr.add(length) } != 0 {
            length += 1;
        }

        let name_bytes = unsafe { std::slice::from_raw_parts(name_ptr, length) };
        let func_name = std::str::from_utf8(name_bytes).unwrap_or("<invalid utf8>");

        // If the function name matches, we return the function address
        if func_name == name {
            let ordinal_index = unsafe { *ordinals_ptr.add(i) } as usize;
            let func_rva = unsafe { *addr_funcptr.add(ordinal_index) };
            let func_addr = unsafe { base.add(func_rva as usize) } as *const u8;
            return Some(func_addr); // Return the function address
        }
    }
    None
 }
 // If the function isn't found, return None