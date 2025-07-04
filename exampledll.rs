/*
use std::ffi::CString;
use std::ptr::null_mut;
use windows::core::PCSTR;
use windows::Win32::Foundation::{HINSTANCE};
use windows::Win32::UI::WindowsAndMessaging::{MessageBoxA, MB_OK};

#[no_mangle]
pub extern "system" fn DllMain(
    _hinst_dll: HINSTANCE,
    fdw_reason: u32,
    _lp_reserved: *mut std::ffi::c_void,
) -> i32 {
    if fdw_reason == 1 {
        unsafe {
            let msg = CString::new("Hello I hacked your computer!").unwrap();
            let title = CString::new("DLL Injection Success!").unwrap();

            MessageBoxA(
                None,                    // HWND → Option<HWND>
                PCSTR(msg.as_ptr() as _),   // LPCSTR → PCSTR
                PCSTR(title.as_ptr() as _), // LPCSTR → PCSTR
                MB_OK,
            );
        }
    }
    1
}
*/