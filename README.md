# VacLogger

If you found this off unknowncheats, I'd appreciate telling me about any bugs in dms!

This VAC logger must be injected into `steam.exe` (steam must have admin) before any game is launched. It will log every call 
to `ReadProcessMemory`, `CreateFileW`, `OpenFileMappingW`, and `WideCharToMultiByte`. More importantly though, it hooks steam's 
call to `_runfunc@20`. When runfunc is called, it will use pattern scanning to detect which module it is in. It will then hook 
into the modules ICE decryption routine, where it will dump ONLY the decrypted module parameters, ignoring import decryption. 
The `IceKey::decrypt` hook tracks the routine progress allowing for automatic seperation and labeling of output, and like I 
already said, allowing for it to ignore import decryption. It should also be noted that the call to runfunc is logged on its 
own along with the other API logs, and logs which module the function belongs to. I also made it dump the encrypted parameters 
because a few bytes technically have a use, though it might aswell be ignored.

This is of course all based on my personal dumps of the anti-cheat, and if the pattern scanning fails for you, you simply need 
to update the patterns. First off, in hooks.cpp, make sure the pattern used to locate the runfunc call works. Next, check tools.cpp 
and make sure all 12 of the patterns in `ModuleIndexFromPtr` are good. If these aren't working for you simply get a unique pattern 
from your own dumps that can be used to identify the modules. The way to tell if the module signatures are outdated is by looking at 
`vLog.txt`, and if the runfunc log doesn't have a number next to it indicating which module it is, that means it failed to identify it.

API/runfunc call logs are logged in `vLog.txt`, decrypted parameters are logged in `pdLog.txt`, and encrypted parameters are logged 
in `pLog.txt`. All of these log files are in the steam directory. It should also be noted you can adds your own API logs very easily 
by just adding a new `CreateHookApi` call in `ThreadEntry`, which obviously requires that you write a hook in hooks.cpp.

# StrDecrypt

This allows you to easily decrypt strings found in VAC modules. You must identify the key and decryption type (XOR or ROL), 
which can be done by xrefing the encrypted string and looking for a while loop that looks like one of the two below.

### ROL decryption
```C
v7 = Advapi32dll[0];
if ( Advapi32dll[0] )
{
  v8 = Advapi32dll;
  do
  {
    *v8++ = __ROL1__(v7, 3);
    v7 = *v8;
  }
  while ( *v8 );
}
```

### XOR decryption
```C
v42 = NtReadVirtualMemory;
v43 = 104;
do
{
  *v42++ = v43 ^ 38;
  v43 = *v42;
}
while ( *v42 );
```

## Usage
Argument format: \<string\> \<type\> \<key\> </br>
Types: r == ROL, x == XOR </br>
String should be surrounded by quotes for safety.

# IceDecrypt

This allows you to take a block of ICE encrypted memory and decrypt it easily. It's a little harder to use than StrDecrypt, first 
you must get a BYTE array of the encrypted block (use ChatGPT to format it after pasting from IDA or x64dbg), which you then must 
paste into ice.hpp in place of the "data" variable at the end of the file. You also must dump the decryption key, which can be done 
very easily by using VacLogger to dump the encryption key, though you'll have to change the code a bit to have it do that.