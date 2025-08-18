# VacLogger

This is a x86 DLL you must inject into steam.exe, and it will then log calls to everything you find in hooks.cpp. You can very easily 
add your own hooks by just adding a CreateHookApi call in dllmain.cpp and then writing a quick hook. One extremely useful feature here 
is the runfunc logging. The way it works is it will hook into the logic that resolved the address of runfunc before its called, and will 
then place a hook at the base of it. This can be used to make sense of subsequently logged calls, aswell as allowing for very easy parameter 
dumping.

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
very easily by using VacLogger to dump runfunc parameters.