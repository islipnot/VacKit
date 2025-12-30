# VacLogger

This VAC logger must be injected into `steam.exe` (steam must have admin) before any game is launched. Note that this is most 
likely detected to some degree. Playing prime comp games loads VAC modules faster. I've stayed green trust the entire time I've 
been using this by manual mapping and avoiding reports. With that being said, it is 100% detectable and most likely IS detected 
to some degree, so use a burner account and don't cheat!

### Logged data
- Multiple relevant API's (with return address & time)
- Decrypted VAC module parameters
- Encrypted VAC module parameters
- Every call to runfunc (with address and time)

While VAC's detection vectors typically don't change between updates, module CRC's will. You must manually use `SigTester` to 
generate .text CRC's for VAC modules and update them in the logger yourself if you want them to be labeled.

# SigTester

Put any VAC modules in the directory of this and it will automatically detect them via the "VLV" binary signature. It will then 
either give you the CRC's of each module it recognizes, or compare CRC's to previously calculated CRC's which are stored in `crc.txt`.

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