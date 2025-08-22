#include "pch.hpp"
#include "ice.hpp"

/* DECRYPTION KEYS
* 
* import key: { 0x58, 0xD2, 0xD6, 0xFD, 0x85, 0xDA, 0x07, 0xF5 } (0xF507DA85FDD6D258)
* VAC-1 param key: { 0xE7, 0x59, 0x78, 0xE1, 0x4D, 0x48, 0x24, 0x38 } (0x3824484DE17859E7)
*/

static void IceDecrypt(BYTE* ctext, BYTE* ptext, UINT size, const BYTE* key)
{
    ICE_KEY ik;

    ice_key_create(&ik);
    ice_set(&ik, key);

    for (UINT i = size / 8; i; --i, ctext += 8, ptext += 8)
    {
        ice_key_decrypt(&ik, ctext, ptext);
    }

    delete[] ik.keys;
}

int main()
{
    // Input the byte array in the data variable in ice.hpp.
    // I suggest using chatgpt to format the array

	BYTE key[8] = { 0xAC, 0xC3, 0x64, 0xE4, 0xAB, 0x03, 0x1F, 0x8A };
	IceDecrypt(data, data, sizeof(data), key);

	std::ofstream result("result.txt", std::ios::out | std::ios::binary | std::ios::trunc);
	result.write((const char*)data, sizeof(data));

	std::cout << "Decryption complete. Check result.txt!\n";
	return 0;
}