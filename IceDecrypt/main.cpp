#include "pch.hpp"
#include "ice.hpp"

/* DECRYPTION KEYS
* 
* import key (FuncNameArray): { 0x58, 0xD2, 0xD6, 0xFD, 0x85, 0xDA, 0x07, 0xF5 } (0xF507DA85FDD6D258)
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
	BYTE key[8] = { 0x58, 0xD2, 0xD6, 0xFD, 0x85, 0xDA, 0x07, 0xF5 };
	IceDecrypt(data, data, sizeof(data), key);

	std::ofstream result("result.txt", std::ios::out | std::ios::binary | std::ios::trunc);
	result.write((const char*)data, sizeof(data));

	std::cout << "Decryption complete. Check result.txt!\n";
	return 0;
}