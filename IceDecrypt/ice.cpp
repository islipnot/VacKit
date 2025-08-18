#include "pch.hpp"
#include "ice.hpp"

// 8-bit Galois Field multiplication of A by B, modulo M.
// Just like arithmetic multiplication, except that additions and
// subtractions are replaced by XOR.
static UINT ice_gf_mult(UINT a, UINT b, UINT m)
{
    UINT result = 0;

    while (b)
    {
        if (b & 1) result ^= a;

        a <<= 1;
        b >>= 1;

        if (a > 255) a ^= m;
    }

    return result;
}

// Galois Field exponentiation.
// Raise the base to the power of 7, modulo M.
static ULONG ice_gf_exp7(UINT b, UINT m)
{
    if (!b) return 0;

    UINT x = ice_gf_mult(b, b, m);
         x = ice_gf_mult(b, x, m);
         x = ice_gf_mult(x, x, m);

    return ice_gf_mult(b, x, m);
}

// Carry out the ICE 32-bit P-box permutation.
static ULONG ice_perm32(ULONG x)
{
    ULONG result = 0;

    for (const ULONG* pbox = ice_pbox; x; x >>= 1, ++pbox)
    {
        if (x & 1) result |= *pbox;
    }

    return result;
}

// Initialize the ICE S-boxes. This only has to be done once.
static void ice_sboxes_init()
{
    for (int i = 0; i < 1024; ++i)
    {
        const int col = static_cast<BYTE>(i >> 1);
        const int row = i & 1 | (i >> 8) & 2;

        UINT x = ice_gf_exp7(col ^ ice_sxor[0][row], ice_smod[0][row]) << 24;
        ice_sbox[0][i] = ice_perm32(x);

        x = ice_gf_exp7(col ^ ice_sxor[1][row], ice_smod[1][row]) << 16;
        ice_sbox[1][i] = ice_perm32(x);

        x = ice_gf_exp7(col ^ ice_sxor[2][row], ice_smod[2][row]) << 8;
        ice_sbox[2][i] = ice_perm32(x);

        x = ice_gf_exp7(col ^ ice_sxor[3][row], ice_smod[3][row]);
        ice_sbox[3][i] = ice_perm32(x);
    }
}

// Set 8 rounds [n, n+7] of the key schedule of an ICE key.
static void ice_sched_build(ICE_KEY* ik, WORD* kb, int n, const int* keyrot)
{
    for (int i = 0; i < 8; ++i)
    {
        ICE_SUBKEY* isk = &ik->keys[n + i];
        int kr = keyrot[i];

        for (int j = 0; j < 3; ++j)
        {
            isk->val[j] = 0;
        }

        for (int j = 0; j < 15; ++j)
        {
            UINT* curr_sk = &isk->val[j % 3];

            for (int k = 0; k < 4; ++k)
            {
                const int curr_kb = (kr + k) & 3;
                const int bit = kb[curr_kb] & 1;

                *curr_sk = bit | (*curr_sk << 1);
                kb[curr_kb] = (kb[curr_kb] >> 1) | (~static_cast<WORD>(bit) << 15);
            }
        }
    }
}

// The single round ICE f function.
static ULONG ice_f(ULONG p, const ICE_SUBKEY* sk)
{
    const ULONG tl = ((p >> 16) & 0x3FF) | (((p >> 14) | (p << 18)) & 0xFFC00);
    const ULONG tr = (p & 0x3FF) | ((p & 0x3FF00) << 2);

    ULONG al = sk->val[2] & (tl ^ tr);
    ULONG ar = tl ^ al ^ sk->val[0];

    al ^= sk->val[1] ^ tr;

    return ice_sbox[0][ar >> 10] | ice_sbox[1][ar & 0x3FF] | ice_sbox[2][al >> 10] | ice_sbox[3][al & 0x3FF];
}

// Set the key schedule of an ICE key.
void ice_set(ICE_KEY* ik, const BYTE* key)
{
    WORD kb[4];

    if (ik->rounds == 8)
    {
        for (int i = 0; i < 4; ++i)
        {
            kb[3 - i] = (key[i * 2] << 8) | key[(i * 2) + 1];
        }

        ice_sched_build(ik, kb, 0, ice_keyrot);
    }
    else
    {
        for (int x = 0, sz = ik->size; x < sz; ++x)
        {
            for (int y = 0; y < 4; ++y)
            {
                kb[3 - y] = (key[(x * 8) + (y * 2)] << 8) | key[(x * 8) + (y * 2) + 1];
            }

            ice_sched_build(ik, kb, x * 8, ice_keyrot);
            ice_sched_build(ik, kb, ik->rounds - (x * 8) - 8, &ice_keyrot[8]);
        }
    }
}

// Create a new ICE key.
void ice_key_create(ICE_KEY* ik)
{
    if (!ice_sboxes_initialized)
    {
        ice_sboxes_init();
        ice_sboxes_initialized = 1;
    }
    
    ik->size   = 1;
    ik->rounds = 16;
    ik->keys   = reinterpret_cast<ICE_SUBKEY*>(new char[192]);
}

// Decrypt a block of 8 bytes of data with the given ICE key.
void ice_key_decrypt(ICE_KEY* ik, const BYTE* ctext, BYTE* ptext)
{
    ULONG l = ctext[3] | ((ctext[2] | (ctext[1] | (ctext[0] << 8)) << 8) << 8);
    ULONG r = ctext[7] | ((ctext[6] | (ctext[5] | (ctext[4] << 8)) << 8) << 8);

    for (int i = ik->rounds - 1; i > 0; i -= 2)
    {
        l ^= ice_f(r, &ik->keys[i]);
        r ^= ice_f(l, &ik->keys[i - 1]);
    }

    for (int i = 0; i < 4; ++i)
    {
        ptext[3 - i] = r;
        ptext[7 - i] = l;

        r >>= 8;
        l >>= 8;
    }
}