/*
 * Crypt.cpp
 *
 *  Created on: 27.07.2015
 *      Author: nikolay shalakin
 *
 *  GOST 28147-89 gamming-crypt algorithm implementation
 *
 */

#include "Crypt.h"
#include <fstream>
#include <cstring>

namespace GOST {;

static const u8 defaultSBox[8][16] =
{
	{  4, 10,  9,  2, 13,  8,  0, 14,  6, 11,  1, 12,  7, 15,  5,  3 },
	{ 14, 11,  4, 12,  6, 13, 15, 10,  2,  3,  8,  1,  0,  7,  5,  9 },
	{  5,  8,  1, 13, 10,  3,  4,  2, 14, 15, 12,  7,  6,  0,  9, 11 },
	{  7, 13, 10,  1,  0,  8,  9, 15, 14,  4,  6, 12, 11,  2,  5,  3 },
	{  6, 12,  7,  1,  5, 15, 13,  8,  4, 10,  9, 14,  0,  3, 11,  2 },
	{  4, 11, 10,  0,  7,  2,  1, 13,  3,  6,  8,  5,  9, 12, 15, 14 },
	{ 13, 11,  4,  1,  3, 15,  5,  9,  0, 10, 14,  7,  6,  8,  2, 12 },
	{  1, 15, 13,  0,  5,  7, 10,  4,  9,  2,  3, 14,  6, 11,  8, 12 }
};

// INTERFACE FUNCTIONS
Crypter::Crypter()
{
    useDefaultTable();
    useDefaultSync();
}

Crypter::~Crypter()
{
}

void Crypter::useDefaultTable()
{
    memcpy(SBox, defaultSBox, 8*16*sizeof(u8));
}

// file with 128 bytes representing SBox table for GOST encryption
void Crypter::setTable(const char* filename)
{
    using namespace std;

    fstream f;
    f.open(filename, fstream::in | fstream::binary);

    byte table[128];
    f.read(reinterpret_cast<char*>(table), 128);
    f.close();

    setTable(table);
}

// 128 bytes representing SBox table for GOST encryption
// this 128 bytes will be transformed to special 4*256 table (for better algorythm performance)
void Crypter::setTable(const byte *table)
{
	memcpy(SBox, table, 8*16*sizeof(u8));
}

void Crypter::useDefaultSync()
{
	Sync[0] = 0x40FD452C;
	Sync[1] = 0xF86EDCDB;
}

void Crypter::setSync(const u64 sync)
{
	Sync[0] = static_cast<u32>(sync);
	Sync[1] = static_cast<u32>(sync>>32);
}

void Crypter::cryptString(byte *dst, const char *scr, const byte *password)
{
    cryptData(dst, reinterpret_cast<const byte *>(scr), strlen(scr), password);
}

void Crypter::decryptString(char *dst, const byte *scr, size_t size, const byte *password)
{
    cryptData(reinterpret_cast<byte *>(dst), reinterpret_cast<const byte *>(scr), size, password);
    dst[size] = '\0';
}

// INTERNAL FUNCTIONS
static const uint C1 = 0x1010104;
static const uint C2 = 0x1010101;

inline u32 addMod32_1(u32 x, u32 y) {
	u32 sum = x + y;
	sum += (sum < x) | (sum < y);
	return sum;
}

void Crypter::cryptData(byte *dst, const byte *src, size_t size, const byte *password)
{
    if(size == 0) {
        return;
    }

	memcpy(X, password, 32);

    size_t remain = size%8;
	if (remain == 0) {
		remain = 8;
	}

    const byte* lastBytes = src + size - remain + 1;

	u32 AB[2];
	u32 &A = AB[0];
	u32 &B = AB[1];

    register u32 N1, N2, N3, N4;

	N3 = Sync[0];
	N4 = Sync[1];

	cryptBlock(N3, N4);

    while(true) {
		N2 = N4 = addMod32_1(N4, C1);
		N1 = N3 = N3 + C2;

		cryptBlock(N1, N2);

        memcpy(&AB, src, 8);
		src += 8;

        A ^= N1;
        B ^= N2;

        if(src < lastBytes) {
            memcpy(dst, &AB, 8);
            dst += 8;
        } else {
            memcpy(dst, &AB, remain);
            break;
        }
    }

	wipememory(X, 32);
}


void Crypter::f(u32 &word)
{
	word =
		SBox[0][word & 0x0f] |
		SBox[1][word >> 4 & 0x0f]  << 4  |
		SBox[2][word >> 8 & 0x0f]  << 8  |
		SBox[3][word >> 12 & 0x0f] << 12 |
		SBox[4][word >> 16 & 0x0f] << 16 |
		SBox[5][word >> 20 & 0x0f] << 20 |
		SBox[6][word >> 24 & 0x0f] << 24 |
		SBox[7][word >> 28 & 0x0f] << 28;

	word = word << 11 | word >> 21;
}

static const u8 cryptRounds[32] =
{
	0,1,2,3,4,5,6,7,
	0,1,2,3,4,5,6,7,
	0,1,2,3,4,5,6,7,
	7,6,5,4,3,2,1,0
};

void Crypter::cryptBlock(u32 &A, u32 &B)
{
	for (u8 i = 0; i < 31; ++i) {
		u32 T = A + X[cryptRounds[i]];
		f(T);
		T ^= B;
		B = A;
		A = T;
	}

	u32 T = A + X[0];
	f(T);
	B ^= T;
}

}
