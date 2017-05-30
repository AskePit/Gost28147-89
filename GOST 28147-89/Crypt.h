/*
 * Crypt.h
 *
 *  Created on: 27.07.2015
 *      Author: nikolay shalakin
 *
 *  GOST 28147-89 gamming-crypt algorithm implementation
 *
 */

#ifndef GOST_CRYPT_INCLUDE
#define GOST_CRYPT_INCLUDE

#include "platform.h"

namespace GOST
{
	class Crypter
	{
	private:
		u32 SBox[4][256]; // this is an internal [4][256] representation of a standart [8][16] GOST table
		uint Sync[2];
		
	public:
		Crypter();

		void cryptData(byte* dst, const byte* scr, const uint size, const byte* password);
		void cryptString(byte* dst, const char* scr, const byte* password);
		void decryptString(char* dst, const byte* scr, uint size, const byte* password);

		void useDefaultTable();
		void setTable(const char* filename); // file with 128 bytes representing SBox table for GOST encryption
		void setTable(const byte* table);    // 128 bytes representing SBox table for GOST encryption

		void useDefaultSync();
		void setSync(const u64 sync);

	private:
		void simpleGOST(uint& A, uint& B);
	};
}

#endif //GOST_CRYPT_INCLUDE