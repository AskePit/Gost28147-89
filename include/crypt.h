#pragma once

#include "gost_types.h"

namespace gost
{

class Crypter
{
public:
	Crypter();
	~Crypter() = default;

	void cryptData(const byte* scr, byte* dst, size_t size, const byte* password);
	void cryptString(const char* scr, byte* dst, const byte* password);
	void decryptString(const byte* scr, char* dst, size_t size, const byte* password);

	void useDefaultTable();
	void setTable(const char* filename); // file with 128 bytes representing SBox table for GOST encryption
	void setTable(const byte* table);    // 128 bytes representing SBox table for GOST encryption

	void useDefaultSync();
	void setSync(const u64 sync);

private:
	u32 SBox[4][256]; // this is an internal [4][256] representation of a standart [8][16] GOST table
	std::array<u32, 2> Sync;
	u32 X[8]; // splitted key

	void cryptBlock(u32& A, u32& B);
	u32 f(u32 word);
};

} // namespace gost
