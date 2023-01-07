#pragma once

#include "secureTypes.h"

namespace gost
{

class Hasher
{
public:
	static void hash(const byte* src, byte* hash, size_t srcLength);
};

} // namespace gost
