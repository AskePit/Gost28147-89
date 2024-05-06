#pragma once

#include "gost_types.h"
#include <vector>

namespace gost::crypt
{

struct TestCase {
	const char* name;
	const byte* key;
	u64 iv;
	const byte* table;
	int size;
	const byte* in;
	const byte* out;
};

const std::vector<std::reference_wrapper<const TestCase>> &getTests();

} // namespace gost::crypt