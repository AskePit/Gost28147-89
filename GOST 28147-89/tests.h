#pragma once

#include "platform.h"
#include <vector>

struct TestCase {
	const char *name;
	const byte *key;
	u64 iv;
	const byte *table;
	int size;
	const byte *in;
	const byte *out;
};

const std::vector<std::reference_wrapper<const TestCase>> &getTests();
