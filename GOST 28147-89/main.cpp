// GOSTtest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "Crypt.h"
#include "tests.h"
#include <iostream>
#include <iomanip>
#include <ctime>

static void print_bytes(const byte *bytes, int size) {
	for (int i = 0; i < size; ++i) {
		if (i % 8 == 0) {
			std::cout << std::endl;
		}
		std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)bytes[i] << ' ';
	}
	std::cout << std::endl << std::endl;
}

static void print_result(bool pass) {
	std::cout << (pass ? "PASS" : "FAIL") << std::endl;
}

static bool run_test(const TestCase &test)
{
	//std::cout << test.name << " ";

	GOST::Crypter c;
	c.setSync(test.iv);
	c.setTable(test.table);

	byte *crypted = new byte[test.size];
	byte *decrypted = new byte[test.size];

	bool pass = true;

	c.cryptData(crypted, test.in, test.size, test.key);
	//print_bytes(crypted, test.size);
	pass &= memcmp(crypted, test.out, test.size) == 0;

	c.cryptData(decrypted, crypted, test.size, test.key);
	//print_bytes(decrypted, test.size);
	pass &= memcmp(decrypted, test.in, test.size) == 0;

	delete[] crypted;
	delete[] decrypted;

	//print_result(pass);

	return pass;
}

int main()
{
	const clock_t begin_time = clock();

	bool pass = true;

	for (int i = 0; i < 1000; ++i)
	for (const auto test : getTests()) {
		pass &= run_test(test);
	}

	print_result(pass);
	std::cout << float(clock() - begin_time) << " ms" << std::endl;

	//new: 520 ms

    return 0;
}
