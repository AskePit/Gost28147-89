#include "crypt.h"
#include "cryptTests.h"

#include <iostream>
#include <iomanip>
#include <ctime>

using namespace gost;

const char* PAD = "  ";

static void printBytes(const byte *bytes, int size) {
	for (int i = 0; i < size; ++i) {
		if (i % 8 == 0) {
			std::cout << std::endl;
		}
		std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)bytes[i] << ' ';
	}
	std::cout << std::endl << std::endl;
}

static void printResult(bool pass)
{
	std::cout << PAD << (pass ? "PASS" : "FAIL") << std::endl;
}

static bool runCryptTest(const crypt::TestCase &test)
{
	//std::cout << test.name << " ";

	Crypter c;
	c.setSync(test.iv);
	c.setTable(test.table);

	byte *crypted = new byte[test.size];
	byte *decrypted = new byte[test.size];

	bool pass = true;

	c.cryptData(test.in, crypted, test.size, test.key);
	//printBytes(crypted, test.size);
	pass &= memcmp(crypted, test.out, test.size) == 0;

	c.cryptData(crypted, decrypted, test.size, test.key);
	//printBytes(decrypted, test.size);
	pass &= memcmp(decrypted, test.in, test.size) == 0;

	delete[] crypted;
	delete[] decrypted;

	//printResult(pass);

	return pass;
}

static bool runCryptTests()
{
	const clock_t begin_time = clock();

	bool pass = true;
	size_t size = 0;

	const int TIMES = 1000;
	for (int i = 0; i < TIMES; ++i)
		for (const auto& test : crypt::getTests()) {
			pass &= runCryptTest(test);
			size += test.get().size;
		}

	float ms = float(clock() - begin_time);
	float speed = (size / 1024.f / 1024.f) / (ms / 1000.f);

	std::cout << PAD << ms << " ms" << std::endl;
	std::cout << PAD << speed << " Mb/s" << std::endl;
	return true;
}

static bool runSecureTypesTests()
{
	// secured memory cleanup
	{
		byte* dataAddr = nullptr;
		size_t n = 0;

		const auto test = [&dataAddr, &n]<typename T>(T&& unsecured) -> bool
		{
			T unsecuredCopy {unsecured};

			{
				Secured<T> secured(std::move(unsecured));
				dataAddr = reinterpret_cast<byte*>(secured.getRaw());
				n = secured.sizeInBytes();
			}

			int res = memcmp(dataAddr, reinterpret_cast<byte*>(unsecuredCopy.data()), n);
			return res != 0;
		};

		bool pass = true;

		pass &= test(std::string("porch"));
		pass &= test(std::string("long string shouldn't fit into std::string buffer, so no short string optimization"));
		pass &= test(std::vector<int>{{ 1, 4, 15, 100, 1001, 1008, 2020, 2023 }});
		pass &= test(std::array<std::byte, 10>{{
			std::byte{ 2 },
			std::byte{ 20 },
			std::byte{ 22 },
			std::byte{ 200 },
			std::byte{ 202 },
			std::byte{ 220 },
			std::byte{ 222 },
			std::byte{ 200 },
			std::byte{ 200 },
			std::byte{ 202 }
		}});
		

		if (!pass) {
			return false;
		}
	}

	// MasterKey
	{
		const auto test = []<typename T>(T&& unsecured) -> bool
		{
			Secured<T> secured(std::move(unsecured));
			GostMasterKey key(std::move(secured));
			{
				GostKeyGuard guard(key);
				guard.get();
			}

			return true;
		};

		bool pass = true;

		pass &= test(std::string("pepcoS"));
		pass &= test(std::vector<std::byte>{ {
			std::byte{ 0x85 },
			std::byte{ 0x54 },
			std::byte{ 0xd6 },
			std::byte{ 0xb0 },
			std::byte{ 0x9f },
			std::byte{ 0x36 },
			std::byte{ 0xaa }
		}});
		pass &= test(std::array<u8, 4>{{0x18, 0x54, 0x00, 0x51}});

		if (!pass) {
			return false;
		}
	}

	return true;
}

static void runTest(bool(*test)(), const char* name)
{
	std::cout << name << " TESTS START" << std::endl;
	printResult( test() );
	std::cout << name << " TESTS FINISH" << std::endl << std::endl;
}

int main()
{
	using TestPair = std::pair<bool(*)(), const char*>;

	for (auto&& [test, name] : {

		TestPair{runCryptTests, "CRYPT"},
		TestPair{runSecureTypesTests, "SECURE TYPES"}

	}) {
		runTest(test, name);
	}

    return 0;
}
