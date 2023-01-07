#include "secureTypes.h"
#include "hash.h"

#include <random>

namespace gost
{

void memwipe(void* ptr, size_t len, byte fill /*= 0*/)
{
	volatile char* vptr = reinterpret_cast<volatile char*>(ptr);
	while (len) {
		*vptr = fill;
		++vptr;
		--len;
	}
}

void memrandomset(void* ptr, size_t len)
{
	static std::random_device dev;
	static std::mt19937 rng(dev());
	static std::uniform_int_distribution<> dist;

	volatile char* vptr = reinterpret_cast<volatile char*>(ptr);
	while (len) {
		*vptr = static_cast<byte>(dist(rng));
		++vptr;
		--len;
	}
}

/*
SecureBytes operator+(const SecureBytes& b1, const SecureBytes& b2)
{
	SecureBytes res(b1.m_data.size() + b2.m_data.size());
	std::ranges::copy(b1.m_data, res.m_data.begin());
	std::ranges::copy(b2.m_data, res.m_data.begin() + b1.m_data.size());
	return res;
}

SecureBytes& SecureBytes::operator^=(const SecureBytes& other)
{
	std::ranges::transform(
		m_data,
		other.m_data,
		m_data.begin(),
		std::bit_xor<std::byte>()
	);

	return *this;
}
*/

void MasterKey::lock() const
{
	memrandomset(m_x);
	m_data ^= m_x;
}

void MasterKey::unlock() const
{
	m_data ^= m_x;
}

MasterKeyGuard::MasterKeyGuard(const MasterKey& master)
	: m_master(master)
{
	m_master.unlock();
}

MasterKeyGuard::~MasterKeyGuard()
{
	m_master.lock();
}

const MasterKeyBytes& MasterKeyGuard::get() const
{
	return m_master.m_data;
}

static SecuredByteArray<7> staticSalt{ {
	std::byte{0x85},
	std::byte{0x54},
	std::byte{0xd6},
	std::byte{0xb0},
	std::byte{0x9f},
	std::byte{0x36},
	std::byte{0xaa}
} };

HashBytes MasterKeyGuard::getHash(const SaltBytes& salt)
{
	SecuredByteVector salted;
	salted.reserve(m_master.m_data.size() + salt.size() + staticSalt.size());
	std::ranges::copy(m_master.m_data, std::back_inserter(salted));
	std::ranges::copy(salt, std::back_inserter(salted));
	std::ranges::copy(staticSalt, std::back_inserter(salted));

	HashBytes hash;

	gost::Hasher::hash(as<byte*>(salted), as<byte*>(hash), salted.size());
	return hash;
}

HashAndSalt MasterKeyGuard::getHash()
{
	SaltBytes salt;
	memrandomset(salt);

	HashBytes hash(getHash(salt));

	return { hash, salt };
}

} // namespace gost