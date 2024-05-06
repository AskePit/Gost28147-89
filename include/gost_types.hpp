#include "gost_types.h"
#include "hash.h"

namespace gost
{

static SecuredByteArray<7> staticSalt{ {
	std::byte{0x85},
	std::byte{0x54},
	std::byte{0xd6},
	std::byte{0xb0},
	std::byte{0x9f},
	std::byte{0x36},
	std::byte{0xaa}
} };

inline HashBytes getHash(const GostKeyGuard& keyGuard, const SaltBytes& salt)
{
	SecuredByteArray<SIZE_OF_KEY + SIZE_OF_SALT + staticSalt.size()> salted;
	std::ranges::copy(keyGuard.get(), salted.begin());
	std::ranges::copy(salt, std::next(salted.begin(), SIZE_OF_KEY));
	std::ranges::copy(staticSalt, std::next(salted.begin(), SIZE_OF_KEY + SIZE_OF_SALT));

	HashBytes hash;

	Hasher::hash(reinterpret_cast<byte*>(salted.data()), reinterpret_cast<byte*>(hash.data()), salted.size());
	return hash;
}

inline HashAndSalt getHash(const GostKeyGuard& keyGuard)
{
	SaltBytes salt;
	memrandomset(salt);

	HashBytes hash(getHash(keyGuard, salt));

	return { hash, salt };
}

} // namespace gost
