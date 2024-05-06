#pragma once

#include "secure_types.h"

namespace gost
{

constexpr size_t SIZE_OF_KEY = 32;
constexpr size_t SIZE_OF_HASH = 64;
constexpr size_t SIZE_OF_SALT = 6;

using MasterKeyBytes = SecuredByteArray<SIZE_OF_KEY>;
using HashBytes = SecuredByteArray<SIZE_OF_HASH>;
using SaltBytes = SecuredByteArray<SIZE_OF_SALT>;

using GostMasterKey = MasterKey<SIZE_OF_KEY>;
using GostKeyGuard = MasterKeyGuard<SIZE_OF_KEY>;

struct HashAndSalt
{
	HashBytes hash;
	SaltBytes salt;
};

HashBytes getHash(const GostKeyGuard& keyGuard, const SaltBytes& salt);
HashAndSalt getHash(const GostKeyGuard& keyGuard);

} // namespace gost

#include "gost_types.hpp"
