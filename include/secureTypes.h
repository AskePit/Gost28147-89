#pragma once

#include <array>
#include <vector>
#include <string>
#include <functional>
#include <algorithm>

namespace gost
{

using byte = uint8_t;
using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using uint = uint32_t;
using u64 = uint64_t;
using uid = uint64_t;

using i8 = int8_t;
using i16 = int16_t;
using i32 = int32_t;
using i64 = int64_t;

template<typename T>
class Secured;

/*
 * To avoid that a compiler optimizes certain memset calls away
 * `wipememory` may be used instead.
 */
void memwipe(void* ptr, size_t len, byte fill = 0);

void memrandomset(void* ptr, size_t len);

template<typename T>
void memrandomset(Secured<T>& bytes)
{
	memrandomset(as<u8*>(bytes.getRaw()), bytes.size());
}

template<class OUT, class IN>
inline auto as(IN* data) {
	return reinterpret_cast<
		typename std::conditional<std::is_const<IN>::value, const OUT, OUT>::type
	>(data);
}

template <class OUT, class IN>
inline auto as(IN& t) -> decltype(as<OUT>(t.data())) {
	return as<OUT>(t.data());
}

constexpr size_t SIZE_OF_KEY = 32;
constexpr size_t SIZE_OF_HASH = 64;
constexpr size_t SIZE_OF_SALT = 6;

template<typename T>
class Secured : public T
{
public:
	Secured() = default;
	Secured(const Secured&) = default;
	Secured(Secured&&) = default;
	Secured& operator=(const Secured&) = default;
	Secured& operator=(Secured&&) = default;

	Secured(T&& val);
	//template<typename U>
	//explicit Secured(Secured<U>&& other);

	~Secured();

	// specialize in unusual cases
	static u8 sizeOfElement();
	size_t sizeInBytes() const;
	typename T::value_type* getRaw();

	template<typename U>
	Secured<T>& operator^=(const Secured<U>& other);
};

template<typename T>
inline Secured<T>::Secured(T&& val)
	: T(std::move(val))
{}

/*
template<typename T>
template<typename U>
Secured<T>::Secured(Secured<U>&& other)
{

}
*/

template<typename T>
inline Secured<T>::~Secured()
{
	memwipe(getRaw(), sizeInBytes());
}

template<typename T>
inline /*static*/ u8 Secured<T>::sizeOfElement()
{
	return sizeof(T::value_type);
}

template<typename T>
inline size_t Secured<T>::sizeInBytes() const
{
	return sizeOfElement() * T::size();
}

template<typename T>
inline typename T::value_type* Secured<T>::getRaw()
{
	constexpr bool hasConstData = requires(const T& t) {
		t.constData();
	};

	if constexpr (hasConstData) {
		return T::constData();
	}
	else {
		return T::data();
	}
}

template<typename T>
template<typename U>
Secured<T>& Secured<T>::operator^=(const Secured<U>& other)
{
	std::ranges::transform(
		*this,
		other,
		T::begin(),
		std::bit_xor<typename T::value_type>()
	);

	return *this;
}

template<size_t N>
using SecuredByteArray = Secured<std::array<std::byte, N>>;
using SecuredByteVector = Secured<std::vector<std::byte>>;

using MasterKeyBytes = SecuredByteArray<SIZE_OF_KEY>;
using HashBytes = SecuredByteArray<SIZE_OF_HASH>;
using SaltBytes = SecuredByteArray<SIZE_OF_SALT>;

class MasterKey
{
	friend class MasterKeyGuard;

public:
	template<typename T>
	explicit MasterKey(Secured<T>&& key);

private:
	mutable MasterKeyBytes m_data;
	mutable MasterKeyBytes m_x;

	void lock() const;
	void unlock() const;
};

template<typename T>
inline MasterKey::MasterKey(Secured<T>&& key)
{
	memcpy(m_data.data(), as<std::byte*>(key.getRaw()), key.sizeInBytes());
	memwipe(m_data.data() + key.sizeInBytes(), SIZE_OF_KEY - key.sizeInBytes());
	key.~Secured();

	lock();
}

struct HashAndSalt {
	HashBytes hash;
	SaltBytes salt;
};

class MasterKeyGuard
{
public:
	explicit MasterKeyGuard(const MasterKey& master);
	~MasterKeyGuard();

	const MasterKeyBytes& get() const;
	HashBytes getHash(const SaltBytes& salt);
	HashAndSalt getHash();

private:
	const MasterKey& m_master;
};

} // namespace gost