#include "secure_types.h"

#include <random>
#include <bit>
#include <functional>

namespace gost
{

inline void memwipe(void* ptr, size_t len, byte fill /*= 0*/)
{
	volatile char* vptr = std::bit_cast<volatile char*>(ptr);
	while (len) {
		*vptr = fill;
		++vptr;
		--len;
	}
}

inline void memrandomset(void* ptr, size_t len)
{
	static std::random_device dev;
	static std::mt19937 rng(dev());
	static std::uniform_int_distribution<> dist;

	volatile char* vptr = std::bit_cast<volatile char*>(ptr);
	while (len) {
		*vptr = static_cast<byte>(dist(rng));
		++vptr;
		--len;
	}
}

template<typename T>
inline constexpr Secured<T>::Secured(T&& val)
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
	constexpr bool hasConstData = requires(const T & t) {
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
inline Secured<T>& Secured<T>::operator^=(const Secured<U>& other)
{
	std::ranges::transform(
		*this,
		other,
		T::begin(),
		std::bit_xor<typename T::value_type>()
	);

	return *this;
}

template<size_t SIZE_OF_KEY>
template<typename T>
inline MasterKey<SIZE_OF_KEY>::MasterKey(Secured<T>&& key)
{
	memcpy(m_data.data(), reinterpret_cast<std::byte*>(key.getRaw()), key.sizeInBytes());
	memwipe(m_data.data() + key.sizeInBytes(), SIZE_OF_KEY - key.sizeInBytes());
	key.~Secured();

	lock();
}

template<size_t SIZE_OF_KEY>
inline void MasterKey<SIZE_OF_KEY>::lock() const
{
	memrandomset(m_x);
	m_data ^= m_x;
}

template<size_t SIZE_OF_KEY>
inline void MasterKey<SIZE_OF_KEY>::unlock() const
{
	m_data ^= m_x;
}

template<size_t SIZE_OF_KEY>
inline MasterKeyGuard<SIZE_OF_KEY>::MasterKeyGuard(const MasterKey<SIZE_OF_KEY>& master)
	: m_master(master)
{
	m_master.unlock();
}

template<size_t SIZE_OF_KEY>
inline MasterKeyGuard<SIZE_OF_KEY>::~MasterKeyGuard()
{
	m_master.lock();
}

template<size_t SIZE_OF_KEY>
inline const SecuredByteArray<SIZE_OF_KEY>& MasterKeyGuard<SIZE_OF_KEY>::get() const
{
	return m_master.m_data;
}

} // namespace gost
