#pragma once

#include <cstdint>
#include <array>
#include <vector>

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
	memrandomset(reinterpret_cast<u8*>(bytes.getRaw()), bytes.size());
}

template<typename T>
class Secured : public T
{
public:
	constexpr Secured() = default;
	constexpr Secured(const Secured&) = default;
	constexpr Secured(Secured&&) = default;
	constexpr Secured& operator=(const Secured&) = default;
	constexpr Secured& operator=(Secured&&) = default;

	constexpr Secured(T&& val);
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

template<size_t N>
using SecuredByteArray = Secured<std::array<std::byte, N>>;
using SecuredByteVector = Secured<std::vector<std::byte>>;

template<size_t SIZE_OF_KEY>
class MasterKeyGuard;

template<size_t SIZE_OF_KEY>
class MasterKey
{
	friend class MasterKeyGuard<SIZE_OF_KEY>;

public:
	template<typename T>
	explicit MasterKey(Secured<T>&& key);

private:
	mutable SecuredByteArray<SIZE_OF_KEY> m_data;
	mutable SecuredByteArray<SIZE_OF_KEY> m_x;

	void lock() const;
	void unlock() const;
};

template<size_t SIZE_OF_KEY>
class MasterKeyGuard
{
public:
	explicit MasterKeyGuard(const MasterKey<SIZE_OF_KEY>& master);
	~MasterKeyGuard();

	const SecuredByteArray<SIZE_OF_KEY>& get() const;

private:
	const MasterKey<SIZE_OF_KEY>& m_master;
};

} // namespace gost

#include "secure_types.hpp"
