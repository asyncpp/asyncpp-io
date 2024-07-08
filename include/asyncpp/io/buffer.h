#pragma once
#include <algorithm>
#include <bit>
#include <cstring>
#include <span>
#include <type_traits>

namespace asyncpp::io {

	template<typename T, std::endian Endian>
		requires(std::is_trivial_v<T>)
	inline void raw_set(void* ptr, std::type_identity_t<T> val) noexcept {
		memcpy(ptr, &val, sizeof(T));
		if constexpr (std::endian::native != Endian)
			std::reverse(static_cast<std::byte*>(ptr), static_cast<std::byte*>(ptr) + sizeof(T));
	}

	template<typename T, std::endian Endian>
		requires(std::is_trivial_v<T>)
	inline T raw_get(const void* ptr) noexcept {
		T res;
		memcpy(&res, ptr, sizeof(T));
		if constexpr (std::endian::native != Endian) {
			std::reverse(reinterpret_cast<std::byte*>(&res), reinterpret_cast<std::byte*>(&res) + sizeof(T));
		}
		return res;
	}

	using buffer = std::span<std::byte>;
	using const_buffer = std::span<const std::byte>;
} // namespace asyncpp::io
