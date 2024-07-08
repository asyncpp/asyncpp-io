#pragma once
#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <numeric>
#include <optional>
#include <span>
#include <string>

struct sockaddr_storage;
struct sockaddr_in;
struct sockaddr_in6;
struct sockaddr_un;
namespace asyncpp::io {
	enum class address_type {
		ipv4,
		ipv6,
#ifndef _WIN32
		uds
#endif
	};

	class ipv4_address {
		alignas(uint32_t) std::array<uint8_t, 4> m_data{};

	public:
		constexpr ipv4_address() noexcept {}
		explicit constexpr ipv4_address(uint32_t nbo_addr, std::endian order = std::endian::big) noexcept
			: m_data{static_cast<uint8_t>(nbo_addr >> 24), static_cast<uint8_t>(nbo_addr >> 16),
					 static_cast<uint8_t>(nbo_addr >> 8), static_cast<uint8_t>(nbo_addr >> 0)} {
			if (order != std::endian::big) std::reverse(m_data.begin(), m_data.end());
		}
		explicit constexpr ipv4_address(std::span<const uint8_t, 4> data, std::endian order = std::endian::big) noexcept
			: m_data{data[0], data[1], data[2], data[3]} {
			if (order != std::endian::big) std::reverse(m_data.begin(), m_data.end());
		}
		constexpr ipv4_address(uint8_t a, uint8_t b, uint8_t c, uint8_t d,
							   std::endian order = std::endian::big) noexcept
			: m_data{a, b, c, d} {
			if (order != std::endian::big) std::reverse(m_data.begin(), m_data.end());
		}
		explicit ipv4_address(const sockaddr_storage& addr);
		explicit ipv4_address(const sockaddr_in& addr) noexcept;

		constexpr std::span<const uint8_t, 4> data() const noexcept { return m_data; }
		constexpr uint32_t integer(std::endian order = std::endian::big) const noexcept {
			if (order == std::endian::big) {
				return (std::uint32_t(m_data[0]) << 24) | (std::uint32_t(m_data[1]) << 16) |
					   (std::uint32_t(m_data[2]) << 8) | (std::uint32_t(m_data[3]) << 0);
			} else {
				return (std::uint32_t(m_data[0]) << 0) | (std::uint32_t(m_data[1]) << 8) |
					   (std::uint32_t(m_data[2]) << 16) | (std::uint32_t(m_data[3]) << 24);
			}
		}

		constexpr bool is_any() const noexcept { return *this == any(); }
		constexpr bool is_multicast() const noexcept { return (m_data[0] & 0xf0) == 0xe0; }
		constexpr bool is_loopback() const noexcept { return m_data[0] == 127; }
		constexpr bool is_private() const noexcept {
			return m_data[0] == 10 || (m_data[0] == 172 && (m_data[1] & 0xf0) == 16) ||
				   (m_data[0] == 192 && m_data[1] == 168);
			// FIXME: technically 0.0.0.0/8, 100.64.0.0/10, 198.18.0.0/15 and 169.254.0.0/16 are considered private as well,
			// however those are usually not meant when talking about private/public ips. In particular 100.64.0.0/10 (carrier grade nat)
			// can appear as a users "public" ip from the perspective of the user.
		}

		constexpr std::strong_ordering operator<=>(const ipv4_address& rhs) const noexcept = default;

		std::string to_string() const {
			char buf[16]{};
			auto ptr = std::begin(buf);
			for (auto& e : m_data) {
				if (ptr != std::begin(buf)) *ptr++ = '.';
				if (e >= 100) {
					*ptr++ = '0' + (e / 100);
					*ptr++ = '0' + ((e % 100) / 10);
					*ptr++ = '0' + (e % 10);
				} else if (e >= 10) {
					*ptr++ = '0' + (e / 10);
					*ptr++ = '0' + (e % 10);
				} else {
					*ptr++ = '0' + e;
				}
			}
			return std::string(buf, ptr);
		}
		std::pair<sockaddr_storage, size_t> to_sockaddr() const noexcept;
		std::pair<sockaddr_in, size_t> to_sockaddr_in() const noexcept;

		static constexpr ipv4_address loopback() noexcept { return ipv4_address(127, 0, 0, 1); }
		static constexpr ipv4_address any() noexcept { return ipv4_address(0, 0, 0, 0); }
		static constexpr std::optional<ipv4_address> parse(std::string_view str) noexcept {
			constexpr auto parse_part = [](std::string_view::const_iterator& it, std::string_view::const_iterator end) {
				if (it == end || (*it < '0' && *it > '9')) return -1;
				int32_t result = 0;
				while (*it >= '0' && *it <= '9') {
					result = (result * 10) + (*it - '0');
					it++;
				}
				return result;
			};
			auto it = str.begin();
			auto p1 = parse_part(it, str.end());
			if (p1 < 0 || p1 > 255 || it == str.end() || *it++ != '.') return std::nullopt;
			auto p2 = parse_part(it, str.end());
			if (p2 < 0 || p2 > 255 || it == str.end() || *it++ != '.') return std::nullopt;
			auto p3 = parse_part(it, str.end());
			if (p3 < 0 || p3 > 255 || it == str.end() || *it++ != '.') return std::nullopt;
			auto p4 = parse_part(it, str.end());
			if (p4 < 0 || p4 > 255 || it != str.end()) return std::nullopt;
			return ipv4_address(p1, p2, p3, p4);
		}
	};

	class ipv6_address {
		alignas(uint64_t) std::array<uint8_t, 16> m_data{};

	public:
		constexpr ipv6_address() noexcept {}
		explicit constexpr ipv6_address(std::span<const uint8_t, 16> data,
										std::endian order = std::endian::big) noexcept
			: m_data{data[0], data[1], data[2],	 data[3],  data[4],	 data[5],  data[6],	 data[7],
					 data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15]} {
			if (order != std::endian::big) std::reverse(m_data.begin(), m_data.end());
		}
		constexpr ipv6_address(uint64_t a, uint64_t b) noexcept
			: m_data{static_cast<std::uint8_t>(a >> 56), static_cast<std::uint8_t>(a >> 48),
					 static_cast<std::uint8_t>(a >> 40), static_cast<std::uint8_t>(a >> 32),
					 static_cast<std::uint8_t>(a >> 24), static_cast<std::uint8_t>(a >> 16),
					 static_cast<std::uint8_t>(a >> 8),	 static_cast<std::uint8_t>(a >> 0),
					 static_cast<std::uint8_t>(b >> 56), static_cast<std::uint8_t>(b >> 48),
					 static_cast<std::uint8_t>(b >> 40), static_cast<std::uint8_t>(b >> 32),
					 static_cast<std::uint8_t>(b >> 24), static_cast<std::uint8_t>(b >> 16),
					 static_cast<std::uint8_t>(b >> 8),	 static_cast<std::uint8_t>(b >> 0)} {}
		constexpr ipv6_address(uint16_t a, uint16_t b, uint16_t c, uint16_t d, uint16_t e, uint16_t f, uint16_t g,
							   uint16_t h) noexcept
			: m_data{static_cast<std::uint8_t>(a >> 8), static_cast<std::uint8_t>(a >> 0),
					 static_cast<std::uint8_t>(b >> 8), static_cast<std::uint8_t>(b >> 0),
					 static_cast<std::uint8_t>(c >> 8), static_cast<std::uint8_t>(c >> 0),
					 static_cast<std::uint8_t>(d >> 8), static_cast<std::uint8_t>(d >> 0),
					 static_cast<std::uint8_t>(e >> 8), static_cast<std::uint8_t>(e >> 0),
					 static_cast<std::uint8_t>(f >> 8), static_cast<std::uint8_t>(f >> 0),
					 static_cast<std::uint8_t>(g >> 8), static_cast<std::uint8_t>(g >> 0),
					 static_cast<std::uint8_t>(h >> 8), static_cast<std::uint8_t>(h >> 0)} {}
		constexpr ipv6_address(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e, uint8_t f, uint8_t g, uint8_t h,
							   uint8_t i, uint8_t j, uint8_t k, uint8_t l, uint8_t m, uint8_t n, uint8_t o,
							   uint8_t p) noexcept
			: m_data{a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p} {}
		explicit constexpr ipv6_address(std::span<const uint16_t, 8> data) noexcept
			: ipv6_address{data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]} {}
		explicit constexpr ipv6_address(ipv4_address addr) noexcept
			: ipv6_address(std::array<uint8_t, 16>{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, addr.data()[0],
												   addr.data()[1], addr.data()[2], addr.data()[3]}) {}
		explicit ipv6_address(const sockaddr_storage& addr);
		explicit ipv6_address(const sockaddr_in6& addr) noexcept;

		constexpr std::span<const uint8_t, 16> data() const noexcept { return m_data; }
		constexpr std::span<const uint8_t, 4> ipv4_data() const noexcept {
			return std::span<const uint8_t, 4>{&m_data[12], &m_data[16]};
		}

		constexpr uint64_t subnet_prefix() const noexcept {
			return static_cast<std::uint64_t>(m_data[0]) << 56 | static_cast<std::uint64_t>(m_data[1]) << 48 |
				   static_cast<std::uint64_t>(m_data[2]) << 40 | static_cast<std::uint64_t>(m_data[3]) << 32 |
				   static_cast<std::uint64_t>(m_data[4]) << 24 | static_cast<std::uint64_t>(m_data[5]) << 16 |
				   static_cast<std::uint64_t>(m_data[6]) << 8 | static_cast<std::uint64_t>(m_data[7]);
		}
		constexpr uint64_t interface_identifier() const noexcept {
			return static_cast<std::uint64_t>(m_data[8]) << 56 | static_cast<std::uint64_t>(m_data[9]) << 48 |
				   static_cast<std::uint64_t>(m_data[10]) << 40 | static_cast<std::uint64_t>(m_data[11]) << 32 |
				   static_cast<std::uint64_t>(m_data[12]) << 24 | static_cast<std::uint64_t>(m_data[13]) << 16 |
				   static_cast<std::uint64_t>(m_data[14]) << 8 | static_cast<std::uint64_t>(m_data[15]);
		}

		constexpr std::strong_ordering operator<=>(const ipv6_address& rhs) const noexcept = default;

		constexpr bool is_any() const noexcept { return *this == any(); }
		constexpr bool is_loopback() const noexcept { return *this == loopback(); }
		constexpr bool is_multicast() const noexcept { return m_data[0] == 0xff; }
		constexpr bool is_link_local() const noexcept { return m_data[0] == 0xfe && (m_data[1] & 0xc0) == 0x80; }
		constexpr bool is_global() const noexcept {
			return !(is_any() || is_loopback() || is_multicast() || is_link_local());
		}
		constexpr bool is_ipv4_mapped() const noexcept {
			for (size_t i = 0; i < 10; i++)
				if (m_data[i]) return false;
			return m_data[10] == 0xff && m_data[11] == 0xff;
		}
		constexpr ipv4_address mapped_ipv4() const noexcept {
			if (!is_ipv4_mapped()) return ipv4_address();
			return ipv4_address(std::span<const uint8_t, 4>(&m_data[12], &m_data[16]));
		}

		std::string to_string(bool full = false) const {
			static constexpr const char* table = "0123456789abcdef";
			// A ipv6 address is represented by 8 16bit blocks separated by a colon.
			// Leading zeros in a block are suppressed, but a block may not be empty.
			// If more than one zero blocks follow each other the longest one may be replaced
			// by ::

			// Search for the longest run of zero blocks
			int zerorun_start = -1;
			int zerorun_length = 0;
			if (!full) {
				for (int i = 0; i < m_data.size(); i += 2) {
					if (m_data[i] == 0 && m_data[i + 1] == 0) {
						int run_start = i;
						for (; i < m_data.size() && m_data[i] == 0 && m_data[i + 1] == 0; i += 2)
							;
						if (i - run_start > zerorun_length && i - run_start >= 4) {
							zerorun_start = run_start;
							zerorun_length = i - run_start;
						}
					}
				}
			}

			std::string res;
			for (int i = 0; i < m_data.size();) {
				// This is the start of the zero run
				if (i == zerorun_start) {
					i += zerorun_length;
					res += ':';
					// if this is the end, append an extra colon, otherwise it is added by the next block
					if (i >= m_data.size()) res += ':';
					continue;
				}
				if (i != 0) res += ':';
				if (full || m_data[i] & 0xf0) res += table[(m_data[i] >> 4) & 0xf];
				if (full || m_data[i]) res += table[m_data[i] & 0xf];
				if (full || m_data[i] || m_data[i + 1] & 0xf0) res += table[(m_data[i + 1] >> 4) & 0xf];
				res += table[m_data[i + 1] & 0xf];
				i += 2;
			}
			return res;
		}
		std::pair<sockaddr_storage, size_t> to_sockaddr() const noexcept;
		std::pair<sockaddr_in6, size_t> to_sockaddr_in6() const noexcept;

		static constexpr ipv6_address any() noexcept { return ipv6_address(); }
		static constexpr ipv6_address loopback() noexcept { return ipv6_address(0, 0, 0, 0, 0, 0, 0, 1); }
		static constexpr std::optional<ipv6_address> parse(std::string_view str) noexcept {
			if (str.starts_with("[")) str.remove_prefix(1);
			if (str.starts_with("]")) str.remove_suffix(1);
			std::array<uint16_t, 8> buf{};
			int idx = 0;
			int dcidx = -1;
			auto it = str.begin();
			auto part_start = it;
			bool is_v4_interop = false;
			if (*it == ':') {
				dcidx = idx++;
				it++;
				if (it == str.end() || *it != ':') return std::nullopt;
				it++;
			}
			while (it != str.end()) {
				part_start = it;
				if (*it == ':') {
					if (dcidx != -1) return std::nullopt;
					dcidx = idx++;
					it++;
				} else {
					while (it != str.end()) {
						if (idx == 8) return std::nullopt;
						if (*it != ':') {
							if (*it >= '0' && *it <= '9')
								buf[idx] = buf[idx] * 16 + (*it - '0');
							else if (*it >= 'a' && *it <= 'f')
								buf[idx] = buf[idx] * 16 + (*it - 'a') + 10;
							else if (*it >= 'A' && *it <= 'F')
								buf[idx] = buf[idx] * 16 + (*it - 'A') + 10;
							else if (*it == '.') {
								auto ip4 = ipv4_address::parse(std::string_view(part_start, str.end()));
								if (!ip4) return std::nullopt;
								auto data = ip4->data();
								buf[idx++] = (static_cast<uint16_t>(data[0]) << 8) | data[1];
								if (idx >= 8) return std::nullopt;
								buf[idx] = (static_cast<uint16_t>(data[2]) << 8) | data[3];
								it = str.end();
								is_v4_interop = true;
								continue;
							} else
								return std::nullopt;
							it++;
						} else {
							if (std::distance(part_start, it) > 4) return std::nullopt;
							it++;
							if (it == str.end()) return std::nullopt;
							break;
						}
					}
					idx++;
				}
			}
			if (dcidx != -1) {
				const auto ncopy = idx - dcidx;
				const auto dest = dcidx + ncopy - 1;
				for (auto i = 0; i < ncopy; i++) {
					buf[7 - i] = buf[dest - i];
					buf[dest - i] = 0;
				}
			} else if (idx != 8)
				return std::nullopt;
			ipv6_address res{buf};
			if (is_v4_interop && !res.is_ipv4_mapped()) return std::nullopt;
			return res;
		}
	};

#ifndef _WIN32
	class uds_address {
		std::array<uint8_t, 108> m_data{};
		uint8_t m_len{};

	public:
		constexpr uds_address() noexcept {}
		explicit constexpr uds_address(std::string_view path) noexcept {
			m_len = (std::min)(path.size(), m_data.size() - 1);
			for (size_t i = 0; i < m_len; i++)
				m_data[i] = path[i];
			for (size_t i = m_len; i < m_data.size(); i++)
				m_data[i] = '\0';
			if (m_len != 0 && m_data[0] == '@') m_data[0] = '\0';
		}
		explicit uds_address(const sockaddr_storage& addr, size_t len);
		explicit uds_address(const sockaddr_un& addr, size_t len) noexcept;

		constexpr std::span<const uint8_t> data() const noexcept { return {m_data.data(), m_len}; }

		constexpr std::strong_ordering operator<=>(const uds_address& rhs) const noexcept = default;

		constexpr bool is_unnamed() const noexcept { return m_len == 0; }
		constexpr bool is_abstract() const noexcept { return m_len != 0 && m_data[0] == '\0'; }

		std::string to_string() const {
			std::string res{reinterpret_cast<const char*>(m_data.data()), m_len};
			if (!res.empty() && res[0] == '\0') res[0] = '@';
			return res;
		}
		std::pair<sockaddr_storage, size_t> to_sockaddr() const noexcept;
		std::pair<sockaddr_un, size_t> to_sockaddr_un() const noexcept;

		static constexpr std::optional<uds_address> parse(std::string_view str) noexcept {
			if (str.size() > 108) return std::nullopt;
			if (!str.empty() && std::accumulate(str.begin(), str.end(), 0ull) == 0) return std::nullopt;
			if (!str.empty() && str[0] == '@' && std::accumulate(str.begin() + 1, str.end(), 0ull) == 0)
				return std::nullopt;
			if (!str.empty() && (str.front() == ' ' || str.back() == ' ')) return std::nullopt;
			return uds_address(str);
		}
	};
#endif

	class address {
		union {
			ipv4_address m_ipv4{};
			ipv6_address m_ipv6;
#ifndef _WIN32
			uds_address m_uds;
#endif
		};
		address_type m_type{address_type::ipv4};

	public:
		constexpr address() noexcept {}
		explicit constexpr address(ipv4_address addr) noexcept : m_ipv4(addr), m_type{address_type::ipv4} {}
		explicit constexpr address(ipv6_address addr) noexcept {
			if (addr.is_ipv4_mapped()) {
				m_ipv4 = addr.mapped_ipv4();
				m_type = address_type::ipv4;
			} else {
				m_ipv6 = addr;
				m_type = address_type::ipv6;
			}
		}
#ifndef _WIN32
		explicit constexpr address(uds_address addr) noexcept : m_uds(addr), m_type{address_type::uds} {}
#endif
		explicit address(const sockaddr_storage& addr, size_t len);

		constexpr address_type type() const noexcept { return m_type; }
		constexpr bool is_ipv4() const noexcept { return m_type == address_type::ipv4; }
		constexpr bool is_ipv6() const noexcept { return m_type == address_type::ipv6; }
#ifndef _WIN32
		constexpr bool is_uds() const noexcept { return m_type == address_type::uds; }
#endif

		constexpr ipv4_address ipv4() const noexcept {
			switch (m_type) {
			case address_type::ipv4: return m_ipv4;
			case address_type::ipv6: return {};
#ifndef _WIN32
			case address_type::uds: return {};
#endif
			}
			return {};
		}
		constexpr ipv6_address ipv6() const noexcept {
			switch (m_type) {
			case address_type::ipv4: return ipv6_address(m_ipv4);
#ifndef _WIN32
			case address_type::uds: return {};
#endif
			case address_type::ipv6: return m_ipv6;
			}
			return {};
		}

#ifndef _WIN32
		constexpr uds_address uds() const noexcept {
			switch (m_type) {
			case address_type::ipv4:
			case address_type::ipv6: return {};
			case address_type::uds: return m_uds;
			}
			return {};
		}
#endif

		constexpr bool is_any() const noexcept {
			switch (m_type) {
			case address_type::ipv4: return m_ipv4.is_any();
			case address_type::ipv6: return m_ipv6.is_any();
#ifndef _WIN32
			case address_type::uds: return false;
#endif
			}
		}
		constexpr bool is_loopback() const noexcept {
			switch (m_type) {
			case address_type::ipv4: return m_ipv4.is_loopback();
			case address_type::ipv6: return m_ipv6.is_loopback();
#ifndef _WIN32
			case address_type::uds: return false;
#endif
			}
		}

		constexpr std::span<const uint8_t> bytes() const noexcept {
			switch (m_type) {
			case address_type::ipv4: return m_ipv4.data();
			case address_type::ipv6: return m_ipv6.data();
#ifndef _WIN32
			case address_type::uds: return m_uds.data();
#endif
			}
		}

		constexpr std::strong_ordering operator<=>(const address& rhs) const noexcept {
			auto order = m_type <=> rhs.m_type;
			if (order != std::strong_ordering::equal) return order;
			switch (m_type) {
			case address_type::ipv4: return m_ipv4 <=> rhs.m_ipv4;
			case address_type::ipv6: return m_ipv6 <=> rhs.m_ipv6;
#ifndef _WIN32
			case address_type::uds: return m_uds <=> rhs.m_uds;
#endif
			}
		}
		constexpr bool operator==(const address& rhs) const noexcept {
			return (*this <=> rhs) == std::strong_ordering::equal;
		}
		constexpr bool operator!=(const address& rhs) const noexcept {
			return (*this <=> rhs) != std::strong_ordering::equal;
		}

		std::string to_string(bool full = false) const {
			switch (m_type) {
			case address_type::ipv4: return m_ipv4.to_string();
			case address_type::ipv6: return m_ipv6.to_string(full);
#ifndef _WIN32
			case address_type::uds: return m_uds.to_string();
#endif
			}
		}
		std::pair<sockaddr_storage, size_t> to_sockaddr() const noexcept;

		static constexpr address any() noexcept { return address(ipv6_address::any()); }
		static constexpr address loopback() noexcept { return address(ipv6_address::loopback()); }
		static constexpr std::optional<address> parse(std::string_view str) noexcept {
			auto ip4 = ipv4_address::parse(str);
			if (ip4) return address(*ip4);
			auto ip6 = ipv6_address::parse(str);
			if (ip6) return address(*ip6);
			return std::nullopt;
		}
	};
} // namespace asyncpp::io

namespace std {
	template<>
	struct hash<asyncpp::io::ipv4_address> {
		size_t operator()(const asyncpp::io::ipv4_address& x) const noexcept {
			return std::hash<uint32_t>{}(x.integer());
		}
	};
	template<>
	struct hash<asyncpp::io::ipv6_address> {
		size_t operator()(const asyncpp::io::ipv6_address& x) const noexcept {
			std::hash<uint64_t> h{};
			auto res = h(x.subnet_prefix());
			return res ^ (h(x.interface_identifier()) + 0x9e3779b99e3779b9ull + (res << 6) + (res >> 2));
		}
	};
#ifndef _WIN32
	template<>
	struct hash<asyncpp::io::uds_address> {
		size_t operator()(const asyncpp::io::uds_address& x) const noexcept {
			size_t res = 0;
			for (auto e : x.data())
				res = res ^ (e + 0x9e3779b99e3779b9ull + (res << 6) + (res >> 2));
			return res;
		}
	};
#endif
	template<>
	struct hash<asyncpp::io::address> {
		size_t operator()(const asyncpp::io::address& x) const noexcept {
			size_t res;
			switch (x.type()) {
			case asyncpp::io::address_type::ipv4: res = std::hash<asyncpp::io::ipv4_address>{}(x.ipv4()); break;
			case asyncpp::io::address_type::ipv6: res = std::hash<asyncpp::io::ipv6_address>{}(x.ipv6()); break;
#ifndef _WIN32
			case asyncpp::io::address_type::uds: res = std::hash<asyncpp::io::uds_address>{}(x.uds()); break;
#endif
			}
			return res ^ (static_cast<size_t>(x.type()) + 0x9e3779b99e3779b9ull + (res << 6) + (res >> 2));
		}
	};
} // namespace std
