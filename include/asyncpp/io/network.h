#pragma once
#include <asyncpp/io/address.h>

#include <bit>
#include <cstdint>
#include <limits>

namespace asyncpp::io {
	class ipv4_network {
		ipv4_address m_ip{};
		uint8_t m_prefix{};

		constexpr static ipv4_address make_canonical(ipv4_address addr, uint8_t prefix) noexcept {
			if (prefix == 0) return ipv4_address();
			if (prefix >= 32) return addr;
			const uint32_t mask = ((uint32_t(1) << prefix) - 1) << (32 - prefix);
			return ipv4_address(addr.integer() & mask);
		}

	public:
		constexpr ipv4_network() noexcept = default;
		constexpr ipv4_network(ipv4_address addr, uint8_t prefix) noexcept
			: m_ip{make_canonical(addr, prefix)}, m_prefix{prefix} {}
		constexpr ipv4_network(ipv4_address addr, ipv4_address mask) noexcept
			: m_ip{}, m_prefix{static_cast<uint8_t>(std::countl_one(mask.integer()))} {
			m_ip = make_canonical(m_ip, m_prefix);
		}

		constexpr uint8_t prefix_length() const noexcept { return m_prefix; }
		constexpr ipv4_address canonical() const noexcept { return m_ip; }
		constexpr ipv4_address broadcast() const noexcept {
			if (m_prefix == 0) return ipv4_address(255, 255, 255, 255);
			if (m_prefix >= 32) return m_ip;
			const uint32_t mask = ((uint32_t(1) << m_prefix) - 1) << (32 - m_prefix);
			return ipv4_address((m_ip.integer() & mask) | (std::numeric_limits<uint32_t>::max() & ~mask));
		}

		constexpr bool is_subnet(const ipv4_network& subnet) const noexcept {
			const auto base = subnet.canonical();
			return (subnet.m_prefix > m_prefix && base >= canonical() && base < broadcast());
		}
		constexpr bool is_subnet_of(const ipv4_network& parent) const noexcept {
			const ipv4_network base(m_ip, parent.m_prefix);
			return parent.m_prefix < m_prefix && base.canonical() == parent.canonical();
		}
		constexpr bool contains(const ipv4_address& host) const noexcept {
			constexpr uint32_t max = std::numeric_limits<uint32_t>::max();
			if (m_prefix == 0) return true;
			const uint32_t mask = m_prefix >= 32 ? max : (((uint32_t(1) << m_prefix) - 1) << (32 - m_prefix));
			return (host.integer() & mask) == (m_ip.integer() & mask);
		}

		constexpr std::strong_ordering operator<=>(const ipv4_network& rhs) const noexcept = default;

		std::string to_string() const { return m_ip.to_string() + "/" + std::to_string(m_prefix); }

		static constexpr std::optional<ipv4_network> parse(std::string_view str) noexcept {
			auto pos = str.find('/');
			auto ip = ipv4_address::parse(str.substr(0, pos));
			if (!ip) return std::nullopt;
			if (pos == std::string::npos) return ipv4_network(*ip, 32);
			if (pos + 1 == str.size()) return std::nullopt;
			uint8_t prefix = 0;
			for (auto it = str.begin() + pos + 1; it != str.end(); it++) {
				if (*it < '0' || *it > '9') return std::nullopt;
				prefix = prefix * 10 + (*it - '0');
			}
			return ipv4_network(*ip, prefix);
		}
	};

	class ipv6_network {
		ipv6_address m_ip{};
		uint8_t m_prefix{};

		constexpr static std::pair<uint64_t, uint64_t> make_mask(uint8_t prefix) noexcept {
			constexpr uint64_t max = std::numeric_limits<uint64_t>::max();
			if (prefix >= 128) return {max, max};
			if (prefix == 0) return {0, 0};
			const uint64_t mask1 = prefix >= 64 ? max : (((uint64_t(1) << prefix) - 1) << (64 - prefix));
			const uint64_t mask2 = prefix < 64 ? 0 : (((uint64_t(1) << (prefix - 64)) - 1) << (64 - (prefix - 64)));
			return {mask1, mask2};
		}

		constexpr static ipv6_address make_canonical(ipv6_address addr, uint8_t prefix) noexcept {
			if (prefix == 0) return ipv6_address();
			if (prefix >= 128) return addr;
			auto [mask1, mask2] = make_mask(prefix);
			return ipv6_address(addr.subnet_prefix() & mask1, addr.interface_identifier() & mask2);
		}

	public:
		constexpr ipv6_network() noexcept = default;
		constexpr ipv6_network(ipv6_address addr, uint8_t prefix) noexcept
			: m_ip{make_canonical(addr, prefix)}, m_prefix{prefix} {}
		constexpr ipv6_network(ipv6_address addr, ipv6_address mask) noexcept : m_ip{}, m_prefix{0} {
			uint8_t prefix = std::countl_one(mask.subnet_prefix());
			if (prefix == 64) prefix = 64 + std::countl_one(mask.interface_identifier());
			m_prefix = prefix;
			m_ip = make_canonical(addr, prefix);
		}

		constexpr uint8_t prefix_length() const noexcept { return m_prefix; }

		constexpr ipv6_address canonical() const noexcept { return m_ip; }
		constexpr ipv6_address broadcast() const noexcept {
			if (m_prefix == 0) return ipv6_address();
			if (m_prefix >= 128) return m_ip;
			constexpr uint64_t max = std::numeric_limits<uint64_t>::max();
			auto [mask1, mask2] = make_mask(m_prefix);
			return ipv6_address((m_ip.subnet_prefix() & mask1) | (max & ~mask1),
								(m_ip.interface_identifier() & mask2) | (max & ~mask2));
		}

		constexpr bool is_subnet(const ipv6_network& subnet) const noexcept {
			const auto base = subnet.canonical();
			return (subnet.m_prefix > m_prefix && base >= canonical() && base < broadcast());
		}
		constexpr bool is_subnet_of(const ipv6_network& parent) const noexcept {
			const ipv6_network base(m_ip, parent.m_prefix);
			return parent.m_prefix < m_prefix && base.canonical() == parent.canonical();
		}
		constexpr bool contains(const ipv6_address& host) const noexcept {
			if (m_prefix == 0) return true;
			if (m_prefix >= 128) return canonical() == host;
			auto [mask1, mask2] = make_mask(m_prefix);
			return (host.subnet_prefix() & mask1) == (m_ip.subnet_prefix() & mask1) &&
				   (host.interface_identifier() & mask2) == (m_ip.interface_identifier() & mask2);
		}

		constexpr std::strong_ordering operator<=>(const ipv6_network& rhs) const noexcept = default;

		std::string to_string(bool full = false) const { return m_ip.to_string(full) + "/" + std::to_string(m_prefix); }

		static constexpr std::optional<ipv6_network> parse(std::string_view str) noexcept {
			auto pos = str.find('/');
			auto ip = ipv6_address::parse(str.substr(0, pos));
			if (!ip) return std::nullopt;
			if (pos == std::string::npos) return ipv6_network(*ip, 128);
			if (pos + 1 == str.size()) return std::nullopt;
			uint16_t prefix = 0;
			for (auto it = str.begin() + pos + 1; it != str.end(); it++) {
				if (*it < '0' || *it > '9') return std::nullopt;
				prefix = prefix * 10 + (*it - '0');
			}
			return ipv6_network(*ip, prefix);
		}
	};
} // namespace asyncpp::io

namespace std {
	template<>
	struct hash<asyncpp::io::ipv4_network> {
		size_t operator()(const asyncpp::io::ipv4_network& x) const noexcept {
			return std::hash<uint64_t>{}((static_cast<uint64_t>(x.canonical().integer()) << 16) | x.prefix_length());
		}
	};
	template<>
	struct hash<asyncpp::io::ipv6_network> {
		size_t operator()(const asyncpp::io::ipv6_network& x) const noexcept {
			std::hash<asyncpp::io::ipv6_address> h{};
			auto res = h(x.canonical());
			return res ^ (x.prefix_length() + 0x9e3779b99e3779b9ull + (res << 6) + (res >> 2));
		}
	};
} // namespace std
