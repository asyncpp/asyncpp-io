#pragma once
#include <asyncpp/io/address.h>

namespace asyncpp::io {
	class ipv4_endpoint {
		ipv4_address m_ip{};
		uint16_t m_port{};

	public:
		constexpr ipv4_endpoint() noexcept {}
		constexpr ipv4_endpoint(ipv4_address addr, uint16_t port) noexcept : m_ip{addr}, m_port{port} {}
		explicit ipv4_endpoint(const sockaddr_storage& addr);
		explicit ipv4_endpoint(const sockaddr_in& addr) noexcept;

		constexpr ipv4_address address() const noexcept { return m_ip; }
		constexpr uint16_t port() const noexcept { return m_port; }

		constexpr std::strong_ordering operator<=>(const ipv4_endpoint& rhs) const noexcept = default;

		std::string to_string() const { return m_ip.to_string() + ":" + std::to_string(m_port); }
		std::pair<sockaddr_storage, size_t> to_sockaddr() const noexcept;
		std::pair<sockaddr_in, size_t> to_sockaddr_in() const noexcept;

		static constexpr std::optional<ipv4_endpoint> parse(std::string_view str) noexcept {
			auto pos = str.find(':');
			auto ip = ipv4_address::parse(str.substr(0, pos));
			if (!ip) return std::nullopt;
			if (pos == std::string::npos) return ipv4_endpoint(*ip, 0);
			if (pos + 1 == str.size()) return std::nullopt;
			uint16_t port = 0;
			for (auto it = str.begin() + pos + 1; it != str.end(); it++) {
				if (*it < '0' || *it > '9') return std::nullopt;
				port = port * 10 + (*it - '0');
			}
			return ipv4_endpoint(*ip, port);
		}
	};

	class ipv6_endpoint {
		ipv6_address m_ip{};
		uint16_t m_port{};

	public:
		constexpr ipv6_endpoint() noexcept {}
		constexpr ipv6_endpoint(ipv6_address addr, uint16_t port) noexcept : m_ip{addr}, m_port{port} {}
		constexpr ipv6_endpoint(ipv4_address addr, uint16_t port) noexcept : m_ip{addr}, m_port{port} {}
		explicit ipv6_endpoint(const sockaddr_storage& addr);
		explicit ipv6_endpoint(const sockaddr_in6& addr) noexcept;

		constexpr ipv6_address address() const noexcept { return m_ip; }
		constexpr uint16_t port() const noexcept { return m_port; }

		constexpr std::strong_ordering operator<=>(const ipv6_endpoint& rhs) const noexcept = default;

		std::string to_string(bool full = false) const {
			return "[" + m_ip.to_string(full) + "]:" + std::to_string(m_port);
		}
		std::pair<sockaddr_storage, size_t> to_sockaddr() const noexcept;
		std::pair<sockaddr_in6, size_t> to_sockaddr_in6() const noexcept;

		static constexpr std::optional<ipv6_endpoint> parse(std::string_view str) noexcept {
			auto pos = str.find(']');
			if (pos == std::string::npos || str[0] != '[') return std::nullopt;
			auto ip = ipv6_address::parse(str.substr(1, pos - 1));
			if (!ip) return std::nullopt;
			pos = str.find(':', pos);
			if (pos == std::string::npos) return ipv6_endpoint(*ip, 0);
			if (pos + 1 == str.size()) return std::nullopt;
			uint16_t port = 0;
			for (auto it = str.begin() + pos + 1; it != str.end(); it++) {
				if (*it < '0' || *it > '9') return std::nullopt;
				port = port * 10 + (*it - '0');
			}
			return ipv6_endpoint(*ip, port);
		}
	};

#ifndef _WIN32
	using uds_endpoint = uds_address;
#endif

	class endpoint {
		union {
			ipv4_endpoint m_ipv4 = {};
			ipv6_endpoint m_ipv6;
#ifndef _WIN32
			uds_endpoint m_uds;
#endif
		};
		address_type m_type{};

	public:
		constexpr endpoint() noexcept {}
		constexpr endpoint(ipv4_address addr, uint16_t port) noexcept
			: m_ipv4(addr, port), m_type(address_type::ipv4) {}
		constexpr endpoint(ipv6_address addr, uint16_t port) noexcept
			: m_ipv6(addr, port), m_type(address_type::ipv6) {}
#ifndef _WIN32
		constexpr endpoint(uds_address addr) noexcept : m_uds(addr), m_type(address_type::uds) {}
#endif
		constexpr endpoint(address addr, uint16_t port) noexcept {
			switch (addr.type()) {
			case address_type::ipv4:
				m_ipv4 = {addr.ipv4(), port};
				m_type = address_type::ipv4;
				break;
			case address_type::ipv6:
				m_ipv6 = {addr.ipv6(), port};
				m_type = address_type::ipv6;
				break;
#ifndef _WIN32
			case address_type::uds:
				m_uds = addr.uds();
				m_type = address_type::uds;
				break;
#endif
			}
		}
		explicit constexpr endpoint(ipv4_endpoint ep) noexcept : m_ipv4(ep), m_type(address_type::ipv4) {}
		explicit constexpr endpoint(ipv6_endpoint ep) noexcept : m_ipv6(ep), m_type(address_type::ipv6) {}
		explicit endpoint(const sockaddr_storage& addr, size_t len);

		constexpr address_type type() const noexcept { return m_type; }
		constexpr bool is_ipv4() const noexcept { return m_type == address_type::ipv4; }
		constexpr bool is_ipv6() const noexcept { return m_type == address_type::ipv6; }
#ifndef _WIN32
		constexpr bool is_uds() const noexcept { return m_type == address_type::uds; }
#endif

		constexpr ipv4_endpoint ipv4() const noexcept {
			switch (m_type) {
			case address_type::ipv4: return m_ipv4;
			case address_type::ipv6: return {};
#ifndef _WIN32
			case address_type::uds: return {};
#endif
			}
		}
		constexpr ipv6_endpoint ipv6() const noexcept {
			switch (m_type) {
			case address_type::ipv4: return {};
			case address_type::ipv6: return m_ipv6;
#ifndef _WIN32
			case address_type::uds: return {};
#endif
			}
		}
#ifndef _WIN32
		constexpr uds_endpoint uds() const noexcept {
			switch (m_type) {
			case address_type::ipv4: return {};
			case address_type::ipv6: return {};
			case address_type::uds: return m_uds;
			}
		}
#endif

		constexpr std::strong_ordering operator<=>(const endpoint& rhs) const noexcept {
			auto order = m_type <=> rhs.m_type;
			if (order != std::strong_ordering::equal) return order;
			switch (m_type) {
			case address_type::ipv4: return m_ipv4 <=> rhs.m_ipv4;
			case address_type::ipv6: return m_ipv6 <=> rhs.m_ipv6;
#ifndef _WIN32
			case address_type::uds: return m_uds <=> rhs.m_uds;
#endif
			}
			return std::strong_ordering::equal;
		}
		constexpr bool operator==(const endpoint& rhs) const noexcept {
			return (*this <=> rhs) == std::strong_ordering::equal;
		}
		constexpr bool operator!=(const endpoint& rhs) const noexcept {
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

		static constexpr std::optional<endpoint> parse(std::string_view str, bool allow_uds = false) noexcept {
			auto ep6 = ipv6_endpoint::parse(str);
			if (ep6) return endpoint(*ep6);
			auto ep4 = ipv4_endpoint::parse(str);
			if (ep4) return endpoint(*ep4);
#ifndef _WIN32
			if (allow_uds) {
				auto epuds = uds_endpoint::parse(str);
				if (epuds) return endpoint(*epuds);
			}
#endif
			return std::nullopt;
		}
	};
} // namespace asyncpp::io

namespace std {
	template<>
	struct hash<asyncpp::io::ipv4_endpoint> {
		size_t operator()(const asyncpp::io::ipv4_endpoint& x) const noexcept {
			return std::hash<uint64_t>{}((static_cast<uint64_t>(x.address().integer()) << 16) | x.port());
		}
	};
	template<>
	struct hash<asyncpp::io::ipv6_endpoint> {
		size_t operator()(const asyncpp::io::ipv6_endpoint& x) const noexcept {
			std::hash<asyncpp::io::ipv6_address> h{};
			auto res = h(x.address());
			return res ^ (x.port() + 0x9e3779b99e3779b9ull + (res << 6) + (res >> 2));
		}
	};
	template<>
	struct hash<asyncpp::io::endpoint> {
		size_t operator()(const asyncpp::io::endpoint& x) const noexcept {
			size_t res{};
			switch (x.type()) {
			case asyncpp::io::address_type::ipv4: res = std::hash<asyncpp::io::ipv4_endpoint>{}(x.ipv4()); break;
			case asyncpp::io::address_type::ipv6: res = std::hash<asyncpp::io::ipv6_endpoint>{}(x.ipv6()); break;
#ifndef _WIN32
			case asyncpp::io::address_type::uds: res = std::hash<asyncpp::io::uds_endpoint>{}(x.uds()); break;
#endif
			}
			return res ^ (static_cast<size_t>(x.type()) + 0x9e3779b99e3779b9ull + (res << 6) + (res >> 2));
		}
	};
} // namespace std
