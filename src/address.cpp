#include <asyncpp/io/address.h>
#include <asyncpp/io/endpoint.h>

#include <cstring>
#include <stdexcept>

#ifndef _WIN32
#include <netinet/in.h>
#include <sys/un.h>
#else
#include <Winsock2.h>
#include <ws2ipdef.h>
#endif

namespace asyncpp::io {
	ipv4_address::ipv4_address(const sockaddr_storage& addr) {
		if (addr.ss_family != AF_INET) throw std::invalid_argument("addr does not contain a valid ipv4 ip");
		*this = ipv4_address(*reinterpret_cast<const sockaddr_in*>(&addr));
	}

	ipv4_address::ipv4_address(const sockaddr_in& addr) noexcept
		: ipv4_address(addr.sin_addr.s_addr, std::endian::native) {}

	std::pair<sockaddr_storage, size_t> ipv4_address::to_sockaddr() const noexcept {
		sockaddr_storage res{};
		res.ss_family = AF_INET;
		memcpy(&reinterpret_cast<sockaddr_in*>(&res)->sin_addr.s_addr, data().data(), 4);
		return {res, sizeof(sockaddr_in)};
	}

	std::pair<sockaddr_in, size_t> ipv4_address::to_sockaddr_in() const noexcept {
		sockaddr_in res{};
		res.sin_family = AF_INET;
		memcpy(&res.sin_addr.s_addr, data().data(), 4);
		return {res, sizeof(sockaddr_in)};
	}

	ipv6_address::ipv6_address(const sockaddr_storage& addr) {
		if (addr.ss_family != AF_INET6) throw std::invalid_argument("addr does not contain a valid ipv6 ip");
		*this = ipv6_address(*reinterpret_cast<const sockaddr_in6*>(&addr));
	}

	ipv6_address::ipv6_address(const sockaddr_in6& addr) noexcept : ipv6_address(addr.sin6_addr.s6_addr) {}

	std::pair<sockaddr_storage, size_t> ipv6_address::to_sockaddr() const noexcept {
		sockaddr_storage res{};
		res.ss_family = AF_INET6;
		memcpy(&reinterpret_cast<sockaddr_in6*>(&res)->sin6_addr.s6_addr, data().data(), 16);
		return {res, sizeof(sockaddr_in6)};
	}

	std::pair<sockaddr_in6, size_t> ipv6_address::to_sockaddr_in6() const noexcept {
		sockaddr_in6 res{};
		res.sin6_family = AF_INET6;
		memcpy(&res.sin6_addr.s6_addr, data().data(), 16);
		return {res, sizeof(sockaddr_in6)};
	}

#ifndef _WIN32
	uds_address::uds_address(const sockaddr_storage& addr, size_t len) {
		if (addr.ss_family != AF_UNIX) throw std::invalid_argument("addr does not contain a valid ipv6 ip");
		*this = uds_address(*reinterpret_cast<const sockaddr_un*>(&addr), len);
	}

	uds_address::uds_address(const sockaddr_un& addr, size_t len) noexcept {
		memcpy(m_data.data(), addr.sun_path, (std::min)(sizeof(sockaddr_un::sun_path), m_data.size()));
		m_len = len - offsetof(struct sockaddr_un, sun_path);
		// If it is not abstract remove trailing zeros. This is the same behavior the linux kernel has.
		if (m_data[0] != '\0') {
			while (m_len && m_data[m_len - 1] == '\0')
				m_len--;
		}
	}

	std::pair<sockaddr_storage, size_t> uds_address::to_sockaddr() const noexcept {
		sockaddr_storage res{};
		res.ss_family = AF_UNIX;
		memcpy(reinterpret_cast<sockaddr_un*>(&res)->sun_path, m_data.data(),
			   (std::min<size_t>)(sizeof(sockaddr_un::sun_path), m_len));
		return {res, sizeof(sockaddr_un)};
	}

	std::pair<sockaddr_un, size_t> uds_address::to_sockaddr_un() const noexcept {
		sockaddr_un res{};
		res.sun_family = AF_UNIX;
		memcpy(res.sun_path, m_data.data(), (std::min<size_t>)(sizeof(sockaddr_un::sun_path), m_len));
		return {res, sizeof(sockaddr_un)};
	}
#endif

	address::address(const sockaddr_storage& addr, size_t len) {
		if (addr.ss_family == AF_INET)
			*this = address(ipv4_address(*reinterpret_cast<const sockaddr_in*>(&addr)));
		else if (addr.ss_family == AF_INET6)
			*this = address(ipv6_address(*reinterpret_cast<const sockaddr_in6*>(&addr)));
#ifndef _WIN32
		else if (addr.ss_family == AF_UNIX)
			*this = address(uds_address(*reinterpret_cast<const sockaddr_un*>(&addr), len));
#endif
		else
			throw std::invalid_argument("addr is not af_inet or af_inet6");
	}

	std::pair<sockaddr_storage, size_t> address::to_sockaddr() const noexcept {
		return is_ipv4() ? ipv4().to_sockaddr() : ipv6().to_sockaddr();
	}

	ipv4_endpoint::ipv4_endpoint(const sockaddr_storage& addr) {
		if (addr.ss_family != AF_INET) throw std::invalid_argument("addr does not contain a valid ipv4 ip");
		auto ep = reinterpret_cast<const sockaddr_in*>(&addr);
		m_ip = ipv4_address(*ep);
		m_port = htons(ep->sin_port);
	}

	ipv4_endpoint::ipv4_endpoint(const sockaddr_in& addr) noexcept {
		m_ip = ipv4_address(addr);
		m_port = htons(addr.sin_port);
	}

	std::pair<sockaddr_storage, size_t> ipv4_endpoint::to_sockaddr() const noexcept {
		auto res = m_ip.to_sockaddr();
		reinterpret_cast<sockaddr_in*>(&res.first)->sin_port = htons(m_port);
		return res;
	}

	std::pair<sockaddr_in, size_t> ipv4_endpoint::to_sockaddr_in() const noexcept {
		auto res = m_ip.to_sockaddr_in();
		res.first.sin_port = htons(m_port);
		return res;
	}

	ipv6_endpoint::ipv6_endpoint(const sockaddr_storage& addr) {
		if (addr.ss_family != AF_INET6) throw std::invalid_argument("addr does not contain a valid ipv6 ip");
		auto ep = reinterpret_cast<const sockaddr_in6*>(&addr);
		m_ip = ipv6_address(*ep);
		m_port = htons(ep->sin6_port);
	}

	ipv6_endpoint::ipv6_endpoint(const sockaddr_in6& addr) noexcept {
		m_ip = ipv6_address(addr);
		m_port = htons(addr.sin6_port);
	}

	std::pair<sockaddr_storage, size_t> ipv6_endpoint::to_sockaddr() const noexcept {
		auto res = m_ip.to_sockaddr();
		reinterpret_cast<sockaddr_in6*>(&res.first)->sin6_port = htons(m_port);
		return res;
	}

	std::pair<sockaddr_in6, size_t> ipv6_endpoint::to_sockaddr_in6() const noexcept {
		auto res = m_ip.to_sockaddr_in6();
		res.first.sin6_port = htons(m_port);
		return res;
	}

	endpoint::endpoint(const sockaddr_storage& addr, size_t len) {
		if (addr.ss_family == AF_INET)
			*this = endpoint(ipv4_endpoint(*reinterpret_cast<const sockaddr_in*>(&addr)));
		else if (addr.ss_family == AF_INET6)
			*this = endpoint(ipv6_endpoint(*reinterpret_cast<const sockaddr_in6*>(&addr)));
#ifndef _WIN32
		else if (addr.ss_family == AF_UNIX)
			*this = endpoint(uds_endpoint(*reinterpret_cast<const sockaddr_un*>(&addr), len));
#endif
		else
			throw std::invalid_argument("addr is not af_inet or af_inet6");
	}

	std::pair<sockaddr_storage, size_t> endpoint::to_sockaddr() const noexcept {
		switch (m_type) {
		case address_type::ipv4: return m_ipv4.to_sockaddr();
		case address_type::ipv6: return m_ipv6.to_sockaddr();
#ifndef _WIN32
		case address_type::uds: return m_uds.to_sockaddr();
#endif
		}
		return {};
	}

} // namespace asyncpp::io
