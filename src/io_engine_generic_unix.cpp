#ifndef _WIN32
#include "io_engine_generic_unix.h"

#include <cstring>

#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

namespace asyncpp::io::detail {

	io_engine::socket_handle_t io_engine_generic_unix::socket_create(address_type domain, socket_type type) {
		int afdomain = -1;
		switch (domain) {
		case address_type::ipv4: afdomain = AF_INET; break;
		case address_type::ipv6: afdomain = AF_INET6; break;
		case address_type::uds: afdomain = AF_UNIX; break;
		}
		int stype = -1;
		switch (type) {
		case socket_type::stream: stype = SOCK_STREAM; break;
		case socket_type::dgram: stype = SOCK_DGRAM; break;
		case socket_type::seqpacket: stype = SOCK_SEQPACKET; break;
		}
		if (afdomain == -1) throw std::system_error(std::make_error_code(std::errc::not_supported));
		if (stype == -1) throw std::system_error(std::make_error_code(std::errc::not_supported));
#ifdef __APPLE__
		auto fd = ::socket(afdomain, stype, 0);
		if (fd < 0) throw std::system_error(errno, std::system_category(), "socket failed");
		int flags = fcntl(fd, F_GETFL, 0);
		if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 || fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
			close(fd);
			throw std::system_error(errno, std::system_category(), "fcntl failed");
		}
#else
		auto fd = ::socket(afdomain, stype | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
		if (fd < 0) throw std::system_error(errno, std::system_category(), "socket failed");
#endif
		if (domain == address_type::ipv6) {
			int opt = 0;
			if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)) < 0) {
				close(fd);
				throw std::system_error(errno, std::system_category(), "setsockopt failed");
			}
		}
		return fd;
	}

	std::pair<io_engine::socket_handle_t, io_engine::socket_handle_t>
	io_engine_generic_unix::socket_create_connected_pair(address_type domain, socket_type type) {
		int afdomain = -1;
		switch (domain) {
		case address_type::ipv4: afdomain = AF_INET; break;
		case address_type::ipv6: afdomain = AF_INET6; break;
		case address_type::uds: afdomain = AF_UNIX; break;
		}
		int stype = -1;
		switch (type) {
		case socket_type::stream: stype = SOCK_STREAM; break;
		case socket_type::dgram: stype = SOCK_DGRAM; break;
		case socket_type::seqpacket: stype = SOCK_SEQPACKET; break;
		}
		if (afdomain == -1) throw std::system_error(std::make_error_code(std::errc::not_supported));
		if (stype == -1) throw std::system_error(std::make_error_code(std::errc::not_supported));

		int socks[2];
#ifndef __APPLE__
		if (socketpair(afdomain, stype | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, socks) != 0)
			throw std::system_error(errno, std::system_category(), "socket failed");
#else
		if (socketpair(domain, stype, 0, socks) != 0)
			throw std::system_error(errno, std::system_category(), "socket failed");
		int flags0 = fcntl(socks[0], F_GETFL, 0);
		int flags1 = fcntl(socks[1], F_GETFL, 0);
		if (flags0 < 0 || flags1 < 0 ||																				  //
			fcntl(socks[0], F_SETFL, flags0 | O_NONBLOCK) < 0 || fcntl(socks[1], F_SETFL, flags1 | O_NONBLOCK) < 0 || //
			fcntl(socks[0], F_SETFD, FD_CLOEXEC) < 0 || fcntl(socks[1], F_SETFD, FD_CLOEXEC) < 0) {
			close(socks[0]);
			close(socks[1]);
			throw std::system_error(errno, std::system_category(), "fcntl failed");
		}
#endif
		return {socks[0], socks[1]};
	}

	void io_engine_generic_unix::socket_close(socket_handle_t socket) {
		if (socket >= 0) close(socket);
	}

	void io_engine_generic_unix::socket_bind(socket_handle_t socket, endpoint ep) {
		auto sa = ep.to_sockaddr();
		auto res = ::bind(socket, reinterpret_cast<sockaddr*>(&sa.first), sa.second);
		if (res < 0) throw std::system_error(errno, std::system_category(), "bind failed");
	}

	void io_engine_generic_unix::socket_listen(socket_handle_t socket, size_t backlog) {
		if (backlog == 0) backlog = 20;
		auto res = ::listen(socket, backlog);
		if (res < 0) throw std::system_error(errno, std::system_category(), "listen failed");
	}

	endpoint io_engine_generic_unix::socket_local_endpoint(socket_handle_t socket) {
		sockaddr_storage sa;
		socklen_t sa_size = sizeof(sa);
		auto res = getsockname(socket, reinterpret_cast<sockaddr*>(&sa), &sa_size);
		if (res >= 0) return endpoint(sa, sa_size);
		throw std::system_error(errno, std::system_category(), "getsockname failed");
	}

	endpoint io_engine_generic_unix::socket_remote_endpoint(socket_handle_t socket) {
		sockaddr_storage sa;
		socklen_t sa_size = sizeof(sa);
		auto res = getpeername(socket, reinterpret_cast<sockaddr*>(&sa), &sa_size);
		if (res >= 0)
			return endpoint(sa, sa_size);
		else if (res < 0 && errno != ENOTCONN)
			throw std::system_error(errno, std::system_category(), "getpeername failed");
		return {};
	}

	void io_engine_generic_unix::socket_enable_broadcast(socket_handle_t socket, bool enable) {
		int opt = enable ? 1 : 0;
		auto res = setsockopt(socket, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));
		if (res < 0) throw std::system_error(errno, std::system_category(), "setsockopt failed");
	}

	void io_engine_generic_unix::socket_shutdown(socket_handle_t socket, bool receive, bool send) {
		int mode = 0;
		if (receive && send)
			mode = SHUT_RDWR;
		else if (receive)
			mode = SHUT_RD;
		else if (send)
			mode = SHUT_WR;
		else
			return;
		auto res = ::shutdown(socket, mode);
		if (res < 0 && errno != ENOTCONN) throw std::system_error(errno, std::system_category(), "shutdown failed");
	}

	io_engine::file_handle_t io_engine_generic_unix::file_open(const char* filename, std::ios_base::openmode mode) {
		if ((mode & std::ios_base::ate) == std::ios_base::ate) throw std::logic_error("unsupported flag");
		int m = 0;
		if ((mode & std::ios_base::app) == std::ios_base::app) m |= O_APPEND;
		if ((mode & std::ios_base::in) == std::ios_base::in)
			m |= ((mode & std::ios_base::out) == std::ios_base::out) ? O_RDWR : O_RDONLY;
		else if ((mode & std::ios_base::out) == std::ios_base::out)
			m |= O_WRONLY;
		else
			throw std::invalid_argument("neither std::ios::in, nor std::ios::out was specified");
		if ((mode & std::ios_base::trunc) == std::ios_base::trunc) m |= O_TRUNC;
		auto res = ::open(filename, m, 0660);
		if (res < 0) throw std::system_error(errno, std::system_category());
		return res;
	}

	void io_engine_generic_unix::file_close(file_handle_t fd) { if(fd >= 0) ::close(fd); }

	uint64_t io_engine_generic_unix::file_size(file_handle_t fd) {
#ifdef __APPLE__
		struct stat info {};
		auto res = fstat(fd, &info);
		if (res < 0) throw std::system_error(errno, std::system_category());
		return info.st_size;
#else
		struct stat64 info {};
		auto res = fstat64(fd, &info);
		if (res < 0) throw std::system_error(errno, std::system_category());
		return info.st_size;
#endif
	}

} // namespace asyncpp::io::detail

#endif
