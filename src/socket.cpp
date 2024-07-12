#include <asyncpp/io/socket.h>

#include <cstring>

#ifndef _WIN32
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace {

	std::system_error sys_error(int code) {
		return std::system_error(std::make_error_code(static_cast<std::errc>(code)));
	}

} // namespace

namespace asyncpp::io {

	socket socket::create_tcp(io_service& io, address_type addrtype) {
		auto fd = io.engine()->socket_create(addrtype, detail::io_engine::socket_type::stream);
		return socket(&io, fd);
	}

	socket_create_and_connect_awaitable socket::create_connected_tcp(io_service& io, endpoint ep) {
		return socket_create_and_connect_awaitable(io, ep);
	}

	socket_create_and_connect_cancellable_awaitable socket::create_connected_tcp(io_service& io, endpoint ep,
																				 asyncpp::stop_token token) {
		return socket_create_and_connect_cancellable_awaitable(std::move(token), io, ep);
	}

	socket socket::create_udp(io_service& io, address_type addrtype) {
		auto fd = io.engine()->socket_create(addrtype, detail::io_engine::socket_type::dgram);
		return socket(&io, fd);
	}

	socket socket::create_and_bind_tcp(io_service& io, const endpoint& ep) {
		auto sock = create_tcp(io, ep.type());
		sock.bind(ep);
		return sock;
	}

	socket socket::create_and_bind_udp(io_service& io, const endpoint& ep) {
		auto sock = create_udp(io, ep.type());
		sock.bind(ep);
		return sock;
	}

	socket socket::from_fd(io_service& io, detail::io_engine::socket_handle_t fd) {
		if (fd < 0) throw std::logic_error("invalid socket");
		io.engine()->socket_register(fd);
		socket sock(&io, fd);
		sock.update_endpoint_info();
		return sock;
	}

#ifndef _WIN32
	std::pair<socket, socket> socket::connected_pair_tcp(io_service& io, address_type addrtype) {
		int domain = -1;
		switch (addrtype) {
		case address_type::ipv4: domain = AF_INET; break;
		case address_type::ipv6: domain = AF_INET6; break;
		case address_type::uds: domain = AF_UNIX; break;
		}
		if (domain == -1) throw sys_error(ENOTSUP);

		int socks[2];
#ifndef __APPLE__
		if (socketpair(domain, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, socks) != 0) throw sys_error(errno);
#else
		if (socketpair(domain, SOCK_STREAM, 0, socks) != 0) throw sys_error(errno);
		int flags0 = fcntl(socks[0], F_GETFL, 0);
		int flags1 = fcntl(socks[1], F_GETFL, 0);
		if (flags0 < 0 || flags1 < 0 ||																				  //
			fcntl(socks[0], F_SETFL, flags0 | O_NONBLOCK) < 0 || fcntl(socks[1], F_SETFL, flags1 | O_NONBLOCK) < 0 || //
			fcntl(socks[0], F_SETFD, FD_CLOEXEC) < 0 || fcntl(socks[1], F_SETFD, FD_CLOEXEC) < 0) {
			close(socks[0]);
			close(socks[1]);
			throw std::system_error(errno, std::system_category(), "pipe failed");
		}
#endif
		std::pair<socket, socket> res{socket(&io, socks[0]), socket(&io, socks[1])};
		res.first.update_endpoint_info();
		res.second.update_endpoint_info();
		return res;
	}

	std::pair<socket, socket> socket::connected_pair_udp(io_service& io, address_type addrtype) {
		int domain = -1;
		switch (addrtype) {
		case address_type::ipv4: domain = AF_INET; break;
		case address_type::ipv6: domain = AF_INET6; break;
		case address_type::uds: domain = AF_UNIX; break;
		}
		if (domain == -1) throw sys_error(ENOTSUP);

		int socks[2];
#ifndef __APPLE__
		if (socketpair(domain, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, socks) != 0) throw sys_error(errno);
#else
		if (socketpair(domain, SOCK_DGRAM, 0, socks) != 0) throw sys_error(errno);
		int flags0 = fcntl(socks[0], F_GETFL, 0);
		int flags1 = fcntl(socks[1], F_GETFL, 0);
		if (flags0 < 0 || flags1 < 0 ||																				  //
			fcntl(socks[0], F_SETFL, flags0 | O_NONBLOCK) < 0 || fcntl(socks[1], F_SETFL, flags1 | O_NONBLOCK) < 0 || //
			fcntl(socks[0], F_SETFD, FD_CLOEXEC) < 0 || fcntl(socks[1], F_SETFD, FD_CLOEXEC) < 0) {
			close(socks[0]);
			close(socks[1]);
			throw std::system_error(errno, std::system_category(), "pipe failed");
		}
#endif
		return {socket(&io, socks[0]), socket(&io, socks[1])};
	}
#endif

	socket::socket(io_service* io, detail::io_engine::socket_handle_t fd) noexcept
		: m_io{io}, m_fd{fd}, m_remote_ep{}, m_local_ep{} {}

	socket::socket(socket&& other) noexcept
		: m_io{other.m_io}, m_fd{other.m_fd}, m_remote_ep{other.m_remote_ep}, m_local_ep{other.m_local_ep} {
		other.m_io = nullptr;
		other.m_fd = detail::io_engine::invalid_socket_handle;
		other.m_local_ep = {};
		other.m_remote_ep = {};
	}

	socket& socket::operator=(socket&& other) noexcept {
		if (m_fd != detail::io_engine::invalid_socket_handle) {
			m_io->engine()->socket_close(m_fd);
			// TODO: Log errors returned from close ?
			m_fd = detail::io_engine::invalid_socket_handle;
		}
		m_io = other.m_io;
		other.m_io = nullptr;
		m_fd = other.m_fd;
		other.m_fd = detail::io_engine::invalid_socket_handle;
		m_local_ep = other.m_local_ep;
		other.m_local_ep = {};
		m_remote_ep = other.m_remote_ep;
		other.m_remote_ep = {};

		return *this;
	}

	socket::~socket() {
		if (m_fd != detail::io_engine::invalid_socket_handle) {
			m_io->engine()->socket_close(m_fd);
			// TODO: Log errors returned from close ?
			m_fd = detail::io_engine::invalid_socket_handle;
		}
	}

	void socket::bind(const endpoint& ep) {
		if (m_fd == detail::io_engine::invalid_socket_handle) throw std::logic_error("invalid socket");
		m_io->engine()->socket_bind(m_fd, ep);
		update_endpoint_info();
	}

	void socket::listen(std::uint32_t backlog) {
		if (m_fd == detail::io_engine::invalid_socket_handle) throw std::logic_error("invalid socket");
		m_io->engine()->socket_listen(m_fd, backlog);
	}

	void socket::allow_broadcast(bool enable) {
		if (m_fd == detail::io_engine::invalid_socket_handle) throw std::logic_error("invalid socket");
		m_io->engine()->socket_enable_broadcast(m_fd, enable);
	}

	void socket::close_send() {
		if (m_fd == detail::io_engine::invalid_socket_handle) throw std::logic_error("invalid socket");
		m_io->engine()->socket_shutdown(m_fd, false, true);
	}

	void socket::close_recv() {
		if (m_fd == detail::io_engine::invalid_socket_handle) throw std::logic_error("invalid socket");
		m_io->engine()->socket_shutdown(m_fd, true, false);
	}

	void socket::update_endpoint_info() {
		auto io = m_io->engine();
		m_remote_ep = io->socket_remote_endpoint(m_fd);
		m_local_ep = io->socket_local_endpoint(m_fd);
	}

} // namespace asyncpp::io
