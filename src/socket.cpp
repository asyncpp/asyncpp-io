#include <asyncpp/io/socket.h>

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

	std::pair<socket, socket> socket::connected_pair_tcp(io_service& io, address_type addrtype) {
		auto socks = io.engine()->socket_create_connected_pair(addrtype, detail::io_engine::socket_type::stream);
		std::pair<socket, socket> res{socket(&io, socks.first), socket(&io, socks.second)};
		res.first.update_endpoint_info();
		res.second.update_endpoint_info();
		return res;
	}

	std::pair<socket, socket> socket::connected_pair_udp(io_service& io, address_type addrtype) {
		auto socks = io.engine()->socket_create_connected_pair(addrtype, detail::io_engine::socket_type::stream);
		std::pair<socket, socket> res{socket(&io, socks.first), socket(&io, socks.second)};
		res.first.update_endpoint_info();
		res.second.update_endpoint_info();
		return res;
	}

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

	void socket::multicast_join(address group, address interface) {
		if (m_fd == detail::io_engine::invalid_socket_handle) throw std::logic_error("invalid socket");
		if (group.type() != interface.type()) throw std::logic_error("group and interface need to be of the same type");
		m_io->engine()->socket_multicast_join(m_fd, group, interface);
	}

	void socket::multicast_join(address group) {
		auto iface = group.type() == address_type::ipv4 ? address{ipv4_address::any()} : address{ipv6_address::any()};
		return multicast_join(group, iface);
	}

	void socket::multicast_drop(address group, address interface) {
		if (m_fd == detail::io_engine::invalid_socket_handle) throw std::logic_error("invalid socket");
		if (group.type() != interface.type()) throw std::logic_error("group and interface need to be of the same type");
		m_io->engine()->socket_multicast_drop(m_fd, group, interface);
	}

	void socket::multicast_drop(address group) {
		auto iface = group.type() == address_type::ipv4 ? address{ipv4_address::any()} : address{ipv6_address::any()};
		return multicast_drop(group, iface);
	}

	void socket::multicast_set_send_interface(address interface) {
		if (m_fd == detail::io_engine::invalid_socket_handle) throw std::logic_error("invalid socket");
		m_io->engine()->socket_multicast_set_send_interface(m_fd, interface);
	}

	void socket::multicast_set_ttl(size_t ttl) {
		if (m_fd == detail::io_engine::invalid_socket_handle) throw std::logic_error("invalid socket");
		m_io->engine()->socket_multicast_set_ttl(m_fd, ttl);
	}

	void socket::multicast_set_loopback(bool enabled) {
		if (m_fd == detail::io_engine::invalid_socket_handle) throw std::logic_error("invalid socket");
		m_io->engine()->socket_multicast_set_loopback(m_fd, enabled);
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
