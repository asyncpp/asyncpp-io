#pragma once
#include <asyncpp/detail/std_import.h>
#include <asyncpp/io/detail/cancel_awaitable.h>
#include <asyncpp/io/detail/io_engine.h>
#include <asyncpp/io/endpoint.h>
#include <asyncpp/io/io_service.h>
#include <asyncpp/stop_token.h>

#include <optional>
#include <system_error>
#include <variant>

namespace asyncpp::io {
	class socket;

	namespace detail {
		class socket_awaitable_base {
			socket_awaitable_base(const socket_awaitable_base&) = delete;
			socket_awaitable_base(socket_awaitable_base&&) = delete;
			socket_awaitable_base& operator=(const socket_awaitable_base&) = delete;
			socket_awaitable_base& operator=(socket_awaitable_base&&) = delete;

			template<typename T>
			friend class detail::cancellable_awaitable;

		protected:
			socket& m_socket;
			detail::io_engine::completion_data m_completion;

		public:
			socket_awaitable_base(socket& sock) noexcept : m_socket{sock}, m_completion{} {}
			bool await_ready() const noexcept { return false; }
		};
	} // namespace detail

	class socket_connect_awaitable;
	class socket_create_and_connect_awaitable;
	class socket_accept_awaitable;
	class socket_accept_error_code_awaitable;
	class socket_send_awaitable;
	class socket_recv_awaitable;
	class socket_recv_exact_awaitable;
	class socket_recv_from_awaitable;
	class socket_send_to_awaitable;

	using socket_connect_cancellable_awaitable = detail::cancellable_awaitable<socket_connect_awaitable>;
	class socket_create_and_connect_cancellable_awaitable;
	using socket_accept_cancellable_awaitable = detail::cancellable_awaitable<socket_accept_awaitable>;
	using socket_accept_error_code_cancellable_awaitable =
		detail::cancellable_awaitable<socket_accept_error_code_awaitable>;
	using socket_send_cancellable_awaitable = detail::cancellable_awaitable<socket_send_awaitable>;
	using socket_recv_cancellable_awaitable = detail::cancellable_awaitable<socket_recv_awaitable>;
	using socket_recv_exact_cancellable_awaitable = detail::cancellable_awaitable<socket_recv_exact_awaitable>;
	using socket_recv_from_cancellable_awaitable = detail::cancellable_awaitable<socket_recv_from_awaitable>;
	using socket_send_to_cancellable_awaitable = detail::cancellable_awaitable<socket_send_to_awaitable>;

	class socket {
	public:
		[[deprecated("use create_tcp instead")]] [[nodiscard]] static socket create_tcpv4(io_service& io) {
			return create_tcp(io, address_type::ipv4);
		}
		[[deprecated("use create_tcp instead")]] [[nodiscard]] static socket create_tcpv6(io_service& io) {
			return create_tcp(io, address_type::ipv6);
		}
		[[nodiscard]] static socket create_tcp(io_service& io, address_type addr_type);
		[[nodiscard]] static socket_create_and_connect_awaitable create_connected_tcp(io_service& io, endpoint ep);
		[[nodiscard]] static socket_create_and_connect_cancellable_awaitable
		create_connected_tcp(io_service& io, endpoint ep, asyncpp::stop_token token);
		[[deprecated("use create_udp instead")]] [[nodiscard]] static socket create_udpv4(io_service& io) {
			return create_udp(io, address_type::ipv4);
		}
		[[deprecated("use create_udp instead")]] [[nodiscard]] static socket create_udpv6(io_service& io) {
			return create_udp(io, address_type::ipv6);
		}
		[[nodiscard]] static socket create_udp(io_service& io, address_type addr_type);
		[[nodiscard]] static socket create_and_bind_tcp(io_service& io, const endpoint& ep);
		[[nodiscard]] static socket create_and_bind_udp(io_service& io, const endpoint& ep);
		[[nodiscard]] static socket from_fd(io_service& io, detail::io_engine::socket_handle_t fd);
		[[nodiscard]] static std::pair<socket, socket> connected_pair_tcp(io_service& io, address_type addrtype);
		[[nodiscard]] static std::pair<socket, socket> connected_pair_udp(io_service& io, address_type addrtype);

		constexpr socket() noexcept = default;
		socket(socket&& other) noexcept;
		socket& operator=(socket&& other) noexcept;
		~socket();

		[[nodiscard]] bool valid() const noexcept { return m_io != nullptr; }
		[[nodiscard]] operator bool() const noexcept { return m_io != nullptr; }
		[[nodiscard]] bool operator!() const noexcept { return m_io == nullptr; }

		[[nodiscard]] io_service& service() const noexcept { return *m_io; }

		[[nodiscard]] const endpoint& local_endpoint() const noexcept { return m_local_ep; }
		[[nodiscard]] const endpoint& remote_endpoint() const noexcept { return m_remote_ep; }

		void bind(const endpoint& ep);
		void listen(std::uint32_t backlog = 0);

		void allow_broadcast(bool enable);
		void multicast_join(address group, address iface);
		void multicast_join(address group);
		void multicast_drop(address group, address iface);
		void multicast_drop(address group);
		void multicast_set_send_interface(address iface);
		void multicast_set_ttl(size_t ttl);
		void multicast_set_loopback(bool enabled);

		[[nodiscard]] detail::io_engine::socket_handle_t native_handle() const noexcept { return m_fd; }
		[[nodiscard]] detail::io_engine::socket_handle_t release() noexcept {
			if (m_io != nullptr && m_fd != detail::io_engine::invalid_socket_handle)
				m_io->engine()->socket_release(m_fd);
			m_io = nullptr;
			m_remote_ep = {};
			m_local_ep = {};
			return std::exchange(m_fd, detail::io_engine::invalid_socket_handle);
		}

		[[nodiscard]] socket_connect_awaitable connect(const endpoint& ep) noexcept;
		[[nodiscard]] socket_connect_awaitable connect(const endpoint& ep, std::error_code& ec) noexcept;
		[[nodiscard]] socket_accept_awaitable accept() noexcept;
		[[nodiscard]] socket_accept_error_code_awaitable accept(std::error_code& ec) noexcept;
		[[nodiscard]] socket_send_awaitable send(const void* buffer, std::size_t size) noexcept;
		[[nodiscard]] socket_send_awaitable send(const void* buffer, std::size_t size, std::error_code& ec) noexcept;
		[[nodiscard]] socket_recv_awaitable recv(void* buffer, std::size_t size) noexcept;
		[[nodiscard]] socket_recv_awaitable recv(void* buffer, std::size_t size, std::error_code& ec) noexcept;
		[[nodiscard]] socket_recv_exact_awaitable recv_exact(void* buffer, std::size_t size) noexcept;
		[[nodiscard]] socket_recv_exact_awaitable recv_exact(void* buffer, std::size_t size,
															 std::error_code& ec) noexcept;
		[[nodiscard]] socket_send_to_awaitable send_to(const void* buffer, std::size_t size,
													   const endpoint& dst_ep) noexcept;
		[[nodiscard]] socket_send_to_awaitable send_to(const void* buffer, std::size_t size, const endpoint& dst_ep,
													   std::error_code& ec) noexcept;
		[[nodiscard]] socket_recv_from_awaitable recv_from(void* buffer, std::size_t size) noexcept;
		[[nodiscard]] socket_recv_from_awaitable recv_from(void* buffer, std::size_t size,
														   std::error_code& ec) noexcept;

		[[nodiscard]] socket_connect_cancellable_awaitable connect(const endpoint& ep, asyncpp::stop_token st) noexcept;
		[[nodiscard]] socket_connect_cancellable_awaitable connect(const endpoint& ep, asyncpp::stop_token st,
																   std::error_code& ec) noexcept;
		[[nodiscard]] socket_accept_cancellable_awaitable accept(asyncpp::stop_token st) noexcept;
		[[nodiscard]] socket_accept_error_code_cancellable_awaitable accept(asyncpp::stop_token st,
																			std::error_code& ec) noexcept;
		[[nodiscard]] socket_send_cancellable_awaitable send(const void* buffer, std::size_t size,
															 asyncpp::stop_token st) noexcept;
		[[nodiscard]] socket_send_cancellable_awaitable send(const void* buffer, std::size_t size,
															 asyncpp::stop_token st, std::error_code& ec) noexcept;
		[[nodiscard]] socket_recv_cancellable_awaitable recv(void* buffer, std::size_t size,
															 asyncpp::stop_token st) noexcept;
		[[nodiscard]] socket_recv_cancellable_awaitable recv(void* buffer, std::size_t size, asyncpp::stop_token st,
															 std::error_code& ec) noexcept;
		[[nodiscard]] socket_recv_exact_cancellable_awaitable recv_exact(void* buffer, std::size_t size,
																		 asyncpp::stop_token st) noexcept;
		[[nodiscard]] socket_recv_exact_cancellable_awaitable
		recv_exact(void* buffer, std::size_t size, asyncpp::stop_token st, std::error_code& ec) noexcept;
		[[nodiscard]] socket_send_to_cancellable_awaitable
		send_to(const void* buffer, std::size_t size, const endpoint& dst_ep, asyncpp::stop_token st) noexcept;
		[[nodiscard]] socket_send_to_cancellable_awaitable send_to(const void* buffer, std::size_t size,
																   const endpoint& dst_ep, asyncpp::stop_token st,
																   std::error_code& ec) noexcept;
		[[nodiscard]] socket_recv_from_cancellable_awaitable recv_from(void* buffer, std::size_t size,
																	   asyncpp::stop_token st) noexcept;
		[[nodiscard]] socket_recv_from_cancellable_awaitable
		recv_from(void* buffer, std::size_t size, asyncpp::stop_token st, std::error_code& ec) noexcept;

		template<typename FN>
			requires(std::is_invocable_v<FN, std::error_code>)
		void connect(const endpoint& ep, FN&& cb, asyncpp::stop_token st = {});
		template<typename FN>
			requires(std::is_invocable_v<FN, std::variant<socket, std::error_code>>)
		void accept(FN&& cb, asyncpp::stop_token st = {});
		template<typename FN>
			requires(std::is_invocable_v<FN, size_t, std::error_code>)
		void send(const void* buffer, std::size_t size, FN&& cb, asyncpp::stop_token st = {});
		template<typename FN>
			requires(std::is_invocable_v<FN, size_t, std::error_code>)
		void recv(void* buffer, std::size_t size, FN&& cb, asyncpp::stop_token st = {});
		template<typename FN>
			requires(std::is_invocable_v<FN, size_t, std::error_code>)
		void send_to(const void* buffer, std::size_t size, const endpoint& dst_ep, FN&& cb,
					 asyncpp::stop_token st = {});
		template<typename FN>
			requires(std::is_invocable_v<FN, size_t, endpoint, std::error_code>)
		void recv_from(void* buffer, std::size_t size, FN&& cb, asyncpp::stop_token st = {});

		void close_send();
		void close_recv();

		friend void swap(socket& a, socket& b) noexcept;

	private:
		socket(io_service* io, detail::io_engine::socket_handle_t fd) noexcept;
		void update_endpoint_info();

		io_service* m_io{};
		detail::io_engine::socket_handle_t m_fd{detail::io_engine::invalid_socket_handle};
		endpoint m_remote_ep{};
		endpoint m_local_ep{};
	};

	inline void swap(socket& a, socket& b) noexcept {
		std::swap(a.m_io, b.m_io);
		std::swap(a.m_fd, b.m_fd);
		std::swap(a.m_local_ep, b.m_local_ep);
		std::swap(a.m_remote_ep, b.m_remote_ep);
	}

	class socket_connect_awaitable : public detail::socket_awaitable_base {
		const endpoint m_ep;
		std::error_code* const m_ec;

	public:
		socket_connect_awaitable(socket& sock, endpoint ep, std::error_code* ec = nullptr) noexcept
			: socket_awaitable_base{sock}, m_ep{ep}, m_ec{ec} {}
		bool await_suspend(coroutine_handle<> hdl);
		void await_resume();
	};

	class socket_create_and_connect_awaitable {
		socket m_sock;
		socket_connect_awaitable m_child;

	public:
		socket_create_and_connect_awaitable(io_service& io, endpoint ep) noexcept
			: m_sock{socket::create_tcp(io, ep.type())}, m_child{m_sock, ep} {}
		bool await_suspend(coroutine_handle<> hdl) { return m_child.await_suspend(hdl); }
		bool await_ready() const noexcept { return false; }
		socket await_resume() {
			m_child.await_resume();
			return std::move(m_sock);
		}
	};

	class socket_create_and_connect_cancellable_awaitable {
		socket m_sock;
		socket_connect_cancellable_awaitable m_child;

	public:
		socket_create_and_connect_cancellable_awaitable(asyncpp::stop_token token, io_service& io, endpoint ep) noexcept
			: m_sock{socket::create_tcp(io, ep.type())}, m_child{std::move(token), m_sock, ep} {}
		bool await_suspend(coroutine_handle<> hdl) { return m_child.await_suspend(hdl); }
		socket await_resume() {
			m_child.await_resume();
			return std::move(m_sock);
		}
		bool await_ready() const noexcept { return false; }
	};

	class socket_send_awaitable : public detail::socket_awaitable_base {
		const void* const m_buffer;
		std::size_t const m_size;
		std::error_code* const m_ec;

	public:
		socket_send_awaitable(socket& sock, const void* buffer, std::size_t size,
							  std::error_code* ec = nullptr) noexcept
			: socket_awaitable_base{sock}, m_buffer{buffer}, m_size{size}, m_ec{ec} {}
		bool await_suspend(coroutine_handle<> hdl);
		void await_resume();
	};

	class socket_recv_awaitable : public detail::socket_awaitable_base {
		void* const m_buffer;
		std::size_t const m_size;
		std::error_code* const m_ec;

	public:
		socket_recv_awaitable(socket& sock, void* buffer, std::size_t size, std::error_code* ec = nullptr) noexcept
			: socket_awaitable_base{sock}, m_buffer{buffer}, m_size{size}, m_ec{ec} {}
		bool await_suspend(coroutine_handle<> hdl);
		size_t await_resume();
	};

	class socket_recv_exact_awaitable : public asyncpp::io::detail::socket_awaitable_base {
		unsigned char* m_buffer;
		std::size_t const m_size;
		std::size_t m_remaining;
		asyncpp::coroutine_handle<> m_handle;
		std::error_code* const m_ec;

	public:
		socket_recv_exact_awaitable(asyncpp::io::socket& sock, void* buffer, std::size_t size,
									std::error_code* ec = nullptr) noexcept
			: socket_awaitable_base{sock}, m_buffer{static_cast<unsigned char*>(buffer)}, m_size{size},
			  m_remaining{size}, m_ec{ec} {}
		bool await_suspend(asyncpp::coroutine_handle<> hdl);
		size_t await_resume();
	};

	class socket_accept_awaitable : public detail::socket_awaitable_base {
	public:
		socket_accept_awaitable(socket& sock) noexcept : socket_awaitable_base{sock} {}
		bool await_suspend(coroutine_handle<> hdl);
		socket await_resume();
	};

	class socket_accept_error_code_awaitable : public detail::socket_awaitable_base {
		std::error_code& m_ec;

	public:
		socket_accept_error_code_awaitable(socket& sock, std::error_code& ec) noexcept
			: socket_awaitable_base{sock}, m_ec{ec} {}
		bool await_suspend(coroutine_handle<> hdl);
		std::optional<socket> await_resume();
	};

	class socket_send_to_awaitable : public detail::socket_awaitable_base {
		const void* const m_buffer;
		std::size_t const m_size;
		endpoint const m_destination;
		std::error_code* const m_ec;

	public:
		socket_send_to_awaitable(socket& sock, const void* buffer, std::size_t size, endpoint dst,
								 std::error_code* ec = nullptr) noexcept
			: socket_awaitable_base{sock}, m_buffer{buffer}, m_size{size}, m_destination{dst}, m_ec{ec} {}
		bool await_suspend(coroutine_handle<> hdl);
		size_t await_resume();
	};

	class socket_recv_from_awaitable : public detail::socket_awaitable_base {
		void* const m_buffer;
		std::size_t const m_size;
		endpoint m_source;
		std::error_code* const m_ec;

	public:
		socket_recv_from_awaitable(socket& sock, void* buffer, std::size_t size, std::error_code* ec = nullptr) noexcept
			: socket_awaitable_base{sock}, m_buffer{buffer}, m_size{size}, m_ec{ec} {}
		bool await_suspend(coroutine_handle<> hdl);
		std::pair<size_t, endpoint> await_resume();
	};

	[[nodiscard]] inline socket_connect_awaitable socket::connect(const endpoint& ep) noexcept {
		return socket_connect_awaitable(*this, ep);
	}

	[[nodiscard]] inline socket_connect_awaitable socket::connect(const endpoint& ep, std::error_code& ec) noexcept {
		return socket_connect_awaitable(*this, ep, &ec);
	}

	[[nodiscard]] inline socket_accept_awaitable socket::accept() noexcept { return socket_accept_awaitable(*this); }

	[[nodiscard]] inline socket_accept_error_code_awaitable socket::accept(std::error_code& ec) noexcept {
		return socket_accept_error_code_awaitable(*this, ec);
	}

	[[nodiscard]] inline socket_send_awaitable socket::send(const void* buffer, std::size_t size) noexcept {
		return socket_send_awaitable(*this, buffer, size);
	}

	[[nodiscard]] inline socket_send_awaitable socket::send(const void* buffer, std::size_t size,
															std::error_code& ec) noexcept {
		return socket_send_awaitable(*this, buffer, size, &ec);
	}

	[[nodiscard]] inline socket_recv_awaitable socket::recv(void* buffer, std::size_t size) noexcept {
		return socket_recv_awaitable(*this, buffer, size);
	}

	[[nodiscard]] inline socket_recv_awaitable socket::recv(void* buffer, std::size_t size,
															std::error_code& ec) noexcept {
		return socket_recv_awaitable(*this, buffer, size, &ec);
	}

	[[nodiscard]] inline socket_recv_exact_awaitable socket::recv_exact(void* buffer, std::size_t size) noexcept {
		return socket_recv_exact_awaitable(*this, buffer, size);
	}

	[[nodiscard]] inline socket_recv_exact_awaitable socket::recv_exact(void* buffer, std::size_t size,
																		std::error_code& ec) noexcept {
		return socket_recv_exact_awaitable(*this, buffer, size, &ec);
	}

	[[nodiscard]] inline socket_send_to_awaitable socket::send_to(const void* buffer, std::size_t size,
																  const endpoint& dst_ep) noexcept {
		return socket_send_to_awaitable(*this, buffer, size, dst_ep);
	}

	[[nodiscard]] inline socket_send_to_awaitable
	socket::send_to(const void* buffer, std::size_t size, const endpoint& dst_ep, std::error_code& ec) noexcept {
		return socket_send_to_awaitable(*this, buffer, size, dst_ep, &ec);
	}

	[[nodiscard]] inline socket_recv_from_awaitable socket::recv_from(void* buffer, std::size_t size) noexcept {
		return socket_recv_from_awaitable(*this, buffer, size);
	}

	[[nodiscard]] inline socket_recv_from_awaitable socket::recv_from(void* buffer, std::size_t size,
																	  std::error_code& ec) noexcept {
		return socket_recv_from_awaitable(*this, buffer, size, &ec);
	}

	[[nodiscard]] inline socket_connect_cancellable_awaitable socket::connect(const endpoint& ep,
																			  asyncpp::stop_token st) noexcept {
		return socket_connect_cancellable_awaitable(std::move(st), *this, ep);
	}

	[[nodiscard]] inline socket_connect_cancellable_awaitable
	socket::connect(const endpoint& ep, asyncpp::stop_token st, std::error_code& ec) noexcept {
		return socket_connect_cancellable_awaitable(std::move(st), *this, ep, &ec);
	}

	[[nodiscard]] inline socket_accept_cancellable_awaitable socket::accept(asyncpp::stop_token st) noexcept {
		return socket_accept_cancellable_awaitable(std::move(st), *this);
	}

	[[nodiscard]] inline socket_accept_error_code_cancellable_awaitable socket::accept(asyncpp::stop_token st,
																					   std::error_code& ec) noexcept {
		return socket_accept_error_code_cancellable_awaitable(std::move(st), *this, ec);
	}

	[[nodiscard]] inline socket_send_cancellable_awaitable socket::send(const void* buffer, std::size_t size,
																		asyncpp::stop_token st) noexcept {
		return socket_send_cancellable_awaitable(std::move(st), *this, buffer, size);
	}

	[[nodiscard]] inline socket_send_cancellable_awaitable
	socket::send(const void* buffer, std::size_t size, asyncpp::stop_token st, std::error_code& ec) noexcept {
		return socket_send_cancellable_awaitable(std::move(st), *this, buffer, size, &ec);
	}

	[[nodiscard]] inline socket_recv_cancellable_awaitable socket::recv(void* buffer, std::size_t size,
																		asyncpp::stop_token st) noexcept {
		return socket_recv_cancellable_awaitable(std::move(st), *this, buffer, size);
	}

	[[nodiscard]] inline socket_recv_cancellable_awaitable
	socket::recv(void* buffer, std::size_t size, asyncpp::stop_token st, std::error_code& ec) noexcept {
		return socket_recv_cancellable_awaitable(std::move(st), *this, buffer, size, &ec);
	}

	[[nodiscard]] inline socket_recv_exact_cancellable_awaitable socket::recv_exact(void* buffer, std::size_t size,
																					asyncpp::stop_token st) noexcept {
		return socket_recv_exact_cancellable_awaitable(std::move(st), *this, buffer, size);
	}

	[[nodiscard]] inline socket_recv_exact_cancellable_awaitable
	socket::recv_exact(void* buffer, std::size_t size, asyncpp::stop_token st, std::error_code& ec) noexcept {
		return socket_recv_exact_cancellable_awaitable(std::move(st), *this, buffer, size, &ec);
	}

	[[nodiscard]] inline socket_send_to_cancellable_awaitable
	socket::send_to(const void* buffer, std::size_t size, const endpoint& dst_ep, asyncpp::stop_token st) noexcept {
		return socket_send_to_cancellable_awaitable(std::move(st), *this, buffer, size, dst_ep);
	}

	[[nodiscard]] inline socket_send_to_cancellable_awaitable socket::send_to(const void* buffer, std::size_t size,
																			  const endpoint& dst_ep,
																			  asyncpp::stop_token st,
																			  std::error_code& ec) noexcept {
		return socket_send_to_cancellable_awaitable(std::move(st), *this, buffer, size, dst_ep, &ec);
	}

	[[nodiscard]] inline socket_recv_from_cancellable_awaitable socket::recv_from(void* buffer, std::size_t size,
																				  asyncpp::stop_token st) noexcept {
		return socket_recv_from_cancellable_awaitable(std::move(st), *this, buffer, size);
	}

	[[nodiscard]] inline socket_recv_from_cancellable_awaitable
	socket::recv_from(void* buffer, std::size_t size, asyncpp::stop_token st, std::error_code& ec) noexcept {
		return socket_recv_from_cancellable_awaitable(std::move(st), *this, buffer, size, &ec);
	}

	inline bool socket_connect_awaitable::await_suspend(coroutine_handle<> hdl) {
		m_completion.callback = [](void* ptr) { coroutine_handle<>::from_address(ptr).resume(); };
		m_completion.userdata = hdl.address();
		return !m_socket.service().engine()->enqueue_connect(m_socket.native_handle(), m_ep, &m_completion);
	}

	inline void socket_connect_awaitable::await_resume() {
		if (!m_completion.result) return;
		if (m_ec == nullptr) throw std::system_error(m_completion.result);
		*m_ec = m_completion.result;
	}

	inline bool socket_send_awaitable::await_suspend(coroutine_handle<> hdl) {
		m_completion.callback = [](void* ptr) { coroutine_handle<>::from_address(ptr).resume(); };
		m_completion.userdata = hdl.address();
		return !m_socket.service().engine()->enqueue_send(m_socket.native_handle(), m_buffer, m_size, &m_completion);
	}

	inline void socket_send_awaitable::await_resume() {
		if (!m_completion.result) return;
		if (m_ec == nullptr) throw std::system_error(m_completion.result);
		*m_ec = m_completion.result;
	}

	inline bool socket_recv_awaitable::await_suspend(coroutine_handle<> hdl) {
		m_completion.callback = [](void* ptr) { coroutine_handle<>::from_address(ptr).resume(); };
		m_completion.userdata = hdl.address();
		return !m_socket.service().engine()->enqueue_recv(m_socket.native_handle(), m_buffer, m_size, &m_completion);
	}

	inline size_t socket_recv_awaitable::await_resume() {
		if (!m_completion.result) return m_completion.result_size;
		if (m_ec == nullptr) throw std::system_error(m_completion.result);
		*m_ec = m_completion.result;
		return 0;
	}

	inline bool socket_recv_exact_awaitable::await_suspend(asyncpp::coroutine_handle<> hdl) {
		m_completion.callback = [](void* ptr) {
			auto that = static_cast<socket_recv_exact_awaitable*>(ptr);
			auto engine = that->m_socket.service().engine();
			do {
				if (that->m_completion.result_size == 0) {
					that->m_completion.result = std::make_error_code(std::errc::not_connected);
				}
				if (that->m_completion.result) {
					that->m_handle.resume();
					break;
				}
				that->m_buffer += that->m_completion.result_size;
				that->m_remaining -= that->m_completion.result_size;
				if (that->m_remaining == 0) {
					that->m_handle.resume();
					break;
				}
			} while (engine->enqueue_recv(that->m_socket.native_handle(), that->m_buffer, that->m_remaining,
										  &that->m_completion));
		};
		m_completion.userdata = this;
		m_handle = hdl;
		auto engine = m_socket.service().engine();
		while (engine->enqueue_recv(m_socket.native_handle(), m_buffer, m_remaining, &m_completion)) {
			if (m_completion.result) return false;
			m_buffer += m_completion.result_size;
			m_remaining -= m_completion.result_size;
			if (m_remaining == 0) return false;
		}
		return true;
	}

	inline size_t socket_recv_exact_awaitable::await_resume() {
		if (!m_completion.result) return m_size - m_remaining;
		if (m_ec == nullptr) throw std::system_error(m_completion.result);
		*m_ec = m_completion.result;
		return m_size - m_remaining;
	}

	inline bool socket_accept_awaitable::await_suspend(coroutine_handle<> hdl) {
		m_completion.callback = [](void* ptr) { coroutine_handle<>::from_address(ptr).resume(); };
		m_completion.userdata = hdl.address();
		return !m_socket.service().engine()->enqueue_accept(m_socket.native_handle(), &m_completion);
	}

	inline socket socket_accept_awaitable::await_resume() {
		if (!m_completion.result) return socket::from_fd(m_socket.service(), m_completion.result_handle);
		throw std::system_error(m_completion.result);
	}

	inline bool socket_accept_error_code_awaitable::await_suspend(coroutine_handle<> hdl) {
		m_completion.callback = [](void* ptr) { coroutine_handle<>::from_address(ptr).resume(); };
		m_completion.userdata = hdl.address();
		return !m_socket.service().engine()->enqueue_accept(m_socket.native_handle(), &m_completion);
	}

	inline std::optional<socket> socket_accept_error_code_awaitable::await_resume() {
		if (!m_completion.result) return socket::from_fd(m_socket.service(), m_completion.result_handle);
		m_ec = m_completion.result;
		return std::nullopt;
	}

	inline bool socket_send_to_awaitable::await_suspend(coroutine_handle<> hdl) {
		m_completion.callback = [](void* ptr) { coroutine_handle<>::from_address(ptr).resume(); };
		m_completion.userdata = hdl.address();
		return !m_socket.service().engine()->enqueue_send_to(m_socket.native_handle(), m_buffer, m_size, m_destination,
															 &m_completion);
	}

	inline size_t socket_send_to_awaitable::await_resume() {
		if (!m_completion.result) return m_completion.result_size;
		if (m_ec == nullptr) throw std::system_error(m_completion.result);
		*m_ec = m_completion.result;
		return 0;
	}

	inline bool socket_recv_from_awaitable::await_suspend(coroutine_handle<> hdl) {
		m_completion.callback = [](void* ptr) { coroutine_handle<>::from_address(ptr).resume(); };
		m_completion.userdata = hdl.address();
		return !m_socket.service().engine()->enqueue_recv_from(m_socket.native_handle(), m_buffer, m_size, &m_source,
															   &m_completion);
	}

	inline std::pair<size_t, endpoint> socket_recv_from_awaitable::await_resume() {
		if (!m_completion.result) return {m_completion.result_size, m_source};
		if (m_ec == nullptr) throw std::system_error(m_completion.result);
		*m_ec = m_completion.result;
		return {};
	}

	template<typename FN>
		requires(std::is_invocable_v<FN, std::error_code>)
	inline void socket::connect(const endpoint& ep, FN&& cb, asyncpp::stop_token st) {
		struct data : detail::io_engine::completion_data {
			FN real_cb;
			asyncpp::stop_callback<detail::cancel_io_stop_callback> stop_cb;

			data(FN&& cb, asyncpp::stop_token st, detail::io_engine* engine)
				: completion_data{&handle, this}, real_cb(std::move(cb)),
				  stop_cb(std::move(st), detail::cancel_io_stop_callback{this, engine}) {}

			static void handle(void* ptr) {
				auto that = static_cast<data*>(ptr);
				that->real_cb(that->result);
				delete that;
			};
		};
		auto info = new data(std::move(cb), std::move(st), service().engine());
		if (service().engine()->enqueue_connect(native_handle(), ep, info)) { data::handle(info); }
	}

	template<typename FN>
		requires(std::is_invocable_v<FN, std::variant<socket, std::error_code>>)
	inline void socket::accept(FN&& cb, asyncpp::stop_token st) {
		struct data : detail::io_engine::completion_data {
			FN real_cb;
			io_service& service;
			asyncpp::stop_callback<detail::cancel_io_stop_callback> stop_cb;

			data(FN&& cb, asyncpp::stop_token st, io_service& s)
				: completion_data{&handle, this}, real_cb(std::move(cb)), service(s),
				  stop_cb(std::move(st), detail::cancel_io_stop_callback{this, s.engine()}) {}

			static void handle(void* ptr) {
				auto that = static_cast<data*>(ptr);
				if (that->result)
					that->real_cb(that->result);
				else
					that->real_cb(socket::from_fd(that->service, that->result_handle));

				delete that;
			};
		};
		auto info = new data(std::move(cb), std::move(st), service());
		if (service().engine()->enqueue_accept(native_handle(), info)) { data::handle(info); }
	}

	template<typename FN>
		requires(std::is_invocable_v<FN, size_t, std::error_code>)
	inline void socket::send(const void* buffer, std::size_t size, FN&& cb, asyncpp::stop_token st) {
		struct data : detail::io_engine::completion_data {
			FN real_cb;
			asyncpp::stop_callback<detail::cancel_io_stop_callback> stop_cb;

			data(FN&& cb, asyncpp::stop_token st, detail::io_engine* engine)
				: completion_data{&handle, this}, real_cb(std::move(cb)),
				  stop_cb(std::move(st), detail::cancel_io_stop_callback{this, engine}) {}

			static void handle(void* ptr) {
				auto that = static_cast<data*>(ptr);
				if (that->result)
					that->real_cb(0, that->result);
				else
					that->real_cb(that->result_size, {});

				delete that;
			};
		};
		auto info = new data(std::move(cb), std::move(st), service().engine());
		if (service().engine()->enqueue_send(native_handle(), buffer, size, info)) { data::handle(info); }
	}

	template<typename FN>
		requires(std::is_invocable_v<FN, size_t, std::error_code>)
	inline void socket::recv(void* buffer, std::size_t size, FN&& cb, asyncpp::stop_token st) {
		struct data : detail::io_engine::completion_data {
			FN real_cb;
			asyncpp::stop_callback<detail::cancel_io_stop_callback> stop_cb;

			data(FN&& cb, asyncpp::stop_token st, detail::io_engine* engine)
				: completion_data{&handle, this}, real_cb(std::move(cb)),
				  stop_cb(std::move(st), detail::cancel_io_stop_callback{this, engine}) {}

			static void handle(void* ptr) {
				auto that = static_cast<data*>(ptr);
				if (that->result)
					that->real_cb(0, that->result);
				else
					that->real_cb(that->result_size, {});

				delete that;
			};
		};
		auto info = new data(std::move(cb), std::move(st), service().engine());
		if (service().engine()->enqueue_recv(native_handle(), buffer, size, info)) { data::handle(info); }
	}

	template<typename FN>
		requires(std::is_invocable_v<FN, size_t, std::error_code>)
	inline void socket::send_to(const void* buffer, std::size_t size, const endpoint& dst_ep, FN&& cb,
								asyncpp::stop_token st) {
		struct data : detail::io_engine::completion_data {
			FN real_cb;
			asyncpp::stop_callback<detail::cancel_io_stop_callback> stop_cb;

			data(FN&& cb, asyncpp::stop_token st, detail::io_engine* engine)
				: completion_data{&handle, this}, real_cb(std::move(cb)),
				  stop_cb(std::move(st), detail::cancel_io_stop_callback{this, engine}) {}

			static void handle(void* ptr) {
				auto that = static_cast<data*>(ptr);
				if (that->result)
					that->real_cb(0, that->result);
				else
					that->real_cb(that->result_size, {});

				delete that;
			};
		};
		auto info = new data(std::move(cb), std::move(st), service().engine());
		if (service().engine()->enqueue_send_to(native_handle(), buffer, size, dst_ep, info)) { data::handle(info); }
	}

	template<typename FN>
		requires(std::is_invocable_v<FN, size_t, endpoint, std::error_code>)
	inline void socket::recv_from(void* buffer, std::size_t size, FN&& cb, asyncpp::stop_token st) {
		struct data : detail::io_engine::completion_data {
			FN real_cb;
			endpoint source;
			asyncpp::stop_callback<detail::cancel_io_stop_callback> stop_cb;

			data(FN&& cb, asyncpp::stop_token st, detail::io_engine* engine)
				: completion_data{&handle, this}, real_cb(std::move(cb)),
				  stop_cb(std::move(st), detail::cancel_io_stop_callback{this, engine}) {}

			static void handle(void* ptr) {
				auto that = static_cast<data*>(ptr);
				if (that->result)
					that->real_cb(0, {}, that->result);
				else
					that->real_cb(that->result_size, that->source, {});

				delete that;
			};
		};
		auto info = new data(std::move(cb), std::move(st), service().engine());
		if (service().engine()->enqueue_recv_from(native_handle(), buffer, size, &info->source, info)) {
			data::handle(info);
		}
	}

} // namespace asyncpp::io
