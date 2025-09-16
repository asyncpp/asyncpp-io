#include <asyncpp/io/detail/io_engine.h>

#ifndef _WIN32
namespace asyncpp::io::detail {
	std::unique_ptr<io_engine> create_io_engine_iocp() { return nullptr; }
} // namespace asyncpp::io::detail
#else

#include <cstring>
#include <mutex>
#include <vector>

#include <WinSock2.h>
#include <cassert>
#include <ioapiset.h>
#include <ws2tcpip.h> // This needs be included before the ones below, otherwise INETADDR_SETANY breaks

#include <mstcpip.h>
#include <mswsock.h>
#include <ws2ipdef.h>

extern "C" {
typedef struct _IO_STATUS_BLOCK {
	union {
		LONG Status;
		PVOID Pointer;
	};
	ULONG Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef enum _FILE_INFORMATION_CLASS {
	FileReplaceCompletionInformation = 61
} FILE_INFORMATION_CLASS,
	*PFILE_INFORMATION_CLASS;

typedef struct _FILE_COMPLETION_INFORMATION {
	HANDLE Port;
	PVOID Key;
} FILE_COMPLETION_INFORMATION, *PFILE_COMPLETION_INFORMATION;

NTSYSAPI NTSTATUS NTAPI NtSetInformationFile(IN HANDLE FileHandle, OUT PIO_STATUS_BLOCK IoStatusBlock,
											 IN PVOID FileInformation, IN ULONG Length,
											 IN FILE_INFORMATION_CLASS FileInformationClass);
}

namespace asyncpp::io::detail {

	struct iocp_engine_state {
		WSAOVERLAPPED overlapped;
		HANDLE handle = io_engine::invalid_file_handle;
		SOCKET accept_sock = INVALID_SOCKET;
		union {
			std::array<uint8_t, (sizeof(sockaddr_in6) + 16) * 2> accept_buffer{};
			struct {
				endpoint* recv_from_ep;
				sockaddr_storage recv_from_sa;
				int recv_from_sa_len;
			};
		};
	};
	static_assert(offsetof(iocp_engine_state, overlapped) == 0,
				  "Code assumes that overlapped is at the start of engine_data");

	class io_engine_iocp : public io_engine {
	public:
		io_engine_iocp();
		io_engine_iocp(const io_engine_iocp&) = delete;
		io_engine_iocp& operator=(const io_engine_iocp&) = delete;
		~io_engine_iocp();

		std::string_view name() const noexcept override;

		size_t run(bool nowait) override;
		void wake() override;

		socket_handle_t socket_create(address_type domain, socket_type type) override;
		std::pair<socket_handle_t, socket_handle_t> socket_create_connected_pair(address_type domain,
																				 socket_type type) override;
		void socket_register(socket_handle_t socket) override;
		void socket_release(socket_handle_t socket) override;
		void socket_close(socket_handle_t socket) override;
		void socket_bind(socket_handle_t socket, endpoint ep) override;
		void socket_listen(socket_handle_t socket, size_t backlog) override;
		endpoint socket_local_endpoint(socket_handle_t socket) override;
		endpoint socket_remote_endpoint(socket_handle_t socket) override;
		void socket_enable_broadcast(socket_handle_t socket, bool enable) override;
		void socket_multicast_join(socket_handle_t socket, address group, address interface) override;
		void socket_multicast_drop(socket_handle_t socket, address group, address interface) override;
		void socket_multicast_set_send_interface(socket_handle_t socket, address interface) override;
		void socket_multicast_set_ttl(socket_handle_t socket, size_t ttl) override;
		void socket_multicast_set_loopback(socket_handle_t socket, bool enabled) override;
		void socket_shutdown(socket_handle_t socket, bool receive, bool send) override;
		bool enqueue_connect(socket_handle_t socket, endpoint ep, completion_data* cd) override;
		bool enqueue_accept(socket_handle_t socket, completion_data* cd) override;
		bool enqueue_recv(socket_handle_t socket, void* buf, size_t len, completion_data* cd) override;
		bool enqueue_send(socket_handle_t socket, const void* buf, size_t len, completion_data* cd) override;
		bool enqueue_recv_from(socket_handle_t socket, void* buf, size_t len, endpoint* source,
							   completion_data* cd) override;
		bool enqueue_send_to(socket_handle_t socket, const void* buf, size_t len, endpoint dst,
							 completion_data* cd) override;

		file_handle_t file_open(const char* filename, std::ios_base::openmode mode) override;
		void file_register(file_handle_t fd) override;
		void file_release(file_handle_t fd) override;
		void file_close(file_handle_t fd) override;
		uint64_t file_size(file_handle_t fd) override;
		bool enqueue_readv(file_handle_t fd, void* buf, size_t len, uint64_t offset, completion_data* cd) override;
		bool enqueue_writev(file_handle_t fd, const void* buf, size_t len, uint64_t offset,
							completion_data* cd) override;
		bool enqueue_fsync(file_handle_t fd, fsync_flags flags, completion_data* cd) override;

		bool cancel(completion_data* cd) override;

	private:
		HANDLE m_completion_port = INVALID_HANDLE_VALUE;
		std::atomic<size_t> m_inflight_count{};

		address_type get_handle_type(socket_handle_t socket);
	};

	std::unique_ptr<io_engine> create_io_engine_iocp() { return std::make_unique<io_engine_iocp>(); }

	io_engine_iocp::io_engine_iocp() {
		WSADATA wsaData;
		if (int res = WSAStartup(MAKEWORD(2, 2), &wsaData); res != 0)
			throw std::runtime_error("failed to initialize WSA");
		m_completion_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
		if (m_completion_port == NULL) {
			WSACleanup();
			throw std::runtime_error("failed to create completion port");
		}
	}

	io_engine_iocp::~io_engine_iocp() {
		if (m_completion_port != INVALID_HANDLE_VALUE) CloseHandle(m_completion_port);
		WSACleanup();
	}

	std::string_view io_engine_iocp::name() const noexcept { return "iocp"; }

	size_t io_engine_iocp::run(bool nowait) {
		DWORD timeout = 0;
		if (!nowait) timeout = 10000;

		DWORD num_transfered;
		ULONG_PTR key;
		LPOVERLAPPED overlapped;
		if (GetQueuedCompletionStatus(m_completion_port, &num_transfered, &key, &overlapped, timeout) == FALSE &&
			overlapped == nullptr) {
			return m_inflight_count;
		}
		if (key == 1) return m_inflight_count;
		m_inflight_count.fetch_sub(1, std::memory_order::relaxed);
		auto state = reinterpret_cast<iocp_engine_state*>(overlapped);
		auto cd = reinterpret_cast<completion_data*>(overlapped);

		DWORD num_bytes, flags;
		auto res = GetOverlappedResult(state->handle, &state->overlapped, &num_bytes, FALSE);
		if (res == TRUE) {
			cd->result.clear();
			if (state->accept_sock != INVALID_SOCKET) {
				if (setsockopt(state->accept_sock, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
							   reinterpret_cast<const char*>(&state->handle), sizeof(state->handle)) == SOCKET_ERROR) {
					closesocket(state->accept_sock);
					cd->result = std::error_code(GetLastError(), std::system_category());
					return true;
				}
				cd->result_handle = state->accept_sock;
			} else {
				cd->result_size = num_bytes;
				if (state->recv_from_ep != nullptr) {
					*state->recv_from_ep = endpoint(state->recv_from_sa, state->recv_from_sa_len);
				}
			}
		} else {
			auto err = GetLastError();
			if (state->accept_sock != INVALID_SOCKET) closesocket(state->accept_sock);
			switch (err) {
			case WSANOTINITIALISED:
			case WSAENETDOWN:
			case WSAENOTSOCK:
			case WSA_INVALID_HANDLE:
			case WSA_INVALID_PARAMETER:
			case WSA_IO_INCOMPLETE:
			case WSAEFAULT: throw std::system_error(err, std::system_category(), "GetOverlappedResult failed");
			default: cd->result = std::error_code(err, std::system_category());
			}
		}

		if (cd->callback) cd->callback(cd->userdata);

		return m_inflight_count;
	}

	void io_engine_iocp::wake() {
		if (PostQueuedCompletionStatus(m_completion_port, 0, 1, NULL) == FALSE)
			throw std::runtime_error("failed to wake cq");
	}

	io_engine::socket_handle_t io_engine_iocp::socket_create(address_type domain, socket_type type) {
		int afdomain = -1;
		switch (domain) {
		case address_type::ipv4: afdomain = AF_INET; break;
		case address_type::ipv6: afdomain = AF_INET6; break;
		}
		int stype = -1;
		switch (type) {
		case socket_type::stream: stype = SOCK_STREAM; break;
		case socket_type::dgram: stype = SOCK_DGRAM; break;
		case socket_type::seqpacket: stype = SOCK_SEQPACKET; break;
		}
		if (afdomain == -1) throw std::system_error(std::make_error_code(std::errc::not_supported));
		if (stype == -1) throw std::system_error(std::make_error_code(std::errc::not_supported));
		auto fd = WSASocket(afdomain, stype, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
		if (fd == INVALID_SOCKET) throw std::system_error(WSAGetLastError(), std::system_category(), "WSASocket");
		u_long mode = 1;
		if (ioctlsocket(fd, FIONBIO, &mode) == SOCKET_ERROR) {
			closesocket(fd);
			throw std::system_error(WSAGetLastError(), std::system_category(), "ioctlsocket failed");
		}
		if (domain == address_type::ipv6) {
			DWORD opt = 0;
			if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&opt), sizeof(opt)) ==
				SOCKET_ERROR) {
				closesocket(fd);
				throw std::system_error(WSAGetLastError(), std::system_category(), "setsockopt failed");
			}
		}
		// Add socket to completion port
		if (CreateIoCompletionPort((HANDLE)fd, m_completion_port, 0, 0) == NULL) {
			closesocket(fd);
			throw std::system_error(GetLastError(), std::system_category(), "CreateIoCompletionPort failed");
		}
		return fd;
	}

	std::pair<io_engine::socket_handle_t, io_engine::socket_handle_t>
	io_engine_iocp::socket_create_connected_pair(address_type domain, socket_type type) {
		if (type != socket_type::stream)
			throw std::system_error(std::make_error_code(std::errc::function_not_supported), "unsupported socket type");

		auto close_and_throw = [](const char* name, auto... sockets) {
			auto err = WSAGetLastError();
			(::closesocket(sockets), ...);
			throw std::system_error(err, std::system_category(), name);
		};

		auto listener = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED);
		if (listener == INVALID_SOCKET) close_and_throw("WSASocket");

		int reuse = 1;
		if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, (socklen_t)sizeof(reuse)) == -1)
			close_and_throw("setsockopt", listener);

		struct sockaddr_in inaddr{};
		inaddr.sin_family = AF_INET;
		inaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		if (bind(listener, reinterpret_cast<sockaddr*>(&inaddr), sizeof(inaddr)) == SOCKET_ERROR)
			close_and_throw("bind", listener);

		inaddr = {};
		int addrlen = sizeof(inaddr);
		if (getsockname(listener, reinterpret_cast<sockaddr*>(&inaddr), &addrlen) == SOCKET_ERROR)
			close_and_throw("getsockname", listener);
		// win32 getsockname may only set the port number
		inaddr.sin_family = AF_INET;
		inaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

		if (listen(listener, 1) == SOCKET_ERROR) close_and_throw("listen", listener);

		auto sock0 = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
		if (sock0 == INVALID_SOCKET) close_and_throw("WSASocket", listener);
		if (connect(sock0, reinterpret_cast<sockaddr*>(&inaddr), sizeof(inaddr)) == SOCKET_ERROR)
			close_and_throw("connect", listener, sock0);

		auto sock1 = accept(listener, NULL, NULL);
		if (sock1 == INVALID_SOCKET) close_and_throw("accept", listener, sock0);

		closesocket(listener);

		u_long mode = 1;
		if (ioctlsocket(sock0, FIONBIO, &mode) == SOCKET_ERROR) close_and_throw("ioctlsocket", listener, sock0, sock1);
		mode = 1;
		if (ioctlsocket(sock1, FIONBIO, &mode) == SOCKET_ERROR) close_and_throw("ioctlsocket", listener, sock0, sock1);

		// Add socket to completion port
		if (CreateIoCompletionPort((HANDLE)sock0, m_completion_port, 0, 0) == NULL)
			close_and_throw("CreateIoCompletionPort", listener, sock0, sock1);
		if (CreateIoCompletionPort((HANDLE)sock1, m_completion_port, 0, 0) == NULL)
			close_and_throw("CreateIoCompletionPort", listener, sock0, sock1);

		return {sock0, sock1};
	}

	void io_engine_iocp::socket_register(socket_handle_t socket) {
		// Make socket non blocking (do we even need to do this ?)
		u_long mode = 1;
		if (ioctlsocket(socket, FIONBIO, &mode) == SOCKET_ERROR)
			throw std::system_error(WSAGetLastError(), std::system_category(), "ioctlsocket failed");
		// Add socket to completion port
		if (CreateIoCompletionPort((HANDLE)socket, m_completion_port, 0, 0) == NULL)
			throw std::system_error(GetLastError(), std::system_category(), "CreateIoCompletionPort failed");
	}

	void io_engine_iocp::socket_release(socket_handle_t socket) {
		// Unhook the socket from our completion port
		// Note: Dark magic ahead
		_IO_STATUS_BLOCK status{};
		FILE_COMPLETION_INFORMATION info{0, NULL};
		if (NtSetInformationFile((HANDLE)socket, &status, &info, sizeof(info), FileReplaceCompletionInformation) < 0)
			throw std::system_error(std::make_error_code(std::errc::io_error), "NtSetInformationFile failed");
	}

	void io_engine_iocp::socket_close(socket_handle_t socket) {
		if (socket != INVALID_SOCKET) closesocket(socket);
	}

	void io_engine_iocp::socket_bind(socket_handle_t socket, endpoint ep) {
		auto sa = ep.to_sockaddr();
		auto res = ::bind(socket, reinterpret_cast<sockaddr*>(&sa.first), sa.second);
		if (res < 0) throw std::system_error(WSAGetLastError(), std::system_category());
	}

	void io_engine_iocp::socket_listen(socket_handle_t socket, size_t backlog) {
		if (backlog == 0) backlog = 20;
		auto res = ::listen(socket, backlog);
		if (res == SOCKET_ERROR) throw std::system_error(WSAGetLastError(), std::system_category());
	}

	endpoint io_engine_iocp::socket_local_endpoint(socket_handle_t socket) {
		sockaddr_storage sa;
		int sa_size = sizeof(sa);
		auto res = getsockname(socket, reinterpret_cast<sockaddr*>(&sa), &sa_size);
		if (res >= 0) return endpoint(sa, sa_size);
		throw std::system_error(WSAGetLastError(), std::system_category());
	}

	endpoint io_engine_iocp::socket_remote_endpoint(socket_handle_t socket) {
		sockaddr_storage sa;
		int sa_size = sizeof(sa);
		auto res = getpeername(socket, reinterpret_cast<sockaddr*>(&sa), &sa_size);
		if (res >= 0)
			return endpoint(sa, sa_size);
		else if (res == SOCKET_ERROR && WSAGetLastError() != WSAENOTCONN)
			throw std::system_error(WSAGetLastError(), std::system_category());
		return {};
	}

	void io_engine_iocp::socket_enable_broadcast(socket_handle_t socket, bool enable) {
		BOOL opt = enable ? TRUE : FALSE;
		auto res = setsockopt(socket, SOL_SOCKET, SO_BROADCAST, reinterpret_cast<const char*>(&opt), sizeof(opt));
		if (res == SOCKET_ERROR) throw std::system_error(WSAGetLastError(), std::system_category());
	}

	void io_engine_iocp::socket_multicast_join(socket_handle_t socket, address group, address interface) {
		if (group.type() != interface.type())
			throw std::system_error(std::make_error_code(std::errc::invalid_argument),
									"group and interface need to be of the same type");
		if (group.is_ipv4()) {
			struct ip_mreq mc_req{};
			mc_req.imr_multiaddr = group.ipv4().to_sockaddr_in().first.sin_addr;
			mc_req.imr_interface = interface.ipv4().to_sockaddr_in().first.sin_addr;
			auto res = setsockopt(socket, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mc_req, sizeof(mc_req));
			if (res < 0) throw std::system_error(WSAGetLastError(), std::system_category(), "setsockopt failed");
		} else if (group.is_ipv6()) {
			struct ipv6_mreq mc_req{};
			mc_req.ipv6mr_multiaddr = group.ipv6().to_sockaddr_in6().first.sin6_addr;
			mc_req.ipv6mr_interface = interface.ipv6().to_sockaddr_in6().first.sin6_scope_id;
			auto res = setsockopt(socket, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mc_req, sizeof(mc_req));
			if (res < 0) throw std::system_error(WSAGetLastError(), std::system_category(), "setsockopt failed");
		} else {
			throw std::system_error(std::make_error_code(std::errc::not_supported),
									"multicast is only supported on IPv4/IPv6");
		}
	}

	void io_engine_iocp::socket_multicast_drop(socket_handle_t socket, address group, address interface) {
		if (group.type() != interface.type())
			throw std::system_error(std::make_error_code(std::errc::invalid_argument),
									"group and interface need to be of the same type");
		if (group.is_ipv4()) {
			struct ip_mreq mc_req{};
			mc_req.imr_multiaddr = group.ipv4().to_sockaddr_in().first.sin_addr;
			mc_req.imr_interface = interface.ipv4().to_sockaddr_in().first.sin_addr;
			auto res = setsockopt(socket, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mc_req, sizeof(mc_req));
			if (res < 0) throw std::system_error(WSAGetLastError(), std::system_category(), "setsockopt failed");
		} else if (group.is_ipv6()) {
			struct ipv6_mreq mc_req{};
			mc_req.ipv6mr_multiaddr = group.ipv6().to_sockaddr_in6().first.sin6_addr;
			mc_req.ipv6mr_interface = interface.ipv6().to_sockaddr_in6().first.sin6_scope_id;
			auto res = setsockopt(socket, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, &mc_req, sizeof(mc_req));
			if (res < 0) throw std::system_error(WSAGetLastError(), std::system_category(), "setsockopt failed");
		} else {
			throw std::system_error(std::make_error_code(std::errc::not_supported),
									"multicast is only supported on IPv4/IPv6");
		}
	}

	void io_engine_iocp::socket_multicast_set_send_interface(socket_handle_t socket, address interface) {
		if (interface.is_ipv4()) {
			auto addr = interface.ipv4().to_sockaddr_in().first.sin_addr.s_addr;
			auto res = setsockopt(socket, IPPROTO_IP, IP_MULTICAST_IF, reinterpret_cast<char*>(&addr), sizeof(addr));
			if (res < 0) throw std::system_error(WSAGetLastError(), std::system_category(), "setsockopt failed");
		} else if (interface.is_ipv6()) {
			auto scope = interface.ipv6().to_sockaddr_in6().first.sin6_scope_id;
			auto res =
				setsockopt(socket, IPPROTO_IPV6, IPV6_MULTICAST_IF, reinterpret_cast<char*>(&scope), sizeof(scope));
			if (res < 0) throw std::system_error(WSAGetLastError(), std::system_category(), "setsockopt failed");
		} else {
			throw std::system_error(std::make_error_code(std::errc::not_supported),
									"multicast is only supported on IPv4/IPv6");
		}
	}

	void io_engine_iocp::socket_multicast_set_ttl(socket_handle_t socket, size_t ttl) {
		auto type = get_handle_type(socket);
		if (ttl > std::numeric_limits<int>::max()) throw std::invalid_argument("ttl value out of range");
		int ittl = ttl;
		if (type == address_type::ipv4) {
			auto res = setsockopt(socket, IPPROTO_IP, IP_MULTICAST_TTL, reinterpret_cast<char*>(&ittl), sizeof(ittl));
			if (res < 0) throw std::system_error(WSAGetLastError(), std::system_category(), "setsockopt failed");
		} else if (type == address_type::ipv6) {
			auto res =
				setsockopt(socket, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, reinterpret_cast<char*>(&ittl), sizeof(ittl));
			if (res < 0) throw std::system_error(WSAGetLastError(), std::system_category(), "setsockopt failed");
		} else {
			throw std::system_error(std::make_error_code(std::errc::not_supported),
									"multicast is only supported on IPv4/IPv6");
		}
	}

	void io_engine_iocp::socket_multicast_set_loopback(socket_handle_t socket, bool enabled) {
		auto type = get_handle_type(socket);
		int val = enabled ? 1 : 0;
		if (type == address_type::ipv4) {
			auto res = setsockopt(socket, IPPROTO_IP, IP_MULTICAST_LOOP, reinterpret_cast<char*>(&val), sizeof(val));
			if (res < 0) throw std::system_error(WSAGetLastError(), std::system_category(), "setsockopt failed");
		} else if (type == address_type::ipv6) {
			auto res =
				setsockopt(socket, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, reinterpret_cast<char*>(&val), sizeof(val));
			if (res < 0) throw std::system_error(WSAGetLastError(), std::system_category(), "setsockopt failed");
		} else {
			throw std::system_error(std::make_error_code(std::errc::not_supported),
									"multicast is only supported on IPv4/IPv6");
		}
	}

	void io_engine_iocp::socket_shutdown(socket_handle_t socket, bool receive, bool send) {
		int mode = 0;
		if (receive && send)
			mode = SD_BOTH;
		else if (receive)
			mode = SD_RECEIVE;
		else if (send)
			mode = SD_SEND;
		else
			return;
		auto res = ::shutdown(socket, mode);
		if (res == SOCKET_ERROR && WSAGetLastError() != WSAENOTCONN)
			throw std::system_error(WSAGetLastError(), std::system_category());
	}

	bool io_engine_iocp::enqueue_connect(socket_handle_t socket, endpoint ep, completion_data* cd) {
		auto sa = ep.to_sockaddr();
		LPFN_CONNECTEX lpfnConnectex = nullptr;
		GUID b = WSAID_CONNECTEX;
		DWORD n;
		if (WSAIoctl(socket, SIO_GET_EXTENSION_FUNCTION_POINTER, &b, sizeof(b), &lpfnConnectex, sizeof(lpfnConnectex),
					 &n, NULL, NULL) == SOCKET_ERROR) {
			cd->result = std::error_code(WSAGetLastError(), std::system_category());
			return true;
		}

		// ConnectEx requires the socket to be bound
		{
			WSAPROTOCOL_INFO info{};
			int optlen = sizeof(info);
			if (getsockopt(socket, SOL_SOCKET, SO_PROTOCOL_INFO, reinterpret_cast<char*>(&info), &optlen) ==
				SOCKET_ERROR) {
				cd->result = std::error_code(WSAGetLastError(), std::system_category());
				return true;
			}
			sockaddr_storage addr{};
			addr.ss_family = info.iAddressFamily;
			INETADDR_SETANY(reinterpret_cast<sockaddr*>(&addr));
			auto res = ::bind(socket, reinterpret_cast<sockaddr*>(&addr), (int)INET_SOCKADDR_LENGTH(addr.ss_family));
			if (res < 0) {
				cd->result = std::error_code(WSAGetLastError(), std::system_category());
				return true;
			}
		}

		auto state = cd->es_init<iocp_engine_state>();
		state->handle = (HANDLE)socket;

		m_inflight_count.fetch_add(1, std::memory_order::relaxed);
		if (lpfnConnectex(socket, reinterpret_cast<const sockaddr*>(&sa.first), sa.second, nullptr, 0, nullptr,
						  &state->overlapped) == TRUE ||
			WSAGetLastError() == WSA_IO_PENDING) {
			// IOCP always pushes even if it finishes synchronously
			return false;
		} else {
			cd->result = std::error_code(WSAGetLastError(), std::system_category());
			m_inflight_count.fetch_sub(1, std::memory_order::relaxed);
			return true;
		}
	}

	bool io_engine_iocp::enqueue_accept(socket_handle_t socket, completion_data* cd) {
		auto state = cd->es_init<iocp_engine_state>();
		state->handle = (HANDLE)socket;

		// Get the socket family to create a second socket for accepting
		WSAPROTOCOL_INFO info{};
		int optlen = sizeof(info);
		if (getsockopt(socket, SOL_SOCKET, SO_PROTOCOL_INFO, reinterpret_cast<char*>(&info), &optlen) == SOCKET_ERROR) {
			cd->result = std::error_code(WSAGetLastError(), std::system_category());
			return true;
		}

		state->accept_sock = WSASocket(info.iAddressFamily, info.iSocketType, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
		if (state->accept_sock == INVALID_SOCKET) {
			cd->result = std::error_code(WSAGetLastError(), std::system_category());
			return true;
		}

		m_inflight_count.fetch_add(1, std::memory_order::relaxed);
		DWORD received;
		if (AcceptEx(socket, state->accept_sock, state->accept_buffer.data(), 0, sizeof(sockaddr_in6) + 16,
					 sizeof(sockaddr_in6) + 16, &received, &state->overlapped) == TRUE ||
			WSAGetLastError() == WSA_IO_PENDING) {
			// IOCP always pushes even if it finishes synchronously
			return false;
		} else {
			closesocket(state->accept_sock);
			cd->result = std::error_code(WSAGetLastError(), std::system_category());
			m_inflight_count.fetch_sub(1, std::memory_order::relaxed);
			return true;
		}

		return false;
	}

	bool io_engine_iocp::enqueue_recv(socket_handle_t socket, void* buf, size_t len, completion_data* cd) {
		auto state = cd->es_init<iocp_engine_state>();
		state->handle = (HANDLE)socket;

		WSABUF buffer;
		buffer.buf = static_cast<char*>(buf);
		buffer.len = len;

		m_inflight_count.fetch_add(1, std::memory_order::relaxed);
		DWORD flags = 0;
		if (WSARecv(socket, &buffer, 1, nullptr, &flags, &state->overlapped, nullptr) == 0 ||
			WSAGetLastError() == WSA_IO_PENDING) {
			// IOCP always pushes even if it finishes synchronously
			return false;
		} else {
			cd->result = std::error_code(WSAGetLastError(), std::system_category());
			m_inflight_count.fetch_sub(1, std::memory_order::relaxed);
			return true;
		}
	}

	bool io_engine_iocp::enqueue_send(socket_handle_t socket, const void* buf, size_t len, completion_data* cd) {
		auto state = cd->es_init<iocp_engine_state>();
		state->handle = (HANDLE)socket;

		WSABUF buffer;
		buffer.buf = const_cast<char*>(static_cast<const char*>(buf));
		buffer.len = len;

		m_inflight_count.fetch_add(1, std::memory_order::relaxed);
		if (WSASend(socket, &buffer, 1, nullptr, 0, &state->overlapped, nullptr) == 0 ||
			WSAGetLastError() == WSA_IO_PENDING) {
			// IOCP always pushes even if it finishes synchronously
			return false;
		} else {
			cd->result = std::error_code(WSAGetLastError(), std::system_category());
			m_inflight_count.fetch_sub(1, std::memory_order::relaxed);
			return true;
		}
	}

	bool io_engine_iocp::enqueue_recv_from(socket_handle_t socket, void* buf, size_t len, endpoint* source,
										   completion_data* cd) {
		auto state = cd->es_init<iocp_engine_state>();
		state->handle = (HANDLE)socket;
		memset(&state->recv_from_sa, 0, sizeof(state->recv_from_sa));
		state->recv_from_sa_len = sizeof(state->recv_from_sa);
		state->recv_from_ep = source;

		WSABUF buffer;
		buffer.buf = static_cast<char*>(buf);
		buffer.len = len;
		DWORD flags = 0;

		m_inflight_count.fetch_add(1, std::memory_order::relaxed);
		if (WSARecvFrom(socket, &buffer, 1, nullptr, &flags, reinterpret_cast<sockaddr*>(&state->recv_from_sa),
						&state->recv_from_sa_len, &state->overlapped, nullptr) == 0 ||
			WSAGetLastError() == WSA_IO_PENDING) {
			// IOCP always pushes even if it finishes synchronously
			return false;
		} else {
			cd->result = std::error_code(WSAGetLastError(), std::system_category());
			m_inflight_count.fetch_sub(1, std::memory_order::relaxed);
			return true;
		}
	}

	bool io_engine_iocp::enqueue_send_to(socket_handle_t socket, const void* buf, size_t len, endpoint dst,
										 completion_data* cd) {
		auto state = cd->es_init<iocp_engine_state>();
		state->handle = (HANDLE)socket;

		auto sa = dst.to_sockaddr();

		WSABUF buffer;
		buffer.buf = const_cast<char*>(static_cast<const char*>(buf));
		buffer.len = len;

		m_inflight_count.fetch_add(1, std::memory_order::relaxed);
		if (WSASendTo(socket, &buffer, 1, nullptr, 0, reinterpret_cast<const sockaddr*>(&sa.first), sa.second,
					  &state->overlapped, nullptr) == 0 ||
			WSAGetLastError() == WSA_IO_PENDING) {
			// IOCP always pushes even if it finishes synchronously
			return false;
		} else {
			cd->result = std::error_code(WSAGetLastError(), std::system_category());
			m_inflight_count.fetch_sub(1, std::memory_order::relaxed);
			return true;
		}
	}

	address_type io_engine_iocp::get_handle_type(socket_handle_t socket) {
		WSAPROTOCOL_INFO info{};
		socklen_t length = sizeof(info);
		auto res = getsockopt(socket, SOL_SOCKET, SO_PROTOCOL_INFO, &info, &length);
		if (res < 0) throw std::system_error(WSAGetLastError(), std::system_category(), "getsockopt failed");
		switch (info.iAddressFamily) {
		case AF_INET: return address_type::ipv4;
		case AF_INET6: return address_type::ipv6;
		default: throw std::logic_error("unknown socket type");
		}
	}

	io_engine::file_handle_t io_engine_iocp::file_open(const char* filename, std::ios_base::openmode mode) {
		DWORD access_mode = 0;
		if ((mode & std::ios_base::in) == std::ios_base::in) access_mode |= GENERIC_READ;
		if ((mode & (std::ios_base::out | std::ios_base::app)) != 0) access_mode |= GENERIC_WRITE;
		if ((mode & (std::ios_base::in | std::ios_base::out | std::ios_base::app)) == 0)
			throw std::invalid_argument("neither std::ios::in, nor std::ios::out was specified");
		HANDLE res = CreateFileA(filename, access_mode, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
								 OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
		if (res == INVALID_HANDLE_VALUE) throw std::system_error(GetLastError(), std::system_category());
		if ((mode & std::ios_base::trunc) == std::ios_base::trunc) {
			if (SetEndOfFile(res) == FALSE) {
				auto err = GetLastError();
				CloseHandle(res);
				throw std::system_error(err, std::system_category());
			}
		}
		if ((mode & (std::ios_base::ate | std::ios_base::app)) != 0) {
			LARGE_INTEGER pos;
			pos.QuadPart = 0;
			if (SetFilePointerEx(res, pos, nullptr, FILE_END) == FALSE) {
				auto err = GetLastError();
				CloseHandle(res);
				throw std::system_error(err, std::system_category());
			}
		}
		if (CreateIoCompletionPort(res, m_completion_port, 0, 0) == NULL) {
			auto err = GetLastError();
			CloseHandle(res);
			throw std::system_error(err, std::system_category(), "CreateIoCompletionPort failed");
		}
		return res;
	}

	void io_engine_iocp::file_register(file_handle_t fd) {
		// Add file to completion port
		if (CreateIoCompletionPort(fd, m_completion_port, 0, 0) == NULL)
			throw std::system_error(GetLastError(), std::system_category(), "CreateIoCompletionPort failed");
	}

	void io_engine_iocp::file_release(file_handle_t fd) {
		// Unhook the file from our completion port
		// Note: Dark magic ahead
		_IO_STATUS_BLOCK status{};
		FILE_COMPLETION_INFORMATION info{0, NULL};
		if (NtSetInformationFile(fd, &status, &info, sizeof(info), FileReplaceCompletionInformation) < 0)
			throw std::system_error(std::make_error_code(std::errc::io_error), "NtSetInformationFile failed");
	}

	void io_engine_iocp::file_close(file_handle_t fd) { ::CloseHandle(fd); }

	uint64_t io_engine_iocp::file_size(file_handle_t fd) {
		DWORD high;
		auto res = GetFileSize(fd, &high);
		if (res == INVALID_FILE_SIZE && GetLastError() != NO_ERROR)
			throw std::system_error(GetLastError(), std::system_category());
		return (static_cast<uint64_t>(high) << 32) + res;
	}

	bool io_engine_iocp::enqueue_readv(file_handle_t fd, void* buf, size_t len, uint64_t offset, completion_data* cd) {
		auto state = cd->es_init<iocp_engine_state>();
		state->handle = fd;
		state->overlapped.Offset = offset & 0xffffffff;
		state->overlapped.OffsetHigh = offset >> 32;

		m_inflight_count.fetch_add(1, std::memory_order::relaxed);
		if (ReadFile(fd, buf, len, nullptr, &state->overlapped) == TRUE || GetLastError() == WSA_IO_PENDING) {
			// IOCP always pushes even if it finishes synchronously
			return false;
		} else {
			cd->result = std::error_code(GetLastError(), std::system_category());
			m_inflight_count.fetch_sub(1, std::memory_order::relaxed);
			return true;
		}
	}

	bool io_engine_iocp::enqueue_writev(file_handle_t fd, const void* buf, size_t len, uint64_t offset,
										completion_data* cd) {
		auto state = cd->es_init<iocp_engine_state>();
		state->handle = fd;
		state->overlapped.Offset = offset & 0xffffffff;
		state->overlapped.OffsetHigh = offset >> 32;

		m_inflight_count.fetch_add(1, std::memory_order::relaxed);
		if (WriteFile(fd, buf, len, nullptr, &state->overlapped) == TRUE || GetLastError() == WSA_IO_PENDING) {
			// IOCP always pushes even if it finishes synchronously
			return false;
		} else {
			cd->result = std::error_code(GetLastError(), std::system_category());
			m_inflight_count.fetch_sub(1, std::memory_order::relaxed);
			return true;
		}
	}

	bool io_engine_iocp::enqueue_fsync(file_handle_t fd, fsync_flags flags, completion_data* cd) {
		// Looks like there is no async version of this
		if (FlushFileBuffers(fd) == FALSE)
			cd->result = std::error_code(GetLastError(), std::system_category());
		else
			cd->result.clear();
		return true;
	}

	bool io_engine_iocp::cancel(completion_data* cd) {
		auto state = cd->es_get<iocp_engine_state>();
		auto res = CancelIoEx(state->handle, &state->overlapped);
		return res == TRUE;
	}

} // namespace asyncpp::io::detail
#endif
