#include <asyncpp/io/detail/io_engine.h>

#ifndef _WIN32
namespace asyncpp::io::detail {
	std::unique_ptr<io_engine> create_io_engine_win32cq() { return nullptr; }
} // namespace asyncpp::io::detail
#else

#include <cstring>
#include <mutex>
#include <vector>

extern "C" {
#include <WinSock2.h>
#include <cassert>
#include <ioapiset.h>
#include <mstcpip.h>
#include <mswsock.h>
#include <ws2ipdef.h>
}

namespace asyncpp::io::detail {

	struct my_overlapped {
		WSAOVERLAPPED overlapped;
		SOCKET sock = INVALID_SOCKET;
		io_engine::completion_data* cd = nullptr;
		SOCKET accept_sock = INVALID_SOCKET;
		std::array<uint8_t, (sizeof(sockaddr_in6) + 16) * 2> accept_buffer{};
	};

	class io_engine_win32cq : public io_engine {
	public:
		io_engine_win32cq();
		io_engine_win32cq(const io_engine_win32cq&) = delete;
		io_engine_win32cq& operator=(const io_engine_win32cq&) = delete;
		~io_engine_win32cq();

		std::string_view name() const noexcept override;

		size_t run(bool nowait) override;
		void wake() override;

		socket_handle_t create_socket(address_type domain, int type) override;
		void socket_bind(socket_handle_t socket, endpoint ep) override;
		bool enqueue_connect(socket_handle_t socket, endpoint ep, completion_data* cd) override;
		bool enqueue_accept(socket_handle_t socket, completion_data* cd) override;
		bool enqueue_recv(socket_handle_t socket, void* buf, size_t len, completion_data* cd) override;
		bool enqueue_send(socket_handle_t socket, const void* buf, size_t len, completion_data* cd) override;
		bool enqueue_recv_from(socket_handle_t socket, void* buf, size_t len, endpoint* source,
							   completion_data* cd) override;
		bool enqueue_send_to(socket_handle_t socket, const void* buf, size_t len, endpoint dst,
							 completion_data* cd) override;

		bool enqueue_readv(file_handle_t fd, void* buf, size_t len, off_t offset, completion_data* cd) override;
		bool enqueue_writev(file_handle_t fd, const void* buf, size_t len, off_t offset, completion_data* cd) override;
		bool enqueue_fsync(file_handle_t fd, fsync_flags flags, completion_data* cd) override;

		bool cancel(completion_data* cd) override;

	private:
		HANDLE m_completion_port = INVALID_HANDLE_VALUE;
		std::atomic<size_t> m_inflight_count{};
	};

	std::unique_ptr<io_engine> create_io_engine_win32cq() { return std::make_unique<io_engine_win32cq>(); }

	io_engine_win32cq::io_engine_win32cq() {
		WSADATA wsaData;
		if (int res = WSAStartup(MAKEWORD(2, 2), &wsaData); res != 0)
			throw std::runtime_error("failed to initialize WSA");
		m_completion_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
		if (m_completion_port == NULL) {
			WSACleanup();
			throw std::runtime_error("failed to create completion port");
		}
	}

	io_engine_win32cq::~io_engine_win32cq() {
		if (m_completion_port != INVALID_HANDLE_VALUE) CloseHandle(m_completion_port);
		WSACleanup();
	}

	std::string_view io_engine_win32cq::name() const noexcept { return "win32cq"; }

	size_t io_engine_win32cq::run(bool nowait) {
		DWORD timeout = 0;
		if (!nowait) timeout = 10000;

		DWORD num_transfered;
		ULONG_PTR key;
		LPOVERLAPPED overlapped;
		if (GetQueuedCompletionStatus(m_completion_port, &num_transfered, &key, &overlapped, timeout) == FALSE) {
			return m_inflight_count;
		}
		if (key == 1) return m_inflight_count;
		m_inflight_count.fetch_sub(1, std::memory_order::relaxed);
		auto state = reinterpret_cast<my_overlapped*>(overlapped);
		auto cd = state->cd;
		printf("got cs %lu %llu %p %p\n", num_transfered, key, state, cd);

		DWORD num_bytes, flags;
		auto res = WSAGetOverlappedResult(state->sock, &state->overlapped, &num_bytes, FALSE, &flags);
		delete state;
		if (res == TRUE) {
			cd->result = num_bytes;
		} else {
			switch (WSAGetLastError()) {
			case WSANOTINITIALISED:
			case WSAENETDOWN:
			case WSAENOTSOCK:
			case WSA_INVALID_HANDLE:
			case WSA_INVALID_PARAMETER:
			case WSA_IO_INCOMPLETE:
			case WSAEFAULT:
				throw std::runtime_error("WSAGetOverlappedResult failed " + std::to_string(WSAGetLastError()));
			default: cd->result = -WSAGetLastError();
			}
		}

		if (cd->callback) cd->callback(cd->userdata);

		return m_inflight_count;
	}

	void io_engine_win32cq::wake() {
		if (PostQueuedCompletionStatus(m_completion_port, 0, 1, NULL) == FALSE)
			throw std::runtime_error("failed to wake cq");
	}

	io_engine::socket_handle_t io_engine_win32cq::create_socket(address_type domain, int type) {
		int afdomain = -1;
		switch (domain) {
		case address_type::ipv4: afdomain = AF_INET; break;
		case address_type::ipv6: afdomain = AF_INET6; break;
		}
		if (afdomain == -1) throw std::system_error(std::make_error_code(std::errc::not_supported));
		auto fd = WSASocket(afdomain, type, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
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

	void io_engine_win32cq::socket_bind(socket_handle_t socket, endpoint ep) {
		auto sa = ep.to_sockaddr();
		auto res = ::bind(socket, reinterpret_cast<sockaddr*>(&sa.first), sa.second);
		if (res < 0) throw std::system_error(WSAGetLastError(), std::system_category());
	}

	bool io_engine_win32cq::enqueue_connect(socket_handle_t socket, endpoint ep, completion_data* cd) {
		printf("enqueue_connect\n");
		auto sa = ep.to_sockaddr();
		LPFN_CONNECTEX lpfnConnectex = nullptr;
		GUID b = WSAID_CONNECTEX;
		DWORD n;
		WSAIoctl(socket, SIO_GET_EXTENSION_FUNCTION_POINTER, &b, sizeof(b), &lpfnConnectex, sizeof(lpfnConnectex), &n,
				 NULL, NULL);

		// ConnectEx requires the socket to be bound
		{
			WSAPROTOCOL_INFO info{};
			int optlen = sizeof(info);
			if (getsockopt(socket, SOL_SOCKET, SO_PROTOCOL_INFO, reinterpret_cast<char*>(&info), &optlen) ==
				SOCKET_ERROR)
				throw std::system_error(WSAGetLastError(), std::system_category());
			sockaddr_storage addr{};
			addr.ss_family = info.iAddressFamily;
			INETADDR_SETANY(reinterpret_cast<sockaddr*>(&addr));
			auto res = ::bind(socket, reinterpret_cast<sockaddr*>(&addr), (int)INET_SOCKADDR_LENGTH(addr.ss_family));
			if (res < 0) throw std::system_error(WSAGetLastError(), std::system_category());
		}

		auto state = new my_overlapped{};
		cd->engine_state = state;
		state->cd = cd;
		state->sock = socket;

		m_inflight_count.fetch_add(1, std::memory_order::relaxed);
		if (lpfnConnectex(socket, reinterpret_cast<const sockaddr*>(&sa.first), sa.second, nullptr, 0, nullptr,
						  &state->overlapped) == TRUE) {
			printf("=> true\n");
			// IOCP always pushes even if it finishes synchronously
			return false;
		} else if (WSAGetLastError() == WSA_IO_PENDING) {
			printf("=> pending\n");
			return false;
		} else {
			delete state;
			cd->result = -WSAGetLastError();
			m_inflight_count.fetch_sub(1, std::memory_order::relaxed);
			printf("=> false err=%d\n", WSAGetLastError());
			return true;
		}
	}

	bool io_engine_win32cq::enqueue_accept(socket_handle_t socket, completion_data* cd) {
		printf("enqueue_accept\n");

		auto state = new my_overlapped{};
		cd->engine_state = state;
		state->cd = cd;
		state->sock = socket;

		// Get the socket family to create a second socket for accepting
		WSAPROTOCOL_INFO info{};
		int optlen = sizeof(info);
		if (getsockopt(socket, SOL_SOCKET, SO_PROTOCOL_INFO, reinterpret_cast<char*>(&info), &optlen) == SOCKET_ERROR)
			throw std::system_error(WSAGetLastError(), std::system_category());

		state->accept_sock =
			WSASocket(info.iAddressFamily, info.iSocketType, info.iProtocol, NULL, 0, WSA_FLAG_OVERLAPPED);
		if (state->accept_sock == INVALID_SOCKET)
			throw std::system_error(WSAGetLastError(), std::system_category(), "WSASocket");

		m_inflight_count.fetch_add(1, std::memory_order::relaxed);
		DWORD received;
		if (AcceptEx(socket, state->accept_sock, state->accept_buffer.data(), 0, sizeof(sockaddr_in6) + 16,
					 sizeof(sockaddr_in6) + 16, &received, &state->overlapped) == 0) {
			printf("=> true\n");
			// IOCP always pushes even if it finishes synchronously
			return false;
		} else if (WSAGetLastError() == WSA_IO_PENDING) {
			printf("=> pending\n");
			return false;
		} else {
			delete state;
			cd->result = -WSAGetLastError();
			m_inflight_count.fetch_sub(1, std::memory_order::relaxed);
			printf("=> false err=%d\n", WSAGetLastError());
			return true;
		}
	}

	bool io_engine_win32cq::enqueue_recv(socket_handle_t socket, void* buf, size_t len, completion_data* cd) {
		printf("enqueue_recv\n");

		auto state = new my_overlapped{};
		cd->engine_state = state;
		state->cd = cd;
		state->sock = socket;

		WSABUF buffer;
		buffer.buf = static_cast<char*>(buf);
		buffer.len = len;

		m_inflight_count.fetch_add(1, std::memory_order::relaxed);
		DWORD flags = 0;
		if (WSARecv(socket, &buffer, 1, nullptr, &flags, &state->overlapped, nullptr) == 0) {
			printf("=> true\n");
			// IOCP always pushes even if it finishes synchronously
			return false;
		} else if (WSAGetLastError() == WSA_IO_PENDING) {
			printf("=> pending\n");
			return false;
		} else {
			delete state;
			cd->result = -WSAGetLastError();
			m_inflight_count.fetch_sub(1, std::memory_order::relaxed);
			printf("=> false err=%d\n", WSAGetLastError());
			return true;
		}
	}

	bool io_engine_win32cq::enqueue_send(socket_handle_t socket, const void* buf, size_t len, completion_data* cd) {
		printf("enqueue_send\n");

		auto state = new my_overlapped{};
		cd->engine_state = state;
		state->cd = cd;
		state->sock = socket;

		WSABUF buffer;
		buffer.buf = const_cast<char*>(static_cast<const char*>(buf));
		buffer.len = len;

		m_inflight_count.fetch_add(1, std::memory_order::relaxed);
		if (WSASend(socket, &buffer, 1, nullptr, 0, &state->overlapped, nullptr) == 0) {
			printf("=> true\n");
			// IOCP always pushes even if it finishes synchronously
			return false;
		} else if (WSAGetLastError() == WSA_IO_PENDING) {
			printf("=> pending\n");
			return false;
		} else {
			delete state;
			cd->result = -WSAGetLastError();
			m_inflight_count.fetch_sub(1, std::memory_order::relaxed);
			printf("=> false err=%d\n", WSAGetLastError());
			return true;
		}
	}

	bool io_engine_win32cq::enqueue_recv_from(socket_handle_t socket, void* buf, size_t len, endpoint* source,
											  completion_data* cd) {
		return false;
	}

	bool io_engine_win32cq::enqueue_send_to(socket_handle_t socket, const void* buf, size_t len, endpoint dst,
											completion_data* cd) {
		return false;
	}

	bool io_engine_win32cq::enqueue_readv(file_handle_t fd, void* buf, size_t len, off_t offset, completion_data* cd) {
		return false;
	}

	bool io_engine_win32cq::enqueue_writev(file_handle_t fd, const void* buf, size_t len, off_t offset,
										   completion_data* cd) {
		return false;
	}

	bool io_engine_win32cq::enqueue_fsync(file_handle_t fd, fsync_flags flags, completion_data* cd) { return false; }

	bool io_engine_win32cq::cancel(completion_data* cd) {
		auto state = reinterpret_cast<my_overlapped*>(cd->engine_state);
		assert(cd == state->cd);
		CancelIoEx((HANDLE)state->sock, &state->overlapped);
		return true;
	}

} // namespace asyncpp::io::detail
#endif
