#include <asyncpp/io/detail/io_engine.h>

#ifdef _WIN32
namespace asyncpp::io::detail {
	std::unique_ptr<io_engine> create_io_engine_select() { return nullptr; }
} // namespace asyncpp::io::detail
#else

#include <cstring>
#include <mutex>
#include <vector>

#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#ifdef __linux__
#define USE_EVENTFD
#endif

#ifdef USE_EVENTFD
#include <sys/eventfd.h>
#endif

namespace asyncpp::io::detail {
	namespace {
		enum class op { connect, accept, recv, send, recv_from, send_to };
		struct entry {
			op operation;
			io_engine::socket_handle_t socket;
			io_engine::completion_data* done;
			union {
				struct {
					void* buf;
					size_t len;
				} recv;
				struct {
					const void* buf;
					size_t len;
				} send;
				struct {
					void* buf;
					size_t len;
					endpoint* source;
				} recv_from;
				struct {
					const void* buf;
					size_t len;
					endpoint destination;
				} send_to;
			} state;
		};
	} // namespace

	class io_engine_select : public io_engine {
	public:
		io_engine_select();
		io_engine_select(const io_engine_select&) = delete;
		io_engine_select& operator=(const io_engine_select&) = delete;
		~io_engine_select();

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
		socket_handle_t m_wake_fd;
#ifndef USE_EVENTFD
		socket_handle_t m_wake_fd_write;
#endif
		std::mutex m_inflight_mtx;
		std::vector<entry> m_inflight;
		std::vector<completion_data*> m_done_callbacks;

		enum { RDY_READ = 1, RDY_WRITE = 2, RDY_ERR = 4 };
		bool handle_io(entry& e, int state);
	};

	std::unique_ptr<io_engine> create_io_engine_select() { return std::make_unique<io_engine_select>(); }

	io_engine_select::io_engine_select() {
#ifdef USE_EVENTFD
		m_wake_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
		if (m_wake_fd < 0) throw std::system_error(errno, std::system_category(), "eventfd failed");
#else
		int fds[2];
		auto res = pipe(fds);
		if (res < 0) throw std::system_error(errno, std::system_category(), "pipe failed");
		int flags0 = fcntl(fds[0], F_GETFL, 0);
		int flags1 = fcntl(fds[1], F_GETFL, 0);
		if (flags0 < 0 || flags1 < 0 ||																			  //
			fcntl(fds[0], F_SETFL, flags0 | O_NONBLOCK) < 0 || fcntl(fds[1], F_SETFL, flags1 | O_NONBLOCK) < 0 || //
			fcntl(fds[0], F_SETFD, FD_CLOEXEC) < 0 || fcntl(fds[1], F_SETFD, FD_CLOEXEC) < 0) {
			close(fds[0]);
			close(fds[1]);
			throw std::system_error(errno, std::system_category(), "pipe failed");
		}
		m_wake_fd = fds[0];
		m_wake_fd_write = fds[1];
#endif
	}

	io_engine_select::~io_engine_select() {
		if (m_wake_fd >= 0) close(m_wake_fd);
#ifndef USE_EVENTFD
		if (m_wake_fd_write >= 0) close(m_wake_fd_write);
#endif
	}

	std::string_view io_engine_select::name() const noexcept { return "select"; }

	size_t io_engine_select::run(bool nowait) {
		fd_set rd_set{}, wrt_set{}, err_set{};
		int max_fd = m_wake_fd;
		FD_SET(m_wake_fd, &rd_set);
		std::unique_lock lck{m_inflight_mtx};
		if (nowait && m_inflight.empty()) return m_inflight.size();
		for (auto& e : m_inflight) {
			switch (e.operation) {
			case op::connect:
			case op::send:
			case op::send_to: FD_SET(e.socket, &wrt_set); break;
			case op::accept:
			case op::recv:
			case op::recv_from: FD_SET(e.socket, &rd_set); break;
			}
			max_fd = (std::max)(e.socket, max_fd);
		}
		lck.unlock();
		struct timeval timeout {};
		if (!nowait) timeout.tv_sec = 10;
		auto res = select(max_fd + 1, &rd_set, &wrt_set, &err_set, &timeout);
		if (res < 0) throw std::system_error(errno, std::system_category(), "select failed");
		if (FD_ISSET(m_wake_fd, &rd_set)) {
			uint64_t val;
			[[maybe_unused]] auto rsize = read(m_wake_fd, &val, sizeof(val));
			// Note we ignore the result because its irrelevant
			res--;
		}
		// Note: inflight might have changed in between, but we dont care.
		lck.lock();
		if (res == 0) return m_inflight.size();
		for (auto it = m_inflight.begin(); it != m_inflight.end();) {
			int state = 0;
			state |= FD_ISSET(it->socket, &rd_set) ? RDY_READ : 0;
			state |= FD_ISSET(it->socket, &wrt_set) ? RDY_WRITE : 0;
			state |= FD_ISSET(it->socket, &err_set) ? RDY_ERR : 0;
			if (state == 0 || !handle_io(*it, state))
				it++;
			else
				it = m_inflight.erase(it);
		}
		lck.unlock();
		for (auto e : m_done_callbacks) {
			e->callback(e->userdata);
		}
		m_done_callbacks.clear();
		return m_inflight.size();
	}

	bool io_engine_select::handle_io(entry& e, int state) {
		switch (e.operation) {
		case op::connect: {
			if ((state & RDY_WRITE) == 0) return false;
			int result;
			socklen_t result_len = sizeof(result);
			if (getsockopt(e.socket, SOL_SOCKET, SO_ERROR, &result, &result_len) < 0) {
				e.done->result = std::error_code(errno, std::system_category());
			} else {
				e.done->result = std::error_code(result, std::system_category());
			}
			m_done_callbacks.push_back(e.done);
			return true;
		}
		case op::send: {
			if ((state & RDY_WRITE) == 0) return false;
			auto res = ::send(e.socket, e.state.send.buf, e.state.send.len, 0);
			if (res >= 0) {
				e.state.send.len -= res;
				e.state.send.buf = static_cast<const uint8_t*>(e.state.send.buf) + res;
				if (e.state.send.len == 0) {
					e.done->result.clear();
					m_done_callbacks.push_back(e.done);
					return true;
				}
			} else if (errno != EAGAIN) {
				e.done->result = std::error_code(errno, std::system_category());
				m_done_callbacks.push_back(e.done);
				return true;
			}
			return false;
		}
		case op::accept: {
			if ((state & RDY_READ) == 0) return false;
			auto res = ::accept(e.socket, nullptr, nullptr);
			if (res >= 0) {
				e.done->result.clear();
				e.done->result_handle = res;
			} else if (errno != EAGAIN) {
				e.done->result = std::error_code(errno, std::system_category());
			} else
				return false;
			m_done_callbacks.push_back(e.done);
			return true;
		}
		case op::recv: {
			if ((state & RDY_READ) == 0) return false;
			auto res = ::recv(e.socket, e.state.recv.buf, e.state.recv.len, 0);
			if (res >= 0) {
				e.done->result.clear();
				e.done->result_size = res;
			} else if (errno != EAGAIN) {
				e.done->result = std::error_code(errno, std::system_category());
			} else
				return false;
			m_done_callbacks.push_back(e.done);
			return true;
		}
		case op::send_to: {
			if ((state & RDY_WRITE) == 0) return false;
			auto sa = e.state.send_to.destination.to_sockaddr();
			auto res = ::sendto(e.socket, e.state.send.buf, e.state.send.len, 0, reinterpret_cast<sockaddr*>(&sa.first),
								sa.second);
			if (res >= 0) {
				e.done->result.clear();
				e.done->result_size = res;
			} else if (errno != EAGAIN) {
				e.done->result = std::error_code(errno, std::system_category());
			} else
				return false;
			m_done_callbacks.push_back(e.done);
			return true;
		}
		case op::recv_from: {
			if ((state & RDY_READ) == 0) return false;
			sockaddr_storage sa;
			socklen_t sa_len = sizeof(sa);
			auto res =
				::recvfrom(e.socket, e.state.recv.buf, e.state.recv.len, 0, reinterpret_cast<sockaddr*>(&sa), &sa_len);
			if (res >= 0) {
				e.done->result.clear();
				e.done->result_size = res;
				if (e.state.recv_from.source) {
					if (sa.ss_family == AF_INET || sa.ss_family == AF_INET6 || sa.ss_family == AF_UNIX)
						*e.state.recv_from.source = endpoint(sa, sa_len);
					else
						*e.state.recv_from.source = endpoint{};
				}
			} else if (errno != EAGAIN) {
				e.done->result = std::error_code(errno, std::system_category());
			} else
				return false;
			m_done_callbacks.push_back(e.done);
			return true;
		}
		default: return true;
		}
	}

	void io_engine_select::wake() {
		uint64_t val = 1;
#ifdef USE_EVENTFD
		write(m_wake_fd, &val, sizeof(val));
#else
		write(m_wake_fd_write, &val, sizeof(val));
#endif
	}

	io_engine::socket_handle_t io_engine_select::create_socket(address_type domain, int type) {
		int afdomain = -1;
		switch (domain) {
		case address_type::ipv4: afdomain = AF_INET; break;
		case address_type::ipv6: afdomain = AF_INET6; break;
		case address_type::uds: afdomain = AF_UNIX; break;
		}
		if (afdomain == -1) throw std::system_error(ENOTSUP, std::system_category());
#ifdef __APPLE__
		auto fd = ::socket(afdomain, type, 0);
		if (fd < 0) throw std::system_error(errno, std::system_category(), "select failed");
		int flags = fcntl(fd, F_GETFL, 0);
		if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 || fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
			close(fd);
			throw std::system_error(errno, std::system_category(), "fcntl failed");
		}
#else
		auto fd = ::socket(afdomain, type | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
		if (fd < 0) throw std::system_error(errno, std::system_category(), "select failed");
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

	void io_engine_select::socket_bind(socket_handle_t socket, endpoint ep) {
		auto sa = ep.to_sockaddr();
		auto res = ::bind(socket, reinterpret_cast<sockaddr*>(&sa.first), sa.second);
		if (res < 0) throw std::system_error(errno, std::system_category(), "select failed");
	}

	bool io_engine_select::enqueue_connect(socket_handle_t socket, endpoint ep, completion_data* cd) {
		auto sa = ep.to_sockaddr();
		auto res = ::connect(socket, reinterpret_cast<sockaddr*>(&sa.first), sa.second);
		if (res == 0 || errno != EINPROGRESS) {
			// Succeeded right away
			cd->result = std::error_code(res ? errno : 0, std::system_category());
			return true;
		}

		entry e{};
		e.operation = op::connect;
		e.socket = socket;
		e.done = cd;
		std::unique_lock lck{m_inflight_mtx};
		m_inflight.push_back(e);
		wake();
		return false;
	}

	bool io_engine_select::enqueue_accept(socket_handle_t socket, completion_data* cd) {
		auto res = ::accept(socket, nullptr, nullptr);
		if (res >= 0) {
			cd->result.clear();
			cd->result_handle = res;
			return true;
		} else if (errno != EAGAIN) {
			cd->result = std::error_code(errno, std::system_category());
			return true;
		}

		entry e{};
		e.operation = op::accept;
		e.socket = socket;
		e.done = cd;
		std::unique_lock lck{m_inflight_mtx};
		m_inflight.push_back(e);
		wake();
		return false;
	}

	bool io_engine_select::enqueue_recv(socket_handle_t socket, void* buf, size_t len, completion_data* cd) {
		auto res = ::recv(socket, buf, len, 0);
		if (res >= 0) {
			cd->result.clear();
			cd->result_size = res;
			return true;
		} else if (errno != EAGAIN) {
			cd->result = std::error_code(errno, std::system_category());
			return true;
		}

		entry e{};
		e.operation = op::recv;
		e.socket = socket;
		e.done = cd;
		e.state.recv.buf = buf;
		e.state.recv.len = len;
		std::unique_lock lck{m_inflight_mtx};
		m_inflight.push_back(e);
		wake();
		return false;
	}

	bool io_engine_select::enqueue_send(socket_handle_t socket, const void* buf, size_t len, completion_data* cd) {
		auto res = ::send(socket, buf, len, 0);
		if (res >= 0) {
			len -= res;
			buf = static_cast<const uint8_t*>(buf) + res;
		} else if (errno != EAGAIN) {
			cd->result = std::error_code(errno, std::system_category());
			return true;
		}
		if (len == 0) {
			cd->result.clear();
			return true;
		}

		entry e{};
		e.operation = op::send;
		e.socket = socket;
		e.done = cd;
		e.state.send.buf = buf;
		e.state.send.len = len;
		std::unique_lock lck{m_inflight_mtx};
		m_inflight.push_back(e);
		wake();
		return false;
	}

	bool io_engine_select::enqueue_recv_from(socket_handle_t socket, void* buf, size_t len, endpoint* source,
											 completion_data* cd) {
		sockaddr_storage sa;
		socklen_t sa_len = sizeof(sa);
		auto res = ::recvfrom(socket, buf, len, 0, reinterpret_cast<sockaddr*>(&sa), &sa_len);
		if (res >= 0) {
			cd->result.clear();
			cd->result_size = res;
			if (source != nullptr) {
				if (sa.ss_family == AF_INET || sa.ss_family == AF_INET6)
					*source = endpoint(sa, sa_len);
				else
					*source = endpoint{};
			}
			return true;
		} else if (errno != EAGAIN) {
			cd->result = std::error_code(errno, std::system_category());
			return true;
		}

		entry e{};
		e.operation = op::recv_from;
		e.socket = socket;
		e.done = cd;
		e.state.recv_from.buf = buf;
		e.state.recv_from.len = len;
		e.state.recv_from.source = source;
		std::unique_lock lck{m_inflight_mtx};
		m_inflight.push_back(e);
		wake();
		return false;
	}

	bool io_engine_select::enqueue_send_to(socket_handle_t socket, const void* buf, size_t len, endpoint dst,
										   completion_data* cd) {
		auto sa = dst.to_sockaddr();
		auto res = ::sendto(socket, buf, len, 0, reinterpret_cast<sockaddr*>(&sa.first), sa.second);
		if (res >= 0) {
			cd->result.clear();
			cd->result_size = res;
			return true;
		} else if (errno != EAGAIN) {
			cd->result = std::error_code(errno, std::system_category());
			return true;
		}

		entry e{};
		e.operation = op::send_to;
		e.socket = socket;
		e.done = cd;
		e.state.send_to.buf = buf;
		e.state.send_to.len = len;
		e.state.send_to.destination = dst;
		std::unique_lock lck{m_inflight_mtx};
		m_inflight.push_back(e);
		wake();
		return false;
	}

	bool io_engine_select::enqueue_readv(file_handle_t fd, void* buf, size_t len, off_t offset, completion_data* cd) {
		// There is no way to do async file io on linux without uring, so just do the read inline
		auto res = pread(fd, buf, len, offset);
		if (res >= 0) {
			cd->result.clear();
			cd->result_size = res;
		} else if (errno != EAGAIN) {
			cd->result = std::error_code(errno, std::system_category());
		}
		return true;
	}

	bool io_engine_select::enqueue_writev(file_handle_t fd, const void* buf, size_t len, off_t offset,
										  completion_data* cd) {
		// There is no way to do async file io on linux without uring, so just do the write inline
		auto res = pwrite(fd, buf, len, offset);
		if (res >= 0) {
			cd->result.clear();
			cd->result_size = res;
		} else if (errno != EAGAIN) {
			cd->result = std::error_code(errno, std::system_category());
		}
		return true;
	}

	bool io_engine_select::enqueue_fsync(file_handle_t fd, fsync_flags flags, completion_data* cd) {
// There is no way to do async file io on linux without uring, so just do the fsync inline
#ifdef __linux__
		auto res = flags == fsync_flags::datasync ? fdatasync(fd) : fsync(fd);
#else
		auto res = fsync(fd);
#endif
		if (res >= 0) {
			cd->result.clear();
			cd->result_size = res;
		} else if (errno != EAGAIN) {
			cd->result = std::error_code(errno, std::system_category());
		}
		return true;
	}

	bool io_engine_select::cancel(completion_data* cd) {
		std::unique_lock lck{m_inflight_mtx};
		for (auto it = m_inflight.begin(); it != m_inflight.end(); it++) {
			if (it->done == cd) {
				it = m_inflight.erase(it);
				lck.unlock();
				cd->result = std::error_code(ECANCELED, std::system_category());
				cd->callback(cd->userdata);
				return true;
			}
		}
		return false;
	}

} // namespace asyncpp::io::detail

#endif
