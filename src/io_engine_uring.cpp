#include <asyncpp/io/detail/io_engine.h>

#if !defined(__linux__) || !defined(ASYNCPP_ENABLE_URING)
namespace asyncpp::io::detail {
	std::unique_ptr<io_engine> create_io_engine_uring() { return nullptr; }
} // namespace asyncpp::io::detail
#else
#include "io_engine_generic_unix.h"

#include <cstring>
#include <mutex>

#include <asm/unistd_64.h>
#include <fcntl.h>
#include <liburing.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

namespace asyncpp::io::detail {

	class io_engine_uring : public io_engine_generic_unix {
	public:
		io_engine_uring(struct io_uring ring) noexcept;
		io_engine_uring(const io_engine_uring&) = delete;
		io_engine_uring& operator=(const io_engine_uring&) = delete;
		~io_engine_uring();

		std::string_view name() const noexcept override;

		size_t run(bool nowait) override;
		void wake() override;

		void socket_register(socket_handle_t socket) override;
		void socket_release(socket_handle_t socket) override;
		bool enqueue_connect(socket_handle_t socket, endpoint ep, completion_data* cd) override;
		bool enqueue_accept(socket_handle_t socket, completion_data* cd) override;
		bool enqueue_recv(socket_handle_t socket, void* buf, size_t len, completion_data* cd) override;
		bool enqueue_send(socket_handle_t socket, const void* buf, size_t len, completion_data* cd) override;
		bool enqueue_recv_from(socket_handle_t socket, void* buf, size_t len, endpoint* source,
							   completion_data* cd) override;
		bool enqueue_send_to(socket_handle_t socket, const void* buf, size_t len, endpoint dst,
							 completion_data* cd) override;

		void file_register(file_handle_t fd) override;
		void file_release(file_handle_t fd) override;
		bool enqueue_readv(file_handle_t fd, void* buf, size_t len, uint64_t offset, completion_data* cd) override;
		bool enqueue_writev(file_handle_t fd, const void* buf, size_t len, uint64_t offset,
							completion_data* cd) override;
		bool enqueue_fsync(file_handle_t fd, fsync_flags flags, completion_data* cd) override;

		bool cancel(completion_data* cd) override;

	private:
		enum class uring_op : uint8_t {
			invalid,
			connect,
			accept,
			recv,
			send,
			recv_from,
			send_to,
			readv,
			writev,
			fsync
		};
		struct uring_engine_state {
			struct msghdr hdr;
			sockaddr_storage sockaddr;
			iovec data;
			asyncpp::io::endpoint* real_endpoint;
			uring_op op;
		};

		std::mutex m_sqe_mtx{};
		std::mutex m_cqe_mtx{};
		std::atomic<size_t> m_inflight_count{};
		struct io_uring m_ring {};
	};

	std::unique_ptr<io_engine> create_io_engine_uring() {
		// check if the kernel supports uring and return nullptr if not
		if (syscall(__NR_io_uring_register, 0, IORING_UNREGISTER_BUFFERS, NULL, 0) && errno == ENOSYS) return nullptr;
		io_uring ring{};
		auto res = io_uring_queue_init(256, &ring, 0);
		if (res < 0) return nullptr;
		std::unique_ptr<struct io_uring_probe, decltype(&free)> probe(io_uring_get_probe_ring(&ring), &free);
		// Make sure all required opcodes are supported
		if (io_uring_opcode_supported(probe.get(), IORING_OP_NOP) == 0 ||
			io_uring_opcode_supported(probe.get(), IORING_OP_CONNECT) == 0 ||
			io_uring_opcode_supported(probe.get(), IORING_OP_ACCEPT) == 0 ||
			io_uring_opcode_supported(probe.get(), IORING_OP_RECV) == 0 ||
			io_uring_opcode_supported(probe.get(), IORING_OP_SEND) == 0 ||
			io_uring_opcode_supported(probe.get(), IORING_OP_RECVMSG) == 0 ||
			io_uring_opcode_supported(probe.get(), IORING_OP_SENDMSG) == 0 ||
			io_uring_opcode_supported(probe.get(), IORING_OP_ASYNC_CANCEL) == 0 ||
			io_uring_opcode_supported(probe.get(), IORING_OP_READV) == 0 ||
			io_uring_opcode_supported(probe.get(), IORING_OP_WRITEV) == 0 ||
			io_uring_opcode_supported(probe.get(), IORING_OP_FSYNC) == 0)
			return nullptr;
		return std::make_unique<io_engine_uring>(std::move(ring));
	}

	io_engine_uring::io_engine_uring(struct io_uring ring) noexcept : m_ring(ring) {}

	io_engine_uring::~io_engine_uring() { io_uring_queue_exit(&m_ring); }

	std::string_view io_engine_uring::name() const noexcept { return "uring"; }

	size_t io_engine_uring::run(bool nowait) {
		__kernel_timespec timeout{};
		if (!nowait) timeout.tv_sec = 10;
		io_uring_cqe* cqe;
		std::unique_lock lck{m_cqe_mtx};
		auto res = io_uring_wait_cqe_timeout(&m_ring, &cqe, &timeout);
		if (res == -ETIME || res == -EINTR) return m_inflight_count;
		if (res < 0) throw std::system_error(-res, std::system_category(), "uring wait cqe failed");
		auto* info = static_cast<completion_data*>(io_uring_cqe_get_data(cqe));
		auto opres = cqe->res;
		io_uring_cqe_seen(&m_ring, cqe);
		// Wakeup call using wake()
		if (info == nullptr) return m_inflight_count;
		m_inflight_count.fetch_sub(1, std::memory_order::relaxed);
		lck.unlock();

		auto state = info->es_get<uring_engine_state>();
		info->result = std::error_code(opres < 0 ? -opres : 0, std::system_category());
		switch (state->op) {
		case uring_op::accept: info->result_handle = opres; break;
		default: info->result_size = static_cast<size_t>(opres); break;
		}

		if (state->real_endpoint != nullptr) {
			if (state->sockaddr.ss_family == AF_INET || state->sockaddr.ss_family == AF_INET6 ||
				state->sockaddr.ss_family == AF_UNIX)
				*state->real_endpoint = endpoint(state->sockaddr, state->hdr.msg_namelen);
			else
				*state->real_endpoint = endpoint();
		}

		if (info->callback) info->callback(info->userdata);

		return m_inflight_count;
	}

	void io_engine_uring::wake() {
		std::lock_guard lck{m_sqe_mtx};
		struct io_uring_sqe* sqe = io_uring_get_sqe(&m_ring);
		io_uring_prep_nop(sqe);
		io_uring_sqe_set_data(sqe, nullptr);
		io_uring_submit(&m_ring);
	}

	void io_engine_uring::socket_register(socket_handle_t socket) {}

	void io_engine_uring::socket_release(socket_handle_t socket) {}

	bool io_engine_uring::enqueue_connect(socket_handle_t socket, endpoint ep, completion_data* cd) {
		auto sa = ep.to_sockaddr();
		std::lock_guard lck{m_sqe_mtx};
		struct io_uring_sqe* sqe = io_uring_get_sqe(&m_ring);
		io_uring_prep_connect(sqe, socket, reinterpret_cast<const sockaddr*>(&sa.first), sa.second);
		io_uring_sqe_set_data(sqe, cd);
		io_uring_submit(&m_ring);
		m_inflight_count.fetch_add(1, std::memory_order::relaxed);
		return false;
	}

	bool io_engine_uring::enqueue_accept(socket_handle_t socket, completion_data* cd) {
		std::lock_guard lck{m_sqe_mtx};
		struct io_uring_sqe* sqe = io_uring_get_sqe(&m_ring);
		io_uring_prep_accept(sqe, socket, nullptr, nullptr, 0);
		io_uring_sqe_set_data(sqe, cd);
		io_uring_submit(&m_ring);
		m_inflight_count.fetch_add(1, std::memory_order::relaxed);
		return false;
	}

	bool io_engine_uring::enqueue_recv(socket_handle_t socket, void* buf, size_t len, completion_data* cd) {
		std::lock_guard lck{m_sqe_mtx};
		struct io_uring_sqe* sqe = io_uring_get_sqe(&m_ring);
		io_uring_prep_recv(sqe, socket, buf, len, 0);
		io_uring_sqe_set_data(sqe, cd);
		io_uring_submit(&m_ring);
		m_inflight_count.fetch_add(1, std::memory_order::relaxed);
		return false;
	}

	bool io_engine_uring::enqueue_send(socket_handle_t socket, const void* buf, size_t len, completion_data* cd) {
		std::lock_guard lck{m_sqe_mtx};
		struct io_uring_sqe* sqe = io_uring_get_sqe(&m_ring);
		io_uring_prep_send(sqe, socket, buf, len, 0);
		io_uring_sqe_set_data(sqe, cd);
		io_uring_submit(&m_ring);
		m_inflight_count.fetch_add(1, std::memory_order::relaxed);
		return false;
	}

	bool io_engine_uring::enqueue_recv_from(socket_handle_t socket, void* buf, size_t len, endpoint* source,
											completion_data* cd) {
		auto* info = cd->es_init<uring_engine_state>();
		info->hdr.msg_name = &info->sockaddr;
		info->hdr.msg_namelen = sizeof(info->sockaddr);
		info->hdr.msg_iov = &info->data;
		info->hdr.msg_iovlen = 1;
		info->data.iov_base = buf;
		info->data.iov_len = len;
		info->real_endpoint = source;

		std::lock_guard lck{m_sqe_mtx};
		struct io_uring_sqe* sqe = io_uring_get_sqe(&m_ring);
		io_uring_prep_recvmsg(sqe, socket, &info->hdr, 0);
		io_uring_sqe_set_data(sqe, cd);
		io_uring_submit(&m_ring);
		m_inflight_count.fetch_add(1, std::memory_order::relaxed);
		return false;
	}

	bool io_engine_uring::enqueue_send_to(socket_handle_t socket, const void* buf, size_t len, endpoint dst,
										  completion_data* cd) {
		auto addr = dst.to_sockaddr();
		auto* info = cd->es_init<uring_engine_state>();
		info->hdr.msg_name = &info->sockaddr;
		info->hdr.msg_namelen = addr.second;
		info->hdr.msg_iov = &info->data;
		info->hdr.msg_iovlen = 1;
		info->sockaddr = addr.first;
		info->data.iov_base = const_cast<void*>(buf);
		info->data.iov_len = len;

		std::lock_guard lck{m_sqe_mtx};
		struct io_uring_sqe* sqe = io_uring_get_sqe(&m_ring);
		io_uring_prep_sendmsg(sqe, socket, &info->hdr, 0);
		io_uring_sqe_set_data(sqe, cd);
		io_uring_submit(&m_ring);
		m_inflight_count.fetch_add(1, std::memory_order::relaxed);
		return false;
	}

	void io_engine_uring::file_register(file_handle_t fd) {}

	void io_engine_uring::file_release(file_handle_t fd) {}

	bool io_engine_uring::enqueue_readv(file_handle_t fd, void* buf, size_t len, uint64_t offset, completion_data* cd) {
		auto* info = cd->es_init<uring_engine_state>();
		info->data.iov_base = buf;
		info->data.iov_len = len;

		std::lock_guard lck{m_sqe_mtx};
		struct io_uring_sqe* sqe = io_uring_get_sqe(&m_ring);
		io_uring_prep_readv(sqe, fd, &info->data, 1, offset);
		io_uring_sqe_set_data(sqe, cd);
		io_uring_submit(&m_ring);
		m_inflight_count.fetch_add(1, std::memory_order::relaxed);
		return false;
	}

	bool io_engine_uring::enqueue_writev(file_handle_t fd, const void* buf, size_t len, uint64_t offset,
										 completion_data* cd) {
		auto* info = cd->es_init<uring_engine_state>();
		info->data.iov_base = const_cast<void*>(buf);
		info->data.iov_len = len;

		std::lock_guard lck{m_sqe_mtx};
		struct io_uring_sqe* sqe = io_uring_get_sqe(&m_ring);
		io_uring_prep_writev(sqe, fd, &info->data, 1, offset);
		io_uring_sqe_set_data(sqe, cd);
		io_uring_submit(&m_ring);
		m_inflight_count.fetch_add(1, std::memory_order::relaxed);
		return false;
	}

	bool io_engine_uring::enqueue_fsync(file_handle_t fd, fsync_flags flags, completion_data* cd) {
		std::lock_guard lck{m_sqe_mtx};
		struct io_uring_sqe* sqe = io_uring_get_sqe(&m_ring);
		io_uring_prep_fsync(sqe, fd, flags == fsync_flags::datasync ? IORING_FSYNC_DATASYNC : 0);
		io_uring_sqe_set_data(sqe, cd);
		io_uring_submit(&m_ring);
		m_inflight_count.fetch_add(1, std::memory_order::relaxed);
		return false;
	}

	bool io_engine_uring::cancel(completion_data* cd) {
		std::lock_guard lck{m_sqe_mtx};
		struct io_uring_sqe* sqe = io_uring_get_sqe(&m_ring);
		io_uring_prep_cancel(sqe, cd, 0);
		io_uring_sqe_set_data(sqe, nullptr);
		io_uring_submit(&m_ring);
		return true;
	}

} // namespace asyncpp::io::detail

#endif
