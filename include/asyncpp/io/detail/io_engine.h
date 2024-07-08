#pragma once
#include <asyncpp/io/endpoint.h>

#include <memory>

namespace asyncpp::io::detail {
	class io_engine {
	public:
		using file_handle_t = int;
		constexpr static file_handle_t invalid_file_handle = -1;
		using socket_handle_t = int;
		constexpr static socket_handle_t invalid_socket_handle = -1;
		enum class fsync_flags { none, datasync };

		struct completion_data {
			// Info provided by caller
			void (*callback)(void*);
			void* userdata;

			// Filled by io_engine
			int result;

			// Private data the engine can use to associate state
			void* engine_state{};
		};

	public:
		virtual ~io_engine() = default;

		virtual std::string_view name() const noexcept = 0;

		virtual size_t run(bool nowait = false) = 0;
		virtual void wake() = 0;

		// Networking api
		virtual bool enqueue_connect(socket_handle_t socket, endpoint ep, completion_data* cd) = 0;
		virtual bool enqueue_accept(socket_handle_t socket, completion_data* cd) = 0;
		virtual bool enqueue_recv(socket_handle_t socket, void* buf, size_t len, completion_data* cd) = 0;
		virtual bool enqueue_send(socket_handle_t socket, const void* buf, size_t len, completion_data* cd) = 0;
		virtual bool enqueue_recv_from(socket_handle_t socket, void* buf, size_t len, endpoint* source,
									   completion_data* cd) = 0;
		virtual bool enqueue_send_to(socket_handle_t socket, const void* buf, size_t len, endpoint dst,
									 completion_data* cd) = 0;

		// Filesystem IO
		virtual bool enqueue_readv(file_handle_t fd, void* buf, size_t len, off_t offset, completion_data* cd) = 0;
		virtual bool enqueue_writev(file_handle_t fd, const void* buf, size_t len, off_t offset,
									completion_data* cd) = 0;
		virtual bool enqueue_fsync(file_handle_t fd, fsync_flags flags, completion_data* cd) = 0;

		// Cancelation
		virtual bool cancel(completion_data* cd) = 0;
	};

	std::unique_ptr<io_engine> create_io_engine();
} // namespace asyncpp::io::detail
