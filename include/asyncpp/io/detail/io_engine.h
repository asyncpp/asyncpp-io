#pragma once
#include <asyncpp/io/endpoint.h>

#include <memory>
#include <cstddef>

namespace asyncpp::io::detail {
	class io_engine {
	public:
#ifndef _WIN32
		using file_handle_t = int;
		constexpr static file_handle_t invalid_file_handle = -1;
		using socket_handle_t = int;
		constexpr static socket_handle_t invalid_socket_handle = -1;
#else
		using file_handle_t = void*;
		constexpr static file_handle_t invalid_file_handle = reinterpret_cast<void*>(static_cast<long long>( - 1));
		using socket_handle_t = unsigned long long;
		constexpr static socket_handle_t invalid_socket_handle = ~static_cast<socket_handle_t>(0);

#endif
		enum class fsync_flags { none, datasync };

		struct completion_data {
			// Info provided by caller
			void (*callback)(void*);
			void* userdata;

			// Private data the engine can use to associate state
			alignas(std::max_align_t) std::array<std::byte, 256> engine_state;

			// Filled by io_engine
			std::error_code result;
			union {
				socket_handle_t result_handle;
				size_t result_size;
			};

			template<typename T>
			T* es_init() noexcept {
				static_assert(std::is_standard_layout_v<T> && std::is_trivial_v<T>);
				static_assert(sizeof(T) <= std::tuple_size_v<decltype(engine_state)>);
				engine_state.fill(std::byte{});
				return es_get<T>();
			}
			template<typename T>
			T* es_get() noexcept {
				static_assert(std::is_standard_layout_v<T> && std::is_trivial_v<T>);
				static_assert(sizeof(T) <= std::tuple_size_v<decltype(engine_state)>);
				return reinterpret_cast<T*>(engine_state.data());
			}
		};

	public:
		virtual ~io_engine() = default;

		virtual std::string_view name() const noexcept = 0;

		virtual size_t run(bool nowait = false) = 0;
		virtual void wake() = 0;

		// Networking api
		virtual socket_handle_t create_socket(address_type domain, int type) = 0;
		virtual void socket_bind(socket_handle_t socket, endpoint ep) = 0;
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
