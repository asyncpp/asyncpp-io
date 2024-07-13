#ifndef _WIN32
#include <asyncpp/io/detail/io_engine.h>

namespace asyncpp::io::detail {

	class io_engine_generic_unix : public io_engine {
	public:
		socket_handle_t socket_create(address_type domain, socket_type type) override;
		std::pair<socket_handle_t, socket_handle_t> socket_create_connected_pair(address_type domain,
																				 socket_type type) override;
		void socket_close(socket_handle_t socket) override;
		void socket_bind(socket_handle_t socket, endpoint ep) override;
		void socket_listen(socket_handle_t socket, size_t backlog) override;
		endpoint socket_local_endpoint(socket_handle_t socket) override;
		endpoint socket_remote_endpoint(socket_handle_t socket) override;
		void socket_enable_broadcast(socket_handle_t socket, bool enable) override;
		void socket_shutdown(socket_handle_t socket, bool receive, bool send) override;

		file_handle_t file_open(const char* filename, std::ios_base::openmode mode) override;
		void file_close(file_handle_t fd) override;
		uint64_t file_size(file_handle_t fd) override;

	private:
	};

} // namespace asyncpp::io::detail

#endif
