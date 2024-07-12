#include <asyncpp/io/detail/io_engine.h>

#include <stdexcept>

namespace asyncpp::io::detail {
	// Select is always supported on posix
	std::unique_ptr<io_engine> create_io_engine_select();
	// Only supported on Linux on kernel 5.1+
	std::unique_ptr<io_engine> create_io_engine_uring();
	// Win32 completion queue
	std::unique_ptr<io_engine> create_io_engine_win32cq();

	std::unique_ptr<io_engine> create_io_engine() {
		if (const auto env = getenv("ASYNCPP_IO_ENGINE"); env != nullptr) {
			std::string_view engine = env;
			if (engine == "uring")
				return create_io_engine_uring();
			else if (engine == "select")
				return create_io_engine_select();
			else if (engine == "win32cq")
				return create_io_engine_win32cq();
			else if (!engine.empty())
				throw std::runtime_error("unknown io engine " + std::string(engine));
		}
#ifdef _WIN32
		return create_io_engine_win32cq();
#else
		if (auto uring = create_io_engine_uring(); uring != nullptr) return uring;
		return create_io_engine_select();
#endif
	}
} // namespace asyncpp::io::detail
