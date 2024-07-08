#include <asyncpp/io/detail/io_engine.h>

#include <stdexcept>

namespace asyncpp::io::detail {
	// Select is always supported
	std::unique_ptr<io_engine> create_io_engine_select();
	// Only supported on Linux on kernel 5.1+
	std::unique_ptr<io_engine> create_io_engine_uring();

	std::unique_ptr<io_engine> create_io_engine() {
		if (const auto env = getenv("ASYNCPP_IO_ENGINE"); env != nullptr) {
			std::string_view engine = env;
			if (engine == "uring")
				return create_io_engine_uring();
			else if (engine == "select")
				return create_io_engine_select();
			else if (!engine.empty())
				throw std::runtime_error("unknown io engine " + std::string(engine));
		}
		if (auto uring = create_io_engine_uring(); uring != nullptr) return uring;
		return create_io_engine_select();
	}
} // namespace asyncpp::io::detail
