#include <asyncpp/io/file.h>

namespace asyncpp::io {
	file::file(io_service& io) : m_io(&io), m_fd(detail::io_engine::invalid_file_handle) {}
	file::file(io_service& io, detail::io_engine::file_handle_t fd) : m_io(&io), m_fd(fd) {}
	file::file(io_service& io, const char* filename, std::ios_base::openmode mode) : file(io) { open(filename, mode); }
	file::file(io_service& io, const std::string& filename, std::ios_base::openmode mode) : file(io) {
		open(filename, mode);
	}
	file::file(io_service& io, const std::filesystem::path& filename, std::ios_base::openmode mode) : file(io) {
		open(filename, mode);
	}
	file::file(file&& other) noexcept
		: m_io(std::exchange(other.m_io, nullptr)),
		  m_fd(std::exchange(other.m_fd, detail::io_engine::invalid_file_handle)) {}
	file& file::operator=(file&& other) noexcept {
		close();
		m_io = std::exchange(other.m_io, nullptr);
		m_fd = std::exchange(other.m_fd, detail::io_engine::invalid_file_handle);
		return *this;
	}
	file::~file() { close(); }

	void file::open(const char* filename, std::ios_base::openmode mode) {
		auto res = m_io->engine()->file_open(filename, mode);
		close();
		m_fd = res;
	}
	void file::open(const std::string& filename, std::ios_base::openmode mode) { return open(filename.c_str(), mode); }
	void file::open(const std::filesystem::path& filename, std::ios_base::openmode mode) {
		return open(filename.string().c_str(), mode);
	}

	bool file::is_open() const noexcept { return m_io != nullptr && m_fd != detail::io_engine::invalid_file_handle; }

	void file::close() {
		if (m_fd != detail::io_engine::invalid_file_handle) {
			m_io->engine()->file_close(m_fd);
			m_fd = detail::io_engine::invalid_file_handle;
		}
	}

	void file::swap(file& other) {
		std::swap(m_io, other.m_io);
		std::swap(m_fd, other.m_fd);
	}

	uint64_t file::size() { return m_io->engine()->file_size(m_fd); }
} // namespace asyncpp::io
