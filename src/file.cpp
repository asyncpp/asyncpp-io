#include <asyncpp/io/file.h>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#else
#include <Windows.h>
#endif

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
	file& file::operator=(file&& other) {
		close();
		m_io = std::exchange(other.m_io, nullptr);
		m_fd = std::exchange(other.m_fd, detail::io_engine::invalid_file_handle);
		return *this;
	}
	file::~file() { close(); }

	void file::open(const char* filename, std::ios_base::openmode mode) {
#ifndef _WIN32
		if ((mode & std::ios_base::ate) == std::ios_base::ate) throw std::logic_error("unsupported flag");
		int m = 0;
		if ((mode & std::ios_base::app) == std::ios_base::app) m |= O_APPEND;
		if ((mode & std::ios_base::in) == std::ios_base::in)
			m |= ((mode & std::ios_base::out) == std::ios_base::out) ? O_RDWR : O_RDONLY;
		else if ((mode & std::ios_base::out) == std::ios_base::out)
			m |= O_WRONLY;
		else
			throw std::invalid_argument("neither std::ios::in, nor std::ios::out was specified");
		if ((mode & std::ios_base::trunc) == std::ios_base::trunc) m |= O_TRUNC;
		auto res = ::open(filename, m, 0660);
		if (res < 0) throw std::system_error(errno, std::system_category());
#else
		DWORD access_mode = 0;
		if ((mode & std::ios_base::in) == std::ios_base::in) access_mode |= GENERIC_READ;
		if ((mode & std::ios_base::out) == std::ios_base::out) access_mode |= GENERIC_WRITE;
		if ((mode & (std::ios_base::in | std::ios_base::out)) == 0)
			throw std::invalid_argument("neither std::ios::in, nor std::ios::out was specified");
		HANDLE h = CreateFileA(filename, access_mode, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
		// TODO: Remaining code
#endif
		close();
		m_fd = res;
	}
	void file::open(const std::string& filename, std::ios_base::openmode mode) { return open(filename.c_str(), mode); }
	void file::open(const std::filesystem::path& filename, std::ios_base::openmode mode) {
		return open(filename.c_str(), mode);
	}

	bool file::is_open() const noexcept { return m_io != nullptr && m_fd != detail::io_engine::invalid_file_handle; }

	void file::close() {
		if (m_fd != detail::io_engine::invalid_file_handle) {
#ifndef _WIN32
			::close(m_fd);
#else
			::CloseHandle(m_fd);
#endif
			m_fd = detail::io_engine::invalid_file_handle;
		}
	}

	void file::swap(file& other) {
		std::swap(m_io, other.m_io);
		std::swap(m_fd, other.m_fd);
	}

	uint64_t file::size() {
#ifdef __APPLE__
		struct stat info {};
		auto res = fstat(m_fd, &info);
#elif defined(_WIN32)
		struct _stat64 info {};
		auto res = _fstat64(m_fd, &info);
#else
		struct stat64 info {};
		auto res = fstat64(m_fd, &info);
#endif
		if (res < 0) throw std::system_error(errno, std::system_category());
		return info.st_size;
	}
} // namespace asyncpp::io
