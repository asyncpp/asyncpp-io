#pragma once
#include <asyncpp/io/detail/cancel_awaitable.h>
#include <asyncpp/io/detail/io_engine.h>
#include <asyncpp/io/io_service.h>

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <streambuf>

namespace asyncpp::io {
	namespace detail {
// C++26 makes this trivial, but sofar this is only implemented on libstdc++ > 14 and libc++ > 18
#if defined(__cpp_lib_fstream_native_handle)
#define ASYNCPP_IO_HANDLE_FROM_FILEBUF 1
		template<typename CharT, typename Traits>
		inline auto get_file_handle_from_filebuf(const std::basic_filebuf<CharT, Traits>* buf) noexcept {
			return buf->native_handle();
		}
#elif defined(__GLIBCXX__) // Lets do a little magic, shall we ?
#define ASYNCPP_IO_HANDLE_FROM_FILEBUF 1
		template<typename CharT, typename Traits>
		inline auto get_file_handle_from_filebuf(const std::basic_filebuf<CharT, Traits>* buf) noexcept {
			if (!buf->is_open()) return -1;
			struct magic : std::basic_filebuf<CharT, Traits> {
				auto get_file() const noexcept { return &this->_M_file; }
			};
			// fd() is actually const because it only calls fileno on the c file, but its not marked as such
			auto f = const_cast<std::__basic_file<CharT>*>(static_cast<const magic*>(buf)->get_file());
			return f->fd();
		}
#elif defined(_LIBCPP_VERSION) // Lets do a little more magic, shall we ?
#define ASYNCPP_IO_HANDLE_FROM_FILEBUF 1
		template<typename CharT, typename Traits>
		inline auto get_file_handle_from_filebuf(const std::basic_filebuf<CharT, Traits>* buf) noexcept {
			// std::filebuf in libc++ has had this layout at least since version 1.0 (release 2010)
			// and we don't care if it changes in the future cause then __cpp_lib_fstream_native_handle above
			// will take over.
			struct magic : public std::basic_streambuf<CharT, Traits> {
				char* __extbuf_;
				const char* __extbufnext_;
				const char* __extbufend_;
				char __extbuf_min_[8];
				size_t __ebs_;
				CharT* __intbuf_;
				size_t __ibs_;
				FILE* __file_;
				const std::codecvt<CharT, char, typename Traits::state_type>* __cv_;
				typename Traits::state_type __st_;
				typename Traits::state_type __st_last_;
				std::ios_base::openmode __om_;
				std::ios_base::openmode __cm_;
				bool __owns_eb_;
				bool __owns_ib_;
				bool __always_noconv_;

				auto fd() const noexcept { return __file_ == nullptr ? -1 : fileno(__file_); }
			};
			static_assert(sizeof(magic) == sizeof(std::filebuf), "Implementation changed");
			return reinterpret_cast<const magic*>(buf)->fd();
		}
#endif

#ifndef ASYNCPP_IO_HANDLE_FROM_FILEBUF
#define ASYNCPP_IO_HANDLE_FROM_FILEBUF 0
#endif

#if ASYNCPP_IO_HANDLE_FROM_FILEBUF
		template<typename CharT, typename Traits>
		inline auto get_file_handle_from_filebuf(const std::basic_filebuf<CharT, Traits>& buf) {
			return get_file_handle_from_filebuf(&buf);
		}
		template<typename CharT, typename Traits>
		inline auto get_file_handle_from_filebuf(const std::basic_streambuf<CharT, Traits>* buf) {
			auto filebuf = dynamic_cast<const std::basic_filebuf<CharT, Traits>*>(buf);
			if (filebuf == nullptr) throw std::logic_error("not a filebuf");
			return get_file_handle_from_filebuf(filebuf);
		}
		template<typename CharT, typename Traits>
		inline auto get_file_handle_from_filebuf(const std::basic_streambuf<CharT, Traits>& buf) {
			return get_file_handle_from_filebuf(&buf);
		}
#endif

		class file_read_awaitable {
			file_read_awaitable(const file_read_awaitable&) = delete;
			file_read_awaitable(file_read_awaitable&&) = delete;
			file_read_awaitable& operator=(const file_read_awaitable&) = delete;
			file_read_awaitable& operator=(file_read_awaitable&&) = delete;

			template<typename T>
			friend class detail::cancellable_awaitable;

			io_engine* const m_engine;
			io_engine::file_handle_t const m_fd;
			void* const m_buf;
			size_t const m_len;
			uint64_t const m_offset;
			std::error_code* const m_ec;

		protected:
			detail::io_engine::completion_data m_completion;

		public:
			constexpr file_read_awaitable(io_engine* engine, io_engine::file_handle_t fd, void* buf, size_t len,
										  uint64_t offset, std::error_code* ec) noexcept
				: m_engine(engine), m_fd(fd), m_buf(buf), m_len(len), m_offset(offset), m_ec(ec), m_completion{} {}
			bool await_ready() const noexcept { return false; }
			bool await_suspend(coroutine_handle<> hdl) {
				m_completion.callback = [](void* ptr) { coroutine_handle<>::from_address(ptr).resume(); };
				m_completion.userdata = hdl.address();
				return !m_engine->enqueue_readv(m_fd, m_buf, m_len, m_offset, &m_completion);
			}
			size_t await_resume() {
				if (m_completion.result >= 0) return static_cast<size_t>(m_completion.result);
				if (m_ec == nullptr)
					throw std::system_error(std::error_code(-m_completion.result, std::system_category()));
				*m_ec = std::error_code(-m_completion.result, std::system_category());
				return 0;
			}
		};

		class file_write_awaitable {
			file_write_awaitable(const file_write_awaitable&) = delete;
			file_write_awaitable(file_write_awaitable&&) = delete;
			file_write_awaitable& operator=(const file_write_awaitable&) = delete;
			file_write_awaitable& operator=(file_write_awaitable&&) = delete;

			template<typename T>
			friend class detail::cancellable_awaitable;

			io_engine* const m_engine;
			io_engine::file_handle_t const m_fd;
			const void* const m_buf;
			size_t const m_len;
			uint64_t const m_offset;
			std::error_code* const m_ec;

		protected:
			detail::io_engine::completion_data m_completion;

		public:
			constexpr file_write_awaitable(io_engine* engine, io_engine::file_handle_t fd, const void* buf, size_t len,
										   uint64_t offset, std::error_code* ec) noexcept
				: m_engine(engine), m_fd(fd), m_buf(buf), m_len(len), m_offset(offset), m_ec(ec), m_completion{} {}
			bool await_ready() const noexcept { return false; }
			bool await_suspend(coroutine_handle<> hdl) {
				m_completion.callback = [](void* ptr) { coroutine_handle<>::from_address(ptr).resume(); };
				m_completion.userdata = hdl.address();
				return !m_engine->enqueue_writev(m_fd, m_buf, m_len, m_offset, &m_completion);
			}
			size_t await_resume() {
				if (m_completion.result >= 0) return static_cast<size_t>(m_completion.result);
				if (m_ec == nullptr)
					throw std::system_error(std::error_code(-m_completion.result, std::system_category()));
				*m_ec = std::error_code(-m_completion.result, std::system_category());
				return 0;
			}
		};

		class file_fsync_awaitable {
			file_fsync_awaitable(const file_fsync_awaitable&) = delete;
			file_fsync_awaitable(file_fsync_awaitable&&) = delete;
			file_fsync_awaitable& operator=(const file_fsync_awaitable&) = delete;
			file_fsync_awaitable& operator=(file_fsync_awaitable&&) = delete;

			template<typename T>
			friend class detail::cancellable_awaitable;

			io_engine* const m_engine;
			io_engine::file_handle_t const m_fd;
			std::error_code* const m_ec;

		protected:
			detail::io_engine::completion_data m_completion;

		public:
			constexpr file_fsync_awaitable(io_engine* engine, io_engine::file_handle_t fd, std::error_code* ec) noexcept
				: m_engine(engine), m_fd(fd), m_ec(ec), m_completion{} {}
			bool await_ready() const noexcept { return false; }
			bool await_suspend(coroutine_handle<> hdl) {
				m_completion.callback = [](void* ptr) { coroutine_handle<>::from_address(ptr).resume(); };
				m_completion.userdata = hdl.address();
				return !m_engine->enqueue_fsync(m_fd, io_engine::fsync_flags::none, &m_completion);
			}
			void await_resume() {
				if (m_completion.result >= 0) return;
				if (m_ec == nullptr)
					throw std::system_error(std::error_code(-m_completion.result, std::system_category()));
				*m_ec = std::error_code(-m_completion.result, std::system_category());
			}
		};
	} // namespace detail

	inline auto read(detail::io_engine& engine, detail::io_engine::file_handle_t fd, void* buf, size_t len,
					 uint64_t offset) {
		return detail::file_read_awaitable(&engine, fd, buf, len, offset, nullptr);
	}

	inline auto read(detail::io_engine& engine, detail::io_engine::file_handle_t fd, void* buf, size_t len,
					 uint64_t offset, std::error_code& ec) {
		return detail::file_read_awaitable(&engine, fd, buf, len, offset, &ec);
	}

	inline auto read(detail::io_engine& engine, detail::io_engine::file_handle_t fd, void* buf, size_t len,
					 uint64_t offset, asyncpp::stop_token st) {
		return detail::cancellable_awaitable<detail::file_read_awaitable>(std::move(st), &engine, fd, buf, len, offset,
																		  nullptr);
	}

	inline auto read(detail::io_engine& engine, detail::io_engine::file_handle_t fd, void* buf, size_t len,
					 uint64_t offset, asyncpp::stop_token st, std::error_code& ec) {
		return detail::cancellable_awaitable<detail::file_read_awaitable>(std::move(st), &engine, fd, buf, len, offset,
																		  &ec);
	}

	inline auto write(detail::io_engine& engine, detail::io_engine::file_handle_t fd, const void* buf, size_t len,
					  uint64_t offset) {
		return detail::file_write_awaitable(&engine, fd, buf, len, offset, nullptr);
	}

	inline auto write(detail::io_engine& engine, detail::io_engine::file_handle_t fd, const void* buf, size_t len,
					  uint64_t offset, std::error_code& ec) {
		return detail::file_write_awaitable(&engine, fd, buf, len, offset, &ec);
	}

	inline auto write(detail::io_engine& engine, detail::io_engine::file_handle_t fd, const void* buf, size_t len,
					  uint64_t offset, asyncpp::stop_token st) {
		return detail::cancellable_awaitable<detail::file_write_awaitable>(std::move(st), &engine, fd, buf, len, offset,
																		   nullptr);
	}

	inline auto write(detail::io_engine& engine, detail::io_engine::file_handle_t fd, const void* buf, size_t len,
					  uint64_t offset, asyncpp::stop_token st, std::error_code& ec) {
		return detail::cancellable_awaitable<detail::file_write_awaitable>(std::move(st), &engine, fd, buf, len, offset,
																		   &ec);
	}

	inline auto fsync(detail::io_engine& engine, detail::io_engine::file_handle_t fd) {
		return detail::file_fsync_awaitable(&engine, fd, nullptr);
	}

	inline auto fsync(detail::io_engine& engine, detail::io_engine::file_handle_t fd, std::error_code& ec) {
		return detail::file_fsync_awaitable(&engine, fd, &ec);
	}

	inline auto fsync(detail::io_engine& engine, detail::io_engine::file_handle_t fd, asyncpp::stop_token st) {
		return detail::cancellable_awaitable<detail::file_fsync_awaitable>(std::move(st), &engine, fd, nullptr);
	}

	inline auto fsync(detail::io_engine& engine, detail::io_engine::file_handle_t fd, asyncpp::stop_token st,
					  std::error_code& ec) {
		return detail::cancellable_awaitable<detail::file_fsync_awaitable>(std::move(st), &engine, fd, &ec);
	}

	class file {
		io_service* m_io;
		detail::io_engine::file_handle_t m_fd;

	public:
		explicit file(io_service& io);
		file(io_service& io, detail::io_engine::file_handle_t fd);
		explicit file(io_service& io, const char* filename,
					  std::ios_base::openmode mode = std::ios_base::in | std::ios_base::out);
		explicit file(io_service& io, const std::string& filename,
					  std::ios_base::openmode mode = std::ios_base::in | std::ios_base::out);
		explicit file(io_service& io, const std::filesystem::path& filename,
					  std::ios_base::openmode mode = std::ios_base::in | std::ios_base::out);
		file(const file&) = delete;
		file(file&&) noexcept;
		file& operator=(const file&) = delete;
		file& operator=(file&&);
		~file();

		[[nodiscard]] io_service& service() const noexcept { return *m_io; }
		[[nodiscard]] detail::io_engine::file_handle_t native_handle() const noexcept { return m_fd; }
		[[nodiscard]] detail::io_engine::file_handle_t release() noexcept {
			return std::exchange(m_fd, detail::io_engine::invalid_file_handle);
		}

		void open(const char* filename, std::ios_base::openmode mode = std::ios_base::in | std::ios_base::out);
		void open(const std::string& filename, std::ios_base::openmode mode = std::ios_base::in | std::ios_base::out);
		void open(const std::filesystem::path& filename,
				  std::ios_base::openmode mode = std::ios_base::in | std::ios_base::out);

		[[nodiscard]] bool is_open() const noexcept;
		[[nodiscard]] bool operator!() const noexcept { return !is_open(); }
		[[nodiscard]] operator bool() const noexcept { return is_open(); }

		void close();

		void swap(file& other);

		[[nodiscard]] uint64_t size();

		auto read(void* buf, size_t len, uint64_t offset) {
			return detail::file_read_awaitable(m_io->engine(), m_fd, buf, len, offset, nullptr);
		}
		auto read(void* buf, size_t len, uint64_t offset, std::error_code& ec) {
			return detail::file_read_awaitable(m_io->engine(), m_fd, buf, len, offset, &ec);
		}
		auto read(void* buf, size_t len, uint64_t offset, asyncpp::stop_token st) {
			return detail::cancellable_awaitable<detail::file_read_awaitable>(std::move(st), m_io->engine(), m_fd, buf,
																			  len, offset, nullptr);
		}
		auto read(void* buf, size_t len, uint64_t offset, asyncpp::stop_token st, std::error_code& ec) {
			return detail::cancellable_awaitable<detail::file_read_awaitable>(std::move(st), m_io->engine(), m_fd, buf,
																			  len, offset, &ec);
		}

		auto write(const void* buf, size_t len, uint64_t offset) {
			return detail::file_write_awaitable(m_io->engine(), m_fd, buf, len, offset, nullptr);
		}
		auto write(const void* buf, size_t len, uint64_t offset, std::error_code& ec) {
			return detail::file_write_awaitable(m_io->engine(), m_fd, buf, len, offset, &ec);
		}
		auto write(const void* buf, size_t len, uint64_t offset, asyncpp::stop_token st) {
			return detail::cancellable_awaitable<detail::file_write_awaitable>(std::move(st), m_io->engine(), m_fd, buf,
																			   len, offset, nullptr);
		}
		auto write(const void* buf, size_t len, uint64_t offset, asyncpp::stop_token st, std::error_code& ec) {
			return detail::cancellable_awaitable<detail::file_write_awaitable>(std::move(st), m_io->engine(), m_fd, buf,
																			   len, offset, &ec);
		}

		auto fsync() { return detail::file_fsync_awaitable(m_io->engine(), m_fd, nullptr); }
		auto fsync(std::error_code& ec) { return detail::file_fsync_awaitable(m_io->engine(), m_fd, &ec); }
		auto fsync(asyncpp::stop_token st) {
			return detail::cancellable_awaitable<detail::file_fsync_awaitable>(std::move(st), m_io->engine(), m_fd,
																			   nullptr);
		}
		auto fsync(asyncpp::stop_token st, std::error_code& ec) {
			return detail::cancellable_awaitable<detail::file_fsync_awaitable>(std::move(st), m_io->engine(), m_fd,
																			   &ec);
		}
	};

	inline void swap(file& lhs, file& rhs) { lhs.swap(rhs); }
} // namespace asyncpp::io
