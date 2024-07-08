#include <asyncpp/io/detail/io_engine.h>
#include <asyncpp/io/io_service.h>

#include <thread>

namespace asyncpp::io {

	io_service::io_service() : m_engine(detail::create_io_engine()) {}

	io_service::~io_service() noexcept(false) {}

	bool io_service::run(run_mode mode) {
		if (mode == run_mode::until_stopped) {
			bool had_tasks = false;
			while (!m_stopped)
				had_tasks = run(run_mode::once);
			return had_tasks;
		} else if (mode == run_mode::while_active) {
			bool had_tasks = true;
			while (had_tasks)
				had_tasks = run(run_mode::once);
			return true;
		}

		auto old_disp = dispatcher::current(this);
		auto had_tasks = m_engine->run(mode == run_mode::nowait) != 0;
		auto task = m_dispatched.pop();
		while (task.has_value()) {
			had_tasks = true;
			task.value()();
			task = m_dispatched.pop();
		}
		dispatcher::current(old_disp);
		return had_tasks;
	}

	void io_service::stop() {
		m_stopped = true;
		if (dispatcher::current() != this) m_engine->wake();
	}

	void io_service::push(std::function<void()> fn) {
		m_dispatched.push(std::move(fn));
		if (dispatcher::current() != this) m_engine->wake();
	}

	namespace {
		class default_io_service final : public io_service {
		public:
			default_io_service() {
				m_thread = std::thread([this]() {
#ifdef __linux__
					pthread_setname_np(pthread_self(), "dflt_io_srv");
#endif
					this->run(run_mode::until_stopped);
				});
			}
			~default_io_service() {
				this->stop();
				if (m_thread.joinable()) m_thread.join();
			}

		private:
			std::thread m_thread;
		};
	} // namespace

	std::shared_ptr<io_service> io_service::get_default() {
		static auto instance = std::make_shared<default_io_service>();
		return instance;
	}
} // namespace asyncpp::io
