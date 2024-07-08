#pragma once
#include <asyncpp/detail/std_import.h>
#include <asyncpp/dispatcher.h>
#include <asyncpp/io/detail/io_engine.h>
#include <asyncpp/io/endpoint.h>
#include <asyncpp/threadsafe_queue.h>

#include <memory>

namespace asyncpp::io {
	namespace detail {
		class io_engine;
	}
	class io_service : public dispatcher {
		std::unique_ptr<detail::io_engine> m_engine;
		threadsafe_queue<std::function<void()>> m_dispatched;
		bool m_stopped{false};

	public:
		enum class run_mode {
			until_stopped,
			while_active,
			once,
			nowait,
		};

		io_service();
		io_service(const io_service&) = delete;
		io_service(io_service&&) = delete;
		io_service& operator=(const io_service&) = delete;
		io_service& operator=(io_service&&) = delete;
		~io_service() noexcept(false);

		bool run(run_mode mode = run_mode::while_active);
		void stop();
		bool stopped() const noexcept { return m_stopped; }

		void push(std::function<void()> fn) override;

		detail::io_engine* engine() noexcept { return m_engine.get(); }

		static std::shared_ptr<io_service> get_default();
	};
} // namespace asyncpp::io
