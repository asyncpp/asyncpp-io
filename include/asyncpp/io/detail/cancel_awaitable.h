#pragma once
#include <asyncpp/detail/std_import.h>
#include <asyncpp/io/detail/io_engine.h>
#include <asyncpp/stop_token.h>

#include <mutex>
#include <optional>

namespace asyncpp::io::detail {
	struct cancel_io_stop_callback {
		io_engine::completion_data* m_data;
		io_engine* m_engine;
		void operator()() noexcept {
			if (m_engine && m_data) m_engine->cancel(m_data);
		}
	};

	template<typename T>
	class cancellable_awaitable {
		T m_child;
		asyncpp::stop_token m_stop_token;
		std::optional<asyncpp::stop_callback<cancel_io_stop_callback>> m_cancel_callback;
		std::mutex m_mtx;

	public:
		template<typename... Args>
		cancellable_awaitable(asyncpp::stop_token st, Args&&... args) noexcept
			: m_child(std::forward<Args>(args)...), m_stop_token{std::move(st)} {}
		bool await_ready() const noexcept { return m_child.await_ready(); }
		bool await_suspend(coroutine_handle<> hdl) {
			std::unique_lock lck(m_mtx);
			if (m_stop_token.stop_requested()) {
				m_child.m_completion.result = std::make_error_code(std::errc::operation_canceled);
				return false;
			}
			auto res = m_child.await_suspend(hdl);
			if (res)
				m_cancel_callback.emplace(
					m_stop_token, cancel_io_stop_callback{&m_child.m_completion, m_child.m_socket.service().engine()});
			return res;
		}
		auto await_resume() {
			std::unique_lock lck(m_mtx);
			return m_child.await_resume();
		}
	};
} // namespace asyncpp::io::detail
