#pragma once
#include <asyncpp/detail/std_import.h>

#include <chrono>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <ostream>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace asyncpp::io::tls {
	enum class method {
		tls,
		sslv3,
		tlsv1,
		tlsv1_1,
		tlsv1_2,
		dtls,
		dtlsv1,
		dtlsv1_2,
	};

	enum class mode { server, client };

	enum class file_type { pem };

	enum class verify_mode { none = 0, peer = 1, fail_if_no_cert = 2, verify_once = 4, verify_post_handshake = 8 };
	inline verify_mode operator|(verify_mode a, verify_mode b) noexcept {
		using type = std::underlying_type_t<verify_mode>;
		return static_cast<verify_mode>(static_cast<type>(a) | static_cast<type>(b));
	}
	inline bool operator&(verify_mode a, verify_mode b) noexcept {
		using type = std::underlying_type_t<verify_mode>;
		return (static_cast<type>(a) & static_cast<type>(b)) != 0;
	}

	class session;
	class cipher;
	class x509;
	class context {
	public:
		class client_hello {
			friend class context;
			void* m_ssl{};
			mutable std::vector<cipher> m_ciphers;
			mutable std::vector<cipher> m_signalling_ciphers;
			mutable std::set<unsigned int> m_extensions_preset;

			client_hello(void* ssl) noexcept;
			client_hello(const client_hello& other) = default;
			client_hello& operator=(const client_hello& other) = default;

		public:
			bool is_v2() const noexcept;
			std::span<const std::byte> random() const noexcept;
			std::span<const std::byte> session_id() const noexcept;
			const std::vector<cipher>& ciphers() const;
			const std::vector<cipher>& signalling_ciphers() const;
			std::span<const std::byte> compression_methods() const noexcept;
			const std::set<unsigned int>& extensions() const;
			bool has_extension(unsigned int type) const;
			std::span<const std::byte> extension(unsigned int type) const noexcept;
			void replace_context(context& new_context) const noexcept;

			session* get_session() const noexcept;

			// Helpers
			std::string_view server_name_indication() const noexcept;
		};

	private:
		const method m_method{};
		const mode m_mode{};
		void* m_ctx{};
		std::function<size_t(char* buf, size_t len, bool encrypt)> m_passwd_cb;
		std::function<bool(const client_hello& info, int& alert_value)> m_client_hello_cb;
		std::function<bool(session&, std::string_view& selected, const std::span<const std::string_view>& protocols)>
			m_alpn_select_cb;
		std::function<void(session&)> m_cert_cb;

		friend class session;

	public:
		context(method meth = method::tls, mode m = mode::client);
		context(const context&) = delete;
		context(context&&) = delete;
		context& operator=(const context&) = delete;
		context& operator=(context&&) = delete;
		~context();

		method get_method() const noexcept { return m_method; }
		mode get_mode() const noexcept { return m_mode; }

		void use_certificate(const std::string& file, file_type type = file_type::pem);
		void use_privatekey(const std::string& file, file_type type = file_type::pem);
		void set_passwd_callback(std::function<size_t(char* buf, size_t len, bool encrypt)> cb);
		void set_passwd(std::string passwd);
		void set_client_hello_callback(std::function<bool(const client_hello& info, int& alert_value)> cb);
		void set_verify(verify_mode mode);
		void set_default_verify_paths();
		void set_default_verify_dir();
		void set_default_verify_file();
		void load_verify_locations(const std::string& file, const std::string& path);
		std::vector<cipher> ciphers() const;
		void set_alpn_protos(const std::vector<std::string>& protos);
		void set_alpn_select_callback(std::function<bool(session&, std::string_view& selected,
														 const std::span<const std::string_view>& protocols)>
										  cb);
		void set_certificate_callback(std::function<void(session&)> cb);

		std::vector<x509> get_chain_certs() const;
		void clear_chain_certs();

		void debug();
	};

	class cipher_write_awaitable;
	class cipher_read_awaitable;
	class plain_write_awaitable;
	class plain_read_awaitable;
	class handshake_awaitable;
	class session {
		void* m_ssl{};
		void* m_input_bio{};
		void* m_output_bio{};
		std::function<void(session&)> m_cert_cb{};

		cipher_read_awaitable* m_cipher_readers{};
		cipher_write_awaitable* m_cipher_writers{};
		plain_read_awaitable* m_plain_readers{};
		plain_write_awaitable* m_plain_writers{};
		handshake_awaitable* m_handshakers{};

		friend class cipher_write_awaitable;
		friend class cipher_read_awaitable;
		friend class plain_write_awaitable;
		friend class plain_read_awaitable;
		friend class handshake_awaitable;

		bool try_resume_cipher_read();
		bool try_resume_cipher_write();
		void try_resume_plain();

	public:
		session(const context& ctx);
		session(const session&) = delete;
		session(session&&) = delete;
		session& operator=(const session&) = delete;
		session& operator=(session&&) = delete;
		~session();

		int try_handshake();
		[[nodiscard]] handshake_awaitable handshake() noexcept;

		void shutdown();

		[[nodiscard]] plain_write_awaitable write(const void* buffer, size_t len) noexcept;
		[[nodiscard]] plain_read_awaitable read(void* buf, size_t len) noexcept;
		[[nodiscard]] bool try_write(const void* buffer, size_t len, size_t& read);
		[[nodiscard]] bool try_read(void* buf, size_t len, size_t& written);

		[[nodiscard]] cipher_write_awaitable cipher_write(const void* buffer, size_t len) noexcept;
		[[nodiscard]] cipher_read_awaitable cipher_read(void* buffer, size_t len) noexcept;

		cipher current_cipher() const noexcept;
		cipher pending_cipher() const noexcept;
		std::vector<cipher> ciphers() const;
		std::vector<cipher> supported_ciphers() const;
		std::vector<cipher> client_ciphers() const;
		std::string_view get_servername() const noexcept;
		void set_servername(const std::string& name);
		void set_verify(verify_mode mode);
		void set_alpn_protos(const std::vector<std::string>& protos);
		std::string_view alpn_selected() const noexcept;
		void set_certificate_callback(std::function<void(session&)> cb);
		x509 get_peer_certificate() const noexcept;
	};

	class cipher {
		const void* m_cipher{};
		mutable char* m_description{};

		friend class context;
		friend class session;

		constexpr cipher(const void* ptr) noexcept : m_cipher(ptr) {}

	public:
		constexpr cipher() noexcept = default;
		constexpr cipher(const cipher& other) noexcept : m_cipher(other.m_cipher) {}
		constexpr cipher& operator=(const cipher& other) noexcept {
			m_cipher = other.m_cipher;
			return *this;
		}
		~cipher();

		bool operator!() const noexcept { return m_cipher == nullptr; }
		operator bool() const noexcept { return m_cipher != nullptr; }
		bool valid() const noexcept { return m_cipher != nullptr; }

		std::string_view name() const noexcept;
		std::string_view standard_name() const noexcept;
		std::string_view cipher_name() const noexcept;
		size_t bit_count() const noexcept;
		std::string_view version() const noexcept;
		std::string_view description() const noexcept;
		int cipher_nid() const noexcept;
		int digest_nid() const noexcept;
		int kx_nid() const noexcept;
		int auth_nid() const noexcept;
		bool is_aead() const noexcept;
		uint32_t id() const noexcept;
		uint32_t protocol_id() const noexcept;
	};
	std::ostream& operator<<(std::ostream& str, const cipher& cipher);

	class x509 {
		void* m_x509;
		friend class context;
		friend class session;

		constexpr x509(void* x509) noexcept : m_x509(x509) {}

	public:
		constexpr x509(x509&& other) noexcept : m_x509(other.m_x509) { other.m_x509 = nullptr; }
		constexpr x509& operator=(x509&& other) noexcept {
			m_x509 = other.m_x509;
			other.m_x509 = nullptr;
			return *this;
		}
		~x509();

		bool operator!() const noexcept { return m_x509 == nullptr; }
		operator bool() const noexcept { return m_x509 != nullptr; }
		bool valid() const noexcept { return m_x509 != nullptr; }

		std::string to_der() const;
		std::string to_pem() const;

		static x509 from_der(const void* ptr, size_t len);
		static x509 from_pem(const void* ptr, size_t len);

		std::chrono::system_clock::time_point not_before() const noexcept;
		std::chrono::system_clock::time_point not_after() const noexcept;
		std::string subject() const;
		std::string issuer() const;

		friend std::strong_ordering operator<=>(const x509& lhs, const x509& rhs) noexcept;
		friend bool operator==(const x509& lhs, const x509& rhs) noexcept;
		friend bool operator!=(const x509& lhs, const x509& rhs) noexcept;
	};

	class plain_read_awaitable {
		plain_read_awaitable(const plain_read_awaitable&) = delete;
		plain_read_awaitable(plain_read_awaitable&&) = delete;
		plain_read_awaitable& operator=(const plain_read_awaitable&) = delete;
		plain_read_awaitable& operator=(plain_read_awaitable&&) = delete;
		friend class session;

		session& m_session;
		void* const m_buffer;
		size_t const m_len;
		size_t m_result{};
		coroutine_handle<> m_handle{};
		plain_read_awaitable* m_next{};

		bool try_resume();

	public:
		constexpr plain_read_awaitable(session& sess, void* buffer, size_t len) noexcept
			: m_session{sess}, m_buffer{buffer}, m_len{len} {}

		bool await_ready() const noexcept;
		bool await_suspend(coroutine_handle<> hdl);
		size_t await_resume();
	};

	class plain_write_awaitable {
		plain_write_awaitable(const plain_write_awaitable&) = delete;
		plain_write_awaitable(plain_write_awaitable&&) = delete;
		plain_write_awaitable& operator=(const plain_write_awaitable&) = delete;
		plain_write_awaitable& operator=(plain_write_awaitable&&) = delete;
		friend class session;

		session& m_session;
		const void* const m_buffer;
		size_t const m_len;
		size_t m_result{};
		coroutine_handle<> m_handle{};
		plain_write_awaitable* m_next{};

		bool try_resume();

	public:
		constexpr plain_write_awaitable(session& sess, const void* buffer, size_t len) noexcept
			: m_session{sess}, m_buffer{buffer}, m_len{len} {}

		bool await_ready() const noexcept;
		bool await_suspend(coroutine_handle<> hdl);
		size_t await_resume();
	};

	class cipher_read_awaitable {
		cipher_read_awaitable(const cipher_read_awaitable&) = delete;
		cipher_read_awaitable(cipher_read_awaitable&&) = delete;
		cipher_read_awaitable& operator=(const cipher_read_awaitable&) = delete;
		cipher_read_awaitable& operator=(cipher_read_awaitable&&) = delete;
		friend class session;

		session& m_session;
		void* const m_buffer;
		size_t const m_len;
		size_t m_result{};
		coroutine_handle<> m_handle{};
		cipher_read_awaitable* m_next{};

		bool try_resume();

	public:
		constexpr cipher_read_awaitable(session& sess, void* buffer, size_t len) noexcept
			: m_session{sess}, m_buffer{buffer}, m_len{len} {}

		bool await_ready() const noexcept;
		bool await_suspend(coroutine_handle<> hdl);
		size_t await_resume();
	};

	class cipher_write_awaitable {
		cipher_write_awaitable(const cipher_write_awaitable&) = delete;
		cipher_write_awaitable(cipher_write_awaitable&&) = delete;
		cipher_write_awaitable& operator=(const cipher_write_awaitable&) = delete;
		cipher_write_awaitable& operator=(cipher_write_awaitable&&) = delete;
		friend class session;

		session& m_session;
		const void* const m_buffer;
		size_t const m_len;
		size_t m_result{};
		coroutine_handle<> m_handle{};
		cipher_write_awaitable* m_next{};

		bool try_resume();

	public:
		constexpr cipher_write_awaitable(session& sess, const void* buffer, size_t len) noexcept
			: m_session{sess}, m_buffer{buffer}, m_len{len} {}

		bool await_ready() const noexcept;
		bool await_suspend(coroutine_handle<> hdl);
		size_t await_resume();
	};

	class handshake_awaitable {
		handshake_awaitable(const handshake_awaitable&) = delete;
		handshake_awaitable(handshake_awaitable&&) = delete;
		handshake_awaitable& operator=(const handshake_awaitable&) = delete;
		handshake_awaitable& operator=(handshake_awaitable&&) = delete;
		friend class session;

		session& m_session;
		int m_result{};
		coroutine_handle<> m_handle{};
		handshake_awaitable* m_next{};

		bool try_resume();

	public:
		constexpr handshake_awaitable(session& sess) noexcept : m_session{sess} {}

		bool await_ready() const noexcept;
		bool await_suspend(coroutine_handle<> hdl);
		void await_resume();
	};

	[[nodiscard]] inline handshake_awaitable session::handshake() noexcept { return handshake_awaitable(*this); }

	[[nodiscard]] inline plain_write_awaitable session::write(const void* buffer, size_t len) noexcept {
		return plain_write_awaitable(*this, buffer, len);
	}

	[[nodiscard]] inline plain_read_awaitable session::read(void* buffer, size_t len) noexcept {
		return plain_read_awaitable(*this, buffer, len);
	}

	[[nodiscard]] inline cipher_write_awaitable session::cipher_write(const void* buffer, size_t len) noexcept {
		return cipher_write_awaitable(*this, buffer, len);
	}

	[[nodiscard]] inline cipher_read_awaitable session::cipher_read(void* buffer, size_t len) noexcept {
		return cipher_read_awaitable(*this, buffer, len);
	}

} // namespace asyncpp::io::tls
