#include <asyncpp/io/tls.h>
#include <asyncpp/scope_guard.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include <cassert>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <memory>
#include <openssl/x509.h>
#include <stdexcept>
#include <string_view>

namespace asyncpp::io::tls {
	namespace {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
		const SSL_METHOD* ossl_method_from_enum(method meth, mode m) {
			switch (meth) {
			case method::tls: return m == mode::server ? TLS_server_method() : TLS_client_method();
#ifndef OPENSSL_NO_SSL3_METHOD
			case method::sslv3: return m == mode::server ? SSLv3_server_method() : SSLv3_client_method();
#endif
			case method::tlsv1: return m == mode::server ? TLSv1_server_method() : TLSv1_client_method();
			case method::tlsv1_1: return m == mode::server ? TLSv1_1_server_method() : TLSv1_1_client_method();
			case method::tlsv1_2: return m == mode::server ? TLSv1_2_server_method() : TLSv1_2_client_method();
			case method::dtls: return m == mode::server ? DTLS_server_method() : DTLS_client_method();
			case method::dtlsv1: return m == mode::server ? DTLSv1_server_method() : DTLSv1_client_method();
			case method::dtlsv1_2: return m == mode::server ? DTLSv1_2_server_method() : DTLSv1_2_client_method();
			default: throw std::logic_error("invalid method");
			}
		}
#pragma GCC diagnostic pop

		void throw_ossl_error() {
			auto error = ERR_get_error();
			ERR_clear_error();
			char buf[128];
			ERR_error_string_n(error, buf, sizeof(buf));
			throw std::runtime_error("Openssl failed: " + std::to_string(error) + " " + std::string(buf));
		}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
		int set_null_on_dup(CRYPTO_EX_DATA* to, const CRYPTO_EX_DATA*, void**, int idx, long, void*) {
#else
		int set_null_on_dup(CRYPTO_EX_DATA* to, const CRYPTO_EX_DATA*, void*, int idx, long, void*) {
#endif
			CRYPTO_set_ex_data(to, idx, nullptr);
			return 1;
		}

		int context_udi() {
			static int index = SSL_CTX_get_ex_new_index(0, nullptr, nullptr, set_null_on_dup, nullptr);
			if (index < 0) throw std::runtime_error("Failed to register custom data");
			return index;
		}

		int ssl_udi() {
			static int index = SSL_get_ex_new_index(0, nullptr, nullptr, set_null_on_dup, nullptr);
			if (index < 0) throw std::runtime_error("Failed to register custom data");
			return index;
		}
	} // namespace

	context::context(method meth, mode m) : m_method(meth), m_mode(m) {
		auto ossl_method = ossl_method_from_enum(meth, m);
		if (ossl_method == nullptr) throw_ossl_error();
		const auto udi = context_udi();
		auto ctx = SSL_CTX_new(ossl_method);
		if (ctx == nullptr) throw_ossl_error();
		m_ctx = ctx;
		SSL_CTX_set_ex_data(ctx, udi, this);
		SSL_CTX_set_options(ctx, SSL_OP_ALL);
		SSL_CTX_set_default_verify_paths(ctx);
		if (m_mode == mode::client) SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
	}

	context::~context() {
		if (m_ctx) {
			assert(SSL_CTX_get_ex_data(static_cast<SSL_CTX*>(m_ctx), context_udi()) == this);
			SSL_CTX_free(static_cast<SSL_CTX*>(m_ctx));
		}
	}

	void context::use_certificate(const std::string& file, file_type type) {
		if (SSL_CTX_use_certificate_chain_file(static_cast<SSL_CTX*>(m_ctx), file.c_str()) != 1) throw_ossl_error();
	}

	void context::use_privatekey(const std::string& file, file_type type) {
		if (SSL_CTX_use_PrivateKey_file(static_cast<SSL_CTX*>(m_ctx), file.c_str(), SSL_FILETYPE_PEM) != 1)
			throw_ossl_error();
		if (!SSL_CTX_check_private_key(static_cast<SSL_CTX*>(m_ctx))) throw_ossl_error();
	}

	void context::set_passwd_callback(std::function<size_t(char* buf, size_t len, bool encrypt)> cb) {
		m_passwd_cb = std::move(cb);
		SSL_CTX_set_default_passwd_cb(static_cast<SSL_CTX*>(m_ctx), [](char* buf, int len, int rw, void* udata) -> int {
			auto that = static_cast<context*>(udata);
			if (that->m_passwd_cb) return that->m_passwd_cb(buf, len, rw == 1);
			buf[0] = '\0';
			return 0;
		});
		SSL_CTX_set_default_passwd_cb_userdata(static_cast<SSL_CTX*>(m_ctx), this);
	}

	void context::set_passwd(std::string passwd) {
		set_passwd_callback([passwd = std::move(passwd)](char* buf, size_t len, bool encrypt) -> size_t {
			strncpy(buf, passwd.c_str(), len);
			buf[len - 1] = '\0';
			return strlen(buf);
		});
	}

	void context::set_client_hello_callback(std::function<bool(const client_hello& info, int& alert_value)> cb) {
		m_client_hello_cb = std::move(cb);
		SSL_CTX_set_client_hello_cb(
			static_cast<SSL_CTX*>(m_ctx),
			[](SSL* ssl, int* al, void* udata) -> int {
				auto that = static_cast<context*>(udata);
				client_hello hello(ssl);
				if (that->m_client_hello_cb)
					return that->m_client_hello_cb(hello, *al) ? SSL_CLIENT_HELLO_SUCCESS : SSL_CLIENT_HELLO_ERROR;
				return SSL_CLIENT_HELLO_SUCCESS;
			},
			this);
	}

	void context::set_verify(verify_mode mode) {
		auto sslmode = SSL_VERIFY_NONE;
		if (mode & verify_mode::peer) sslmode = SSL_VERIFY_PEER;
		if (mode & verify_mode::fail_if_no_cert) sslmode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
		if (mode & verify_mode::verify_once) sslmode |= SSL_VERIFY_CLIENT_ONCE;
		if (mode & verify_mode::verify_post_handshake) sslmode |= SSL_VERIFY_POST_HANDSHAKE;
		SSL_CTX_set_verify(static_cast<SSL_CTX*>(m_ctx), sslmode, nullptr);
	}

	void context::set_default_verify_paths() {
		if (SSL_CTX_set_default_verify_paths(static_cast<SSL_CTX*>(m_ctx)) != 1) throw_ossl_error();
	}

	void context::set_default_verify_dir() {
		if (SSL_CTX_set_default_verify_dir(static_cast<SSL_CTX*>(m_ctx)) != 1) throw_ossl_error();
	}

	void context::set_default_verify_file() {
		if (SSL_CTX_set_default_verify_file(static_cast<SSL_CTX*>(m_ctx)) != 1) throw_ossl_error();
	}

	void context::load_verify_locations(const std::string& file, const std::string& path) {
		if (SSL_CTX_load_verify_locations(static_cast<SSL_CTX*>(m_ctx), file.empty() ? nullptr : file.c_str(),
										  path.empty() ? nullptr : path.c_str()) != 1)
			throw_ossl_error();
	}

	std::vector<cipher> context::ciphers() const {
		auto ciphers = SSL_CTX_get_ciphers(static_cast<SSL_CTX*>(m_ctx));
		if (ciphers == nullptr) return {};
		std::vector<cipher> result(sk_SSL_CIPHER_num(ciphers));
		for (size_t i = 0; i < result.size(); i++)
			result[i] = cipher(sk_SSL_CIPHER_value(ciphers, i));
		return result;
	}

	void context::set_alpn_protos(const std::vector<std::string>& protos) {
		if (protos.empty()) throw std::runtime_error("alpn list must not be empty");
		size_t list_length = 0;
		for (auto& e : protos) {
			if (e.empty()) continue;
			if (e.size() > 255) throw std::runtime_error("alpn too large");
			list_length += 1 + e.size();
		}
		std::vector<uint8_t> list(list_length);
		for (size_t i = 0; auto& e : protos) {
			if (e.empty()) continue;
			list[i] = e.size();
			memcpy(&list[i + 1], e.data(), e.size());
			i += 1 + e.size();
		}
		if (SSL_CTX_set_alpn_protos(static_cast<SSL_CTX*>(m_ctx), list.data(), list.size()) != 0)
			throw std::runtime_error("failed to set alpn protocols");
	}

	void context::set_alpn_select_callback(
		std::function<bool(session&, std::string_view& selected, const std::span<const std::string_view>& protocols)>
			cb) {
		m_alpn_select_cb = std::move(cb);
		SSL_CTX_set_alpn_select_cb(
			static_cast<SSL_CTX*>(m_ctx),
			[](SSL* ssl, const unsigned char** out, unsigned char* outlen, const unsigned char* in, unsigned int inlen,
			   void* arg) -> int {
				const auto that = static_cast<context*>(arg);
				const auto wrapper = static_cast<session*>(SSL_get_ex_data(ssl, ssl_udi()));
				// Early out if no callback is set
				if (that == nullptr || wrapper == nullptr || !that->m_alpn_select_cb) return SSL_TLSEXT_ERR_NOACK;

				// Figure out number of protocols available
				size_t num_protocols = 0;
				for (unsigned int i = 0; i < inlen; i += 1 + in[i]) {
					if (i + in[i] + 1 > inlen) return SSL_TLSEXT_ERR_NOACK;
					num_protocols++;
				}

				// Allocate and fill string_view array
				std::unique_ptr<std::string_view[]> protocols_ptr(new (std::nothrow) std::string_view[num_protocols]);
				if (!protocols_ptr) return SSL_TLSEXT_ERR_NOACK;
				std::span<std::string_view> protocols{protocols_ptr.get(), num_protocols};
				for (unsigned int i = 0, ip = 0; i < inlen; i += 1 + in[i])
					protocols[ip++] = {reinterpret_cast<const char*>(&in[i + 1]), in[i]};

				// Call callback
				std::string_view res;
				try {
					if (!that->m_alpn_select_cb(*wrapper, res, protocols)) return SSL_TLSEXT_ERR_NOACK;
				} catch (...) { return SSL_TLSEXT_ERR_NOACK; }

				// If the returned value is not withing supplied array (e.g. a constant was assigned) search for it
				if (res.data() < reinterpret_cast<const char*>(in) ||
					res.data() >= reinterpret_cast<const char*>(in + inlen)) {
					bool found = false;
					for (auto& e : protocols) {
						if (e == res) {
							res = e;
							found = true;
							break;
						}
					}
					if (!found) return SSL_TLSEXT_ERR_NOACK;
				}
				*out = reinterpret_cast<const unsigned char*>(res.data());
				*outlen = res.size();
				return SSL_TLSEXT_ERR_OK;
			},
			this);
	}

	void context::set_certificate_callback(std::function<void(session&)> cb) {
		m_cert_cb = std::move(cb);
		SSL_CTX_set_cert_cb(
			static_cast<SSL_CTX*>(m_ctx),
			[](SSL* ssl, void* arg) -> int {
				try {
					const auto that = static_cast<context*>(arg);
					if (!that->m_cert_cb) return 1;
					const auto wrapper = static_cast<session*>(SSL_get_ex_data(ssl, ssl_udi()));
					if (wrapper == nullptr) return 0;
					that->m_cert_cb(*wrapper);
				} catch (...) { return 0; }
				return 1;
			},
			this);
	}

	std::vector<x509> context::get_chain_certs() const {
		std::vector<x509> res;
		STACK_OF(X509)* certs = nullptr;
		if (SSL_CTX_get0_chain_certs(static_cast<SSL_CTX*>(m_ctx), &certs) != 1) throw_ossl_error();
		if (certs == nullptr) return res;
		res.reserve(sk_X509_num(certs));
		for (int i = 0; i < sk_X509_num(certs); i++) {
			auto cert = sk_X509_value(certs, i);
			X509_up_ref(cert);
			res.push_back(cert);
		}
		return res;
	}

	void context::clear_chain_certs() {
		if (SSL_CTX_clear_chain_certs(static_cast<SSL_CTX*>(m_ctx)) != 1) throw_ossl_error();
	}

	void context::debug() {
		STACK_OF(X509)* sks = nullptr;
		[[maybe_unused]] auto res = SSL_CTX_get0_chain_certs(static_cast<SSL_CTX*>(m_ctx), &sks);
		printf("sks=%p\n", sks);
		printf("\tsize=%d\n", sk_X509_num(sks));
		for (int i = 0; i < sk_X509_num(sks); i++) {
			//std::cout << x509(sk_X509_value(sks, i)).to_der() << std::endl;
		}
	}

	context::client_hello::client_hello(void* ssl) noexcept : m_ssl(ssl) {}

	bool context::client_hello::is_v2() const noexcept { return SSL_client_hello_isv2(static_cast<SSL*>(m_ssl)) != 0; }

	std::span<const std::byte> context::client_hello::random() const noexcept {
		const unsigned char* ptr = nullptr;
		auto size = SSL_client_hello_get0_random(static_cast<SSL*>(m_ssl), &ptr);
		return std::as_bytes(std::span{ptr, size});
	}

	std::span<const std::byte> context::client_hello::session_id() const noexcept {
		const unsigned char* ptr = nullptr;
		auto size = SSL_client_hello_get0_session_id(static_cast<SSL*>(m_ssl), &ptr);
		return std::as_bytes(std::span{ptr, size});
	}

	const std::vector<cipher>& context::client_hello::ciphers() const {
		if (!m_ciphers.empty()) return m_ciphers;

		const unsigned char* bytes = nullptr;
		STACK_OF(SSL_CIPHER)* sk = NULL, *scsv = NULL;
		auto len = SSL_client_hello_get0_ciphers(static_cast<SSL*>(m_ssl), &bytes);
		if (SSL_bytes_to_cipher_list(static_cast<SSL*>(m_ssl), bytes, len,
									 SSL_client_hello_isv2(static_cast<SSL*>(m_ssl)), &sk, &scsv) == 0)
			throw std::runtime_error("failed to parse cipher list");

		scope_guard del([sk, scsv]() noexcept {
			sk_SSL_CIPHER_free(sk);
			sk_SSL_CIPHER_free(scsv);
		});
		m_ciphers.resize(sk_SSL_CIPHER_num(sk));
		for (size_t i = 0; i < m_ciphers.size(); i++)
			m_ciphers[i] = cipher(sk_SSL_CIPHER_value(sk, i));
		m_signalling_ciphers.resize(sk_SSL_CIPHER_num(scsv));
		for (size_t i = 0; i < m_signalling_ciphers.size(); i++)
			m_signalling_ciphers[i] = cipher(sk_SSL_CIPHER_value(scsv, i));
		return m_ciphers;
	}

	const std::vector<cipher>& context::client_hello::signalling_ciphers() const {
		if (m_ciphers.empty() && m_signalling_ciphers.empty()) ciphers();
		return m_signalling_ciphers;
	}

	std::span<const std::byte> context::client_hello::compression_methods() const noexcept {
		const unsigned char* ptr = nullptr;
		auto size = SSL_client_hello_get0_compression_methods(static_cast<SSL*>(m_ssl), &ptr);
		return std::as_bytes(std::span{ptr, size});
	}

	const std::set<unsigned int>& context::client_hello::extensions() const {
		if (!m_extensions_preset.empty()) return m_extensions_preset;
		int* exts = nullptr;
		size_t len = 0;
		if (SSL_client_hello_get1_extensions_present(static_cast<SSL*>(m_ssl), &exts, &len) == 0)
			throw std::runtime_error("failed to get present extensions");
		if (exts == nullptr) return m_extensions_preset;
		for (size_t i = 0; i < len; i++)
			m_extensions_preset.emplace(static_cast<unsigned int>(exts[i]));
		OPENSSL_free(exts);
		return m_extensions_preset;
	}

	bool context::client_hello::has_extension(unsigned int type) const { return extensions().contains(type); }

	std::span<const std::byte> context::client_hello::extension(unsigned int type) const noexcept {
		const unsigned char* ptr = nullptr;
		size_t len = 0;
		if (SSL_client_hello_get0_ext(static_cast<SSL*>(m_ssl), type, &ptr, &len) == 0) return {};
		return std::as_bytes(std::span{ptr, len});
	}

	void context::client_hello::replace_context(context& new_context) const noexcept {
		SSL_set_SSL_CTX(static_cast<SSL*>(m_ssl), static_cast<SSL_CTX*>(new_context.m_ctx));
		SSL_clear_options(static_cast<SSL*>(m_ssl), 0xFFFFFFFFL);
		SSL_set_options(static_cast<SSL*>(m_ssl), SSL_CTX_get_options(static_cast<SSL_CTX*>(new_context.m_ctx)));
	}

	session* context::client_hello::get_session() const noexcept {
		return static_cast<session*>(SSL_get_ex_data(static_cast<SSL*>(m_ssl), ssl_udi()));
	}

	std::string_view context::client_hello::server_name_indication() const noexcept {
		auto ext = extension(TLSEXT_TYPE_server_name);
		if (ext.size() <= 2) return "";
		size_t len = static_cast<uint8_t>(ext[0]) << 8;
		len += static_cast<uint8_t>(ext[1]);
		if (len + 2 != ext.size()) return "";
		ext = ext.subspan(2, len);
		if (ext.size() < 3 || static_cast<uint8_t>(ext[0]) != TLSEXT_NAMETYPE_host_name) return "";
		len = static_cast<uint8_t>(ext[1]) << 8;
		len += static_cast<uint8_t>(ext[2]);
		if (len + 3 != ext.size()) return "";
		auto ptr = reinterpret_cast<const char*>(ext.subspan(3).data());
		return {ptr, len};
	}

	session::session(const context& ctx) {
		const auto udi = ssl_udi();
		auto ssl = SSL_new(static_cast<SSL_CTX*>(ctx.m_ctx));
		if (ssl == nullptr) throw_ossl_error();
		SSL_set_ex_data(ssl, udi, this);
		if (ctx.m_mode == mode::server)
			SSL_set_accept_state(ssl);
		else
			SSL_set_connect_state(ssl);
		auto ibio = BIO_new(BIO_s_mem());
		if (ibio == nullptr) {
			SSL_free(ssl);
			throw_ossl_error();
		}
		auto obio = BIO_new(BIO_s_mem());
		if (obio == nullptr) {
			BIO_free_all(ibio);
			SSL_free(ssl);
			throw_ossl_error();
		}
		BIO_set_mem_eof_return(obio, -1);

		SSL_set_bio(ssl, ibio, obio);

		m_ssl = ssl;
		m_input_bio = ibio;
		m_output_bio = obio;
	}

	session::~session() {
		if (m_ssl) {
			assert(SSL_get_ex_data(static_cast<SSL*>(m_ssl), ssl_udi()) == this);
			SSL_free(static_cast<SSL*>(m_ssl));
		}
	}

	int session::try_handshake() {
		do {
			auto res = SSL_do_handshake(static_cast<SSL*>(m_ssl));
			try_resume_cipher_read();
			try_resume_cipher_write();
			if (res != 1) {
				auto error = SSL_get_error(static_cast<SSL*>(m_ssl), res);
				if (error == SSL_ERROR_WANT_WRITE && try_resume_cipher_read())
					continue;
				else if (error == SSL_ERROR_WANT_READ && try_resume_cipher_write())
					continue;
			}
			return res;
		} while (true);
	}

	void session::shutdown() {
		SSL_shutdown(static_cast<SSL*>(m_ssl));
		try_resume_cipher_read();
		try_resume_cipher_write();
		try_resume_plain();
	}

	bool session::try_resume_cipher_read() {
		bool did_resume = false;
		while (m_cipher_readers && m_cipher_readers->try_resume())
			did_resume = true;
		return did_resume;
	}

	bool session::try_resume_cipher_write() {
		bool did_resume = false;
		while (m_cipher_writers && m_cipher_writers->try_resume())
			did_resume = true;
		return did_resume;
	}

	void session::try_resume_plain() {
		while (m_plain_readers && m_plain_readers->try_resume())
			;
		while (m_plain_writers && m_plain_writers->try_resume())
			;
		while (m_handshakers && m_handshakers->try_resume())
			;
	}

	bool session::try_read(void* buf, size_t len, size_t& read) {
		if (SSL_get_shutdown(static_cast<SSL*>(m_ssl))) {
			read = 0;
			return true;
		}
		do {
			if (!SSL_is_init_finished(static_cast<SSL*>(m_ssl))) try_handshake();
			auto res = SSL_read_ex(static_cast<SSL*>(m_ssl), buf, len, &read);
			if (res == 0) {
				auto error = SSL_get_error(static_cast<SSL*>(m_ssl), res);
				if (error == SSL_ERROR_WANT_WRITE && try_resume_cipher_read()) continue;
				if (error == SSL_ERROR_WANT_READ && try_resume_cipher_write()) continue;
				if (error == SSL_ERROR_ZERO_RETURN) {
					read = 0;
					return true;
				}
				if (error != SSL_ERROR_WANT_WRITE && error != SSL_ERROR_WANT_READ)
					throw std::runtime_error("SSL protocol error");
			}
			return res == 1;
		} while (true);
	}

	bool session::try_write(const void* buf, size_t len, size_t& written) {
		if (SSL_get_shutdown(static_cast<SSL*>(m_ssl))) {
			written = 0;
			return true;
		}
		do {
			if (!SSL_is_init_finished(static_cast<SSL*>(m_ssl))) try_handshake();
			auto res = SSL_write_ex(static_cast<SSL*>(m_ssl), buf, len, &written);
			if (res == 0) {
				auto error = SSL_get_error(static_cast<SSL*>(m_ssl), res);
				if (error == SSL_ERROR_WANT_WRITE && try_resume_cipher_read()) continue;
				if (error == SSL_ERROR_WANT_READ && try_resume_cipher_write()) continue;
			}
			try_resume_cipher_read();
			return res == 1;
		} while (true);
	}

	cipher session::current_cipher() const noexcept { return cipher(SSL_get_current_cipher(static_cast<SSL*>(m_ssl))); }

	cipher session::pending_cipher() const noexcept { return cipher(SSL_get_pending_cipher(static_cast<SSL*>(m_ssl))); }

	std::vector<cipher> session::ciphers() const {
		auto ciphers = SSL_get_ciphers(static_cast<SSL*>(m_ssl));
		if (ciphers == nullptr) return {};
		std::vector<cipher> result(sk_SSL_CIPHER_num(ciphers));
		for (size_t i = 0; i < result.size(); i++)
			result[i] = cipher(sk_SSL_CIPHER_value(ciphers, i));
		return result;
	}

	std::vector<cipher> session::supported_ciphers() const {
		auto ciphers = SSL_get1_supported_ciphers(static_cast<SSL*>(m_ssl));
		if (ciphers == nullptr) return {};
		scope_guard del([ciphers]() noexcept { sk_SSL_CIPHER_free(ciphers); });
		std::vector<cipher> result(sk_SSL_CIPHER_num(ciphers));
		for (size_t i = 0; i < result.size(); i++)
			result[i] = cipher(sk_SSL_CIPHER_value(ciphers, i));
		return result;
	}

	std::vector<cipher> session::client_ciphers() const {
		auto ciphers = SSL_get_client_ciphers(static_cast<SSL*>(m_ssl));
		if (ciphers == nullptr) return {};
		std::vector<cipher> result(sk_SSL_CIPHER_num(ciphers));
		for (size_t i = 0; i < result.size(); i++)
			result[i] = cipher(sk_SSL_CIPHER_value(ciphers, i));
		return result;
	}

	std::string_view session::get_servername() const noexcept {
		auto res = SSL_get_servername(static_cast<SSL*>(m_ssl), TLSEXT_NAMETYPE_host_name);
		return res ? res : "";
	}

	void session::set_servername(const std::string& name) {
		if (SSL_set_tlsext_host_name(static_cast<SSL*>(m_ssl), name.c_str()) == 0)
			throw std::runtime_error("failed to set hostname");
	}

	void session::set_verify(verify_mode mode) {
		auto sslmode = SSL_VERIFY_NONE;
		if (mode & verify_mode::peer) sslmode = SSL_VERIFY_PEER;
		if (mode & verify_mode::fail_if_no_cert) sslmode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
		if (mode & verify_mode::verify_once) sslmode |= SSL_VERIFY_CLIENT_ONCE;
		if (mode & verify_mode::verify_post_handshake) sslmode |= SSL_VERIFY_POST_HANDSHAKE;
		SSL_set_verify(static_cast<SSL*>(m_ssl), sslmode, nullptr);
	}

	void session::set_alpn_protos(const std::vector<std::string>& protos) {
		if (protos.empty()) throw std::runtime_error("alpn list must not be empty");
		size_t list_length = 0;
		for (auto& e : protos) {
			if (e.empty()) continue;
			if (e.size() > 255) throw std::runtime_error("alpn too large");
			list_length += 1 + e.size();
		}
		std::vector<uint8_t> list(list_length);
		for (size_t i = 0; auto& e : protos) {
			if (e.empty()) continue;
			list[i] = e.size();
			memcpy(&list[i + 1], e.data(), e.size());
			i += 1 + e.size();
		}
		if (SSL_set_alpn_protos(static_cast<SSL*>(m_ssl), list.data(), list.size()) != 0)
			throw std::runtime_error("failed to set alpn protocols");
	}

	std::string_view session::alpn_selected() const noexcept {
		const unsigned char* data = nullptr;
		unsigned int len = 0;
		SSL_get0_alpn_selected(static_cast<SSL*>(m_ssl), &data, &len);
		if (data == nullptr || len == 0) return "";
		return {reinterpret_cast<const char*>(data), len};
	}

	void session::set_certificate_callback(std::function<void(session&)> cb) {
		m_cert_cb = std::move(cb);
		SSL_set_cert_cb(
			static_cast<SSL*>(m_ssl),
			[](SSL* ssl, void* arg) -> int {
				try {
					const auto that = static_cast<session*>(arg);
					if (!that->m_cert_cb) return 1;
					that->m_cert_cb(*that);
				} catch (...) { return 0; }
				return 1;
			},
			this);
	}

	x509 session::get_peer_certificate() const noexcept { return SSL_get_peer_certificate(static_cast<SSL*>(m_ssl)); }

	cipher::~cipher() {
		if (m_description) OPENSSL_free(m_description);
	}

	std::string_view cipher::name() const noexcept {
		return SSL_CIPHER_get_name(static_cast<const SSL_CIPHER*>(m_cipher));
	}

	std::string_view cipher::standard_name() const noexcept {
		return SSL_CIPHER_standard_name(static_cast<const SSL_CIPHER*>(m_cipher));
	}

	std::string_view cipher::cipher_name() const noexcept {
		return OPENSSL_cipher_name(SSL_CIPHER_standard_name(static_cast<const SSL_CIPHER*>(m_cipher)));
	}

	size_t cipher::bit_count() const noexcept {
		return SSL_CIPHER_get_bits(static_cast<const SSL_CIPHER*>(m_cipher), nullptr);
	}

	std::string_view cipher::version() const noexcept {
		return SSL_CIPHER_get_version(static_cast<const SSL_CIPHER*>(m_cipher));
	}

	std::string_view cipher::description() const noexcept {
		if (!m_cipher) return "(null)";
		if (!m_description) return m_description;
		m_description = SSL_CIPHER_description(static_cast<const SSL_CIPHER*>(m_cipher), nullptr, 128);
		return m_description;
	}

	int cipher::cipher_nid() const noexcept {
		return SSL_CIPHER_get_cipher_nid(static_cast<const SSL_CIPHER*>(m_cipher));
	}

	int cipher::digest_nid() const noexcept {
		return SSL_CIPHER_get_digest_nid(static_cast<const SSL_CIPHER*>(m_cipher));
	}

	int cipher::kx_nid() const noexcept { return SSL_CIPHER_get_kx_nid(static_cast<const SSL_CIPHER*>(m_cipher)); }

	int cipher::auth_nid() const noexcept { return SSL_CIPHER_get_auth_nid(static_cast<const SSL_CIPHER*>(m_cipher)); }

	bool cipher::is_aead() const noexcept { return SSL_CIPHER_is_aead(static_cast<const SSL_CIPHER*>(m_cipher)) == 1; }

	uint32_t cipher::id() const noexcept { return SSL_CIPHER_get_id(static_cast<const SSL_CIPHER*>(m_cipher)); }

	uint32_t cipher::protocol_id() const noexcept {
		return SSL_CIPHER_get_protocol_id(static_cast<const SSL_CIPHER*>(m_cipher));
	}

	std::ostream& operator<<(std::ostream& str, const cipher& cipher) { return str << cipher.description(); }

	x509::~x509() {
		if (m_x509) X509_free(static_cast<X509*>(m_x509));
	}

	std::string x509::to_der() const {
		unsigned char* out = nullptr;
		auto len = i2d_X509(static_cast<X509*>(m_x509), &out);
		if (out == nullptr || len == 0) throw std::runtime_error("failed to convert to der");
		std::string res;
		res.assign(reinterpret_cast<char*>(out), len);
		OPENSSL_free(out);
		return res;
	}

	std::string x509::to_pem() const {
		auto bio = BIO_new(BIO_s_mem());
		scope_guard guard{[bio]() noexcept { BIO_free(bio); }};
		if (PEM_write_bio_X509(bio, static_cast<X509*>(m_x509)) != 1)
			throw std::runtime_error("failed to convert to pem");
		BUF_MEM* bptr = nullptr;
		BIO_get_mem_ptr(bio, &bptr);
		return std::string{bptr->data, bptr->length};
	}

	x509 x509::from_der(const void* ptr, size_t len) {
		auto u8ptr = reinterpret_cast<const unsigned char*>(ptr);
		auto res = d2i_X509(nullptr, &u8ptr, len);
		return x509(res);
	}

	x509 x509::from_pem(const void* ptr, size_t len) {
		auto bio = BIO_new(BIO_s_mem());
		scope_guard guard{[bio]() noexcept { BIO_free(bio); }};
		BIO_write(bio, ptr, len);
		auto res = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
		return x509(res);
	}

	std::chrono::system_clock::time_point x509::not_before() const noexcept {
		int day = 0, sec = 0;
		ASN1_TIME_diff(&day, &sec, nullptr, X509_get0_notBefore(static_cast<X509*>(m_x509)));
		auto now = std::chrono::system_clock::now();
		return now + std::chrono::days(day) + std::chrono::seconds(sec);
	}

	std::chrono::system_clock::time_point x509::not_after() const noexcept {
		int day = 0, sec = 0;
		ASN1_TIME_diff(&day, &sec, nullptr, X509_get0_notAfter(static_cast<X509*>(m_x509)));
		auto now = std::chrono::system_clock::now();
		return now + std::chrono::days(day) + std::chrono::seconds(sec);
	}

	std::string x509::subject() const {
		auto name = X509_get_subject_name(static_cast<X509*>(m_x509));
		auto bio = BIO_new(BIO_s_mem());
		scope_guard guard{[bio]() noexcept { BIO_free(bio); }};
		if (X509_NAME_print_ex(bio, name, 0, XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB) == -1) throw_ossl_error();
		BUF_MEM* bptr = nullptr;
		BIO_get_mem_ptr(bio, &bptr);
		return std::string{bptr->data, bptr->length};
	}

	std::string x509::issuer() const {
		auto name = X509_get_issuer_name(static_cast<X509*>(m_x509));
		auto bio = BIO_new(BIO_s_mem());
		scope_guard guard{[bio]() noexcept { BIO_free(bio); }};
		if (X509_NAME_print_ex(bio, name, 0, XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB) == -1) throw_ossl_error();
		BUF_MEM* bptr = nullptr;
		BIO_get_mem_ptr(bio, &bptr);
		return std::string{bptr->data, bptr->length};
	}

	std::strong_ordering operator<=>(const x509& lhs, const x509& rhs) noexcept {
		if (lhs.m_x509 == rhs.m_x509) return std::strong_ordering::equal;
		if (lhs.m_x509 == nullptr) return std::strong_ordering::less;
		if (rhs.m_x509 == nullptr) return std::strong_ordering::greater;
		const auto res = X509_cmp(static_cast<X509*>(lhs.m_x509), static_cast<X509*>(rhs.m_x509));
		if (res < 0)
			return std::strong_ordering::less;
		else if (res > 0)
			return std::strong_ordering::greater;
		else
			return std::strong_ordering::equal;
	}

	bool operator==(const x509& lhs, const x509& rhs) noexcept { return (lhs <=> rhs) == std::strong_ordering::equal; }

	bool operator!=(const x509& lhs, const x509& rhs) noexcept { return (lhs <=> rhs) != std::strong_ordering::equal; }

	bool plain_read_awaitable::try_resume() {
		auto res = m_session.try_read(m_buffer, m_len, m_result);
		if (res) {
			m_handle.resume();
			return true;
		}
		return false;
	}

	bool plain_read_awaitable::await_ready() const noexcept { return false; }

	bool plain_read_awaitable::await_suspend(coroutine_handle<> hdl) {
		auto res = m_session.try_read(m_buffer, m_len, m_result);
		if (!res) {
			m_handle = hdl;
			plain_read_awaitable** last = &m_session.m_plain_readers;
			while (*last != nullptr)
				last = &(*last)->m_next;
			*last = this;
		}
		return !res;
	}

	size_t plain_read_awaitable::await_resume() {
		if (m_handle) {
			assert(m_session.m_plain_readers == this);
			m_session.m_plain_readers = m_next;
		}
		return m_result;
	}

	bool plain_write_awaitable::try_resume() {
		auto res = m_session.try_write(m_buffer, m_len, m_result);
		if (res && m_result != 0) {
			m_handle.resume();
			return true;
		}
		return false;
	}

	bool plain_write_awaitable::await_ready() const noexcept { return false; }

	bool plain_write_awaitable::await_suspend(coroutine_handle<> hdl) {
		auto res = m_session.try_write(m_buffer, m_len, m_result);
		if (!res) {
			m_handle = hdl;
			plain_write_awaitable** last = &m_session.m_plain_writers;
			while (*last != nullptr)
				last = &(*last)->m_next;
			*last = this;
		}
		return !res;
	}

	size_t plain_write_awaitable::await_resume() {
		if (m_handle) {
			assert(m_session.m_plain_writers == this);
			m_session.m_plain_writers = m_next;
		}
		return m_result;
	}

	bool cipher_read_awaitable::try_resume() {
		if (SSL_get_shutdown(static_cast<SSL*>(m_session.m_ssl))) {
			m_result = 0;
			m_handle.resume();
			return true;
		}
		auto res = BIO_read_ex(static_cast<BIO*>(m_session.m_output_bio), m_buffer, m_len, &m_result);
		if (res == 1 && m_result != 0) {
			m_handle.resume();
			return true;
		}
		return false;
	}

	bool cipher_read_awaitable::await_ready() const noexcept { return false; }

	bool cipher_read_awaitable::await_suspend(coroutine_handle<> hdl) {
		if (SSL_get_shutdown(static_cast<SSL*>(m_session.m_ssl))) {
			m_result = 0;
			return false;
		}
		auto res = BIO_read_ex(static_cast<BIO*>(m_session.m_output_bio), m_buffer, m_len, &m_result);
		bool suspend = !(res == 1 && m_result != 0);
		if (suspend) {
			m_handle = hdl;
			cipher_read_awaitable** last = &m_session.m_cipher_readers;
			while (*last != nullptr)
				last = &(*last)->m_next;
			*last = this;
		}
		return suspend;
	}

	size_t cipher_read_awaitable::await_resume() {
		if (m_handle) {
			assert(m_session.m_cipher_readers == this);
			m_session.m_cipher_readers = m_next;
		}
		return m_result;
	}

	bool cipher_write_awaitable::try_resume() {
		if (BIO_ctrl_pending(static_cast<BIO*>(m_session.m_input_bio)) > 256 * 1024) {
			if (m_len == 0) m_session.shutdown();
			size_t len;
			auto res = BIO_write_ex(static_cast<BIO*>(m_session.m_input_bio), m_buffer, m_len, &len);
			m_session.try_resume_plain();
			// Write
			assert(res == 1);
			assert(len == m_len);
			m_handle.resume();
			return true;
		}
		return false;
	}

	bool cipher_write_awaitable::await_ready() const noexcept { return false; }

	bool cipher_write_awaitable::await_suspend(coroutine_handle<> hdl) {
		if (BIO_ctrl_pending(static_cast<BIO*>(m_session.m_input_bio)) > 256 * 1024) {
			// Memory bios can grow indefinitly, to avoid buffering to much data we suspend if the amount
			// exceeds 256K.
			m_handle = hdl;
			cipher_write_awaitable** last = &m_session.m_cipher_writers;
			while (*last != nullptr)
				last = &(*last)->m_next;
			*last = this;
			return true;
		}
		if (m_len == 0) m_session.shutdown();
		auto res = BIO_write_ex(static_cast<BIO*>(m_session.m_input_bio), m_buffer, m_len, &m_result);
		// Write
		assert(m_result == 0 || res == 1);
		assert(m_result == m_len);
		m_session.try_resume_plain();
		return false;
	}

	size_t cipher_write_awaitable::await_resume() {
		if (m_handle) {
			assert(m_session.m_cipher_writers == this);
			m_session.m_cipher_writers = m_next;
		}
		return m_result;
	}

	bool handshake_awaitable::try_resume() {
		auto res = m_session.try_handshake();
		if (res != 1) {
			auto error = SSL_get_error(static_cast<SSL*>(m_session.m_ssl), res);
			if (error == SSL_ERROR_WANT_WRITE || error == SSL_ERROR_WANT_READ) return false;
			m_result = error;
		}
		m_handle.resume();
		return true;
	}

	bool handshake_awaitable::await_ready() const noexcept {
		return SSL_is_init_finished(static_cast<SSL*>(m_session.m_ssl));
	}

	bool handshake_awaitable::await_suspend(coroutine_handle<> hdl) {
		auto res = m_session.try_handshake();
		if (res != 1) {
			auto error = SSL_get_error(static_cast<SSL*>(m_session.m_ssl), res);
			if (error == SSL_ERROR_WANT_WRITE || error == SSL_ERROR_WANT_READ) {
				m_handle = hdl;
				handshake_awaitable** last = &m_session.m_handshakers;
				while (*last != nullptr)
					last = &(*last)->m_next;
				*last = this;
				return true;
			}
			m_result = error;
		}
		return false;
	}

	void handshake_awaitable::await_resume() {
		if (m_handle) {
			assert(m_session.m_handshakers == this);
			m_session.m_handshakers = m_next;
		}
		if (m_result != 0)
			throw std::runtime_error("SSL Handshake failed: " +
									 std::to_string(SSL_get_verify_result(static_cast<SSL*>(m_session.m_ssl))));
	}

} // namespace asyncpp::io::tls
