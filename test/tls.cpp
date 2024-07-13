#include <asyncpp/io/io_service.h>
#include <asyncpp/io/socket.h>
#include <asyncpp/io/tls.h>
#include <asyncpp/launch.h>
#include <asyncpp/task.h>

#include <chrono>
#include <filesystem>
#include <gtest/gtest.h>

using namespace asyncpp::io;

TEST(ASYNCPP_IO, TLSContext) {
	tls::context ctx;
	ASSERT_EQ(ctx.get_method(), tls::method::tls);
	ASSERT_EQ(ctx.get_mode(), tls::mode::client);
}

TEST(ASYNCPP_IO, TLSRoundtrip) {
	std::cout.sync_with_stdio(true);
	// Generate cert if missing
	if (!std::filesystem::exists("ssl.crt") || !std::filesystem::exists("ssl.key")) {
#ifdef _WIN32
		GTEST_SKIP() << "Can not generate certs on windows";
#endif
		std::cout << "Generating temporary cert..." << std::endl;
		system("openssl req -x509 -newkey rsa:2048 -keyout ssl.key -out ssl.crt -sha256 -days 2 -nodes -subj "
			   "\"/C=XX/ST=StateName/L=SomeCity/O=ASYNCPP/OU=ASYNCPP-TEST/CN=server1\"");
		atexit([]() {
			unlink("ssl.key");
			unlink("ssl.crt");
		});
	}

	tls::context ctx_client(tls::method::tls, tls::mode::client);
	tls::context ctx_server(tls::method::tls, tls::mode::server);
	ctx_server.use_certificate("ssl.crt");
	//ctx_server.use_certificate("sample.pem");
	ctx_server.debug();
	for (auto& e : ctx_server.get_chain_certs()) {
		std::cout << e.to_pem() << std::endl;
	}
	ctx_server.use_privatekey("ssl.key");
	ctx_server.set_client_hello_callback([](const tls::context::client_hello& hello, int& alert) {
		std::cout << "sni: '" << hello.server_name_indication() << "'" << std::endl;
		return true;
	});
	ctx_server.set_verify(tls::verify_mode::none);
	ctx_server.set_alpn_select_callback(
		[](tls::session&, std::string_view& res, const std::span<const std::string_view>& available) {
			std::cout << "alpn:";
			for (auto e : available)
				std::cout << " '" << e << "'";
			std::cout << std::endl;
			res = available.front();
			return true;
		});
	ctx_client.set_verify(tls::verify_mode::none);
	ctx_client.set_alpn_protos({"http/1.1", "h2"});

	tls::session session_client(ctx_client);
	tls::session session_server(ctx_server);

	session_client.set_servername("server1");

	launch([](tls::session& client, tls::session& server) -> asyncpp::task<> {
		char buffer[1024];
		while (true) {
			auto len = co_await client.cipher_read(buffer, sizeof(buffer));
			co_await server.cipher_write(buffer, len);
			if (len == 0) break;
		}
	}(session_client, session_server));

	launch([](tls::session& client, tls::session& server) -> asyncpp::task<> {
		char buffer[1024];
		while (true) {
			auto len = co_await server.cipher_read(buffer, sizeof(buffer));
			co_await client.cipher_write(buffer, len);
			if (len == 0) break;
		}
	}(session_client, session_server));

	bool done = false;
	launch([](tls::session& server, bool& done) -> asyncpp::task<> {
		while (!done) {
			char buf[1024];
			auto res = co_await server.read(buf, sizeof(buf));
			if (res > 0) {
				std::cout << std::string_view(buf, res) << std::endl;
				done = true;
			}
		}
		server.shutdown();
	}(session_server, done));

	while (!done) {
		const char* test = "Hello World\n";
		size_t size{};
		[[maybe_unused]] auto res = session_client.try_write(test, strlen(test), size);
	}

	auto cert = session_client.get_peer_certificate();
	std::cout << cert.to_pem() << std::endl;
	std::cout << "nbf:    " << std::chrono::system_clock::to_time_t(cert.not_before()) << std::endl;
	std::cout << "naf:    " << std::chrono::system_clock::to_time_t(cert.not_after()) << std::endl;
	std::cout << "subject:" << cert.subject() << std::endl;
	std::cout << "issuer: " << cert.issuer() << std::endl;

	ASSERT_EQ("http/1.1", session_server.alpn_selected());
	ASSERT_EQ("http/1.1", session_client.alpn_selected());
	ASSERT_EQ("server1", session_server.get_servername());
	ASSERT_EQ("server1", session_client.get_servername());
}

TEST(ASYNCPP_IO, TLSClient) {
	std::cout.sync_with_stdio(true);
	tls::context ctx_client(tls::method::tls, tls::mode::client);
#ifdef _WIN32
	// I am too lazy to figure out the cert locations and
	// we only want to test interaction with async io anyway
	ctx_client.set_verify(tls::verify_mode::none);
#endif
	ctx_client.load_verify_locations("", "/etc/ssl/certs/");
	ctx_client.set_alpn_protos({"http/1.1"});
	tls::session ssl_client(ctx_client);
	io_service service;
	asyncpp::async_launch_scope scope;
	auto sock = socket::create_tcp(service, address_type::ipv4);
	ssl_client.set_servername("thalhammer.it");

	scope.invoke([&ssl_client, &sock, &service, &scope]() -> asyncpp::task<> {
		const auto ip = endpoint::parse("194.36.147.124:443").value();
		co_await sock.connect(ip);

		scope.invoke([&ssl_client, &sock]() -> asyncpp::task<> {
			char buffer[64 * 1024];
			while (true) {
				auto len = co_await ssl_client.cipher_read(buffer, sizeof(buffer));
				if (len == 0) break;
				co_await sock.send(buffer, len);
			}
		});

		scope.invoke([&ssl_client, &sock]() -> asyncpp::task<> {
			char buffer[64 * 1024];
			while (true) {
				auto len = co_await sock.recv(buffer, sizeof(buffer));
				co_await ssl_client.cipher_write(buffer, len);
				if (len == 0) break;
			}
		});

		co_await ssl_client.handshake();
		constexpr std::string_view req = "GET / HTTP/1.1\r\nHost: thalhammer.it\r\nConnection: close\r\n\r\n";
		co_await ssl_client.write(req.data(), req.size());
		while (true) {
			char buf[64 * 1024];
			auto res = co_await ssl_client.read(buf, sizeof(buf));
			if (res == 0) break;
			if (res > 0) { std::cout << std::string_view(buf, res) << std::endl; }
		}
		service.stop();
	});

	while (!scope.all_done())
		service.run(io_service::run_mode::once);
}
