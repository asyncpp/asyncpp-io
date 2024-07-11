#include <asyncpp/io/io_service.h>
#include <asyncpp/io/socket.h>
#include <asyncpp/launch.h>
#include <asyncpp/task.h>
#include <asyncpp/timer.h>

#include <gtest/gtest.h>

using namespace asyncpp::io;
using asyncpp::launch;
using asyncpp::task;

asyncpp::stop_token timeout(std::chrono::nanoseconds ts) {
	asyncpp::stop_source source;
	asyncpp::timer::get_default().schedule([source](bool) mutable { source.request_stop(); }, ts);
	return source.get_token();
}

TEST(ASYNCPP_IO, IOService) {
	io_service service;
	service.run(io_service::run_mode::nowait);
}

TEST(ASYNCPP_IO, IOServicePush) {
	static bool did_trigger = false;
	auto service = io_service::get_default();
	service->push([]() { did_trigger = true; });
	for (size_t i = 0; i < 10 && !did_trigger; i++) {
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}
	ASSERT_TRUE(did_trigger) << "io_service did not wake up within 100ms";
}

TEST(ASYNCPP_IO, Socket) {
	std::string result;
	io_service service;
	launch([](io_service& service, std::string& result) -> task<> {
		const auto ip = endpoint::parse("194.36.147.124:80").value();
		auto client = socket::create_tcp(service, ip.type());
		co_await client.connect(ip);
		constexpr std::string_view req = "GET / HTTP/1.0\r\n\r\n";
		co_await client.send(req.data(), req.size());
		while (true) {
			char buf[1024];
			auto res = co_await client.recv(buf, 1024);
			result.append(buf, res);
			if (res == 0 || result.size() >= 1024) break;
		}
	}(service, result));

	service.run();

	ASSERT_FALSE(result.empty());
	ASSERT_TRUE(result.starts_with("HTTP"));
}

TEST(ASYNCPP_IO, SocketSelf) {
	io_service service;
	std::string received;
	auto stop = timeout(std::chrono::seconds(2));
	launch([](io_service& service, std::string& received, asyncpp::stop_token st) -> task<> {
		// Launch a tcp server that accepts a single connection and sends "HELLO"
		auto server = socket::create_and_bind_tcp(service, endpoint(ipv4_address::any(), 0));
		launch([](io_service& service, socket& server, asyncpp::stop_token st) -> task<> {
			server.listen();
			auto client = co_await server.accept(st);
			co_await client.send("HELLO", 5, st);
		}(service, server, st));
		// Connect to said server
		auto client = socket::create_tcp(service, server.local_endpoint().type());
		co_await client.connect(server.local_endpoint(), st);
		// and read until connection is closed
		while (true) {
			char buf[128];
			auto res = co_await client.recv(&buf, 128, st);
			if (res == 0) break;
			received.append(buf, res);
		}
	}(service, received, stop));

	service.run();

	ASSERT_EQ(received.size(), 5);
	ASSERT_EQ(received, "HELLO");
}

TEST(ASYNCPP_IO, SocketUDP) {
	io_service service;
	launch([](io_service& service) -> task<> {
		const auto ip = endpoint::parse("185.194.142.4:10070").value();
		auto client = socket::create_udp(service, ip.type());
		constexpr uint8_t buf[] = {0x00, 0x00, 0xe4, 0x00};
		co_await client.send_to(buf, sizeof(buf), ip);
		uint8_t receive_buf[128];
		auto [res, source] =
			co_await client.recv_from(&receive_buf, sizeof(receive_buf), timeout(std::chrono::seconds(2)));
		printf("got %zu bytes from %s\n", res, source.to_string().c_str());
	}(service));

	service.run();
}

TEST(ASYNCPP_IO, SocketValid) {
	auto service = io_service::get_default();

	socket sock;
	ASSERT_FALSE(sock);
	sock = socket::create_tcp(*service, address_type::ipv4);
	ASSERT_TRUE(sock);
	socket sock2 = std::move(sock);
	ASSERT_FALSE(sock);
	ASSERT_FALSE(sock.valid());
	ASSERT_TRUE(sock2);
	ASSERT_TRUE(sock2.valid());
	auto fd = sock2.release();
	ASSERT_FALSE(sock2);
	close(fd);
}

#ifdef __linux__
TEST(ASYNCPP_IO, SocketPair) {
	io_service service;
	std::string received;
	asyncpp::async_launch_scope scope;
	scope.invoke([&service, &received]() -> task<> {
		auto stop = timeout(std::chrono::seconds(2));
		auto pair = socket::connected_pair_tcp(service, address_type::uds);
		co_await pair.first.send("Hello", 5, stop);
		pair.first.close_send();
		while (true) {
			char buf[128];
			auto res = co_await pair.second.recv(&buf, 128, stop);
			if (res == 0) break;
			received.append(buf, res);
		}
		service.stop();
	});

	service.run();

	ASSERT_TRUE(scope.all_done());
	ASSERT_EQ(received.size(), 5);
	ASSERT_EQ(received, "Hello");
}
#endif
