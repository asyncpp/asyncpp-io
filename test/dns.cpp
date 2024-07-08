#include <asyncpp/io/address.h>
#include <asyncpp/io/buffer.h>
#include <asyncpp/io/dns.h>
#include <asyncpp/io/endpoint.h>
#include <asyncpp/io/io_service.h>
#include <asyncpp/launch.h>
#include <asyncpp/task.h>
#include <asyncpp/timer.h>

#include <chrono>
#include <exception>
#include <gtest/gtest.h>
#include <stdexcept>

using namespace asyncpp::io;

TEST(ASYNCPP_IO, DNSResolve) {
	io_service service;
	dns::client client(service);

	client.add_nameserver(address::parse("1.1.1.1").value());
	client.set_retries(3);
	client.set_timeout(std::chrono::milliseconds(250));

	dns::api_error error = dns::api_error::timeout;
	client.query("thalhammer.it", dns::qtype::a, dns::qclass::in,
				 [&client, &error](dns::api_error e, const_buffer res) {
					 if (e == dns::api_error::ok) {
						 dns::visit_answer(res, [&](std::string_view name, dns::qtype rtype, dns::qclass rclass,
													uint32_t ttl, asyncpp::io::const_buffer rdata) {
							 if (rtype == dns::qtype::a && rclass == dns::qclass::in) {
								 std::error_code ec;
								 auto rr = dns::parse_a(rdata, res, ec);
								 if (!ec) std::cout << rr.to_string() << std::endl;
							 }
							 return true;
						 });
					 } else
						 std::cout << e << std::endl;

					 error = e;
					 client.stop();
				 });

	service.run(io_service::run_mode::while_active);

	ASSERT_EQ(error, dns::api_error::ok);
}

TEST(ASYNCPP_IO, DNSResolveTimeout) {
	io_service service;
	dns::client client(service);

	client.add_nameserver(address::parse("2.2.2.2").value());
	client.set_retries(0);
	client.set_timeout(std::chrono::milliseconds(100));

	auto now = std::chrono::steady_clock::now();
	std::chrono::milliseconds dur;

	dns::api_error error = dns::api_error::timeout;
	client.query("thalhammer.it", dns::qtype::a, dns::qclass::in, [&](dns::api_error e, const_buffer res) {
		error = e;
		dur = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - now);
		client.stop();
		service.stop();
	});

	service.run(io_service::run_mode::while_active);

	ASSERT_EQ(error, dns::api_error::timeout);
	ASSERT_LE(dur, std::chrono::milliseconds(500)) << "Query took too long to react to timeout";
}
