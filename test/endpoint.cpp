#include <asyncpp/io/endpoint.h>

#include <gtest/gtest.h>

using namespace asyncpp::io;

TEST(ASYNCPP_IO, IPv4EndpointParse) {
	ASSERT_EQ(ipv4_endpoint::parse("1.0.0.1"), ipv4_endpoint(ipv4_address(1, 0, 0, 1), 0));
	ASSERT_EQ(ipv4_endpoint::parse("1.0.0.1:"), std::nullopt);
	ASSERT_EQ(ipv4_endpoint::parse("1.0.0.1:1"), ipv4_endpoint(ipv4_address(1, 0, 0, 1), 1));
}

TEST(ASYNCPP_IO, IPv6EndpointParse) {
	ASSERT_EQ(ipv6_endpoint::parse("[::1]"), ipv6_endpoint(ipv6_address::loopback(), 0));
	ASSERT_EQ(ipv6_endpoint::parse("[::1]:"), std::nullopt);
	ASSERT_EQ(ipv6_endpoint::parse("[::1]:1"), ipv6_endpoint(ipv6_address::loopback(), 1));
}

TEST(ASYNCPP_IO, EndpointParse) {
	ASSERT_EQ(endpoint::parse("[::1]"), endpoint(ipv6_address::loopback(), 0));
	ASSERT_EQ(endpoint::parse("[::1]:"), std::nullopt);
	ASSERT_EQ(endpoint::parse("[::1]:1"), endpoint(ipv6_address::loopback(), 1));
	ASSERT_EQ(endpoint::parse("1.0.0.1"), endpoint(ipv4_address(1, 0, 0, 1), 0));
	ASSERT_EQ(endpoint::parse("1.0.0.1:"), std::nullopt);
	ASSERT_EQ(endpoint::parse("1.0.0.1:1"), endpoint(ipv4_address(1, 0, 0, 1), 1));
}
