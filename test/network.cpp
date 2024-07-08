#include <asyncpp/io/address.h>
#include <asyncpp/io/network.h>

#include <gtest/gtest.h>

using namespace asyncpp::io;

TEST(ASYNCPP_IO, IPv4NetworkContains) {
	ASSERT_FALSE(ipv4_network(ipv4_address(10, 0, 0, 0), 24).contains(ipv4_address(10, 0, 1, 1)));
	ASSERT_TRUE(ipv4_network(ipv4_address(10, 0, 0, 0), 24).contains(ipv4_address(10, 0, 0, 1)));
	ASSERT_TRUE(ipv4_network(ipv4_address(10, 0, 0, 0), 0).contains(ipv4_address(233, 1, 22, 5)));
	ASSERT_FALSE(ipv4_network(ipv4_address(10, 0, 0, 0), 1).contains(ipv4_address(233, 1, 22, 5)));
	ASSERT_TRUE(ipv4_network(ipv4_address(10, 0, 0, 1), 32).contains(ipv4_address(10, 0, 0, 1)));
}

TEST(ASYNCPP_IO, IPv6NetworkContains) {
	const ipv6_address ip(0x0102030405060708, 0x090A0B0C0D0E0F10);
	const ipv6_address ip2(0x090A0B0C0D0E0F10, 0x0102030405060708);
	for (size_t i = 0; i <= 128; i++) {
		ASSERT_TRUE(ipv6_network(ip, i).contains(ip));
	}
	ASSERT_TRUE(ipv6_network(ip, 1).contains(ip2));
	ASSERT_TRUE(ipv6_network(ip, 2).contains(ip2));
	ASSERT_TRUE(ipv6_network(ip, 3).contains(ip2));
	ASSERT_TRUE(ipv6_network(ip, 4).contains(ip2));
	for (size_t i = 5; i <= 128; i++) {
		ASSERT_FALSE(ipv6_network(ip, i).contains(ip2));
		ASSERT_FALSE(ipv6_network(ip2, i).contains(ip));
	}
}

TEST(ASYNCPP_IO, IPv4Network) {
	const ipv4_address ip(10, 0, 0, 22);
	ASSERT_EQ(ipv4_network(ip, 24).canonical(), ipv4_address(10, 0, 0, 0));
	ASSERT_EQ(ipv4_network(ip, 24).broadcast(), ipv4_address(10, 0, 0, 255));
}

TEST(ASYNCPP_IO, IPv6Network) {
	const ipv6_address ip(0x0102030405060708, 0x090A0B0C0D0E0F10);
	ASSERT_EQ(ipv6_network(ip, 64).canonical(), ipv6_address(0x0102030405060708, 0));
	ASSERT_EQ(ipv6_network(ip, 64).broadcast(), ipv6_address(0x0102030405060708, 0xffffffffffffffff));
}

TEST(ASYNCPP_IO, IPv6Test) {
	auto ip = ipv6_network(ipv6_address::parse("2003::").value(), 19);
	auto ip2 = ipv6_network(ipv6_address::parse("2003:8:f401::").value(), 48);
	auto ip3 = ipv6_network(ipv6_address::parse("2003:8:f40e::").value(), 48);
	ASSERT_TRUE(ip2 > ip);
	ASSERT_FALSE(ip2 < ip);
	ASSERT_TRUE(ip3 > ip2);
}
