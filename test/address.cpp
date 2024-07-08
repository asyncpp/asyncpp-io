#include <asyncpp/io/address.h>

#include <gtest/gtest.h>

using namespace asyncpp::io;

TEST(ASYNCPP_IO, IPv4ConstructAndAccess) {
	ASSERT_EQ(ipv4_address().integer(), 0) << "Default constructor should result in 0.0.0.0";
	ASSERT_EQ(ipv4_address(127, 0, 0, 1).integer(), 0x7f000001u) << "Piecewise construction";
	ASSERT_EQ(ipv4_address(127, 0, 0, 1).integer(std::endian::little), 0x0100007fu)
		<< "Piecewise construction is big endian";
	ASSERT_EQ(ipv4_address(0x7f000001u).integer(), 0x7f000001u) << "uint32_t construction";
	ASSERT_EQ(ipv4_address(0x0100007fu, std::endian::little).integer(), 0x7f000001u)
		<< "uint32_t construction (little endian)";
	ASSERT_EQ(ipv4_address(std::array<uint8_t, 4>{127, 0, 0, 1}), ipv4_address(127, 0, 0, 1))
		<< "Array of uint8_t construction";
	uint8_t data[] = {127, 0, 0, 1};
	ASSERT_EQ(ipv4_address(data), ipv4_address(127, 0, 0, 1)) << "Array of uint8_t construction";
}

TEST(ASYNCPP_IO, IPv4AddrType) {
	ASSERT_EQ(ipv4_address::loopback(), ipv4_address(127, 0, 0, 1)) << "loopback() returns 127.0.0.1";
	ASSERT_EQ(ipv4_address::any(), ipv4_address(0, 0, 0, 0)) << "any() returns 0.0.0.0";
	ASSERT_TRUE(ipv4_address::loopback().is_loopback());
	ASSERT_FALSE(ipv4_address::any().is_loopback());
	ASSERT_FALSE(ipv4_address::loopback().is_private());
	ASSERT_FALSE(ipv4_address::any().is_private());
	ASSERT_TRUE(ipv4_address(10, 0, 0, 1).is_private());
	ASSERT_FALSE(ipv4_address(8, 8, 8, 8).is_private());
}

TEST(ASYNCPP_IO, IPv4Parse) {
	ASSERT_EQ(ipv4_address::parse(""), std::nullopt);
	ASSERT_EQ(ipv4_address::parse("1"), std::nullopt);
	ASSERT_EQ(ipv4_address::parse("1.0.01"), std::nullopt);
	ASSERT_EQ(ipv4_address::parse("10.0.0.1 "), std::nullopt);
	ASSERT_EQ(ipv4_address::parse(" 10.0.0.1"), std::nullopt);
	ASSERT_EQ(ipv4_address::parse("256.0.0.1"), std::nullopt);
	ASSERT_EQ(ipv4_address::parse("1.0.0.1"), ipv4_address(1, 0, 0, 1));
	ASSERT_EQ(ipv4_address::parse("10.0.0.1"), ipv4_address(10, 0, 0, 1));
	ASSERT_EQ(ipv4_address::parse("100.0.0.1"), ipv4_address(100, 0, 0, 1));

	static constexpr auto static_parse = ipv4_address::parse("10.0.0.1");
	static_assert(static_parse.has_value());
	static_assert(static_parse.value() == ipv4_address(10, 0, 0, 1));
}

TEST(ASYNCPP_IO, IPv4ToString) {
	ASSERT_EQ(ipv4_address(0, 0, 0, 0).to_string(), "0.0.0.0");
	ASSERT_EQ(ipv4_address(1, 0, 0, 0).to_string(), "1.0.0.0");
	ASSERT_EQ(ipv4_address(10, 0, 0, 0).to_string(), "10.0.0.0");
	ASSERT_EQ(ipv4_address(100, 0, 0, 0).to_string(), "100.0.0.0");
	ASSERT_EQ(ipv4_address(0, 0, 0, 0).to_string(), "0.0.0.0");
	ASSERT_EQ(ipv4_address(0, 1, 0, 0).to_string(), "0.1.0.0");
	ASSERT_EQ(ipv4_address(0, 10, 0, 0).to_string(), "0.10.0.0");
	ASSERT_EQ(ipv4_address(0, 100, 0, 0).to_string(), "0.100.0.0");
}

TEST(ASYNCPP_IO, IPv6Parse) {
	ASSERT_EQ(ipv6_address::parse(""), std::nullopt);
	ASSERT_EQ(ipv6_address::parse("123"), std::nullopt);
	ASSERT_EQ(ipv6_address::parse("foo"), std::nullopt);
	ASSERT_EQ(ipv6_address::parse(":1234"), std::nullopt);
	ASSERT_EQ(ipv6_address::parse("0102:0304:0506:0708:090a:0b0c:0d0e:0f10 "), std::nullopt);
	ASSERT_EQ(ipv6_address::parse(" 0102:0304:0506:0708:090a:0b0c:0d0e:0f10"), std::nullopt);
	ASSERT_EQ(ipv6_address::parse("0102:0304:0506:0708:090a:0b0c:0d0e:0f10:"), std::nullopt);
	ASSERT_EQ(ipv6_address::parse("0102:0304:0506:0708:090a:0b0c:0d0e"), std::nullopt);
	ASSERT_EQ(ipv6_address::parse("01022:0304:0506:0708:090a:0b0c:0d0e:0f10"), std::nullopt);
	ASSERT_EQ(ipv6_address::parse("0102:0304:0506:192.168.0.1:0b0c:0d0e:0f10"), std::nullopt);
	ASSERT_EQ(ipv6_address::parse("::"), ipv6_address(0, 0));
	ASSERT_EQ(ipv6_address::parse("::1"), ipv6_address::loopback());
	ASSERT_EQ(ipv6_address::parse("::01"), ipv6_address::loopback());
	ASSERT_EQ(ipv6_address::parse("::001"), ipv6_address::loopback());
	ASSERT_EQ(ipv6_address::parse("::0001"), ipv6_address::loopback());
	ASSERT_EQ(ipv6_address::parse("0102:0304:0506:0708:090a:0b0c:0d0e:0f10"),
			  ipv6_address(0x0102030405060708, 0x090A0B0C0D0E0F10));
	ASSERT_EQ(ipv6_address::parse("0002:0304:0506:0708:090a:0b0c:0d0e:0f10"),
			  ipv6_address(0x0002030405060708, 0x090A0B0C0D0E0F10));
	ASSERT_EQ(ipv6_address::parse("0000:0304:0506:0708:090a:0b0c:0d0e:0f10"),
			  ipv6_address(0x0000030405060708, 0x090A0B0C0D0E0F10));
	ASSERT_EQ(ipv6_address::parse("::0506:0708:090a:0b0c:0d0e:0f10"),
			  ipv6_address(0x0000000005060708, 0x090A0B0C0D0E0F10));
	ASSERT_EQ(ipv6_address::parse("0102:0304::0b0c:0d0e:0f10"), ipv6_address(0x0102030400000000, 0x00000B0C0D0E0F10));
	ASSERT_EQ(ipv6_address::parse("0102:0304:0506:0708:090a:0b0c::"),
			  ipv6_address(0x0102030405060708, 0x090A0B0C00000000));
	ASSERT_EQ(ipv6_address::parse("2001:db8:85a3:8d3:1319:8a2e:370:7348"),
			  ipv6_address(0x20010db885a308d3, 0x13198a2e03707348));

	ASSERT_EQ(ipv6_address::parse("::ffff:192.168.0.1"), ipv6_address(0x0, 0xffffc0a80001));
	// https://www.rfc-editor.org/rfc/rfc4291#section-2.5.5.2 requires a ipv4 mapped address to be in the form of ::ffff:xxxx:xxxx
	ASSERT_EQ(ipv6_address::parse("0102:0304::128.69.32.17"), std::nullopt);
	ASSERT_EQ(ipv6_address::parse("0102:0304::128.69.32.17"), std::nullopt);

	// Hexadecimal chars in dotted decimal part
	ASSERT_EQ(ipv6_address::parse("64:ff9b::12f.100.30.1"), std::nullopt);
	ASSERT_EQ(ipv6_address::parse("64:ff9b::123.10a.30.1"), std::nullopt);
	ASSERT_EQ(ipv6_address::parse("64:ff9b::123.100.3d.1"), std::nullopt);
	ASSERT_EQ(ipv6_address::parse("64:ff9b::12f.100.30.f4"), std::nullopt);

	// Overflow of individual parts of dotted decimal notation
	ASSERT_EQ(ipv6_address::parse("::ffff:456.12.45.30"), std::nullopt);
	ASSERT_EQ(ipv6_address::parse("::ffff:45.256.45.30"), std::nullopt);
	ASSERT_EQ(ipv6_address::parse("::ffff:45.25.677.30"), std::nullopt);
	ASSERT_EQ(ipv6_address::parse("::ffff:123.12.45.301"), std::nullopt);

	static constexpr auto static_parse = ipv6_address::parse("::1");
	static_assert(static_parse.has_value());
	static_assert(static_parse.value() == ipv6_address::loopback());
}

TEST(ASYNCPP_IO, IPv6MapIPv4) {
	ASSERT_EQ(ipv6_address(ipv4_address(10, 0, 0, 1)).to_string(), "::ffff:a00:1");
	ASSERT_TRUE(ipv6_address(ipv4_address(10, 0, 0, 1)).is_ipv4_mapped());
	ASSERT_EQ(ipv6_address(ipv4_address(10, 0, 0, 1)).mapped_ipv4(), ipv4_address(10, 0, 0, 1));
	ASSERT_FALSE(ipv6_address(0x0102030405060708, 0x090A0B0C00000000).is_ipv4_mapped());
}

TEST(ASYNCPP_IO, IPv6ToString) {
	ASSERT_EQ(ipv6_address(0, 0).to_string(), "::");
	ASSERT_EQ(ipv6_address::loopback().to_string(), "::1");
	ASSERT_EQ(ipv6_address::loopback().to_string(true), "0000:0000:0000:0000:0000:0000:0000:0001");

	ASSERT_EQ(ipv6_address(0x0102030405060708, 0x090A0B0C0D0E0F10).to_string(), "102:304:506:708:90a:b0c:d0e:f10");
	ASSERT_EQ(ipv6_address(0x0001001001001000, 0x0).to_string(), "1:10:100:1000::");
	ASSERT_EQ(ipv6_address(0x0002030405060708, 0x090A0B0C0D0E0F10).to_string(), "2:304:506:708:90a:b0c:d0e:f10");
	ASSERT_EQ(ipv6_address(0x0000030405060708, 0x090A0B0C0D0E0F10).to_string(), "0:304:506:708:90a:b0c:d0e:f10");
	ASSERT_EQ(ipv6_address(0x0000000005060708, 0x090A0B0C0D0E0F10).to_string(), "::506:708:90a:b0c:d0e:f10");
	ASSERT_EQ(ipv6_address(0x0102030400000000, 0x00000B0C0D0E0F10).to_string(), "102:304::b0c:d0e:f10");
	ASSERT_EQ(ipv6_address(0x0102030405060708, 0x090A0B0C0D0E0000).to_string(), "102:304:506:708:90a:b0c:d0e:0");
	ASSERT_EQ(ipv6_address(0x0102030405060708, 0x090A0B0C00000000).to_string(), "102:304:506:708:90a:b0c::");

	// Check that it contracts the first of multiple equal-length zero runs.
	ASSERT_EQ(ipv6_address(0x0102030400000000, 0x090A0B0C00000000).to_string(), "102:304::90a:b0c:0:0");
}

TEST(ASYNCPP_IO, UDSParse) {
	ASSERT_EQ(uds_address::parse(std::string_view("\0", 1)), std::nullopt);
	ASSERT_EQ(uds_address::parse(std::string_view("@")), std::nullopt);
	ASSERT_EQ(uds_address::parse(std::string_view("@\0", 2)), std::nullopt);
	ASSERT_EQ(uds_address::parse(std::string_view(" test.sock")), std::nullopt);
	ASSERT_EQ(uds_address::parse(std::string_view("test.sock ")), std::nullopt);
	ASSERT_EQ(uds_address::parse(std::string(109, 's')), std::nullopt);
	auto addr = uds_address::parse("uds.socket");
	ASSERT_TRUE(addr.has_value());
	ASSERT_EQ(addr->data().size(), 10);
	ASSERT_TRUE(memcmp(addr->data().data(), "uds.socket", 10) == 0);
	addr = uds_address::parse("./uds.socket");
	ASSERT_TRUE(addr.has_value());
	ASSERT_EQ(addr->data().size(), 12);
	ASSERT_TRUE(memcmp(addr->data().data(), "./uds.socket", 12) == 0);
	addr = uds_address::parse("@uds.socket");
	ASSERT_TRUE(addr.has_value());
	ASSERT_EQ(addr->data().size(), 11);
	ASSERT_TRUE(memcmp(addr->data().data(), "\0uds.socket", 11) == 0);
	addr = uds_address::parse("");
	ASSERT_TRUE(addr.has_value());
	ASSERT_EQ(addr->data().size(), 0);

	static constexpr auto static_parse = uds_address::parse("@uds.socket");
	static_assert(static_parse.has_value());
}

TEST(ASYNCPP_IO, UDSToString) {
	ASSERT_EQ(uds_address("@uds").to_string(), "@uds");
	ASSERT_EQ(uds_address(std::string_view("\0uds", 4)).to_string(), "@uds");
	ASSERT_EQ(uds_address("./uds").to_string(), "./uds");
}

TEST(ASYNCPP_IO, UDSTypes) {
	ASSERT_TRUE(uds_address("@uds").is_abstract());
	ASSERT_FALSE(uds_address("@uds").is_unnamed());
	ASSERT_FALSE(uds_address("uds").is_abstract());
	ASSERT_FALSE(uds_address("uds").is_unnamed());
	ASSERT_FALSE(uds_address("").is_abstract());
	ASSERT_TRUE(uds_address("").is_unnamed());
}
