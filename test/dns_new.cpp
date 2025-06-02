#include <asyncpp/io/address.h>
#include <asyncpp/io/dns/reader.h>
#include <asyncpp/io/dns/record.h>
#include <asyncpp/io/dns/writer.h>

#include <chrono>
#include <gtest/gtest.h>

using namespace asyncpp::io;
using namespace asyncpp::io::dns;

template<size_t N>
std::vector<std::byte> as_vec(const char (&v)[N]) {
	std::vector<std::byte> res(N - 1);
	memcpy(res.data(), v, N - 1);
	return res;
}

namespace std {
	void PrintTo(const vector<std::byte>& val, std::ostream* os) {
		for (auto e : val) {
			const char* table = "0123456789abcdef";
			char buf[3];
			buf[0] = table[static_cast<uint8_t>(e) >> 4];
			buf[1] = table[static_cast<uint8_t>(e) & 0x0f];
			buf[2] = ' ';
			os->write(buf, 3);
		}
	}
} // namespace std

TEST(ASYNCPP_IO, DNSQnameSubName) {
	qname name({"dummy", "domain", "de"});
	ASSERT_EQ(name.size(), 3);
	ASSERT_EQ(name[0], "dummy");
	ASSERT_EQ(name[1], "domain");
	ASSERT_EQ(name[2], "de");

	auto sub = name.subname(1);
	ASSERT_EQ(sub.size(), 2);
	ASSERT_EQ(sub[0], "domain");
	ASSERT_EQ(sub[1], "de");

	sub = name.subname(0, 1);
	ASSERT_EQ(sub.size(), 1);
	ASSERT_EQ(sub[0], "dummy");

	sub = name.subname(1, 1);
	ASSERT_EQ(sub.size(), 1);
	ASSERT_EQ(sub[0], "domain");
}

TEST(ASYNCPP_IO, DNSQnameToString) {
	ASSERT_EQ(qname().to_string(), "");
	ASSERT_EQ(qname({"de"}).to_string(), "de");
	ASSERT_EQ(qname({"domain", "de"}).to_string(), "domain.de");
	ASSERT_EQ(qname({"dummy", "domain", "de"}).to_string(), "dummy.domain.de");
}

TEST(ASYNCPP_IO, DNSQnameSerialize) {
	qname name({"domain"});

	ASSERT_EQ(name.serialize_to_msg({}, 0), 0);
	std::vector<std::byte> buf;
	buf.resize(6);
	ASSERT_EQ(name.serialize_to_msg(buf, 0), 0);
	buf.resize(7);
	ASSERT_EQ(name.serialize_to_msg(buf, 0), 0);
	buf.resize(8);
	ASSERT_EQ(name.serialize_to_msg(buf, 0), 8);
	ASSERT_EQ(buf, as_vec("\x06\x64\x6f\x6d\x61\x69\x6e\x00"));
	buf.resize(9);
	memset(buf.data(), 0xff, 8);
	ASSERT_EQ(name.serialize_to_msg(buf, 0), 8);
	ASSERT_EQ(buf, as_vec("\x06\x64\x6f\x6d\x61\x69\x6e\x00\x00"));
}

TEST(ASYNCPP_IO, DNSQnameSerializeCompress) {
	qname name({"dummy", "domain", "de"});

	qname::compression_table table{};

	ASSERT_EQ(name.serialize_to_msg({}, 0, &table), 0);
	ASSERT_TRUE(table.empty());

	std::vector<std::byte> buf;
	buf.resize(17);
	ASSERT_EQ(name.serialize_to_msg(buf, 0, &table), 17);
	ASSERT_EQ(buf, as_vec("\x05\x64\x75\x6d\x6d\x79\x06\x64\x6f\x6d\x61\x69\x6e\x02\x64\x65\x00"));
	ASSERT_FALSE(table.empty());
	ASSERT_TRUE(table.contains(name));
	ASSERT_TRUE(table.contains(name.subname(1)));
	ASSERT_TRUE(table.contains(name.subname(2)));
	ASSERT_EQ(table.at(name), 0);
	ASSERT_EQ(table.at(name.subname(1)), 6);
	ASSERT_EQ(table.at(name.subname(2)), 13);
	buf.resize(2);
	ASSERT_EQ(name.serialize_to_msg(buf, 0, &table), 2);
	ASSERT_EQ(buf, as_vec("\xc0\x00"));
	ASSERT_EQ(name.subname(1).serialize_to_msg(buf, 0, &table), 2);
	ASSERT_EQ(buf, as_vec("\xc0\x06"));
	ASSERT_EQ(name.subname(2).serialize_to_msg(buf, 0, &table), 2);
	ASSERT_EQ(buf, as_vec("\xc0\x0d"));

	table.clear();
	buf.resize(4);
	ASSERT_EQ(name.subname(2).serialize_to_msg(buf, 0, &table), 4);
	ASSERT_EQ(buf, as_vec("\x02\x64\x65\x00"));
	ASSERT_FALSE(table.empty());
	ASSERT_TRUE(table.contains(name.subname(2)));
	ASSERT_EQ(table.at(name.subname(2)), 0);

	buf.resize(9);
	ASSERT_EQ(name.subname(1).serialize_to_msg(buf, 0, &table), 9);
	ASSERT_EQ(buf, as_vec("\x06\x64\x6f\x6d\x61\x69\x6e\xc0\x00"));
	ASSERT_FALSE(table.empty());
	ASSERT_TRUE(table.contains(name.subname(1)));
	ASSERT_TRUE(table.contains(name.subname(2)));
	ASSERT_EQ(table.at(name.subname(1)), 0);
	ASSERT_EQ(table.at(name.subname(2)), 0);

	buf.resize(8);
	ASSERT_EQ(name.serialize_to_msg(buf, 0, &table), 8);
	ASSERT_EQ(buf, as_vec("\x05\x64\x75\x6d\x6d\x79\xc0\x00"));
	ASSERT_FALSE(table.empty());
	ASSERT_TRUE(table.contains(name));
	ASSERT_TRUE(table.contains(name.subname(1)));
	ASSERT_TRUE(table.contains(name.subname(2)));
	ASSERT_EQ(table.at(name), 0);
	ASSERT_EQ(table.at(name.subname(1)), 0);
	ASSERT_EQ(table.at(name.subname(2)), 0);

	buf.resize(2);
	ASSERT_EQ(name.serialize_to_msg(buf, 0, &table), 2);
	ASSERT_EQ(buf, as_vec("\xc0\x00"));
	ASSERT_FALSE(table.empty());
	ASSERT_TRUE(table.contains(name));
	ASSERT_TRUE(table.contains(name.subname(1)));
	ASSERT_TRUE(table.contains(name.subname(2)));
	ASSERT_EQ(table.at(name), 0);
	ASSERT_EQ(table.at(name.subname(1)), 0);
	ASSERT_EQ(table.at(name.subname(2)), 0);
}

TEST(ASYNCPP_IO, DNSWriter) {
	const auto res = writer()
						 .set_id(0x21d0)
						 .set_opcode(opcode::query)
						 .set_rd(true)
						 .set_answer_authenticated(true)
						 .add_query({"google", "de"}, qtype::a, qclass::in)
						 .rr_begin_additional({}, qtype::opt, static_cast<qclass>(1232), std::chrono::seconds(0))
						 .rr_put_u16(10)
						 .rr_put_u16(8)
						 .rr_put_raw(std::as_bytes(std::span("\x66\xa9\x04\x9b\x5e\xea\xe6\x59", 8)))
						 .rr_end()
						 .build();
	const auto expect = as_vec(
		"\x21\xd0\x01\x20\x00\x01\x00\x00\x00\x00\x00\x01\x06\x67\x6f\x6f\x67\x6c\x65\x02\x64\x65\x00\x00\x01\x00\x01"
		"\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x0c\x00\x0a\x00\x08\x66\xa9\x04\x9b\x5e\xea\xe6\x59");
	ASSERT_EQ(res, expect);
}

TEST(ASYNCPP_IO, DNSWriterCompress) {
	const auto res = writer()
						 .set_id(0xa978)
						 .set_qr(true)
						 .set_opcode(opcode::query)
						 .set_rd(true)
						 .set_ra(true)
						 .add_query({"dns", "cloudflare", "com"}, qtype::a, qclass::in)
						 .rr_begin_answer({"dns", "cloudflare", "com"}, qtype::a, qclass::in, std::chrono::seconds{280})
						 .rr_put_raw(std::as_bytes(std::span("\x68\x10\x85\xe5", 4)))
						 .rr_begin_answer({"dns", "cloudflare", "com"}, qtype::a, qclass::in, std::chrono::seconds{280})
						 .rr_put_raw(std::as_bytes(std::span("\x68\x10\x84\xe5", 4)))
						 .rr_end()
						 .build();
	const auto expect =
		as_vec("\xa9\x78\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00\x03\x64\x6e\x73\x0a\x63\x6c\x6f\x75\x64\x66\x6c\x61"
			   "\x72\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x18\x00\x04\x68\x10"
			   "\x85\xe5\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x18\x00\x04\x68\x10\x84\xe5");
	ASSERT_EQ(res, expect);
}

TEST(ASYNCPP_IO, DNSWriterTSIG) {
	const auto key = as_vec("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f");
	const auto res = writer()
						 .set_id(0xa978)
						 .set_qr(true)
						 .set_opcode(opcode::query)
						 .set_rd(true)
						 .set_ra(true)
						 .add_query({"dns", "cloudflare", "com"}, qtype::a, qclass::in)
						 .rr_begin_answer({"dns", "cloudflare", "com"}, qtype::a, qclass::in, std::chrono::seconds{280})
						 .rr_put_raw(std::as_bytes(std::span("\x68\x10\x85\xe5", 4)))
						 .rr_begin_answer({"dns", "cloudflare", "com"}, qtype::a, qclass::in, std::chrono::seconds{280})
						 .rr_put_raw(std::as_bytes(std::span("\x68\x10\x84\xe5", 4)))
						 .rr_end()
						 .sign_tsig({"dummy"}, tsig_algorithm::hmac_md5, key, 0, {},
									std::chrono::system_clock::from_time_t(1721124299))
						 .build();
	const auto expect =
		as_vec("\xa9\x78\x81\x80\x00\x01\x00\x02\x00\x00\x00\x01\x03\x64\x6e\x73\x0a\x63\x6c\x6f\x75\x64\x66\x6c\x61"
			   "\x72\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x18\x00\x04\x68\x10"
			   "\x85\xe5\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x18\x00\x04\x68\x10\x84\xe5\x05\x64\x75\x6d\x6d\x79\x00"
			   "\x00\xfa\x00\xff\x00\x00\x00\x00\x00\x3a\x08\x68\x6d\x61\x63\x2d\x6d\x64\x35\x07\x73\x69\x67\x2d\x61"
			   "\x6c\x67\x03\x72\x65\x67\x03\x69\x6e\x74\x00\x00\x00\x66\x96\x45\xcb\x01\x2c\x00\x10\xbe\xd2\x47\x3d"
			   "\x9b\x70\x27\x8d\x21\x06\xee\x8d\x3f\x36\xd7\xc2\xa9\x78\x00\x00\x00\x00");
	ASSERT_EQ(res, expect);
}

TEST(ASYNCPP_IO, DNSReader) {
	const auto msg =
		as_vec("\xa9\x78\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00\x03\x64\x6e\x73\x0a\x63\x6c\x6f\x75\x64\x66\x6c\x61"
			   "\x72\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x18\x00\x04\x68\x10"
			   "\x85\xe5\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x18\x00\x04\x68\x10\x84\xe5");

	reader rdr(msg);
	ASSERT_EQ(rdr.get_id(), 0xa978);
	ASSERT_TRUE(rdr.get_qr());
	ASSERT_EQ(rdr.get_opcode(), opcode::query);
	ASSERT_TRUE(rdr.get_rd());
	ASSERT_TRUE(rdr.get_ra());
	ASSERT_EQ(rdr.questions_count(), 1);
	ASSERT_EQ(rdr.answers_count(), 2);
	ASSERT_EQ(rdr.authorities_count(), 0);
	ASSERT_EQ(rdr.additionals_count(), 0);

	for (auto& q : rdr.questions()) {
		ASSERT_EQ(q.get_name(), qname({"dns", "cloudflare", "com"}));
		ASSERT_EQ(q.get_class(), qclass::in);
		ASSERT_EQ(q.get_type(), qtype::a);
	}

	for (auto& rr : rdr.answers()) {
		ASSERT_EQ(rr.get_name(), qname({"dns", "cloudflare", "com"}));
		ASSERT_EQ(rr.get_class(), qclass::in);
		ASSERT_EQ(rr.get_type(), qtype::a);
		ASSERT_EQ(rr.get_ttl(), std::chrono::seconds(280));
		auto rdata = rr.get_rdata();
		ASSERT_EQ(rdata.remaining(), 4);
		auto val = rdata.pop_u32();
		ASSERT_TRUE(val == 0x681085e5 || val == 0x681084e5);
		ASSERT_EQ(rdata.remaining(), 0);
	}
	for ([[maybe_unused]] auto& rr : rdr.authorities())
		FAIL() << "There should not be authority entries";
	for ([[maybe_unused]] auto& rr : rdr.additionals())
		FAIL() << "There should not be additional entries";
}

TEST(ASYNCPP_IO, DNSReaderTSIG) {
	const auto msg =
		as_vec("\xa9\x78\x81\x80\x00\x01\x00\x02\x00\x00\x00\x01\x03\x64\x6e\x73\x0a\x63\x6c\x6f\x75\x64\x66\x6c\x61"
			   "\x72\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x18\x00\x04\x68\x10"
			   "\x85\xe5\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x18\x00\x04\x68\x10\x84\xe5\x05\x64\x75\x6d\x6d\x79\x00"
			   "\x00\xfa\x00\xff\x00\x00\x00\x00\x00\x3a\x08\x68\x6d\x61\x63\x2d\x6d\x64\x35\x07\x73\x69\x67\x2d\x61"
			   "\x6c\x67\x03\x72\x65\x67\x03\x69\x6e\x74\x00\x00\x00\x66\x96\x45\xcb\x01\x2c\x00\x10\xbe\xd2\x47\x3d"
			   "\x9b\x70\x27\x8d\x21\x06\xee\x8d\x3f\x36\xd7\xc2\xa9\x78\x00\x00\x00\x00");

	reader rdr(msg);
	ASSERT_EQ(rdr.get_id(), 0xa978);
	ASSERT_TRUE(rdr.get_qr());
	ASSERT_EQ(rdr.get_opcode(), opcode::query);
	ASSERT_TRUE(rdr.get_rd());
	ASSERT_TRUE(rdr.get_ra());
	ASSERT_EQ(rdr.questions_count(), 1);
	ASSERT_EQ(rdr.answers_count(), 2);
	ASSERT_EQ(rdr.authorities_count(), 0);
	ASSERT_EQ(rdr.additionals_count(), 1);

	for (auto& rr : rdr.additionals()) {
		ASSERT_EQ(rr.get_name(), qname({"dummy"}));
		ASSERT_EQ(rr.get_class(), qclass::any);
		ASSERT_EQ(rr.get_type(), qtype::tsig);
		ASSERT_EQ(rr.get_ttl(), std::chrono::seconds(0));
	}

	rdr.remove_tsig();
	ASSERT_EQ(rdr.additionals_count(), 0);

	for ([[maybe_unused]] auto& rr : rdr.additionals()) {
		FAIL() << "There should not be a additional anymore";
	}

	const auto key = as_vec("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f");

	rdr = reader(msg);
	rdr.validate_tsig({"dummy"}, tsig_algorithm::hmac_md5, key, std::chrono::system_clock::from_time_t(1721124299));
}

TEST(ASYNCPP_IO, DNSRecordA) {
	const auto res = writer().rr_add_answer<qtype::a>({"d"}, ipv4_address(10, 0, 0, 1)).build();
	const auto expect = as_vec("\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x64\x00\x00\x01\x00\x01\x00\x00"
							   "\x0e\x10\x00\x04\x0a\x00\x00\x01");
	ASSERT_EQ(res, expect);

	reader rdr(res);
	ASSERT_EQ(rdr.answers_count(), 1);
	for (auto& e : rdr.answers())
		ASSERT_EQ(e.get_rdata<qtype::a>(), ipv4_address(10, 0, 0, 1));
}

TEST(ASYNCPP_IO, DNSRecordAAAA) {
	const auto res =
		writer()
			.rr_add_answer<qtype::aaaa>({"d"}, ipv6_address(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15))
			.build();
	const auto expect = as_vec("\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x64\x00\x00\x1c\x00\x01\x00\x00\x0e\x10\x00\x10\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f");
	ASSERT_EQ(res, expect);

	reader rdr(res);
	ASSERT_EQ(rdr.answers_count(), 1);
	for (auto& e : rdr.answers())
		ASSERT_EQ(e.get_rdata<qtype::aaaa>(), ipv6_address(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15));
}