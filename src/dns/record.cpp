#include <asyncpp/io/dns/record.h>

#include <asyncpp/io/address.h>
#include <asyncpp/io/dns/reader.h>
#include <asyncpp/io/dns/writer.h>

namespace asyncpp::io::dns {
	namespace {
		template<typename T, size_t Size>
		std::array<T, Size> to_fixed_array(std::span<const std::byte> val) {
			std::array<T, Size> res;
			if (val.size_bytes() != sizeof(T) * Size) throw std::logic_error("invalid size span");
			memcpy(res.data(), val.data(), val.size_bytes());
			return res;
		}
	} // namespace

	void record_traits<qtype::a, qclass::in>::parse(rdata_type& val, reader_rdata& rdr) {
		val = ipv4_address(to_fixed_array<uint8_t, 4>(rdr.pop_raw(4)), std::endian::big);
	}

	void record_traits<qtype::a, qclass::in>::serialize(const rdata_type& val, writer& wrt) {
		wrt.rr_put_raw(std::as_bytes(val.data()));
	}

	void record_traits<qtype::ns, qclass::in>::parse(rdata_type& val, reader_rdata& rdr) {
		val = rdr.pop_domain_name();
	}

	void record_traits<qtype::ns, qclass::in>::serialize(const rdata_type& val, writer& wrt) {
		wrt.rr_put_domain_name(val);
	}

	void record_traits<qtype::md, qclass::in>::parse(rdata_type& val, reader_rdata& rdr) {
		val = rdr.pop_domain_name();
	}

	void record_traits<qtype::md, qclass::in>::serialize(const rdata_type& val, writer& wrt) {
		wrt.rr_put_domain_name(val);
	}

	void record_traits<qtype::mf, qclass::in>::parse(rdata_type& val, reader_rdata& rdr) {
		val = rdr.pop_domain_name();
	}

	void record_traits<qtype::mf, qclass::in>::serialize(const rdata_type& val, writer& wrt) {
		wrt.rr_put_domain_name(val);
	}

	void record_traits<qtype::cname, qclass::in>::parse(rdata_type& val, reader_rdata& rdr) {
		val = rdr.pop_domain_name();
	}

	void record_traits<qtype::cname, qclass::in>::serialize(const rdata_type& val, writer& wrt) {
		wrt.rr_put_domain_name(val);
	}

	void record_traits<qtype::soa, qclass::in>::parse(rdata_type& val, reader_rdata& rdr) {
		val.mname = rdr.pop_domain_name();
		val.rname = rdr.pop_domain_name();
		val.serial = rdr.pop_u32();
		val.refresh = std::chrono::seconds{rdr.pop_u32()};
		val.retry = std::chrono::seconds{rdr.pop_u32()};
		val.expire = std::chrono::seconds{rdr.pop_u32()};
		val.minimum = std::chrono::seconds{rdr.pop_u32()};
	}

	void record_traits<qtype::soa, qclass::in>::serialize(const rdata_type& val, writer& wrt) {
		wrt.rr_put_domain_name(val.mname)
			.rr_put_domain_name(val.rname)
			.rr_put_u32(val.serial)
			.rr_put_u32(val.refresh.count())
			.rr_put_u32(val.retry.count())
			.rr_put_u32(val.expire.count())
			.rr_put_u32(val.minimum.count());
	}

	void record_traits<qtype::mb, qclass::in>::parse(rdata_type& val, reader_rdata& rdr) {
		val = rdr.pop_domain_name();
	}

	void record_traits<qtype::mb, qclass::in>::serialize(const rdata_type& val, writer& wrt) {
		wrt.rr_put_domain_name(val);
	}

	void record_traits<qtype::mg, qclass::in>::parse(rdata_type& val, reader_rdata& rdr) {
		val = rdr.pop_domain_name();
	}

	void record_traits<qtype::mg, qclass::in>::serialize(const rdata_type& val, writer& wrt) {
		wrt.rr_put_domain_name(val);
	}

	void record_traits<qtype::mr, qclass::in>::parse(rdata_type& val, reader_rdata& rdr) {
		val = rdr.pop_domain_name();
	}

	void record_traits<qtype::mr, qclass::in>::serialize(const rdata_type& val, writer& wrt) {
		wrt.rr_put_domain_name(val);
	}

	void record_traits<qtype::null, qclass::in>::parse(rdata_type& val, reader_rdata& rdr) {
		auto data = rdr.pop_raw(rdr.remaining());
		val.resize(data.size());
		memcpy(val.data(), data.data(), data.size());
	}

	void record_traits<qtype::null, qclass::in>::serialize(const rdata_type& val, writer& wrt) { wrt.rr_put_raw(val); }

	void record_traits<qtype::wks, qclass::in>::parse(rdata_type& val, reader_rdata& rdr) {
		val.address = ipv4_address(to_fixed_array<uint8_t, 4>(rdr.pop_raw(4)), std::endian::big);
		val.protocol = rdr.pop_u8();
		const auto ports = rdr.pop_raw(rdr.remaining());
		const auto len = std::min(ports.size(), val.ports.size());
		memcpy(val.ports.data(), ports.data(), len);
		memset(val.ports.data() + len, 0, val.ports.size() - len);
	}

	void record_traits<qtype::wks, qclass::in>::serialize(const rdata_type& val, writer& wrt) {
		wrt.rr_put_raw(std::as_bytes(val.address.data()));
		wrt.rr_put_u8(val.protocol);
		size_t highest = 0;
		for (size_t i = val.ports.size(); i > 0; i--) {
			if (val.ports[i] == 0) continue;
			highest = i;
			break;
		}
		wrt.rr_put_raw(std::as_bytes(std::span(val.ports)).subspan(0, highest + 1));
	}

	void record_traits<qtype::ptr, qclass::in>::parse(rdata_type& val, reader_rdata& rdr) {
		val = rdr.pop_domain_name();
	}

	void record_traits<qtype::ptr, qclass::in>::serialize(const rdata_type& val, writer& wrt) {
		wrt.rr_put_domain_name(val);
	}

	void record_traits<qtype::hinfo, qclass::in>::parse(rdata_type& val, reader_rdata& rdr) {
		val.cpu = rdr.pop_string();
		val.os = rdr.pop_string();
	}

	void record_traits<qtype::hinfo, qclass::in>::serialize(const rdata_type& val, writer& wrt) {
		wrt.rr_put_string(val.cpu);
		wrt.rr_put_string(val.os);
	}

	void record_traits<qtype::minfo, qclass::in>::parse(rdata_type& val, reader_rdata& rdr) {
		val.rmailbx = rdr.pop_domain_name();
		val.emailbx = rdr.pop_domain_name();
	}

	void record_traits<qtype::minfo, qclass::in>::serialize(const rdata_type& val, writer& wrt) {
		wrt.rr_put_domain_name(val.rmailbx);
		wrt.rr_put_domain_name(val.emailbx);
	}

	void record_traits<qtype::mx, qclass::in>::parse(rdata_type& val, reader_rdata& rdr) {
		val.preference = rdr.pop_u16();
		val.exchange = rdr.pop_domain_name();
	}

	void record_traits<qtype::mx, qclass::in>::serialize(const rdata_type& val, writer& wrt) {
		wrt.rr_put_u16(val.preference);
		wrt.rr_put_domain_name(val.exchange);
	}

	void record_traits<qtype::txt, qclass::in>::parse(rdata_type& val, reader_rdata& rdr) {
		while (rdr.remaining() != 0) {
			val.emplace_back(rdr.pop_string());
		}
	}

	void record_traits<qtype::txt, qclass::in>::serialize(const rdata_type& val, writer& wrt) {
		for (auto& e : val)
			wrt.rr_put_string(e);
	}

	void record_traits<qtype::rp, qclass::in>::parse(rdata_type& val, reader_rdata& rdr) {
		val.mbox = rdr.pop_domain_name();
		val.txt = rdr.pop_domain_name();
	}

	void record_traits<qtype::rp, qclass::in>::serialize(const rdata_type& val, writer& wrt) {
		wrt.rr_put_domain_name(val.mbox);
		wrt.rr_put_domain_name(val.txt);
	}

	void record_traits<qtype::afsdb, qclass::in>::parse(rdata_type& val, reader_rdata& rdr) {
		val.subtype = rdr.pop_u16();
		val.hostname = rdr.pop_domain_name();
	}

	void record_traits<qtype::afsdb, qclass::in>::serialize(const rdata_type& val, writer& wrt) {
		wrt.rr_put_u16(val.subtype);
		wrt.rr_put_domain_name(val.hostname);
	}

	void record_traits<qtype::x25, qclass::in>::parse(rdata_type& val, reader_rdata& rdr) { val = rdr.pop_string(); }

	void record_traits<qtype::x25, qclass::in>::serialize(const rdata_type& val, writer& wrt) {
		wrt.rr_put_string(val);
	}

	void record_traits<qtype::isdn, qclass::in>::parse(rdata_type& val, reader_rdata& rdr) {
		val.address = rdr.pop_string();
		if (rdr.remaining() != 0) val.sa = rdr.pop_string();
	}

	void record_traits<qtype::isdn, qclass::in>::serialize(const rdata_type& val, writer& wrt) {
		wrt.rr_put_string(val.address);
		if(!val.sa.empty()) wrt.rr_put_string(val.sa);
	}

	void record_traits<qtype::rt, qclass::in>::parse(rdata_type& val, reader_rdata& rdr) {
		val.preference = rdr.pop_u16();
		val.intermediate_host = rdr.pop_domain_name();
	}

	void record_traits<qtype::rt, qclass::in>::serialize(const rdata_type& val, writer& wrt) {
		wrt.rr_put_u16(val.preference);
		wrt.rr_put_domain_name(val.intermediate_host);
	}

	void record_traits<qtype::nsap, qclass::in>::parse(rdata_type& val, reader_rdata& rdr) {
		auto data = rdr.pop_raw(rdr.remaining());
		val.resize(data.size());
		memcpy(val.data(), data.data(), data.size());
	}

	void record_traits<qtype::nsap, qclass::in>::serialize(const rdata_type& val, writer& wrt) { wrt.rr_put_raw(val); }

	void record_traits<qtype::nsap_ptr, qclass::in>::parse(rdata_type& val, reader_rdata& rdr) {
		val = rdr.pop_domain_name();
	}

	void record_traits<qtype::nsap_ptr, qclass::in>::serialize(const rdata_type& val, writer& wrt) {
		wrt.rr_put_domain_name(val);
	}

	void record_traits<qtype::aaaa, qclass::in>::parse(rdata_type& val, reader_rdata& rdr) {
		val = ipv6_address(to_fixed_array<uint8_t, 16>(rdr.pop_raw(16)), std::endian::big);
	}

	void record_traits<qtype::aaaa, qclass::in>::serialize(const rdata_type& val, writer& wrt) {
		wrt.rr_put_raw(std::as_bytes(val.data()));
	}

	void record_traits<qtype::srv, qclass::in>::parse(rdata_type& val, reader_rdata& rdr) {
		val.priority = rdr.pop_u16();
		val.weight = rdr.pop_u16();
		val.port = rdr.pop_u16();
		val.target = rdr.pop_domain_name();
	}

	void record_traits<qtype::srv, qclass::in>::serialize(const rdata_type& val, writer& wrt) {
		wrt.rr_put_u16(val.priority);
		wrt.rr_put_u16(val.weight);
		wrt.rr_put_u16(val.port);
		wrt.rr_put_domain_name(val.target);
	}

} // namespace asyncpp::io::dns