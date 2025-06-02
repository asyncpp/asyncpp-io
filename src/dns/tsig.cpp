#include <asyncpp/io/dns/reader.h>
#include <asyncpp/io/dns/writer.h>

#include <openssl/evp.h>

namespace asyncpp::io::dns {
	namespace {
		qname alg_name(tsig_algorithm alg) {
			switch (alg) {
			case tsig_algorithm::hmac_md5: return {"hmac-md5", "sig-alg", "reg", "int"};
			case tsig_algorithm::hmac_sha1: return {"hmac-sha1"};
			case tsig_algorithm::hmac_sha224: return {"hmac-sha224"};
			case tsig_algorithm::hmac_sha256: return {"hmac-sha256"};
			case tsig_algorithm::hmac_sha256_128: return {"hmac-sha256-128"};
			case tsig_algorithm::hmac_sha384: return {"hmac-sha384"};
			case tsig_algorithm::hmac_sha384_192: return {"hmac-sha384-192"};
			case tsig_algorithm::hmac_sha512: return {"hmac-sha512"};
			case tsig_algorithm::hmac_sha512_256: return {"hmac-sha512-256"};
			}
			throw std::logic_error("invalid algorithm");
		}

		class hmac {
			EVP_MAC* m_mac{};
			EVP_MAC_CTX* m_ctx{};

		public:
			constexpr hmac() noexcept {}
			hmac(const hmac&) = delete;
			hmac& operator=(const hmac&) = delete;
			~hmac() {
				if (m_mac != nullptr) EVP_MAC_free(m_mac);
				if (m_ctx != nullptr) EVP_MAC_CTX_free(m_ctx);
			}
			void init(const char* name, std::span<const std::byte> key) {
				if (m_mac != nullptr) EVP_MAC_free(m_mac);
				if (m_ctx != nullptr) EVP_MAC_CTX_free(m_ctx);

				m_mac = EVP_MAC_fetch(nullptr, "hmac", nullptr);
				if (m_mac == nullptr) throw std::runtime_error("failed to find hmac");
				m_ctx = EVP_MAC_CTX_new(m_mac);
				if (m_mac == nullptr) throw std::runtime_error("failed to allocate context");

				OSSL_PARAM param[3];
				param[0] = OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>(name), 0);
				param[1] = OSSL_PARAM_construct_octet_string("key", const_cast<std::byte*>(key.data()), key.size());
				param[2] = OSSL_PARAM_construct_end();
				if (EVP_MAC_init(m_ctx, nullptr, 0, param) != 1) throw std::runtime_error("failed to initialize mac");
			}
			void update(std::span<const std::byte> data) {
				if (EVP_MAC_update(m_ctx, reinterpret_cast<const uint8_t*>(data.data()), data.size()) != 1)
					throw std::runtime_error("failed to update mac");
			}
			size_t finish(std::span<std::byte> mac) {
				size_t mdlen;
				if (EVP_MAC_final(m_ctx, nullptr, &mdlen, 0) != 1) throw std::runtime_error("failed to get mac");
				if (mac.size() < mdlen) throw std::runtime_error("mac buffer too small");
				if (EVP_MAC_final(m_ctx, reinterpret_cast<uint8_t*>(mac.data()), &mdlen, mac.size()) != 1)
					throw std::runtime_error("failed to get mac");
				return mdlen;
			}
		};
	} // namespace

	writer& writer::sign_tsig(qname keyname, tsig_algorithm alg, std::span<const std::byte> key, uint16_t error,
							  std::span<const std::byte> otherdata, std::chrono::system_clock::time_point ts,
							  std::chrono::seconds fudge) {
		// Make sure the message is complete
		if (m_rr_offset != 0) rr_end();

		std::array<std::byte, max_message_size> tsigdata{};
		auto offset = keyname.serialize_to_msg(tsigdata, 0);
		// Class (always any)
		raw_set<uint16_t, std::endian::big>(tsigdata.data() + offset, static_cast<uint16_t>(qclass::any));
		offset += 2;
		// TTL (always 0)
		raw_set<uint32_t, std::endian::big>(tsigdata.data() + offset, 0);
		offset += 4;
		// Algorithm name
		auto algname = alg_name(alg);
		offset = algname.serialize_to_msg(tsigdata, offset);
		uint64_t ts_in_sec = std::chrono::system_clock::to_time_t(ts);
		static_assert(sizeof(ts_in_sec) >= 6);
		// Timestamp (48bit unix seconds)
		tsigdata[offset++] = static_cast<std::byte>((ts_in_sec >> 40) & 0xff);
		tsigdata[offset++] = static_cast<std::byte>((ts_in_sec >> 32) & 0xff);
		tsigdata[offset++] = static_cast<std::byte>((ts_in_sec >> 24) & 0xff);
		tsigdata[offset++] = static_cast<std::byte>((ts_in_sec >> 16) & 0xff);
		tsigdata[offset++] = static_cast<std::byte>((ts_in_sec >> 8) & 0xff);
		tsigdata[offset++] = static_cast<std::byte>(ts_in_sec & 0xff);
		// Fudge
		uint16_t fudge_in_sec = fudge.count();
		tsigdata[offset++] = static_cast<std::byte>((fudge_in_sec >> 8) & 0xff);
		tsigdata[offset++] = static_cast<std::byte>(fudge_in_sec & 0xff);
		// Error
		tsigdata[offset++] = static_cast<std::byte>((error >> 8) & 0xff);
		tsigdata[offset++] = static_cast<std::byte>(error & 0xff);
		// Other len
		tsigdata[offset++] = static_cast<std::byte>((otherdata.size() >> 8) & 0xff);
		tsigdata[offset++] = static_cast<std::byte>(otherdata.size() & 0xff);
		// Other data
		if (tsigdata.size() - offset < otherdata.size()) throw std::out_of_range("query exceeds message size");
		for (auto c : otherdata)
			tsigdata[offset++] = c;

		hmac hash;
		switch (alg) {
		case tsig_algorithm::hmac_md5: hash.init("md5", key); break;
		case tsig_algorithm::hmac_sha1: hash.init("sha1", key); break;
		case tsig_algorithm::hmac_sha224: hash.init("sha224", key); break;
		case tsig_algorithm::hmac_sha256:
		case tsig_algorithm::hmac_sha256_128: hash.init("sha256", key); break;
		case tsig_algorithm::hmac_sha384:
		case tsig_algorithm::hmac_sha384_192: hash.init("sha384", key); break;
		case tsig_algorithm::hmac_sha512:
		case tsig_algorithm::hmac_sha512_256: hash.init("sha512", key); break;
		}

		// TODO: Support for request mac
		hash.update(std::span(m_message).subspan(0, m_current_offset));
		hash.update(std::span(tsigdata).subspan(0, offset));

		std::array<std::byte, EVP_MAX_MD_SIZE> hash_out{};
		auto hashlen = hash.finish(hash_out);
		switch (alg) {
		case tsig_algorithm::hmac_sha256_128:
		case tsig_algorithm::hmac_sha384_192:
		case tsig_algorithm::hmac_sha512_256: hashlen /= 2; break;
		default: break;
		}

		this->rr_begin_additional(keyname, qtype::tsig, qclass::any, std::chrono::seconds{0})
			.rr_put_domain_name(algname, false)
			.rr_put_u48(ts_in_sec)
			.rr_put_u16(fudge_in_sec)
			.rr_put_u16(hashlen)
			.rr_put_raw(std::span(hash_out).subspan(0, hashlen))
			.rr_put_u16(raw_get<uint16_t, std::endian::big>(m_message.data()))
			.rr_put_u16(error)
			.rr_put_u16(otherdata.size())
			.rr_put_raw(otherdata)
			.rr_end();
		return *this;
	}

	void reader::validate_tsig(qname keyname, tsig_algorithm alg, std::span<const std::byte> key,
							   std::chrono::system_clock::time_point now) {
		throw std::logic_error("not implemented");
	}

	void reader::remove_tsig() {
		auto it = additionals_begin();
		for (size_t i = 0; it != additionals_end(); ++it) {
			if (it->get_type() != qtype::tsig || it->get_class() != qclass::any) {
				i++;
				continue;
			}
			if (i != additionals_count() - 1) throw std::runtime_error("tsig is not the last record");
			m_message = m_message.subspan(0, it.offset());
			raw_set<uint16_t, std::endian::big>(m_header.data() + 10,
												raw_get<uint16_t, std::endian::big>(m_header.data() + 10) - 1);
			break;
		}
	}

} // namespace asyncpp::io::dns
