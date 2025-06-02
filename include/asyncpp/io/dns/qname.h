#pragma once
#include <asyncpp/io/buffer.h>

#include <array>
#include <cassert>
#include <cstdint>
#include <map>
#include <span>
#include <stdexcept>
#include <string_view>

namespace asyncpp::io::dns {
	class qname {
		std::array<std::byte, 256> m_data{};

		qname(std::span<const std::byte> data) : m_data{} {
			memcpy(m_data.data(), data.data(), std::min(data.size(), m_data.size()));
		}

	public:
		using compression_table = std::map<qname, size_t>;

		qname() = default;
		qname(const qname&) = default;
		qname& operator=(const qname&) = default;
		bool operator==(const qname&) const noexcept = default;
		bool operator!=(const qname&) const noexcept = default;
		auto operator<=>(const qname&) const noexcept = default;

		qname(std::initializer_list<const std::string_view> parts);
		qname(std::span<const std::string_view> parts);
		static qname parse_from_msg(std::span<const std::byte> msg, size_t& offset);
		size_t serialize_to_msg(std::span<std::byte> msg, size_t offset, compression_table* table = nullptr);

		size_t size() const noexcept;
		std::string_view operator[](size_t idx) const;
		std::string to_string() const;

		qname subname(size_t start, size_t len = 256) const;

		friend std::ostream& operator<<(std::ostream& os, const qname& n);
	};

	inline qname::qname(std::initializer_list<const std::string_view> parts)
		: qname(std::span(parts.begin(), parts.end())) {}

	inline qname::qname(std::span<const std::string_view> parts) {
		size_t pos = 0;
		for (auto e : parts) {
			if (e.size() > 63 || pos + 1 + e.size() > 254) throw std::runtime_error("invalid domain name");
			m_data[pos++] = static_cast<std::byte>(e.size());
			for (auto c : e)
				m_data[pos++] = static_cast<std::byte>(c);
		}
		m_data[pos++] = static_cast<std::byte>(0);
	}

	inline qname qname::parse_from_msg(std::span<const std::byte> msg, size_t& offset) {
		qname res{};
		size_t pos = 0;
		if (offset >= msg.size()) throw std::runtime_error("invalid domain name");
		auto l = static_cast<uint8_t>(msg[offset]);
		while (l != 0 && (l & 0xc0) == 0) {
			if (pos + l + 1 >= res.m_data.size() || offset + l + 1 >= msg.size())
				throw std::runtime_error("invalid domain name");
			res.m_data[pos++] = msg[offset++];
			for (size_t i = 0; i < l; i++)
				res.m_data[pos++] = msg[offset++];
			l = static_cast<uint8_t>(msg[offset]);
		}
		size_t moffset = offset;
		offset += ((l & 0xc0) == 0) ? 1 : 2;
		while (l != 0) {
			if ((l & 0xc0) == 0) {
				if (pos + l + 1 >= res.m_data.size() || moffset + l + 1 >= msg.size())
					throw std::runtime_error("invalid domain name");
				res.m_data[pos++] = msg[moffset++];
				for (size_t i = 0; i < l; i++)
					res.m_data[pos++] = msg[moffset++];
			} else {
				if (moffset + 2 >= msg.size()) throw std::runtime_error("invalid domain name");
				moffset = raw_get<uint16_t, std::endian::big>(msg.data() + moffset) & 0x3fff;
				if (moffset >= msg.size()) throw std::runtime_error("invalid domain name");
			}
			l = static_cast<uint8_t>(msg[moffset]);
		}
		res.m_data[pos] = static_cast<std::byte>(0);
		return res;
	}

	inline size_t qname::serialize_to_msg(std::span<std::byte> msg, size_t offset, compression_table* table) {
		if (table != nullptr) {
			for (size_t i = 0; i < size(); i++) {
				auto it = table->find(subname(i));
				if (it != table->end()) {
					// We have a suffix, add a pointer to the end and break out
					auto prefix = subname(0, i);
					std::array<std::byte, 256> out{};
					auto len = prefix.serialize_to_msg(out, 0, nullptr);
					assert(len > 0 && len < 255);
					if (offset + len + 1 > msg.size()) return 0;
					raw_set<uint16_t, std::endian::big>(out.data() + len - 1, 0xc000 | it->second);
					memcpy(msg.data() + offset, out.data(), len + 1);
					for (size_t pos = 0; pos < len - 1;) {
						table->emplace(qname(std::span(m_data.data() + pos, m_data.size() - pos)), offset + pos);
						pos += static_cast<uint8_t>(out[pos]) + 1;
					}
					return offset + len + 1;
				}
			}
		}

		// Either no compression requested or no matching prefix
		size_t i = 0;
		for (; i < m_data.size() && m_data[i] != static_cast<std::byte>(0);
			 i += (static_cast<uint8_t>(m_data[i]) & 0x3f) + 1) {}
		assert(i < m_data.size());
		assert(m_data[i] == static_cast<std::byte>(0));
		if (offset + i + 1 > msg.size()) return 0;
		memcpy(msg.data() + offset, m_data.data(), i + 1);
		if (table != nullptr) {
			for (size_t pos = 0; pos < i;) {
				table->emplace(qname(std::span(m_data.data() + pos, i - pos)), offset + pos);
				pos += static_cast<uint8_t>(m_data[pos]) + 1;
			}
		}
		return offset + i + 1;
	}

	inline size_t qname::size() const noexcept {
		size_t idx = 0;
		for (auto p = m_data.data(); static_cast<uint8_t>(*p) != 0; p += 1 + static_cast<uint8_t>(*p))
			idx++;
		return idx;
	}

	inline std::string_view qname::operator[](size_t idx) const {
		size_t curidx = 0;
		for (auto p = m_data.data(); static_cast<uint8_t>(*p) != 0; p += 1 + static_cast<uint8_t>(*p)) {
			if (curidx == idx) return std::string_view(reinterpret_cast<const char*>(p + 1), static_cast<uint8_t>(*p));
			curidx++;
		}
		throw std::out_of_range("invalid index");
	}

	inline std::string qname::to_string() const {
		size_t len = 0;
		while (len < m_data.size() && static_cast<uint8_t>(m_data[len]) != 0)
			len += 1 + static_cast<uint8_t>(m_data[len]);
		std::string res;
		if (len == 0) return res;
		res.reserve(len);
		for (size_t pos = 0; pos < len && static_cast<uint8_t>(m_data[pos]) != 0;
			 pos += 1 + static_cast<uint8_t>(m_data[pos])) {
			res.append(reinterpret_cast<const char*>(&m_data[pos + 1]), static_cast<uint8_t>(m_data[pos]));
			res += '.';
		}
		if (!res.empty()) res.resize(res.size() - 1);
		return res;
	}

	inline qname qname::subname(size_t start, size_t len) const {
		qname res;
		for (size_t i = 0; i < m_data.size() && m_data[i] != static_cast<std::byte>(0);
			 i += (static_cast<uint8_t>(m_data[i]) & 0x3f) + 1) {
			if (start == 0) {
				memcpy(res.m_data.data(), m_data.data() + i, m_data.size() - i);
				break;
			}
			start--;
		}
		for (size_t i = 0; i < res.m_data.size() && res.m_data[i] != static_cast<std::byte>(0);
			 i += (static_cast<uint8_t>(res.m_data[i]) & 0x3f) + 1) {
			if (len == 0) {
				memset(res.m_data.data() + i, 0, res.m_data.size() - i);
				break;
			}
			len--;
		}
		return res;
	}

	inline std::ostream& operator<<(std::ostream& os, const qname& n) {
		for (auto p = n.m_data.data(); p < n.m_data.end() && static_cast<uint8_t>(*p) != 0;) {
			os << std::string_view(reinterpret_cast<const char*>(p + 1), static_cast<uint8_t>(*p));
			p += 1 + static_cast<uint8_t>(*p);
			if (*p != std::byte{}) os << std::string_view(".");
		}
		return os;
	}

} // namespace asyncpp::io::dns