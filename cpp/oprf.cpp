// Code A: a teaching OPRF over ristretto255 with libsodium.
// For learning, not production: RFC 9497 hashes to the group with
// expand_message_xmd and a domain-separation tag; this uses plain SHA-512.
//
// Usage: oprf [password] [r_hex k_hex]
#include <sodium.h>

#include <array>
#include <cstdio>
#include <stdexcept>
#include <string>

using Point = std::array<unsigned char, crypto_core_ristretto255_BYTES>;
using Scalar = std::array<unsigned char, crypto_core_ristretto255_SCALARBYTES>;
using Digest = std::array<unsigned char, crypto_hash_sha512_BYTES>;

static Point mul(const Scalar& k, const Point& p) {
    Point out;
    if (crypto_scalarmult_ristretto255(out.data(), k.data(), p.data()) != 0)
        throw std::runtime_error("invalid point");
    return out;
}

static Point hash_to_group(const std::string& x) {  // H'(x)
    Digest h;
    crypto_hash_sha512(h.data(), reinterpret_cast<const unsigned char*>(x.data()), x.size());
    Point p;
    crypto_core_ristretto255_from_hash(p.data(), h.data());
    return p;
}

static Digest outer_hash(const std::string& x, const Point& e) {  // H(x, e)
    crypto_hash_sha512_state st;
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, reinterpret_cast<const unsigned char*>(x.data()), x.size());
    crypto_hash_sha512_update(&st, e.data(), e.size());
    Digest d;
    crypto_hash_sha512_final(&st, d.data());
    return d;
}

static Point blind(const std::string& x, const Scalar& r) { return mul(r, hash_to_group(x)); }
static Point evaluate(const Scalar& k, const Point& a) { return mul(k, a); }
static Digest finalize(const std::string& x, const Scalar& r, const Point& b) {
    Scalar r_inv;
    crypto_core_ristretto255_scalar_invert(r_inv.data(), r.data());
    return outer_hash(x, mul(r_inv, b));
}

static Scalar scalar_arg(const char* hex) {
    Scalar s{};
    size_t len = 0;
    if (sodium_hex2bin(s.data(), s.size(), hex, std::char_traits<char>::length(hex), nullptr, &len,
                       nullptr) != 0 || len != s.size())
        throw std::runtime_error("scalar must be 32 bytes of hex");
    return s;
}

template <size_t N>
static std::string hex(const std::array<unsigned char, N>& b) {
    std::string out(N * 2 + 1, '\0');
    sodium_bin2hex(out.data(), out.size(), b.data(), N);
    out.pop_back();
    return out;
}

int main(int argc, char** argv) {
    if (sodium_init() < 0) return 1;
    const std::string x = argc > 1 ? argv[1] : "correct horse battery staple";
    Scalar r, k;
    if (argc > 3) {
        r = scalar_arg(argv[2]);
        k = scalar_arg(argv[3]);
    } else {
        crypto_core_ristretto255_scalar_random(r.data());
        crypto_core_ristretto255_scalar_random(k.data());
    }

    const Point a = blind(x, r);          // client -> server
    const Point b = evaluate(k, a);       // server -> client
    const Digest out = finalize(x, r, b); // client

    const Digest direct = outer_hash(x, mul(k, hash_to_group(x)));
    const bool same = sodium_memcmp(out.data(), direct.data(), out.size()) == 0;
    std::printf("server saw a = %s\nF(k, x)      = %s\nmatches unblinded evaluation: %s\n",
                hex(a).c_str(), hex(out).c_str(), same ? "True" : "False");
    return same ? 0 : 1;
}
