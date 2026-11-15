// Code D (client): registers and logs in against python/server.py over plain
// HTTP. Same library on both sides (libopaque), two languages.
//
// Usage: client <user> <password> [login-password] [port]
#include "opaque.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <string>

constexpr std::string_view kContext = "opaque-examples-v1";
constexpr std::string_view kServerId = "example.com";

struct Response { int status; op::Bytes body; };

// One HTTP/1.0 POST over a fresh socket; enough for a demo, not a real client.
static Response post(int port, const std::string& path, const op::Bytes& body) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (fd < 0 || connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0)
        throw std::runtime_error("cannot connect to server");

    std::string req = "POST " + path + " HTTP/1.0\r\nHost: localhost\r\nContent-Length: " +
                      std::to_string(body.size()) + "\r\n\r\n";
    req.append(body.begin(), body.end());
    for (size_t sent = 0; sent < req.size();) {
        ssize_t n = send(fd, req.data() + sent, req.size() - sent, 0);
        if (n <= 0) throw std::runtime_error("send failed");
        sent += n;
    }
    std::string raw;
    char buf[4096];
    for (ssize_t n; (n = recv(fd, buf, sizeof buf, 0)) > 0;) raw.append(buf, n);
    close(fd);

    const size_t split = raw.find("\r\n\r\n");
    if (split == std::string::npos) throw std::runtime_error("bad HTTP response");
    return {std::stoi(raw.substr(9, 3)), op::Bytes(raw.begin() + split + 4, raw.end())};
}

static bool login(int port, const std::string& user, const std::string& password) {
    const op::Ids ids{user, kServerId};
    auto client = op::create_credential_request(password);
    auto r = post(port, "/login/start?user=" + user, client.ke1);           // KE1 -> KE2
    if (r.status != 200) return false;

    const auto nl = std::find(r.body.begin(), r.body.end(), '\n');
    const std::string session(r.body.begin(), nl);
    const op::Bytes ke2(nl + 1, r.body.end());
    try {
        auto rec = op::recover_credentials(ke2, client.sec, kContext, ids);
        return post(port, "/login/finish?session=" + session, rec.ke3).status == 200;  // KE3
    } catch (const op::Error&) {
        return false;  // wrong password: the server's MAC in KE2 did not verify
    }
}

int main(int argc, char** argv) {
    if (sodium_init() < 0 || argc < 3) {
        std::fprintf(stderr, "usage: client <user> <password> [login-password] [port]\n");
        return 2;
    }
    const std::string user = argv[1], password = argv[2];
    const std::string attempt = argc > 3 ? argv[3] : password;
    const int port = argc > 4 ? std::stoi(argv[4]) : 8765;
    const op::Ids ids{user, kServerId};

    // Registration: three messages, the password never leaves this process.
    auto reg = op::create_registration_request(password);
    auto resp = post(port, "/register/start?user=" + user, reg.request);
    auto fin = op::finalize_request(reg.sec, resp.body, ids);
    post(port, "/register/finish?user=" + user, fin.record);
    std::printf("registered %s\n", user.c_str());

    const bool ok = login(port, user, attempt);
    std::printf("user %s\n", ok ? "authenticated" : "NOT authenticated");
    return ok == (attempt == password) ? 0 : 1;
}
