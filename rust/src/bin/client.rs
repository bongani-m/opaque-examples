//! Code D (Rust client): registers and logs in against python/server.py, which runs libopaque.
//! opaque-ke on this side, libopaque on the other: same suite, same KSF, same context and ids.
//!
//! Usage: client <user> <password> [login-password] [port] [--login-only] [--default-ksf]
use opaque_examples::{ksf, Suite, CONTEXT};
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration, ClientRegistrationFinishParameters,
    CredentialResponse, Identifiers, RegistrationResponse,
};
use rand_core::OsRng;
use std::io::{Read, Write};
use std::net::TcpStream;

/// One HTTP/1.0 POST; enough for a demo, not a real client.
fn post(port: u16, path: &str, body: &[u8]) -> (u16, Vec<u8>) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("cannot connect to server");
    write!(s, "POST {path} HTTP/1.0\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n", body.len()).unwrap();
    s.write_all(body).unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("bad HTTP response");
    let status = std::str::from_utf8(&raw[9..12]).unwrap().parse().unwrap();
    (status, raw[split + 4..].to_vec())
}

fn main() {
    // Flags: --login-only (the user was registered by another client, e.g. the C++ one) and
    // --default-ksf (use opaque-ke's default Argon2 parameters instead of libopaque's).
    let all: Vec<String> = std::env::args().skip(1).collect();
    let flag = |f: &str| all.iter().any(|a| a == f);
    let args: Vec<&String> = all.iter().filter(|a| !a.starts_with("--")).collect();
    let (user, password) = (args[0], args[1].as_bytes());
    let attempt = args.get(2).map(|s| s.as_bytes()).unwrap_or(password);
    let port: u16 = args.get(3).map(|p| p.parse().unwrap()).unwrap_or(8765);
    let ids = Identifiers { client: Some(user.as_bytes()), server: Some(b"example.com") };
    let custom = ksf();
    let k = if flag("--default-ksf") { None } else { Some(&custom) };

    if !flag("--login-only") {
        register(port, user, password, ids, k);
    }

    // Login
    let login = ClientLogin::<Suite>::start(&mut OsRng, attempt).unwrap();
    let (_, body) = post(port, &format!("/login/start?user={user}"), &login.message.serialize());
    let nl = body.iter().position(|&b| b == b'\n').unwrap();
    let session = std::str::from_utf8(&body[..nl]).unwrap();
    let ke2 = CredentialResponse::deserialize(&body[nl + 1..]).unwrap();
    let ok = match login.state.finish(&mut OsRng, attempt, ke2, ClientLoginFinishParameters::new(Some(CONTEXT), ids, k)) {
        Ok(done) => post(port, &format!("/login/finish?session={session}"), &done.message.serialize()).0 == 200,
        Err(_) => false, // the server MAC in KE2 did not verify: wrong password (or wrong KSF)
    };
    println!("user {}", if ok { "authenticated" } else { "NOT authenticated" });
    std::process::exit(if ok == (attempt == password) { 0 } else { 1 });
}

fn register(port: u16, user: &str, password: &[u8], ids: Identifiers, k: Option<&argon2::Argon2<'static>>) {
    let reg = ClientRegistration::<Suite>::start(&mut OsRng, password).unwrap();
    let (_, resp) = post(port, &format!("/register/start?user={user}"), &reg.message.serialize());
    let fin = reg
        .state
        .finish(
            &mut OsRng,
            password,
            RegistrationResponse::deserialize(&resp).unwrap(),
            ClientRegistrationFinishParameters::new(ids, k),
        )
        .unwrap();
    post(port, &format!("/register/finish?user={user}"), &fin.message.serialize());
    println!("registered {user}");
}
