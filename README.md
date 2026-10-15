# Digital Signature Server (DSS)

Project for the *Foundations of Cybersecurity* course (Computer Engineering, A.Y. 2024/25).

A Digital Signature Service is a trusted third party that creates and stores RSA key pairs for
the employees of an organization and signs documents on their behalf. It is implemented as a
multi-threaded client-server application in C++ on top of OpenSSL 3.x.

## Features

Employees are registered offline: each one receives the server public key, which they keep to
authenticate the server, and a temporary password that must be changed at the first login.

Before issuing any operation, the client establishes a secure channel with the server. The user
authenticates the server through its public key and authenticates to the server with their
password. The channel guarantees perfect forward secrecy, integrity, no-replay and
non-malleability. Once authenticated, a user can:

| Operation      | Command | Description                                                              |
|----------------|---------|--------------------------------------------------------------------------|
| CreateKeys     | `CRT`   | Create and store an RSA-2048 key pair for the user (no effect if present) |
| SignDoc        | `SGN`   | Sign a document on behalf of the user and return the signature           |
| GetPublicKey   | `GET`   | Return the public key of a given user                                    |
| DeleteKeys     | `DEL`   | Delete the user's key pair (a new one requires a new offline registration) |

Extra commands: `LST` (list users with a public key), `VRF` (verify a signature),
`CNG` (change password), `HLP` (help), `EXT` (close the connection).

User private keys are never stored in cleartext: the server keeps them only in encrypted form.

## Security overview

- **Server authentication and PFS**: ephemeral Diffie-Hellman (FFDHE2048) handshake; the server
  signs the transcript (nonces + DH public keys) with its long-term RSA-2048 key.
- **Session keys**: HKDF-SHA256 derives four keys, one encryption key and one MAC key per direction.
- **Confidentiality, integrity, non-malleability**: every message is AES-256-CBC encrypted and
  authenticated with HMAC-SHA256 (Encrypt-then-MAC).
- **No-replay**: fresh nonces on every message, checked against the set of already used ones.
- **User authentication**: password, stored as salted SHA-256 hash.
- **Key storage**: user private keys are stored encrypted with AES-256-CBC under the DSS master key.

Protocol details, message formats and sequence diagrams are in
[docs/DSS project documentation.pdf](docs/DSS%20project%20documentation.pdf).

## Project structure

```
├── src/          client.cpp, server.cpp, utility.cpp, utility.h
├── keys/         server_pub.pem, server_priv.pem, dss_master.key
├── data/         employees.csv (user database)
├── documents/    sample documents to sign
├── docs/         full project documentation (PDF)
├── build/        compiled binaries (generated)
└── Makefile
```

The files in `keys/` are not tracked by git: `server_priv.pem` and `dss_master.key` are secrets,
while `server_pub.pem` is useless without its private key and is generated together with it by `make keys`.

## Requirements

- `g++` (C++11) and `make`
- OpenSSL 3.x with development headers
  (`brew install openssl@3` on macOS, `sudo apt install libssl-dev` on Debian/Ubuntu)

## How to run

All commands must be run from the project root, since file paths are relative to it.

**1. Generate the keys** (DSS master key and server RSA key pair; existing files are kept):

```sh
make keys
```

**2. Compile** server and client into `build/`:

```sh
make
```

**3. Start the server** (it listens on `127.0.0.1:4444`):

```sh
./build/server reset
```

`reset` recreates `data/employees.csv` with the default users below; run `./build/server`
without arguments to keep the existing database.

| Username  | Initial password |
|-----------|------------------|
| `alice`   | `alice`          |
| `bob`     | `bob`            |
| `charlie` | `charlie`        |

**4. Start the client** in another terminal:

```sh
./build/client
```

The client establishes the secure channel, asks for username and password and, at the first
login, for a new password. Then commands can be issued, for example:

```
Enter command: CRT
Enter command: SGN
Enter file name to sign: documents/doc.txt
Enter command: VRF
Enter file name to verify signature: documents/doc.txt
Enter the signer username: bob
Enter signature (hex): <signature returned by SGN>
Enter command: EXT
```

Documents are read by the server, so their path is relative to the directory the server was
started from.

`make clean` removes the compiled binaries.
