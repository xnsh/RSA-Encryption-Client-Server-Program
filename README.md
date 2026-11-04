# Encrypted Client-Server Chat (RSA + SHA-256)

A two-way terminal chat in Python. A server and a client talk over a TCP socket. Each message is encrypted with RSA (written from scratch, no crypto libraries) and sent with a SHA-256 hash, so you can tell if it was changed on the way.

> **Note:** This is a learning project made to show how RSA and hash checks work. The keys are tiny and the cipher is easy to break. Do not use it to protect real data.

## Features

- **Socket chat:** two-way TCP chat between `ServerEnc.py` and `ClientEnc.py`
- **Threads:** a background thread gets messages while you type, so both sides can talk at any time
- **RSA from scratch:** key making, encryption and decryption using Python's built-in `pow()`
- **Public key exchange:** each side prints its public key and types in the other side's key
- **Integrity check:** each message comes with a SHA-256 hash (also encrypted). The receiver hashes what it got and compares the two

## How It Works

### 1. Key generation

Each program makes its own RSA key pair from two hard-coded primes:

| Program | p | q | n = p·q | e | Public key |
|---|---|---|---|---|---|
| Server | 619 | 151 | 93469 | 61 | `(93469, 61)` |
| Client | 101 | 113 | 11413 | 61 | `(11413, 61)` |

The private exponent comes from `d = pow(e, -1, φ(n))`, where `φ(n) = (p-1)(q-1)`.

### 2. Sending a message

1. Strip the message and make its SHA-256 hash (64 hex characters).
2. Encrypt each character with the **receiver's** public key: `c = ord(char)^e mod n`.
3. Pack each number `c` into characters:
   - `c % 256 <= 127` → 2 chars: `[c // 256][c % 256 + 1]` (the `+1` keeps the low char from ever being `\0`)
   - `c % 256 > 127` → 3 chars: `[c // 256][\0][c % 256 - 128]` (the `\0` marks this form)
4. Encrypt the hash the same way.
5. Send the encrypted message, then the encrypted hash. Each send ends with an end-of-message marker (``).

### 3. Receiving a message

1. Buffer incoming bytes until a full message (ending in the marker) has arrived.
2. Unpack the characters back into numbers (looking for the `\0` marker).
3. Decrypt each one with the receiver's **private** key: `char = c^d mod n`.
4. Print the message along with a SHA-256 hash of what was received.
5. The sender's hash comes in next as its own message.
6. **If the two hashes do not match, the message was changed in transit.**

```
 Server                                              Client
 ------                                              ------
 type "hello"
 hash = SHA256("hello")
 encrypt msg + hash with client's public key
            ── encrypted msg ──────────────────────▶ decrypt with private key
            ── encrypted hash ─────────────────────▶ decrypt with private key
                                                     compare SHA256(msg) vs hash
```

## Requirements

- Python **3.8+** (needs `pow(e, -1, m)` for the modular inverse)
- Standard library only: `socket`, `threading`, `hashlib`

## Usage

Use two terminals. Start the server first.

**Terminal 1 - server**

```bash
python ServerEnc.py
```

It prints its public key: `(93469, 61)`.

**Terminal 2 - client**

```bash
python ClientEnc.py
```

It prints its public key: `(11413, 61)`.

**Swap keys.** When asked, type the other side's key one number at a time:

| Program | First number (n) | Second number (e) |
|---|---|---|
| Server enters client key | `11413` | `61` |
| Client enters server key | `93469` | `61` |

The client connects once both keys are in. Then type and press Enter to chat. Type `bye` to quit. The other side will see a message saying you left; it can press Enter to close.

### Example output

```
Server: hello
The received message has the hash of: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
You:
Server: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
You:
```

Both hashes match, so the message was not changed.

### Running on two computers

Server binds to `127.0.0.1` (this machine only). To chat across a network:

- In `ServerEnc.py`, set `HOST = "0.0.0.0"`
- In `ClientEnc.py`, set `SERVER_HOST` to the server's IP
- Make sure port `5000` is open

## Project Structure

```
.
├── ServerEnc.py   # Waits for a client, encrypts/decrypts with its RSA keys
├── ClientEnc.py   # Connects to the server, encrypts/decrypts with its RSA keys
├── LICENSE
└── README.md
```

## Known Limitations

This project is built to teach, not to be secure:

- **Tiny keys:** `n` is 5 digits, so it can be factored in a split second.
- **Per-character encryption:** the same letter always encrypts to the same value. That makes it a substitution cipher, open to frequency analysis.
- **No padding:** textbook RSA with no padding (such as OAEP).
- **Hash is not a signature:** the hash is encrypted with the receiver's public key, which anyone can use. It catches accidental changes, but an attacker could swap in a new message with a matching hash. A real system would sign with the sender's private key or use an HMAC.
- **Hard-coded keys:** keys are fixed in the code, and public keys are swapped by hand.
- **`bye` is not encrypted:** it is sent as plain text so both sides can spot it.
- **Character limits:** characters whose code is ≥ the receiver's `n` (such as emoji) can't be encrypted. Messages with them are blocked and not sent.
- **One client only:** the server accepts a single connection.

## Possible Improvements

- Make large random primes at runtime, or use the `cryptography` library
- Encrypt whole blocks with proper padding, not single characters
- Sign the hash with the sender's private key (digital signature)
- Send keys automatically during a handshake
- Encode ciphertext as fixed-width numbers or Base64 for a simpler wire format

## License

**All Rights Reserved.** This code is public for viewing and learning only. You may not copy it, reuse it, or submit it as schoolwork. See [LICENSE](LICENSE) for the full terms.

> **Academic integrity:** If you are a student, do not turn in this code as your own. That is plagiarism.

Parts of this code build on starter code from a course instructor. Those parts are not covered by this license.

## Author

**Jonathan Niznik**
