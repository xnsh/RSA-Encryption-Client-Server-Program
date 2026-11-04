"""
ServerEnc.py - Server side of a two-way encrypted chat.

How it works:
  1. Builds its own small RSA key pair and prints the public key (n, e).
  2. Asks the user for the CLIENT's public key (n, e).
  3. Waits for one client to connect over TCP.
  4. Runs two loops at the same time:
       - recv_loop (background thread): decrypts and prints client messages.
       - send_loop (main thread): encrypts and sends what the user types.
  Every message is sent with a SHA-256 hash of the plaintext (also encrypted),
  so the reader can check if the message was changed in transit.

NOTE: This is a learning project. The RSA keys are tiny and each character is
encrypted on its own, so this is NOT secure for real use.
"""

import socket
import threading
import hashlib

# End-of-message marker. Each send ends with it so the receiver can tell
# where one message stops (TCP can merge or split sends). Its code (0xE000)
# is far above any packed ciphertext char, so it never shows up by accident.
DELIM = "\uE000"
DELIM_BYTES = DELIM.encode("utf-8")

HOST = "127.0.0.1"   # localhost only; use "0.0.0.0" to listen on all interfaces
PORT = 5000

# ---------------- RSA key setup ----------------
# Two small primes. Real RSA uses primes hundreds of digits long.
p = 619
q = 151

n = p * q                 # modulus (part of both keys) = 93469
piN = (p-1) * (q-1)       # Euler's totient, phi(n)
e = 61                    # public exponent (must share no factors with phi(n))
public_key = (n, e)

d = pow(e, -1, piN)       # private exponent: modular inverse of e mod phi(n)
private_key = (n, d)
print(public_key)         # share this with the client user

# Ask for the other side's public key. "First digit" = n, "second digit" = e.
contact_key1 = int(input("Enter the first digit of the public key for who you are trying to contact in the following format: xx --> "))
contact_key2 = int(input("Enter the second digit of the public key for who you are trying to contact in the following format: xx --> "))
final_contact = (contact_key1, contact_key2)   # (n, e) of the client

print("While you are using this software, remember that if you see a mismatch in hashes, the message has been modified.")
print("If the hash your program generates is DIFFERENT in any way from the one sent by the client, your message has been modified while in transit.")

def recv_loop(conn: socket.socket):
    """Receive messages from the client and print them."""

    buffer = b''         # bytes received but not yet handled
    expect_hash = False  # messages come in pairs: text first, then its hash
    try:
        while True:
            # Read until one full message (ending in DELIM) is in the buffer
            while DELIM_BYTES not in buffer:
                data = conn.recv(1024)      # read up to 1024 bytes
                if not data:                # empty read = client closed socket
                    print("\n[Client disconnected]")
                    return
                buffer += data
            # Take one message off the front, keep the rest for next time
            data, buffer = buffer.split(DELIM_BYTES, 1)

            data = data.decode('utf-8', errors='replace')
            # "bye" is sent as plain text, so check for it before decrypting
            if data.lower() == "bye":
                print("\n[Client left the chat. Press Enter to exit]")
                break
            #CDT Niznik ----
            # ---- Decrypt ----
            # Each ciphertext number c was packed as characters:
            #   2 chars: [c // 256][c % 256 + 1]        when c % 256 <= 127
            #            (+1 so the low char is never chr(0), the marker)
            #   3 chars: [c // 256][chr(0)][c % 256 - 128]  when c % 256 > 127
            # A chr(0) in the second spot marks the 3-char form.
            cip_text = data
            plaintext = ''

            idx = 0
            while (idx < len(cip_text)):
                if ord(cip_text[idx + 1]) == 0:
                    # 3-char form: rebuild c and add back the 128 that was removed
                    cv = ord(cip_text[idx]) * 256 + ord(cip_text[idx + 2]) + 128
                    M = pow(cv, private_key[1], private_key[0])   # M = c^d mod n
                    plaintext += chr(M)
                    idx += 3
                else:
                    # 2-char form: high byte * 256 + low byte (minus the +1 shift)
                    cv = ord(cip_text[idx]) * 256 + ord(cip_text[idx + 1]) - 1
                    M = pow(cv, private_key[1], private_key[0])   # M = c^d mod n
                    plaintext += chr(M)
                    idx += 2

            data = plaintext


            print("\nClient: " + plaintext)
            # Messages alternate: text, then the sender's hash of that text.
            # For text, print a fresh SHA-256 hash so the user can compare it
            # against the sender's hash that arrives next.
            if not expect_hash:
             print("The received message has the hash of: " + hashlib.sha256(data.encode()).hexdigest())
            expect_hash = not expect_hash
            print("You: ", end="", flush=True)
            #CDT Niznik, the two lines above this comment are modified forms of the provided code.
    except ConnectionResetError:
        print("\n[Client disconnected abruptly]")
    finally:
        try:
            conn.close()
        except:
            pass

def send_loop(conn: socket.socket):
    """Read from stdin and send messages to the client."""
    try:
        while True:
            msg = input("You: ")
            if msg.lower() == "bye":
                # "bye" is sent as plain text (not encrypted) and ends the chat
                conn.sendall((msg + DELIM).encode("utf-8"))
                break

            #CDT Niznik ----
            msg = msg.strip()
            # RSA can only encrypt numbers smaller than n. Skip messages with
            # characters too big for the receiver's key (e.g. emoji).
            if any(ord(ch) >= final_contact[0] for ch in msg):
                print("[Message has a character that can't be encrypted with this key. Not sent.]")
                continue
            # SHA-256 hash of the plaintext, used for the integrity check
            hash = hashlib.sha256(msg.encode()).hexdigest()
            enc_hash = ''
            cip_text = ''


            # ---- Encrypt the message, one character at a time ----
            for char in msg:
                M = ord(char)                                   # char -> number
                c = pow(M, final_contact[1], final_contact[0])  # c = M^e mod n (client key)

                # Pack c into characters (see recv_loop for the format)
                if (c %256) > 127:
                    cip_text += (chr(c // 256) + chr(0) + chr(c % 128))
                else:
                    cip_text += (chr(c // 256) + chr(c % 128 + 1))

            # ---- Encrypt the hash the same way ----
            for char in hash:
                M = ord(char)
                c = pow(M, final_contact[1], final_contact[0])

                if (c %256) > 127:
                    enc_hash += (chr(c // 256) + chr(0) + chr(c % 128))
                else:
                    enc_hash += (chr(c // 256) + chr(c % 128 + 1))

            msg = cip_text

            # CDT Niznik -----
            # Send ciphertext, then the encrypted hash, as two separate sends
            conn.sendall((msg + DELIM).encode("utf-8"))
            conn.sendall((enc_hash + DELIM).encode("utf-8"))
    except (BrokenPipeError, OSError):
        print("\n[Can't send, connection closed]")
    finally:
        try:
            conn.close()
        except:
            pass

def main():
    """Open a TCP socket, wait for one client, then start chatting."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Let the port be reused right away after a restart
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(1)                      # accept only one client

        print(f"[Server listening on {HOST}:{PORT}]")
        conn, addr = s.accept()          # blocks until a client connects
        print(f"[Client connected from {addr}]")

        # Receive in a background thread so the user can type and read at once
        t_recv = threading.Thread(target=recv_loop, args=(conn,), daemon=True)
        t_recv.start()

        send_loop(conn)                  # main thread handles sending
        print("[Server exiting]")

if __name__ == "__main__":
    main()
