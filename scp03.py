import asyncio
import os
import hmac
from nats.aio.client import Client as NATS
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import cmac, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class SCP03Keys:
    def __init__(self, enc_key=None, mac_key=None, rmac_key=None):
        """secure channel keys"""

        self.static_enc_key = enc_key or bytes.fromhex('0123456789ABCDEF0123456789ABCDEF')
        self.static_mac_key = mac_key or bytes.fromhex('0123456789ABCDEF0123456789ABCDEF')
        self.static_rmac_key = rmac_key or bytes.fromhex('0123456789ABCDEF0123456789ABCDEF')
        
        self.session_enc_key = None
        self.session_mac_key = None
        self.session_rmac_key = None
        
        # Command and response MAC chaining
        self.mac_chaining_value = None
        self.rmac_chaining_value = None
        
        self.command_counter = 0
        self.response_counter = 0
    
    def derive_session_keys(self, host_challenge, card_challenge, card_cryptogram=None):
        """Derive session keys according to SCP03 specifications"""
        # Context for session key derivation
        context = host_challenge + card_challenge
        print(f"DEBUG - Key derivation:")
        print(f"DEBUG - Host challenge: {host_challenge.hex()}")
        print(f"DEBUG - Card challenge: {card_challenge.hex()}")
        print(f"DEBUG - Derivation context: {context.hex()}")
        
        if card_cryptogram:
            self.verify_card_cryptogram(context, card_cryptogram)
        
        # Derive encryption key
        derivation_data = bytes([0x04, 0x01]) + context
        print(f"DEBUG - ENC key derivation data: {derivation_data.hex()}")
        self.session_enc_key = self._derive_key(self.static_enc_key, derivation_data)
        print(f"DEBUG - Derived ENC key: {self.session_enc_key.hex()}")
        
        # Derive command MAC key
        derivation_data = bytes([0x06, 0x01]) + context
        print(f"DEBUG - MAC key derivation data: {derivation_data.hex()}")
        self.session_mac_key = self._derive_key(self.static_mac_key, derivation_data)
        print(f"DEBUG - Derived MAC key: {self.session_mac_key.hex()}")
        
        # Derive response MAC key
        derivation_data = bytes([0x07, 0x01]) + context
        print(f"DEBUG - RMAC key derivation data: {derivation_data.hex()}")
        self.session_rmac_key = self._derive_key(self.static_rmac_key, derivation_data)
        print(f"DEBUG - Derived RMAC key: {self.session_rmac_key.hex()}")
        
        # Initialize MAC chaining values
        self.mac_chaining_value = bytes([0x00] * 16)
        self.rmac_chaining_value = bytes([0x00] * 16)
        print(f"DEBUG - Initial MAC chaining value: {self.mac_chaining_value.hex()}")
        print(f"DEBUG - Initial RMAC chaining value: {self.rmac_chaining_value.hex()}")
        
        # Reset sequence counters
        self.command_counter = 0
        self.response_counter = 0
        
        return self.generate_host_cryptogram(context)

    def _derive_key(self, key, derivation_data):
        """Derive key using CMAC-based KDF as per SCP03"""
        c = cmac.CMAC(algorithms.AES(key), backend=default_backend())
        c.update(derivation_data)
        return c.finalize()
    
    def generate_host_cryptogram(self, context):
        """Generate host cryptogram for mutual authentication"""
        derivation_data = bytes([0x05, 0x01]) + context
        c = cmac.CMAC(algorithms.AES(self.static_mac_key), backend=default_backend())
        c.update(derivation_data)
        return c.finalize()
    
    def verify_card_cryptogram(self, context, card_cryptogram):
        """Verify card cryptogram for mutual authentication"""
        derivation_data = bytes([0x05, 0x00]) + context
        c = cmac.CMAC(algorithms.AES(self.static_mac_key), backend=default_backend())
        c.update(derivation_data)
        expected_cryptogram = c.finalize()
    
        print(f"DEBUG - Expected cryptogram: {expected_cryptogram.hex()}")
        print(f"DEBUG - Received cryptogram: {card_cryptogram.hex()}")
    
        if not hmac.compare_digest(expected_cryptogram[:8], card_cryptogram[:8]):  # Compare only first 8 bytes
            raise ValueError("Card cryptogram verification failed")

    def encrypt_data(self, data):
        """Encrypt data with session encryption key"""
        if not self.session_enc_key:
            raise ValueError("Session not established")
        
        # Pad data to multiple of 16 bytes
        padded_data = self._apply_padding(data)
        
        # Create ICV for encryption
        iv = self._generate_command_iv()
        
        # Encrypt using AES-CBC
        cipher = Cipher(algorithms.AES(self.session_enc_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        return encrypted_data
    
    def decrypt_data(self, encrypted_data):
        """Decrypt data with session encryption key"""
        if not self.session_enc_key:
            raise ValueError("Session not established")
        
        # Create ICV for decryption
        iv = self._generate_response_iv()
        
        # Decrypt using AES-CBC
        cipher = Cipher(algorithms.AES(self.session_enc_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Remove padding
        return self._remove_padding(decrypted_data)
    
    def generate_command_mac(self, header, data):
        """Generate MAC for command APDU"""
        if not self.session_mac_key:
            raise ValueError("Session not established")
        
        # Create MAC input
        mac_input = self.mac_chaining_value + header + bytes([len(data)]) + data
        print(f"DEBUG - MAC Generation:")
        print(f"DEBUG - MAC key: {self.session_mac_key.hex()}")
        print(f"DEBUG - MAC chaining value: {self.mac_chaining_value.hex()}")
        print(f"DEBUG - Header: {header.hex()}")
        print(f"DEBUG - Data length: {len(data)}")
        print(f"DEBUG - Data: {data.hex()}")
        print(f"DEBUG - Complete MAC input: {mac_input.hex()}")
        
        # Generate MAC
        c = cmac.CMAC(algorithms.AES(self.session_mac_key), backend=default_backend())
        c.update(mac_input)
        mac = c.finalize()
        
        print(f"DEBUG - Generated full MAC: {mac.hex()}")
        print(f"DEBUG - Truncated MAC (8 bytes): {mac[:8].hex()}")
        
        # Update MAC chaining value for next command
        self.mac_chaining_value = mac
        print(f"DEBUG - New MAC chaining value: {self.mac_chaining_value.hex()}")
        
        return mac[:8]  # Return first 8 bytes as per SCP03

    def generate_response_mac(self, header, data):
        """Generate MAC for response APDU"""
        if not self.session_rmac_key:
            raise ValueError("Session not established")
        
        # Create MAC input
        mac_input = self.rmac_chaining_value + header + bytes([len(data)]) + data
        print(f"DEBUG - Response MAC Generation:")
        print(f"DEBUG - RMAC key: {self.session_rmac_key.hex()}")
        print(f"DEBUG - RMAC chaining value: {self.rmac_chaining_value.hex()}")
        print(f"DEBUG - Header: {header.hex()}")
        print(f"DEBUG - Data length: {len(data)}")
        print(f"DEBUG - Data: {data.hex() if data else 'empty'}")
        print(f"DEBUG - Complete MAC input: {mac_input.hex()}")
        
        # Generate MAC
        c = cmac.CMAC(algorithms.AES(self.session_rmac_key), backend=default_backend())
        c.update(mac_input)
        mac = c.finalize()
        
        print(f"DEBUG - Generated full response MAC: {mac.hex()}")
        print(f"DEBUG - Truncated response MAC (8 bytes): {mac[:8].hex()}")
        
        # Update RMAC chaining value for next response
        self.rmac_chaining_value = mac
        print(f"DEBUG - New RMAC chaining value: {self.rmac_chaining_value.hex()}")
        
        return mac[:8]  # Return first 8 bytes as per SCP03
    
    def _generate_command_iv(self):
        """Generate IV for command encryption/MAC based on counter"""
        self.command_counter += 1
        return bytes([0x00] * 12 + [(self.command_counter >> 24) & 0xFF, 
                                    (self.command_counter >> 16) & 0xFF,
                                    (self.command_counter >> 8) & 0xFF,
                                    self.command_counter & 0xFF])
    
    def _generate_response_iv(self):
        """Generate IV for response decryption/MAC based on counter"""
        self.response_counter += 1
        return bytes([0x00] * 12 + [(self.response_counter >> 24) & 0xFF, 
                                    (self.response_counter >> 16) & 0xFF,
                                    (self.response_counter >> 8) & 0xFF,
                                    self.response_counter & 0xFF])
    
    def _apply_padding(self, data):
        pad_len = 16 - (len(data) % 16)
        padded_data =  data + bytes([0x80] + [0x00] * (pad_len - 1))
        print(f"DEBUG - Apply Padding bef: {data.hex()}")
        print(f"DEBUG - Apply Padding aft: {padded_data.hex()}")
        return padded_data
    
    def _remove_padding(self, padded_data):
        print(f"DEBUG - Remove Padding bef: {padded_data.hex()}")
        # Find the 0x80 padding byte
        for i in range(len(padded_data) - 1, -1, -1):
            if padded_data[i] == 0x80:
                # Check that all bytes after are zeros
                if all(b == 0 for b in padded_data[i + 1:]):
                    return padded_data[:i]
            elif padded_data[i] != 0:
                break
        print(f"DEBUG - Remove 2 Padding aft: {padded_data.hex()}")

        # If we didn't find valid padding, return as is
        return padded_data


class SCP03Client:
    def __init__(self):
        self.nc = NATS()
        self.keys = SCP03Keys()
        self.session_established = False
    
    async def start(self, nats_url="nats://localhost:4222"):
        await self.nc.connect(nats_url)
        print("SCP03 Client connected to NATS")
    
    async def establish_secure_channel(self):
        """SCP03 mutual authentication and secure channel establishment"""
        # Generate host challenge
        host_challenge = os.urandom(8)
        
        # Prepare INITIALIZE UPDATE command
        init_update_apdu = bytes([0x80, 0x50, 0x00, 0x00, 0x08]) + host_challenge + bytes([0x00])
        
        # Send INITIALIZE UPDATE (not encrypted or MAC'd)
        response = await self.nc.request("apdu.command", init_update_apdu, timeout=5)
        
        # Process response
        response_data = response.data
        if len(response_data) < 30:  # 28 bytes data + 2 bytes status word
            raise ValueError(f"Invalid INITIALIZE UPDATE response: {response_data.hex()}")
        
        # Extract key diversification data, card challenge, card cryptogram and sequence counter
        key_diversification_data = response_data[:10]
        card_challenge = response_data[12:20]
        card_cryptogram = response_data[20:28]
        
        # Verify status word
        status_word = (response_data[-2] << 8) | response_data[-1]
        if status_word != 0x9000:
            raise ValueError(f"INITIALIZE UPDATE failed: {hex(status_word)}")
        
        # Derive session keys and generate host cryptogram
        full_host_cryptogram = self.keys.derive_session_keys(host_challenge, card_challenge, card_cryptogram)
        host_cryptogram = full_host_cryptogram[:8]  # Only use first 8 bytes
        print(f"CLIENT - Session keys derived:")
        print(f"CLIENT - ENC key: {self.keys.session_enc_key.hex()}")
        print(f"CLIENT - MAC key: {self.keys.session_mac_key.hex()}")
        print(f"CLIENT - RMAC key: {self.keys.session_rmac_key.hex()}")
        print(f"CLIENT - Initial MAC chaining value: {self.keys.mac_chaining_value.hex()}")

        # Prepare EXTERNAL AUTHENTICATE command
        ext_auth_apdu = bytes([0x84, 0x82, 0x03, 0x00, 0x08]) + host_cryptogram
        
        # Generate MAC for command
        header = ext_auth_apdu[:4]
        data = host_cryptogram
        mac = self.keys.generate_command_mac(header, data)
        
        # Add MAC to command
        ext_auth_apdu_with_mac = ext_auth_apdu + mac
        
        # Before generating MAC for EXTERNAL AUTHENTICATE
        print(f"CLIENT - External Auth header: {header.hex()}")
        print(f"CLIENT - External Auth data: {data.hex()}")
        print(f"CLIENT - MAC input: {(self.keys.mac_chaining_value + header + bytes([len(data)]) + data).hex()}")

        # Send EXTERNAL AUTHENTICATE
        response = await self.nc.request("apdu.command", ext_auth_apdu_with_mac, timeout=5)
        
        # Verify response status word
        status_word = (response.data[-2] << 8) | response.data[-1]
        if status_word != 0x9000:
            raise ValueError(f"EXTERNAL AUTHENTICATE failed: {hex(status_word)}")
        
        # Secure channel established
        self.session_established = True
        print("CLIENT - Secure channel established successfully!")
        self.keys.command_counter = 0
        self.keys.response_counter = 0

    async def send_encrypted_apdu(self, cla, ins, p1, p2, data=None, le=None):
        """Send a secure APDU command using SCP03"""
        if not self.session_established:
            raise ValueError("Secure channel not established")
        
        # Set class byte to indicate secure messaging
        secure_cla = cla | 0x04  # Set bit 2 for secure messaging
        
        # Prepare command header
        header = bytes([secure_cla, ins, p1, p2])
        print(f"CLIENT - header: {header.hex()}")

        # Prepare command data
        command_data = data or bytes()
        print(f"CLIENT - data: {command_data.hex()}")
        
        # Encrypt command data if present
        if command_data:
            encrypted_data = self.keys.encrypt_data(command_data)
        else:
            encrypted_data = bytes()
        print(f"CLIENT - encrypted data: {encrypted_data.hex()}")
        
        # Generate MAC
        mac = self.keys.generate_command_mac(header, encrypted_data)
        print(f"CLIENT - mac: {mac.hex()}")

        # Assemble complete APDU
        lc = len(encrypted_data) + 8  # Data length + MAC length
        apdu = header + bytes([lc]) + encrypted_data + mac
        
        if le is not None:
            apdu += bytes([le])
        
        print(f"CLIENT - Sending secure APDU: {apdu.hex()}")
        
        # Send command
        response = await self.nc.request("apdu.command", apdu, timeout=5)
        response_data = response.data
        
        # Extract response components
        if len(response_data) < 10:  # Minimum: MAC (8) + SW (2)
            raise ValueError(f"Invalid secure response: {response_data.hex()}")
        
        status_word = (response_data[-2] << 8) | response_data[-1]
        response_mac = response_data[-10:-2]  # 8 bytes MAC before status word
        encrypted_response_data = response_data[:-10] if len(response_data) > 10 else bytes()
        
        print(f"CLIENT - Response verification:")
        print(f"CLIENT - Full response: {response_data.hex()}")
        print(f"CLIENT - Status Word: {hex(status_word)}")
        print(f"CLIENT - Response MAC: {response_mac.hex()}")
        print(f"CLIENT - Encrypted data: {encrypted_response_data.hex() if encrypted_response_data else 'empty'}")


        # Verify response MAC
        header = bytes([0x00, 0x00, 0x00, 0x00])  # Response header for MAC verification
        expected_mac = self.keys.generate_response_mac(header, encrypted_response_data)
        print(f"CLIENT - Expected response MAC: {expected_mac.hex()}")
        print(f"CLIENT - Received response MAC: {response_mac.hex()}")
        print(f"CLIENT - MAC match: {hmac.compare_digest(expected_mac, response_mac)}")

        if not hmac.compare_digest(expected_mac, response_mac):
            raise ValueError("Response MAC verification failed")
        
        # Decrypt response data if present
        if encrypted_response_data:
            decrypted_data = self.keys.decrypt_data(encrypted_response_data)
        else:
            decrypted_data = bytes()
        
        print(f"CLIENT - Received secure response. SW={hex(status_word)}")
        print(f"CLIENT - Decrypted data: {decrypted_data.hex() if decrypted_data else 'None'}")
        
        return {
            "status_word": status_word,
            "data": decrypted_data
        }
    
    async def close(self):
        await self.nc.close()


class SCP03Server:
    def __init__(self):
        self.nc = NATS()
        self.keys = SCP03Keys()
        self.clients = {}  # Store session info for multiple clients
    
    async def start(self, nats_url="nats://localhost:4222"):
        await self.nc.connect(nats_url)
        print("SCP03 Server connected to NATS")
        
        # Subscribe to APDU command subject
        await self.nc.subscribe("apdu.command", cb=self.process_apdu)
        print("Server listening for APDU commands")
    
    async def process_apdu(self, msg):
        """Process incoming APDU commands"""
        try:
            apdu_bytes = msg.data
            
            if len(apdu_bytes) < 4:
                response = bytes([0x67, 0x00])  # Wrong length
                await self.nc.publish(msg.reply, response)
                return
            
            cla = apdu_bytes[0]
            ins = apdu_bytes[1]
            p1  = apdu_bytes[2]
            p2  = apdu_bytes[3]
            
            # Check if it's an SCP03 initialization command
            if cla == 0x80 and ins == 0x50:  # INITIALIZE UPDATE
                response = self.handle_initialize_update(apdu_bytes, msg.subject)
                await self.nc.publish(msg.reply, response)
                return
            
            # Check if it's an EXTERNAL AUTHENTICATE command
            if cla == 0x84 and ins == 0x82:  # EXTERNAL AUTHENTICATE
                response = self.handle_external_authenticate(apdu_bytes, msg.subject)
                await self.nc.publish(msg.reply, response)
                return
            
            # Handle secure messaging for established sessions
            if (cla & 0x04) == 0x04:  # Bit 2 set indicates secure messaging
                response = await self.handle_secure_command(apdu_bytes, msg.subject)
                await self.nc.publish(msg.reply, response)
                return
            
            # Default response for unsupported or unrecognized commands
            response = bytes([0x6D, 0x00])  # INS not supported
            await self.nc.publish(msg.reply, response)
            
        except Exception as e:
            print(f"Error processing APDU: {e}")
            error_response = bytes([0x6F, 0x00])  # Unknown error
            await self.nc.publish(msg.reply, error_response)
    
    
    def handle_initialize_update(self, apdu, client_id):
        """Handle INITIALIZE UPDATE command for SCP03"""
        # Extract host challenge
        if len(apdu) < 13:  # 5 bytes header + 8 bytes challenge
            return bytes([0x67, 0x00])  # Wrong length
        
        host_challenge = apdu[5:13]
        
        # Generate card challenge
        card_challenge = os.urandom(8)
        
        # Key diversification data
        key_diversification_data = bytes([0x00] * 10)
        
        # Sequence counter
        sequence_counter = bytes([0x00, 0x00])
        
        # Create session keys context
        context = host_challenge + card_challenge
        
        print(f"SERVER - Host challenge: {host_challenge.hex()}")
        print(f"SERVER - Card challenge: {card_challenge.hex()}")
        print(f"SERVER - Context: {context.hex()}")

        # Store new SCP03 session for this client
        if client_id not in self.clients:
            self.clients[client_id] = SCP03Keys()
        
        # Generate card cryptogram
        derivation_data = bytes([0x05, 0x00]) + context
        c = cmac.CMAC(algorithms.AES(self.clients[client_id].static_mac_key), backend=default_backend())
        c.update(derivation_data)
        card_cryptogram = c.finalize()[:8]  # Only first 8 bytes used as cryptogram
        
        print(f"SERVER - Card cryptogram (full): {card_cryptogram.hex()}")
        print(f"SERVER - Card cryptogram (sent): {card_cryptogram[:8].hex()}")

        # Derive session keys but don't initialize MAC chaining yet
        self.clients[client_id].derive_session_keys(host_challenge, card_challenge)
        
        print(f"SERVER - Session keys for client {client_id}:")
        print(f"SERVER - ENC key: {self.clients[client_id].session_enc_key.hex()}")
        print(f"SERVER - MAC key: {self.clients[client_id].session_mac_key.hex()}")
        print(f"SERVER - RMAC key: {self.clients[client_id].session_rmac_key.hex()}")
        print(f"SERVER - Initial MAC chaining value: {self.clients[client_id].mac_chaining_value.hex()}")

        # Reset MAC chaining values explicitly
        self.clients[client_id].mac_chaining_value = bytes([0x00] * 16)
        self.clients[client_id].rmac_chaining_value = bytes([0x00] * 16)
        
        # Assemble response
        response_data = (key_diversification_data + sequence_counter + 
                        card_challenge + card_cryptogram)
        
        # Add status word
        response = response_data + bytes([0x90, 0x00])
        
        return response


    def handle_external_authenticate(self, apdu, client_id):
        """Handle EXTERNAL AUTHENTICATE command for SCP03"""
        if client_id not in self.clients:
            return bytes([0x6A, 0x88])  # Referenced data not found
        
        # Extract host cryptogram and MAC
        if len(apdu) < 21:  # 5 bytes header + 16 bytes (cryptogram + MAC)
            return bytes([0x67, 0x00])  # Wrong length
        
        host_cryptogram = apdu[5:13]
        received_mac = apdu[13:21]
        
        print(f"SERVER - EXTERNAL AUTH - Received APDU: {apdu.hex()}")
        print(f"SERVER - EXTERNAL AUTH - Host cryptogram: {host_cryptogram.hex()}")
        print(f"SERVER - EXTERNAL AUTH - Received MAC: {received_mac.hex()}")
        print(f"SERVER - EXTERNAL AUTH - Client state before MAC verification:")
        print(f"SERVER - MAC key: {self.clients[client_id].session_mac_key.hex()}")
        print(f"SERVER - MAC chaining value: {self.clients[client_id].mac_chaining_value.hex()}")
        print(f"SERVER - Command counter: {self.clients[client_id].command_counter}")
        
        # Verify MAC
        header = apdu[:4]
        data = host_cryptogram
        
        print(f"SERVER - EXTERNAL AUTH - MAC input components:")
        print(f"SERVER - Header: {header.hex()}")
        print(f"SERVER - Data: {data.hex()}")
        print(f"SERVER - Data length byte: {bytes([len(data)]).hex()}")
        print(f"SERVER - MAC chaining value: {self.clients[client_id].mac_chaining_value.hex()}")
        print(f"SERVER - Complete MAC input: {(self.clients[client_id].mac_chaining_value + header + bytes([len(data)]) + data).hex()}")
        
        expected_mac = self.clients[client_id].generate_command_mac(header, data)
        
        print(f"SERVER - Expected MAC: {expected_mac.hex()}")
        print(f"SERVER - Received MAC: {received_mac.hex()}")
        print(f"SERVER - MAC match: {hmac.compare_digest(expected_mac, received_mac)}")
        
        if not hmac.compare_digest(expected_mac, received_mac):
            return bytes([0x63, 0x00])  # Security condition not satisfied
        
        # Session is now established
        print(f"SERVER - Secure channel established for client {client_id}")
        print(f"SERVER - Updated MAC chaining value: {self.clients[client_id].mac_chaining_value.hex()}")
        
        return bytes([0x90, 0x00])

    async def handle_secure_command(self, apdu, client_id):
        """Handle a secure APDU command using SCP03"""
        if client_id not in self.clients:
            return bytes([0x6A, 0x88])  # Referenced data not found
        
        # Extract components
        header = apdu[:4]
        if len(apdu) < 5:
            return bytes([0x67, 0x00])  # Wrong length
        
        lc = apdu[4]
        if len(apdu) < 5 + lc:
            return bytes([0x67, 0x00])
        print(f"SERVER - LC : {lc}")

        # Extract MAC (last 8 bytes of command data)
        command_mac = apdu[-8:]
        encrypted_data = apdu[5:-8] if len(apdu) > 13 else bytes()
        
        # Verify command MAC
        try:
            expected_mac = self.clients[client_id].generate_command_mac(header, encrypted_data)
            if not hmac.compare_digest(expected_mac, command_mac):
                return bytes([0x63, 0x00])  # Security condition not satisfied
        except Exception as e:
            print(f"MAC verification error: {e}")
            return bytes([0x66, 0x00])  # Security-related issue
        
        # Decrypt command data if present
        if encrypted_data:
            try:
                decrypted_data = self.clients[client_id].decrypt_data(encrypted_data)
            except Exception as e:
                print(f"Decryption error: {e}")
                return bytes([0x66, 0x00])
        else:
            decrypted_data = bytes()
        
        # Get original command parameters
        cla = header[0] & 0xFB  # Remove secure messaging bit
        ins = header[1]
        p1  = header[2]
        p2  = header[3]
        
        print(f"SERVER - Processing secure command: CLA={hex(cla)}, INS={hex(ins)}, P1={hex(p1)}, P2={hex(p2)}")
        print(f"SERVER - Decrypted data: {decrypted_data.hex() if decrypted_data else 'None'}")
        
        # Process the command
        if ins == 0xA4:  # SELECT command
            response_data = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]) 
        elif ins == 0xB0:  # Loop Back capitalized Strings
            response_data = bytes([x if not (97 <= x <= 122) else x - 32 for x in decrypted_data])
        else:
            # Command not supported
            return bytes([0x6D, 0x00])
        
        # Encrypt response data
        encrypted_response = self.clients[client_id].encrypt_data(response_data)
        
        # Generate response MAC
        response_header = bytes([0x00, 0x00, 0x00, 0x00]) 

        response_mac = self.clients[client_id].generate_response_mac(response_header, encrypted_response)
        print(f"SERVER - Response MAC generation:")
        print(f"SERVER - Generated response MAC: {response_mac.hex()}")
        print(f"SERVER - Response header: {response_header.hex()}")
        print(f"SERVER - Encrypted response data: {encrypted_response.hex() if encrypted_response else 'empty'}")
        print(f"SERVER - RMAC key: {self.clients[client_id].session_rmac_key.hex()}")
        print(f"SERVER - RMAC chaining value: {self.clients[client_id].rmac_chaining_value.hex()}")
        print(f"SERVER - Response counter: {self.clients[client_id].response_counter}")

        # Assemble secure response
        secure_response = encrypted_response + response_mac[:8] + bytes([0x90, 0x00])
        print(f"SERVER - Complete secure response: {secure_response.hex()}")

        return secure_response


async def run_demo():
    # Start the server
    server = SCP03Server()
    await server.start()
    
    # Give server time to initialize
    await asyncio.sleep(1)
    
    # Start the client
    client = SCP03Client()
    await client.start()
    
    try:
        # Establish secure channel
        await client.establish_secure_channel()
        
        print(f"DEMO - send select command----------------------------------------")
        response = await client.send_encrypted_apdu(
            cla=0x00,
            ins=0xA4,  # SELECT
            p1=0x04,
            p2=0x00,
            data=bytes([0x32, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53, 0x2E, 0x44, 0x44, 0x46, 0x30, 0x31])  # PPSE AID
        )
        
        print(f"DEMO - Select command response: SW={hex(response['status_word'])}")
        print(f"DEMO - Data: {response['data'].hex() if response['data'] else 'None'}")
        
        print(f"DEMO - send 1st secure command----------------------------------------")
        response = await client.send_encrypted_apdu(
            cla=0x00,
            ins=0xB0,  
            p1=0x00,
            p2=0x00,
            data=bytes([0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A]) 
        )
        print(f"DEMO - Read Binary command response: SW={hex(response['status_word'])}")
        print(f"DEMO - Data: {response['data'].hex() if response['data'] else 'None'}")

        print(f"DEMO - send 2nd secure command----------------------------------------")
        response = await client.send_encrypted_apdu(
            cla=0x00,
            ins=0xB0,  
            p1=0x00,
            p2=0x00,
            data=bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]) 
        )

        print(f"DEMO - Read Binary command response: SW={hex(response['status_word'])}")
        print(f"DEMO - Data: {response['data'].hex() if response['data'] else 'None'}")
        
        print(f"DEMO - send 3nd secure command----------------------------------------")
        response = await client.send_encrypted_apdu(
            cla=0x00,
            ins=0xB0,  
            p1=0x00,
            p2=0x00,
            data=bytes([0x11, 0x22, 0x33, 0x44]) 
        )

        print(f"DEMO - Read Binary command response: SW={hex(response['status_word'])}")
        print(f"DEMO - Data: {response['data'].hex() if response['data'] else 'None'}")

    finally:
        await client.close()

if __name__ == "__main__":
    asyncio.run(run_demo())