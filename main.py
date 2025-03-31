import tkinter as tk
from tkinter import ttk, scrolledtext
import asyncio
import threading
import sys
import traceback
from scp03 import SCP03Server, SCP03Client

class AsyncApp:
    """Helper class to run asyncio tasks from tkinter"""
    def __init__(self, loop=None):
        self.loop = loop or asyncio.new_event_loop()
        self.thread = None
    
    def start(self):
        if self.thread is not None and self.thread.is_alive():
            return
        
        def run_loop():
            asyncio.set_event_loop(self.loop)
            self.loop.run_forever()
        
        self.thread = threading.Thread(target=run_loop, daemon=True)
        self.thread.start()
    
    def stop(self):
        if self.loop and self.loop.is_running():
            self.loop.call_soon_threadsafe(self.loop.stop)
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1)
    
    def run_coroutine(self, coro):
        """Run a coroutine in the event loop and return a future"""
        return asyncio.run_coroutine_threadsafe(coro, self.loop)

class SCP03UI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SCP03 APDU Sender")
        self.geometry("700x600")
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Initialize async runner
        self.async_app = AsyncApp()
        self.async_app.start()
        
        # Initialize server and client
        self.server = None
        self.client = None
        self.secure_channel_established = False
        
        # Input type (hex/string)
        self.is_string_input = tk.BooleanVar(value=False)
        
        self.create_widgets()
    
    def create_widgets(self):
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create server/client control section
        control_frame = ttk.LabelFrame(main_frame, text="Server/Client Control")
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        server_client_frame = ttk.Frame(control_frame)
        server_client_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.start_server_btn = ttk.Button(server_client_frame, text="Start Server", command=self.start_server)
        self.start_server_btn.pack(side=tk.LEFT, padx=5)
        
        self.start_client_btn = ttk.Button(server_client_frame, text="Start Client", command=self.start_client, state=tk.DISABLED)
        self.start_client_btn.pack(side=tk.LEFT, padx=5)
        
        self.establish_secure_channel_btn = ttk.Button(server_client_frame, text="Establish Secure Channel", 
                                                  command=self.establish_secure_channel, state=tk.DISABLED)
        self.establish_secure_channel_btn.pack(side=tk.LEFT, padx=5)
        
        # APDU command section
        input_frame = ttk.LabelFrame(main_frame, text="APDU Command Input")
        input_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # APDU parameters
        params_frame = ttk.Frame(input_frame)
        params_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # CLA
        ttk.Label(params_frame, text="CLA (hex):").grid(row=0, column=0, padx=5, pady=2, sticky=tk.W)
        self.cla_input = ttk.Entry(params_frame, width=5)
        self.cla_input.grid(row=0, column=1, padx=5, pady=2, sticky=tk.W)
        self.cla_input.insert(0, "00")
        
        # INS
        ttk.Label(params_frame, text="INS (hex):").grid(row=0, column=2, padx=5, pady=2, sticky=tk.W)
        self.ins_input = ttk.Entry(params_frame, width=5)
        self.ins_input.grid(row=0, column=3, padx=5, pady=2, sticky=tk.W)
        self.ins_input.insert(0, "A4")
        
        # P1
        ttk.Label(params_frame, text="P1 (hex):").grid(row=0, column=4, padx=5, pady=2, sticky=tk.W)
        self.p1_input = ttk.Entry(params_frame, width=5)
        self.p1_input.grid(row=0, column=5, padx=5, pady=2, sticky=tk.W)
        self.p1_input.insert(0, "04")
        
        # P2
        ttk.Label(params_frame, text="P2 (hex):").grid(row=0, column=6, padx=5, pady=2, sticky=tk.W)
        self.p2_input = ttk.Entry(params_frame, width=5)
        self.p2_input.grid(row=0, column=7, padx=5, pady=2, sticky=tk.W)
        self.p2_input.insert(0, "00")
        
        # Data input
        data_frame = ttk.Frame(params_frame)
        data_frame.grid(row=1, column=0, columnspan=8, padx=5, pady=2, sticky=tk.W+tk.E)
        
        self.data_type_switch = ttk.Checkbutton(
            data_frame, 
            text="String Input", 
            variable=self.is_string_input,
            command=self.toggle_data_input_type
        )
        self.data_type_switch.pack(side=tk.LEFT, padx=5)
        
        # Data label (will change based on input type)
        self.data_label = ttk.Label(data_frame, text="Data (hex):")
        self.data_label.pack(side=tk.LEFT, padx=5)
        
        self.data_input = ttk.Entry(data_frame, width=60)
        self.data_input.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.data_input.insert(0, "325041592E5359532E4444463031")  # PPSE AID
        
        # Quick commands samples section
        quick_frame = ttk.Frame(input_frame)
        quick_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(quick_frame, text="Quick Commands:").pack(side=tk.LEFT, padx=5)
        select_ppse_btn = ttk.Button(quick_frame, text="Select PPSE", command=self.select_ppse)
        select_ppse_btn.pack(side=tk.LEFT, padx=5)
        
        send_data_btn = ttk.Button(quick_frame, text="String Sample", command=self.send_data)
        send_data_btn.pack(side=tk.LEFT, padx=5)
        
        # Send button
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.send_button = ttk.Button(button_frame, text="Send APDU", command=self.send_apdu, state=tk.DISABLED)
        self.send_button.pack(side=tk.LEFT, padx=5)
        
        self.clear_button = ttk.Button(button_frame, text="Clear Log", command=self.clear_log)
        self.clear_button.pack(side=tk.LEFT, padx=5)
        
        log_frame = ttk.LabelFrame(main_frame, text="Log and Response")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=15)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready - Click 'Start Server' to begin")
        status_bar = ttk.Label(self, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def toggle_data_input_type(self):
        is_string = self.is_string_input.get()
        if is_string:
            self.data_label.config(text="Data (STR):")
            # Try to convert the current hex data to string if possible
            try:
                current_hex = self.data_input.get().strip().replace(" ", "")
                if current_hex and len(current_hex) % 2 == 0:
                    string_value = bytes.fromhex(current_hex).decode('utf-8', errors='replace')
                    self.data_input.delete(0, tk.END)
                    self.data_input.insert(0, string_value)
            except Exception as e:
                self.log(f"Could not convert hex to string: {str(e)}")
        else:
            self.data_label.config(text="Data (hex):")
            # Try to convert the current string to hex if possible
            try:
                current_string = self.data_input.get()
                if current_string:
                    hex_value = current_string.encode('utf-8').hex().upper()
                    self.data_input.delete(0, tk.END)
                    self.data_input.insert(0, hex_value)
            except Exception as e:
                self.log(f"Could not convert string to hex: {str(e)}")
    
    def log(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
    
    def clear_log(self):
        self.log_text.delete(1.0, tk.END)
    
    def start_server(self):
        self.log("Starting SCP03 server...")
        self.status_var.set("Starting server...")
        self.start_server_btn.config(state=tk.DISABLED)
        
        async def do_start_server():
            try:
                self.server = SCP03Server()
                await self.server.start()
                return True
            except Exception as e:
                self.log(f"Error starting server: {str(e)}")
                return False
        
        future = self.async_app.run_coroutine(do_start_server())
        
        def server_started(future):
            try:
                result = future.result()
                if result:
                    self.log("SCP03 server started successfully")
                    self.status_var.set("Server running - Start client next")
                    self.start_client_btn.config(state=tk.NORMAL)
                else:
                    self.start_server_btn.config(state=tk.NORMAL)
                    self.status_var.set("Server failed to start")
            except Exception as e:
                self.log(f"Exception in start_server callback: {str(e)}")
                self.start_server_btn.config(state=tk.NORMAL)
                self.status_var.set("Server failed to start")
        
        future.add_done_callback(server_started)
    
    def start_client(self):
        self.log("Starting SCP03 client...")
        self.status_var.set("Starting client...")
        self.start_client_btn.config(state=tk.DISABLED)
        
        async def do_start_client():
            try:
                self.client = SCP03Client()
                await self.client.start()
                return True
            except Exception as e:
                self.log(f"Error starting client: {str(e)}")
                return False
        
        future = self.async_app.run_coroutine(do_start_client())
        
        def client_started(future):
            try:
                result = future.result()
                if result:
                    self.log("SCP03 client started successfully")
                    self.status_var.set("Client running - Establish secure channel next")
                    self.establish_secure_channel_btn.config(state=tk.NORMAL)
                else:
                    self.start_client_btn.config(state=tk.NORMAL)
                    self.status_var.set("Client failed to start")
            except Exception as e:
                self.log(f"Exception in start_client callback: {str(e)}")
                self.start_client_btn.config(state=tk.NORMAL)
                self.status_var.set("Client failed to start")
        
        future.add_done_callback(client_started)
    
    def establish_secure_channel(self):
        self.log("Establishing secure channel...")
        self.status_var.set("Establishing secure channel...")
        self.establish_secure_channel_btn.config(state=tk.DISABLED)
        
        async def do_establish_secure_channel():
            try:
                await self.client.establish_secure_channel()
                return True
            except Exception as e:
                self.log(f"Error establishing secure channel: {str(e)}")
                return False
        
        future = self.async_app.run_coroutine(do_establish_secure_channel())
        
        def channel_established(future):
            try:
                result = future.result()
                if result:
                    self.secure_channel_established = True
                    self.log("Secure channel established successfully")
                    self.status_var.set("Secure channel established - Ready to send APDUs")
                    self.send_button.config(state=tk.NORMAL)
                else:
                    self.establish_secure_channel_btn.config(state=tk.NORMAL)
                    self.status_var.set("Failed to establish secure channel")
            except Exception as e:
                self.log(f"Exception in establish_secure_channel callback: {str(e)}")
                self.establish_secure_channel_btn.config(state=tk.NORMAL)
                self.status_var.set("Failed to establish secure channel")
        
        future.add_done_callback(channel_established)
    
    def send_apdu(self):
        if not self.client or not self.secure_channel_established:
            self.log("Client not ready or secure channel not established")
            return
        
        try:
            cla = int(self.cla_input.get(), 16)
            ins = int(self.ins_input.get(), 16)
            p1  = int(self.p1_input.get(), 16)
            p2  = int(self.p2_input.get(), 16)
            
            # Process data field based on input type
            data_input = self.data_input.get().strip()
            
            if self.is_string_input.get():
                # Convert string to hex bytes
                data = data_input.encode('utf-8')
                self.log(f"Converting string to hex: '{data_input}' -> {data.hex().upper()}")
            else:
                # Process hex string directly - convert hex string to bytes
                data_hex = data_input.replace(" ", "")
                if data_hex:
                    data = bytes.fromhex(data_hex)
                else:
                    data = bytes()
            
            self.log(f"Sending APDU: CLA={hex(cla)}, INS={hex(ins)}, P1={hex(p1)}, P2={hex(p2)}, Data={data.hex().upper()}")
            
            async def do_send_apdu():
                try:
                    response = await self.client.send_encrypted_apdu(
                        cla=cla,
                        ins=ins,
                        p1=p1,
                        p2=p2,
                        data=data
                    )
                    return response
                except Exception as e:
                    self.log(f"Error sending APDU: {str(e)}")
                    return None
            
            future = self.async_app.run_coroutine(do_send_apdu())
            
            def apdu_sent(future):
                try:
                    response = future.result()
                    if response is not None:
                        if isinstance(response, bytes):
                            response_hex = response.hex().upper()
                            self.log(f"Response (bytes): {response_hex}")
                            
                            # Try to parse status word
                            if len(response) >= 2:
                                sw = response[-2:].hex().upper()
                                self.log(f"Status Word: {sw}")
                                
                                # Interpret common status words
                                sw_meanings = {
                                    "9000": "Success",
                                    "6A82": "File not found",
                                    "6A86": "Incorrect P1-P2",
                                    "6A80": "Incorrect data",
                                    "6982": "Security status not satisfied"
                                }
                                if sw in sw_meanings:
                                    self.log(f"Status meaning: {sw_meanings[sw]}")
                                
                                # Try to decode response data as string if it looks like text
                                if len(response) > 2:
                                    response_data = response[:-2]  # Remove status word
                                    try:
                                        # Check if the data appears to be text
                                        is_text = all(32 <= b <= 126 for b in response_data)
                                        if is_text:
                                            text = response_data.decode('utf-8', errors='replace')
                                            self.log(f"Response as text: '{text}'")
                                    except Exception:
                                        pass  # Ignore if not decodable as text
                        
                        elif isinstance(response, dict):
                            # Handle dictionary response
                            self.log("Response (dictionary):")
                            for key, value in response.items():
                                if isinstance(value, bytes):
                                    self.log(f"  {key}: {value.hex().upper()}")
                                    
                                    # Try to decode as text 
                                    try:
                                        if key == 'data' and all(32 <= b <= 126 for b in value):
                                            text = value.decode('utf-8', errors='replace')
                                            self.log(f"  {key} as text: '{text}'")
                                    except Exception:
                                        pass  
                            if 'status_word' in response:
                                sw = response['status_word']
                                self.log(f"Status Word: {sw:x}")
                                
                                # Interpret common status words
                                sw_meanings = {
                                    "9000": "Success",
                                    "6A82": "File not found",
                                    "6A86": "Incorrect P1-P2",
                                    "6A80": "Incorrect data",
                                    "6982": "Security status not satisfied"
                                }
                                if sw in sw_meanings:
                                    self.log(f"Status meaning: {sw_meanings[sw]}")
                        
                        else:
                            self.log(f"Response (other type): {str(response)}")
                    else:
                        self.log("No response received or empty response")
                except Exception as e:
                    self.log(f"Exception in apdu_sent callback: {str(e)}\n{traceback.format_exc()}")
            
            future.add_done_callback(apdu_sent)
            
        except ValueError as e:
            self.log(f"Invalid input format: {str(e)}")
        except Exception as e:
            self.log(f"Error preparing APDU: {str(e)}")
    
    def select_ppse(self):
        # Set fields for SELECT PPSE command
        self.cla_input.delete(0, tk.END)
        self.cla_input.insert(0, "00")
        
        self.ins_input.delete(0, tk.END)
        self.ins_input.insert(0, "A4")
        
        self.p1_input.delete(0, tk.END)
        self.p1_input.insert(0, "04")
        
        self.p2_input.delete(0, tk.END)
        self.p2_input.insert(0, "00")
        
        # Set to hex mode
        self.is_string_input.set(False)
        self.toggle_data_input_type()
        
        self.data_input.delete(0, tk.END)
        self.data_input.insert(0, "325041592E5359532E4444463031")  # PPSE AID
    
    def send_data(self):
        self.cla_input.delete(0, tk.END)
        self.cla_input.insert(0, "00")
        
        self.ins_input.delete(0, tk.END)
        self.ins_input.insert(0, "B0")
        
        self.p1_input.delete(0, tk.END)
        self.p1_input.insert(0, "00")
        
        self.p2_input.delete(0, tk.END)
        self.p2_input.insert(0, "00")
        
        # Set to hex mode
        self.is_string_input.set(False)
        self.toggle_data_input_type()
        
        self.data_input.delete(0, tk.END)
        self.data_input.insert(0, "6162636465666768696A6B6C6D6E6F707172737475767778797A")

    def on_closing(self):
        if self.async_app:
            self.async_app.stop()
        self.destroy()

if __name__ == "__main__":
    app = SCP03UI()
    app.mainloop()