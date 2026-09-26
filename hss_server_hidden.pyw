"""HSS PowerShell server for a trusted Windows local network."""  # Describes this file; Python treats this first string as the module's documentation.

from __future__ import annotations  # Lets type hints refer to classes defined later in this file.

import argparse  # Reads options such as the server's host and port from the command line.
import socketserver  # Provides ready-made TCP and UDP server classes.
import subprocess  # Starts and controls external Windows programs such as PowerShell.
import sys  # Gives access to information about the Python runtime and operating system.
import threading  # Runs server tasks at the same time using separate threads.
from typing import TextIO, cast  # Imports a stream type and a helper for telling the type checker about a value.
import os  # Provides a portable way of using operating system dependent functionality, such as checking the platform.


PASSWORD = "WeltaITBusinessIncorperatedITSecurePasswordHSSSystem"  # Password clients must send to authenticate; keep this secret and change it for real use.
DEFAULT_HOST = "0.0.0.0"  # Listens on every network interface unless another host is specified.
DEFAULT_PORT = 8765  # TCP port used for authenticated PowerShell commands.
DISCOVERY_PORT = 8766  # UDP port used by clients to find this server on the local network.
MAX_COMMAND_LENGTH = 8192  # Maximum number of bytes accepted for one client command.
REMOTE_CWD_MARKER = "__HSS_REMOTE_CWD__:"  # Text prefix used to tell the client the server's current folder.


def ensure_firewall_rule(port: int) -> None:  # Defines a function that checks or creates a Windows firewall rule for the given port.
	if sys.platform != "win32":  # Checks whether this program is running on Windows.
		return  # Stops here because the firewall commands below are Windows-specific.

	rule_name = f"HSS_TCP_{port}"  # Builds a unique name for the firewall rule using the TCP port.
	existing_rule = subprocess.run(  # Runs netsh to check whether the firewall rule already exists.
		["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name}"],  # Supplies netsh's command-line arguments as a list.
		capture_output=True,  # Saves command output instead of printing it directly.
		text=True,  # Returns command output as text rather than raw bytes.
		creationflags=subprocess.CREATE_NO_WINDOW,  # Prevents a separate command window from appearing.
	)  # Ends the subprocess.run call.
	if existing_rule.returncode == 0:  # A zero return code means netsh found the rule successfully.
		return  # No change is needed, so finish this function.

	rule_arguments = (  # Starts building the arguments that describe the firewall rule to add.
		f"advfirewall firewall add rule name={rule_name} dir=in action=allow "  # Allows incoming connections and gives the rule its name.
		f"protocol=TCP localport={port} remoteip=localsubnet profile=private"  # Limits it to this TCP port, the local subnet, and private networks.
	)  # Combines the adjacent text pieces into one string.
	powershell_command = (  # Builds a PowerShell command that runs netsh with administrator approval.
		f"$rule = Start-Process -FilePath netsh.exe -ArgumentList '{rule_arguments}' "  # Starts netsh and stores information about the started process.
		"-Verb RunAs -Wait -PassThru; exit $rule.ExitCode"  # Requests elevation, waits for completion, and returns netsh's exit code.
	)  # Combines the adjacent text pieces into one command string.
	result = subprocess.run(  # Runs PowerShell to create the firewall rule.
		["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", powershell_command],  # Starts PowerShell without profiles or interactive prompts.
		capture_output=True,  # Captures output so errors can be shown below.
		text=True,  # Reads captured output as text.
		creationflags=subprocess.CREATE_NO_WINDOW,  # Avoids opening an extra console window.
	)  # Ends the subprocess.run call.
	if result.returncode != 0:  # Checks whether PowerShell or netsh reported a failure.
		detail = result.stderr.strip() or "UAC approval may have been cancelled."  # Uses the error text, or a helpful fallback if it is empty.
		raise SystemExit(f"Could not add the Windows Firewall rule: {detail}")  # Stops the program and explains why the rule could not be added.
	print(f"Added a Private-network firewall rule for TCP port {port}.")  # Tells the user the firewall rule was created.


class HssRequestHandler(socketserver.StreamRequestHandler):  # Defines how one connected TCP client is handled.
	def handle(self) -> None:  # Runs automatically when a client connects to the TCP server.
		server = cast(HssServer, self.server)  # Tells the type checker this connection belongs to our HSS server.
		self.wfile.write(b"HSS/1\n")  # Sends the client a short message identifying the server protocol version.
		self.wfile.flush()  # Sends buffered data immediately instead of waiting.

		auth_line = self.rfile.readline(256).decode("utf-8", errors="replace").rstrip("\r\n")  # Reads and cleans up the client's first line, which should contain its password.
		if not auth_line.startswith("AUTH "):  # Checks whether the client used the expected authentication message format.
			self.wfile.write(b"ERR authentication required\n")  # Tells the client it must authenticate first.
			self.wfile.flush()  # Sends the error message now.
			return  # Ends handling this client connection.
		if auth_line[5:] != server.password:  # Compares the text after "AUTH " with the server's password.
			self.wfile.write(b"ERR authentication failed\n")  # Tells the client that its password was incorrect.
			self.wfile.flush()  # Sends the error message now.
			return  # Ends handling this client connection.

		self.wfile.write(b"OK authenticated\n")  # Confirms that the client passed the password check.
		self.wfile.flush()  # Sends the confirmation immediately.
		print(f"Authenticated HSS client: {self.client_address[0]}")  # Logs the client's IP address on the server.


		try:  # Starts PowerShell and catches errors in case it cannot be launched.
			powershell = subprocess.Popen(  # Opens PowerShell while keeping its input and output connected to this Python program.
				["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "-"],  # Starts PowerShell without a logo or profile and reads commands from standard input.
				stdin=subprocess.PIPE,  # Lets Python send commands to PowerShell.
				stdout=subprocess.PIPE,  # Lets Python read normal PowerShell output.
				stderr=subprocess.PIPE,  # Lets Python read PowerShell error output separately.
				text=True,  # Uses strings for the PowerShell input and output streams.
				bufsize=1,  # Uses line buffering so output can be forwarded promptly.
			)  # Ends the subprocess.Popen call and stores the running PowerShell process.
		except OSError as error:  # Handles an operating-system error, such as PowerShell not being installed.
			self.wfile.write(f"ERR could not start PowerShell: {error}\n".encode("utf-8", errors="replace"))  # Sends the error to the client as UTF-8 bytes.
			self.wfile.flush()  # Sends the error message immediately.
			return  # Ends handling this connection because no shell is available.

		if powershell.stdin is None or powershell.stdout is None or powershell.stderr is None:  # Checks that all requested PowerShell communication pipes were created.
			powershell.kill()  # Stops PowerShell because the server cannot communicate with it safely.
			return  # Ends handling this connection.
		powershell.stdin.write(f"Write-Output ('{REMOTE_CWD_MARKER}' + (Get-Location).Path)\n")  # Asks PowerShell to report its current folder using the special marker.
		powershell.stdin.flush()  # Sends that first PowerShell command immediately.

		output_threads = [  # Makes one background thread for each kind of PowerShell output.
			threading.Thread(target=self.forward_output, args=(powershell.stdout, b"OUT "), daemon=True),  # Forwards normal output to the client with an OUT label.
			threading.Thread(target=self.forward_output, args=(powershell.stderr, b"ERR "), daemon=True),  # Forwards error output to the client with an ERR label.
		]  # Ends the list of output-forwarding threads.
		for thread in output_threads:  # Goes through both output-forwarding threads.
			thread.start()  # Starts this thread so output can be sent while commands are being received.

		try:  # Handles client disconnects while receiving and forwarding commands.
			while True:  # Repeats until the client disconnects or asks to exit.
				raw_line = self.rfile.readline(MAX_COMMAND_LENGTH + 2)  # Reads one command, with a small extra allowance for line endings.
				if not raw_line:  # An empty read means the client closed the connection.
					break  # Leaves the command loop.
				if len(raw_line) == MAX_COMMAND_LENGTH + 2 and not raw_line.endswith(b"\n"):  # Detects a line that filled the read limit without ending.
					self.wfile.write(b"ERR command too long\n")  # Tells the client its command exceeded the allowed length.
					self.wfile.flush()  # Sends the error immediately.
					break  # Stops accepting commands from this client.

				command = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")  # Turns received bytes into text and removes the line ending.
				if command in {":quit", ":exit"}:  # Checks whether the client sent either supported exit command.
					break  # Leaves the command loop and starts cleaning up.
				if not command:  # Checks whether the line was empty.
					continue  # Ignores an empty line and waits for another command.
				powershell.stdin.write(command + "\n")  # Sends the client's command to PowerShell followed by a newline.
				powershell.stdin.write(f"Write-Output ('{REMOTE_CWD_MARKER}' + (Get-Location).Path)\n")  # Requests the current PowerShell folder after the command.
				powershell.stdin.flush()  # Makes both written lines available to PowerShell immediately.
		except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError, OSError):  # Handles common network or pipe errors during communication.
			pass  # Ignores the disconnect error; the cleanup below still needs to run.
		finally:  # Runs this cleanup whether the loop ended normally or because of an error.
			powershell.stdin.close()  # Tells PowerShell that no more commands will be sent.
			try:  # Gives PowerShell a short time to finish after its input is closed.
				powershell.wait(timeout=3)  # Waits up to three seconds for the PowerShell process to stop.
			except subprocess.TimeoutExpired:  # Runs if PowerShell did not stop before the timeout.
				powershell.kill()  # Forcefully stops the PowerShell process.
				powershell.wait()  # Waits until the forced stop has completed.
			print(f"HSS client disconnected: {self.client_address[0]}")  # Logs the IP address of the client that has disconnected.

			os.system('powershell -command "(New-Object -ComObject Shell.Application).MinimizeAll()"')

	def forward_output(self, stream: TextIO, prefix: bytes) -> None:  # Defines a helper that copies one PowerShell output stream to the client.
		for line in iter(stream.readline, ""):  # Reads output one line at a time until the stream ends.
			try:  # Attempts to send this output line across the network connection.
				self.wfile.write(prefix + line.encode("utf-8", errors="replace"))  # Adds an OUT or ERR label, converts text to bytes, and sends it.
				self.wfile.flush()  # Sends the output line immediately.
			except OSError:  # Handles a closed or broken client connection.
				return  # Stops forwarding because the client can no longer receive data.


class HssDiscoveryHandler(socketserver.BaseRequestHandler):  # Defines how the server answers UDP discovery messages.
	def handle(self) -> None:  # Runs automatically when a UDP message arrives.
		message, discovery_socket = self.request  # Separates the received message from the socket used to reply.
		if message.decode("utf-8", errors="replace").strip() == "HSS_DISCOVER":  # Checks that the message asks to find an HSS server.
			server = cast(HssDiscoveryServer, self.server)  # Tells the type checker this is our discovery server.
			discovery_socket.sendto(f"HSS/1 {server.tcp_port}\n".encode("utf-8"), self.client_address)  # Replies to the sender with the protocol version and TCP port.


class HssDiscoveryServer(socketserver.ThreadingUDPServer):  # Creates a UDP server that can process discovery messages on separate threads.
	allow_reuse_address = True  # Allows the address and port to be reused soon after the server stops.
	daemon_threads = True  # Lets the program exit without waiting for request threads to finish.

	def __init__(self, address: tuple[str, int], tcp_port: int):  # Initializes the UDP discovery server with its address and TCP port.
		self.tcp_port = tcp_port  # Saves the TCP port so discovery replies can tell clients where to connect.
		super().__init__(address, HssDiscoveryHandler)  # Lets the built-in UDP server initialize using our discovery handler.


class HssServer(socketserver.ThreadingTCPServer):  # Creates the main TCP server for client connections.
	allow_reuse_address = True  # Allows the address and port to be reused soon after the server stops.
	daemon_threads = True  # Lets the program exit without waiting for client threads to finish.

	def __init__(self, address: tuple[str, int], password: str):  # Initializes the TCP server with its listening address and password.
		self.password = password  # Saves the password so each client handler can check it.
		super().__init__(address, HssRequestHandler)  # Lets the built-in TCP server initialize using our request handler.


def main() -> None:  # Defines the main function that starts and runs the servers.
	parser = argparse.ArgumentParser(description="Run the HSS PowerShell server")  # Creates a parser for command-line options.
	parser.add_argument("--host", default=DEFAULT_HOST, help="Address to listen on")  # Adds an option for which network address to listen on.
	parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="TCP port")  # Adds an option for the TCP port and converts its value to an integer.
	args = parser.parse_args()  # Reads the options supplied when the program was started.

	print("HSS server starting. Use only on a trusted private network.")  # Shows a startup notice and network-safety warning.
	with HssServer((args.host, args.port), PASSWORD) as server:  # Creates the TCP server and ensures it is closed when this block ends.
		with HssDiscoveryServer((args.host, DISCOVERY_PORT), args.port) as discovery_server:  # Creates the UDP server used for local-network discovery.
			ensure_firewall_rule(args.port)  # Checks that Windows Firewall allows connections to the selected TCP port.
			print(f"Listening on server address {args.host}:{args.port}; press Ctrl+C to stop.")  # Displays the address and port that clients can use.
			discovery_thread = threading.Thread(target=discovery_server.serve_forever, daemon=True)  # Prepares UDP discovery to run in the background.
			discovery_thread.start()  # Starts listening for discovery messages.
			print(f"LAN discovery enabled on UDP port {DISCOVERY_PORT}.")  # Tells the user which UDP port is being used.
			try:  # Catches the keyboard interrupt used to stop the server with Ctrl+C.
				server.serve_forever()  # Keeps accepting and handling TCP client connections.
			except KeyboardInterrupt:  # Runs when the user presses Ctrl+C.
				print("\nHSS server stopped.")  # Prints a clean shutdown message.


if __name__ == "__main__":  # Checks whether this file was run directly rather than imported by another file.
	main()  # Starts the server when this script is run directly.
