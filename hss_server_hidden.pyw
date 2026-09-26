"""HSS PowerShell server for a trusted Windows local network."""

from __future__ import annotations

import argparse
import socketserver
import subprocess
import sys
import threading
from typing import TextIO, cast


PASSWORD = "WeltaITBusinessIncorperatedITSecurePasswordHSSSystem"
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8765
DISCOVERY_PORT = 8766
MAX_COMMAND_LENGTH = 8192
REMOTE_CWD_MARKER = "__HSS_REMOTE_CWD__:"


def ensure_firewall_rule(port: int) -> None:
	if sys.platform != "win32":
		return

	rule_name = f"HSS_TCP_{port}"
	existing_rule = subprocess.run(
		["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name}"],
		capture_output=True,
		text=True,
		creationflags=subprocess.CREATE_NO_WINDOW,
	)
	if existing_rule.returncode == 0:
		return

	rule_arguments = (
		f"advfirewall firewall add rule name={rule_name} dir=in action=allow "
		f"protocol=TCP localport={port} remoteip=localsubnet profile=private"
	)
	powershell_command = (
		f"$rule = Start-Process -FilePath netsh.exe -ArgumentList '{rule_arguments}' "
		"-Verb RunAs -Wait -PassThru; exit $rule.ExitCode"
	)
	result = subprocess.run(
		["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", powershell_command],
		capture_output=True,
		text=True,
		creationflags=subprocess.CREATE_NO_WINDOW,
	)
	if result.returncode != 0:
		detail = result.stderr.strip() or "UAC approval may have been cancelled."
		raise SystemExit(f"Could not add the Windows Firewall rule: {detail}")
	print(f"Added a Private-network firewall rule for TCP port {port}.")


class HssRequestHandler(socketserver.StreamRequestHandler):
	def handle(self) -> None:
		server = cast(HssServer, self.server)
		self.wfile.write(b"HSS/1\n")
		self.wfile.flush()

		auth_line = self.rfile.readline(256).decode("utf-8", errors="replace").rstrip("\r\n")
		if not auth_line.startswith("AUTH "):
			self.wfile.write(b"ERR authentication required\n")
			self.wfile.flush()
			return
		if auth_line[5:] != server.password:
			self.wfile.write(b"ERR authentication failed\n")
			self.wfile.flush()
			return

		self.wfile.write(b"OK authenticated\n")
		self.wfile.flush()
		print(f"Authenticated HSS client: {self.client_address[0]}")

		try:
			powershell = subprocess.Popen(
				["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "-"],
				stdin=subprocess.PIPE,
				stdout=subprocess.PIPE,
				stderr=subprocess.PIPE,
				text=True,
				bufsize=1,
			)
		except OSError as error:
			self.wfile.write(f"ERR could not start PowerShell: {error}\n".encode("utf-8", errors="replace"))
			self.wfile.flush()
			return

		if powershell.stdin is None or powershell.stdout is None or powershell.stderr is None:
			powershell.kill()
			return
		powershell.stdin.write(f"Write-Output ('{REMOTE_CWD_MARKER}' + (Get-Location).Path)\n")
		powershell.stdin.flush()

		output_threads = [
			threading.Thread(target=self.forward_output, args=(powershell.stdout, b"OUT "), daemon=True),
			threading.Thread(target=self.forward_output, args=(powershell.stderr, b"ERR "), daemon=True),
		]
		for thread in output_threads:
			thread.start()

		try:
			while True:
				raw_line = self.rfile.readline(MAX_COMMAND_LENGTH + 2)
				if not raw_line:
					break
				if len(raw_line) == MAX_COMMAND_LENGTH + 2 and not raw_line.endswith(b"\n"):
					self.wfile.write(b"ERR command too long\n")
					self.wfile.flush()
					break

				command = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
				if command in {":quit", ":exit"}:
					break
				if not command:
					continue
				powershell.stdin.write(command + "\n")
				powershell.stdin.write(f"Write-Output ('{REMOTE_CWD_MARKER}' + (Get-Location).Path)\n")
				powershell.stdin.flush()
		except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError, OSError):
			pass
		finally:
			powershell.stdin.close()
			try:
				powershell.wait(timeout=3)
			except subprocess.TimeoutExpired:
				powershell.kill()
				powershell.wait()
			print(f"HSS client disconnected: {self.client_address[0]}")

	def forward_output(self, stream: TextIO, prefix: bytes) -> None:
		for line in iter(stream.readline, ""):
			try:
				self.wfile.write(prefix + line.encode("utf-8", errors="replace"))
				self.wfile.flush()
			except OSError:
				return


class HssDiscoveryHandler(socketserver.BaseRequestHandler):
	def handle(self) -> None:
		message, discovery_socket = self.request
		if message.decode("utf-8", errors="replace").strip() == "HSS_DISCOVER":
			server = cast(HssDiscoveryServer, self.server)
			discovery_socket.sendto(f"HSS/1 {server.tcp_port}\n".encode("utf-8"), self.client_address)


class HssDiscoveryServer(socketserver.ThreadingUDPServer):
	allow_reuse_address = True
	daemon_threads = True

	def __init__(self, address: tuple[str, int], tcp_port: int):
		self.tcp_port = tcp_port
		super().__init__(address, HssDiscoveryHandler)


class HssServer(socketserver.ThreadingTCPServer):
	allow_reuse_address = True
	daemon_threads = True

	def __init__(self, address: tuple[str, int], password: str):
		self.password = password
		super().__init__(address, HssRequestHandler)


def main() -> None:
	parser = argparse.ArgumentParser(description="Run the HSS PowerShell server")
	parser.add_argument("--host", default=DEFAULT_HOST, help="Address to listen on")
	parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="TCP port")
	args = parser.parse_args()

	print("HSS server starting. Use only on a trusted private network.")
	with HssServer((args.host, args.port), PASSWORD) as server:
		with HssDiscoveryServer((args.host, DISCOVERY_PORT), args.port) as discovery_server:
			ensure_firewall_rule(args.port)
			print(f"Listening on server address {args.host}:{args.port}; press Ctrl+C to stop.")
			discovery_thread = threading.Thread(target=discovery_server.serve_forever, daemon=True)
			discovery_thread.start()
			print(f"LAN discovery enabled on UDP port {DISCOVERY_PORT}.")
			try:
				server.serve_forever()
			except KeyboardInterrupt:
				print("\nHSS server stopped.")


if __name__ == "__main__":
	main()
