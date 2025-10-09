# BypassingAVs
### Loader Component

1. Anti-Sandbox: Clever Evasion
Traditional sandbox checks (CPU, memory, disk) are outdated and easily detected by AVs. We take a smarter approach:

Desktop Shortcut Detection: Scans for shortcuts of popular apps like Google Chrome, Microsoft Office, Discord, and OneDrive. Sandboxes rarely have these, making them a reliable indicator of a real user system.
User Activity Check: Uses GetLastInputInfo to detect recent mouse/keyboard activity. No activity suggests a sandbox environment.
Running Process Check: Verifies the presence of processes like chrome.exe and explorer.exe using CreateToolhelp32Snapshot to confirm an active system.

If the environment score (based on shortcuts, files, and activity) is below 40%, the program exits to avoid sandbox analysis.
2. Ntdll Unhooking and Dynamic API Calls
Antiviruses often hook sensitive APIs. We bypass them with:

Ntdll Unhooking: Loads a clean ntdll.dll from the system directory and replaces the hooked .text section in the current process, removing any hooks.
Dynamic API Calls: Instead of direct function calls, we enumerate the export table of target DLLs, hashing function names to retrieve their addresses and invoke them via pointers. This enables stealthy calls to APIs like VirtualAlloc and CreateThread.

3. Shellcode and Loader Separation
The shellcode is encoded to evade AV detection and separated from the loader. By keeping the shellcode out of the EXE, it becomes much harder for antiviruses to flag the program.

Shellcode Component
The shellcode undergoes multi-layer obfuscation: XOR + RC4 + Base64 + MAC format. The final MAC address format leverages Windows' tolerance for such strings, reducing detection risks.
Usage Instructions

Obfuscate the Shellcode:

Use ShellcodeObfuscator.cpp.
Replace the original_shellcode array with your raw shellcode (e.g., unsigned char original_shellcode[] = {0x90, 0x90, ...};).
Compile and run (g++ ShellcodeObfuscator.cpp -o obfuscator).
Copy the generated mac_shellcode array and RC4 key ("MySecret").


Run the Shellcode:

DynamicShellcodeRunner.cpp (Dynamic Input):

Compile with ShellcodeDecryptor.cpp (g++ DynamicShellcodeRunner.cpp -o runner).
Run with MAC addresses as arguments (e.g., ./runner <MAC1> <MAC2> ...).


EmbeddedShellcodeRunner.cpp (Static Input):

Paste the mac_shellcode array into the mac_shellcode variable.
Compile with ShellcodeDecryptor.cpp (g++ EmbeddedShellcodeRunner.cpp -o static_runner).
Run directly (./static_runner).


Ensure encryption keys (RC4: "MySecret", XOR: 0xAB) match between obfuscator and runner.

### №Repository Structure

ShellcodeObfuscator.cpp: Encodes shellcode using XOR, RC4, Base64, and MAC format.
DynamicShellcodeRunner.cpp: Loads and executes shellcode passed via command-line arguments.
EmbeddedShellcodeRunner.cpp: Loads and executes shellcode embedded in the code.
ShellcodeDecryptor.cpp: Modular file with decryption functions (MAC → Base64 → RC4 → XOR).

### Requirements

Compile on Windows using a C++ compiler (e.g., g++ or Visual Studio).
Test on a system with Chrome, Office, or similar shortcuts to pass environment checks.

⚠ Warning: This code is for educational purposes and security testing in controlled environments only. Unauthorized use may be illegal.
Thanks for exploring!

License
Licensed under the MIT License for educational and authorized security testing purposes only. See LICENSE for details.

Ethical Use
is for authorized security testing only. Unauthorized use may violate laws such as the Computer Fraud and Abuse Act (CFAA) or local cybersecurity regulations. Always obtain explicit permission from system owners before testing.
