# IATelligence
IATelligence is a Python script that extracts the Import Address Table (IAT) from a PE file and uses AI to provide details about each Windows API imported by the file. The script searches for related MITRE ATT&CK techniques and explains how each API could potentially be used by attackers.

It also displays the hashes of the file. IATelligence is a proof of concept for using large language models for malware analysis and quickly assessing the behavior of a malware sample based on its IAT.

> **Note:** This fork has been updated to use the **Anthropic Claude API** instead of OpenAI's GPT-3. See [Key Changes](#key-changes-from-the-original) below.

The request can take longer depending of the size of the IAT. 


# Getting Started

## Prerequisites

To run this tool you will need access to the [Anthropic API](https://platform.anthropic.com/). Sign up at `platform.anthropic.com` — new accounts receive approximately **$5 in free API credits** with no credit card required. You will then need to modify the script to add your own API. 

```python
# Initialise the Anthropic client
client = anthropic.Anthropic(api_key="YOUR_API_KEY_HERE")
```

You will also need to install the requirements.

```
pip install -r requirements.txt
```

# Usage

To run the tool just simply specify a PE file as argument to the script. 

```
python iatelligence.py sample.exe
```

The script will also calculate the hashes as well as the estimated cost of the request. 

```
[+] IAT Request from the file: .\sample.exe
[+] 33 functions will be requested to Claude!
[+] MD5: 2f82623f9523c0d167862cad0eff6806
[+] SHA1: 5d77804b87735e66d7d1e263c31c4ef010f16153
[+] SHA256: 9c2c8a8588fe6db09c09337e78437cb056cd557db1bcf5240112cbfb7b600efb
[+] Imphash: 8eeaa9499666119d13b3f44ecd77a729
[!] Estimated cost of requests: $0.0693
```

The result can be visualize in a table. Below is a truncated extract.

```
+------------------------------------------+-----------------------------+------------------------------------------+
| Libraries                                | API                         | Claude Verdict                              |
+------------------------------------------+-----------------------------+------------------------------------------+
| SHELL32.dll                              | ShellExecuteW               | The purpose of this API, ShellExecuteW,  |
|                                          |                             | is to launch an application or open a    |
|                                          |                             | file in the Windows operating system. It |
|                                          |                             | is associated with MITRE ATT&CK          |
|                                          |                             | technique T1218 - Execution Through      |
|                                          |                             | Module Load. This technique involves     |
|                                          |                             | using shell32.dll to execute malicious   |
|                                          |                             | code without directly invoking the       |
|                                          |                             | executable file itself, which can help   |
|                                          |                             | attackers evade detection and gain       |
|                                          |                             | access to systems.                       |
|                                          |                             |                                          |
| KERNEL32.dll                             | GetCurrentThreadId          | The purpose of this API is to retrieve   |
|                                          |                             | the identifier of the calling thread. It |
|                                          |                             | is associated with MITRE ATT&CK          |
|                                          |                             | technique T1155 - Thread Execution,      |
|                                          |                             | which involves creating and running      |
|                                          |                             | threads within a process or code         |
|                                          |                             | injection into an existing thread. The   |
|                                          |                             | GetCurrentThreadId() function allows     |
|                                          |                             | attackers to identify and target         |
|                                          |                             | specific threads for malicious           |
|                                          |                             | activities.                              |
|                                          |                             |                                          |
| KERNEL32.dll                             | GetSystemTimeAsFileTime     | The purpose of this API is to retrieve   |
|                                          |                             | the current system time as a file time   |
|                                          |                             | format. It is associated with the MITRE  |
|                                          |                             | ATT&CK technique T1124 - System Time     |
|                                          |                             | Discovery, which is used by adversaries  |
|                                          |                             | to gain insight into when certain        |
|                                          |                             | activities occurred or are scheduled to  |
|                                          |                             | occur. This allows them to perform       |
|                                          |                             | timing-based attacks and evade           |
|                                          |                             | detection.                               |
|                                          |                             |                                          |
| KERNEL32.dll                             | GetTickCount                | The purpose of this API is to retrieve   |
|                                          |                             | the number of milliseconds since Windows |
|                                          |                             | was started. It is associated with MITRE |
|                                          |                             | ATT&CK technique T1082 - System Time     |
|                                          |                             | Discovery, which involves an adversary   |
|                                          |                             | querying system information to gain      |
|                                          |                             | insight into file and system times or to |
|                                          |                             | determine valid accounts. This can be    |
|                                          |                             | used for various malicious activities    |
|                                          |                             | such as enumeration, credential dumping, |
|                                          |                             | and lateral movement.                    |
|                                          |                             |                                          |
| KERNEL32.dll                             | RtlCaptureContext           | The purpose of this API is to capture    |
|                                          |                             | the Context Record of a thread in order  |
|                                          |                             | to provide information about its state.  |
|                                          |                             | This can be used for debugging, logging  |
|                                          |                             | or other purposes. The associated MITRE  |
|                                          |                             | ATT&CK technique is T1113 - Process      |
|                                          |                             | Injection, as this API can be used to    |
|                                          |                             | inject code into a running process.      |
|                                          |                             |                                          |
| KERNEL32.dll                             | GetCurrentProcessId         | The purpose of this API is to retrieve   |
|                                          |                             | the current process identifier (PID) for |
|                                          |                             | a process running on Windows. This can   |
|                                          |                             | be used to identify which processes are  |
|                                          |                             | currently active and running on a        |
|                                          |                             | system. It is associated with MITRE      |
|                                          |                             | ATT&CK technique T1057 - Process         |
|                                          |                             | Discovery, as it allows an adversary to  |
|                                          |                             | gain knowledge about the processes that  |
|                                          |                             | are running on a system.                 |
|                                          |                             |                                          |
| KERNEL32.dll                             | RtlVirtualUnwind            | The purpose of this API is to provide an |
|                                          |                             | unwinding mechanism that can be used to  |
|                                          |                             | traverse the stack frames of a program.  |
|                                          |                             | It is associated with the MITRE ATT&CK   |
|                                          |                             | technique called "Stack Walking"         |
|                                          |                             | (T1063). This technique involves using   |
|                                          |                             | APIs like RtlVirtualUnwind() to walk     |
|                                          |                             | through the stack frames, which can help |
|                                          |                             | attackers gain access to sensitive       |
|                                          |                             | information or bypass security controls. |
|                                          |                             |                                          |
| KERNEL32.dll                             | UnhandledExceptionFilter    | The purpose of this API is to provide an |
|                                          |                             | exception handler for unhandled          |
|                                          |                             | exceptions in the Windows operating      |
|                                          |                             | system. It is associated with the MITRE  |
|                                          |                             | ATT&CK technique T1136 - Create or       |
|                                          |                             | Modify System Process, as it allows a    |
|                                          |                             | program to be able to handle unexpected  |
|                                          |                             | events that may occur during its         |
|                                          |                             | execution.                               |
```

## API Access & Cost

The Claude API is a **pay-as-you-go** service billed per token (roughly 1 token ≈ 0.75 words), completely separate from any claude.ai subscription. Current pricing per million tokens:

| Model             | Input | Output | Best For                   |
| ----------------- | ----- | ------ | -------------------------- |
| Claude Haiku 4.5  | $1.00 | $5.00  | Fast, high-volume analysis |
| Claude Sonnet 4.6 | $3.00 | $15.00 | Balanced capability & cost |
| Claude Opus 4.6   | $5.00 | $25.00 | Maximum capability         |

This script uses **Claude Sonnet 4.6** by default. For a typical PE file with 50–100 imported functions, the total cost per run is usually just a few cents. You can switch to Haiku for cheaper, faster results, or Opus for the most thorough analysis.

For the most up-to-date pricing, see the [Anthropic pricing page](https://docs.anthropic.com/en/docs/about-claude/pricing).

# Key Changes from the Original

This version replaces the OpenAI GPT-3 backend with the Anthropic Claude API. Here is a summary of what changed:

**API client:** Replaced the `openai` package with `anthropic`. Install with `pip install anthropic`.

**Client initialization:** The Anthropic SDK uses `anthropic.Anthropic(api_key=...)` rather than setting a module-level `openai.api_key`.

**API call structure:** Switched from `openai.Completion.create()` to `client.messages.create()`. The Anthropic API uses a `messages` list with role/content pairs rather than a raw `prompt` string.

**Model:** Uses `claude-sonnet-4-20250514` by default. You can swap in `claude-haiku-4-5-20251001` for faster and cheaper responses, or `claude-opus-4-20250514` for maximum analytical depth.

**Response parsing:** Claude returns `message.content[0].text` rather than `result["choices"][0]["text"]`.

**Cost estimation removed:** The original hardcoded an OpenAI price-per-token estimate. Since Anthropic pricing varies by model, this line has been removed. Refer to the [pricing page](https://docs.anthropic.com/en/docs/about-claude/pricing) and the table above for current rates.

# Limitations
The cost of using Claude to analyze the imported Windows APIs in a PE file can vary depending on the size of the IAT. While the cost of individual requests is not expensive, the total cost can quickly add up for larger files. The estimated cost provided by the script is an approximation and may vary.

Due to the design of the script, the analysis is performed one API at a time, which can make the process slow. A progress bar is displayed to show the progress of the analysis.

It is important to note that Claude is a language model, so the results may not always be accurate. Additionally, the script provides details about related MITRE ATT&CK techniques without any context, so the information should be carefully considered by a malware analyst.

# Built with

- [Anthropic Claude](https://www.anthropic.com/) (originally OpenAI GPT-3)
- [Pefile](https://github.com/erocarrera/pefile)
- [PrettyTable](https://github.com/jazzband/prettytable)

# ORIGINAL AUTHOR

Twitter: [@fr0gger_](https://twitter.com/fr0gger_)
