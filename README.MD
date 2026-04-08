# IATelligence
IATelligence is a Python script that extracts the Import Address Table (IAT) from a PE file and uses AI to provide details about each Windows API imported by the file. The script searches for related MITRE ATT&CK techniques and explains how each API could potentially be used by attackers.

It also displays the hashes of the file. IATelligence is a proof of concept for using large language models for malware analysis and quickly assessing the behavior of a malware sample based on its IAT.

> **Note:** This fork has been updated to use the **Anthropic Claude API** instead of OpenAI's GPT-3. See [Key Changes](#key-changes-from-the-original) below.

The request can take longer depending of the size of the IAT. 

[loadingcalc.png]

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
python iatelligencebedrock.py C:\Windows\System32\calc.exe
```

The script will also calculate the hashes.

```
[+] IAT Request from the file: C:\Windows\System32\calc.exe
[+] 33 functions will be requested to Claude!
[+] MD5: 5da8c98136d98dfec4716edd79c7145f
[+] SHA1: ed13af4a0a754b8daee4929134d2ff15ebe053cd
[+] SHA256: 58189cbd4e6dc0c7d8e66b6a6f75652fc9f4afc7ce0eba7d67d8c3feb0d5381f
[+] Imphash: 8eeaa9499666119d13b3f44ecd77a729
```

The result can be visualised in a table. This is a shortened version.

```
+------------------------------------------+-----------------------------+------------------------------------------+
| Libraries                                | API                         | Claude Verdict                           |
+------------------------------------------+-----------------------------+------------------------------------------+
| SHELL32.dll                              | ShellExecuteW               | ## ShellExecuteW Analysis                |
|                                          |                             |                                          |
|                                          |                             | ### Purpose                              |
|                                          |                             | `ShellExecuteW` (Unicode version) opens, |
|                                          |                             | runs, or performs an action on a         |
|                                          |                             | specified file/application. It can       |
|                                          |                             | launch executables, open documents,      |
|                                          |                             | URLs, or invoke shell verbs (e.g.,       |
|                                          |                             | `open`, `runas`, `print`).               |
|                                          |                             |                                          |
|                                          |                             | ---                                      |
|                                          |                             |                                          |
|                                          |                             | ### MITRE ATT&CK Association             |
|                                          |                             |                                          |
|                                          |                             | | Detail | Value |                       |
|                                          |                             | |--------|-------|                       |
|                                          |                             | | **Technique** | T1059 – Command and    |
|                                          |                             | Scripting Interpreter |                  |
|                                          |                             | | **Also relevant** | T1106 – Native API |
|                                          |                             | |                                        |
|                                          |                             | | **Sub-technique context** | T1218 –    |
|                                          |                             | System Binary Proxy Execution (if        |
|                                          |                             | abused) |                                |
|                                          |                             |                                          |
|                                          |                             | ---                                      |
|                                          |                             |                                          |
|                                          |                             | ### Why It's Associated                  |
|                                          |                             | - Adversaries abuse `ShellExecuteW` to   |
|                                          |                             | **spawn processes, execute payloads, or  |
|                                          |                             | elevate privileges** (`runas` verb for   |
|                                          |                             | UAC bypass → **T1548.002**)              |
|                                          |                             | - Commonly used in malware to **launch   |
|                                          |                             | child processes indirectly**, evading    |
|                                          |                             | simple process-creation monitoring       |
|                                          |                             | - Can execute files from **suspicious    |
|                                          |                             | paths or URLs**, supporting              |
|                                          |                             | delivery/execution stages                |
|                                          |                             | - Often observed in **droppers, loaders, |
|                                          |                             | and living-off-the-land** techniques     |
|                                          |                             | since it blends with legitimate activity |
|                                          |                             |                                          |
| KERNEL32.dll                             | GetCurrentThreadId          | ## GetCurrentThreadId                    |
|                                          |                             |                                          |
|                                          |                             | ### Purpose                              |
|                                          |                             | Returns the **thread ID of the calling   |
|                                          |                             | thread**. Used for thread                |
|                                          |                             | identification, logging,                 |
|                                          |                             | synchronization, and debugging within a  |
|                                          |                             | process.                                 |
|                                          |                             |                                          |
|                                          |                             | ---                                      |
|                                          |                             |                                          |
|                                          |                             | ### MITRE ATT&CK Association             |
|                                          |                             | **Weakly associated** with:              |
|                                          |                             | - **T1055 – Process Injection**: Malware |
|                                          |                             | commonly calls `GetCurrentThreadId`      |
|                                          |                             | during injection routines to             |
|                                          |                             | identify/avoid injecting into its own    |
|                                          |                             | thread, or to manage thread-level        |
|                                          |                             | operations during shellcode execution.   |
|                                          |                             | - **T1106 – Native API**: General use of |
|                                          |                             | Windows APIs to execute malicious        |
|                                          |                             | behavior.                                |
|                                          |                             |                                          |
|                                          |                             | ---                                      |
|                                          |                             |                                          |
|                                          |                             | ### Why                                  |
|                                          |                             | On its own, `GetCurrentThreadId` is      |
|                                          |                             | **benign and extremely common**. It      |
|                                          |                             | becomes relevant in malicious context    |
|                                          |                             | when observed alongside APIs like        |
|                                          |                             | `CreateRemoteThread`,                    |
|                                          |                             | `NtQueueApcThread`, or `SuspendThread`,  |
|                                          |                             | where thread awareness is needed for     |
|                                          |                             | **evasion or injection logic**.          |
|                                          |                             |                                          |
| KERNEL32.dll                             | GetSystemTimeAsFileTime     | ## GetSystemTimeAsFileTime               |
|                                          |                             |                                          |
|                                          |                             | ### Purpose                              |
|                                          |                             | Retrieves the **current system date and  |
|                                          |                             | time in UTC**, expressed in **FILETIME   |
|                                          |                             | format** (a 64-bit value representing    |
|                                          |                             | the number of 100-nanosecond intervals   |
|                                          |                             | since January 1, 1601).                  |
|                                          |                             |                                          |
|                                          |                             | ---                                      |
|                                          |                             |                                          |
|                                          |                             | ### MITRE ATT&CK Association             |
|                                          |                             | **T1124 – System Time Discovery**        |
|                                          |                             |                                          |
|                                          |                             | ---                                      |
|                                          |                             |                                          |
|                                          |                             | ### Why                                  |
|                                          |                             | Malware commonly uses this API to:       |
|                                          |                             | - **Fingerprint execution environment**  |
|                                          |                             | (detect sandboxes via time checks)       |
|                                          |                             | - **Implement time-based logic**         |
|                                          |                             | (delayed execution/detonation)           |
|                                          |                             | - **Anti-analysis**: Sandboxes often     |
|                                          |                             | accelerate time; comparing timestamps    |
|                                          |                             | can reveal this                          |
|                                          |                             | - **Timestomping preparation** or        |
|                                          |                             | logging activity timestamps              |
|                                          |                             |                                          |
|                                          |                             | It is a low-suspicion, commonly abused   |
|                                          |                             | API that blends in with legitimate       |
|                                          |                             | software behaviour.                      |
|                                          |                             |                                          |
| KERNEL32.dll                             | GetTickCount                | ## GetTickCount – Purpose & MITRE ATT&CK |
|                                          |                             |                                          |
|                                          |                             | ### Purpose                              |
|                                          |                             | Returns the number of **milliseconds     |
|                                          |                             | elapsed since system boot**. It          |
|                                          |                             | retrieves the current value of the       |
|                                          |                             | system timer (low-resolution timestamp). |
|                                          |                             |                                          |
|                                          |                             | ---                                      |
|                                          |                             |                                          |
|                                          |                             | ### MITRE ATT&CK Association             |
|                                          |                             | **T1497.003 – Virtualization/Sandbox     |
|                                          |                             | Evasion: Time Based Evasion**            |
|                                          |                             |                                          |
|                                          |                             | ### Why                                  |
|                                          |                             | Malware uses `GetTickCount` to **detect  |
|                                          |                             | sandbox/analysis environments** by:      |
|                                          |                             | - Checking if too little time has passed |
|                                          |                             | (sandboxes often fast-forward execution) |
|                                          |                             | - Measuring time **before/after** a      |
|                                          |                             | sleep call (`Sleep()`) to detect if the  |
|                                          |                             | sandbox accelerated time                 |
|                                          |                             | - If the delta is abnormally small,      |
|                                          |                             | malware concludes it's being analyzed    |
|                                          |                             | and **halts or alters malicious          |
|                                          |                             | behaviour**                              |
|                                          |                             |                                          |
|                                          |                             | This is a classic **anti-analysis**      |
|                                          |                             | technique used to evade automated        |
|                                          |                             | dynamic analysis environments.           |
|                                          |                             |                                          |
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

## Alternative: AWS Bedrock

If you have trouble with Anthropic's direct billing (for example, Australian users may encounter GST/ABN requirements), you can run the script through **AWS Bedrock** instead. Bedrock provides access to the same Claude models via your AWS account, which handles regional billing automatically.

A separate script `iatelligencebedrock.py` is included for this purpose.

### Bedrock Prerequisites

1. An [AWS account](https://aws.amazon.com)
2. Claude Sonnet 4.6 enabled under **Bedrock → Model access** in the AWS Console
3. An AWS Access Key ID and Secret Access Key from **AWS Console → Account → Security credentials → Access keys**

### Bedrock Setup Notes

- **Model ID:** Claude Sonnet 4.6 on Bedrock uses `anthropic.claude-sonnet-4-6`

- **Inference type:** The model uses cross-region inference, so you must prefix the model ID with your region prefix (`us.` or `ap.`) when invoking it:

  ```
  us.anthropic.claude-sonnet-4-6
  ```

- **Region:** Keep `region_name="us-east-1"` in the script regardless of where your AWS account is based — cross-region inference routes through US East

- **Model access:** If the Bedrock console shows an "Open in playground" button rather than a "Request access" button, access is already granted

### Bedrock Requirements

Replace `requirements.txt` with:

```
boto3
pefile
tqdm
prettytable
```

### Bedrock Usage

Add your AWS credentials to the script:

```python
bedrock = boto3.client(
    service_name="bedrock-runtime",
    region_name="us-east-1",
    aws_access_key_id="YOUR_ACCESS_KEY_ID",
    aws_secret_access_key="YOUR_SECRET_ACCESS_KEY"
)
```

Then run identically to the standard version:

```
python iatelligencebedrock.py C:\Windows\System32\calc.exe
```

### Bedrock Cost

Pricing through Bedrock is the same per-token rate as the direct Anthropic API. A typical test run against `calc.exe` (~33 functions) costs approximately **$0.05 USD**. A larger file like `notepad.exe` (~259 functions) costs roughly **$0.82 USD**.

# Key Changes from the Original

This version replaces the OpenAI GPT-3 backend with the Anthropic Claude API. Here is a summary of what changed:

**API client:** Replaced the `openai` package with `anthropic`. Install with `pip install anthropic`.

**Client initialisation:** The Anthropic SDK uses `anthropic.Anthropic(api_key=...)` rather than setting a module-level `openai.api_key`.

**API call structure:** Switched from `openai.Completion.create()` to `client.messages.create()`. The Anthropic API uses a `messages` list with role/content pairs rather than a raw `prompt` string.

**Model:** Uses `claude-sonnet-4-20250514` by default. You can swap in `claude-haiku-4-5-20251001` for faster and cheaper responses, or `claude-opus-4-20250514` for maximum analytical depth.

**Response parsing:** Claude returns `message.content[0].text` rather than `result["choices"][0]["text"]`.

**Cost estimation removed:** The original hardcoded an OpenAI price-per-token estimate. Since Anthropic pricing varies by model, this line has been removed. Refer to the [pricing page](https://docs.anthropic.com/en/docs/about-claude/pricing) and the table above for current rates.

# Limitations
The cost of using Claude to analyse the imported Windows APIs in a PE file can vary depending on the size of the IAT. While the cost of individual requests is not expensive, the total cost can quickly add up for larger files.

Due to the design of the script, the analysis is performed one API at a time, which can make the process slow. A progress bar is displayed to show the progress of the analysis.

It is important to note that Claude is a language model, so the results may not always be accurate. Additionally, the script provides details about related MITRE ATT&CK techniques without any context, so the information should be carefully considered by a malware analyst.

# Built with

- [Anthropic Claude](https://www.anthropic.com/) (originally OpenAI GPT-3)
- [Pefile](https://github.com/erocarrera/pefile)
- [PrettyTable](https://github.com/jazzband/prettytable)

# ORIGINAL AUTHOR

Twitter: [@fr0gger_](https://twitter.com/fr0gger_)
