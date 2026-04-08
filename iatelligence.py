#!/usr/bin/env python

"""
IATelligence: A Python script that extracts the IAT from a PE file 
and requests Claude for more details.

Original Author: Thomas Roccia | @fr0gger_
Updated to use Anthropic Claude API
"""

import sys
import hashlib
import pefile
import anthropic
import tqdm

from prettytable import PrettyTable

# Initialize the Anthropic client
client = anthropic.Anthropic(api_key="YOUR_API_KEY_HERE")

def calculate_hashes(file):
    """
    Calculate the MD5, SHA1, and SHA256 hashes of a file.
    
    :param file: The file to be hashed.
    :return: A dictionary containing the MD5, SHA1, and SHA256 hashes of the file.
    """
    hashes = {}
    
    with open(file, "rb") as pef:
        md5 = hashlib.md5()
        md5.update(pef.read())
        hashes["md5"] = md5.hexdigest()
        
        pef.seek(0) 
        sha1 = hashlib.sha1()
        sha1.update(pef.read())
        hashes["sha1"] = sha1.hexdigest()
        
        pef.seek(0)
        sha256 = hashlib.sha256()
        sha256.update(pef.read())
        hashes["sha256"] = sha256.hexdigest()
        
    return hashes


def extract_iat(pe):
    """
    Extract the Import Address Table (IAT) entries from a PE file.

    :param pe: The PE file to extract the IAT entries from.
    :return: A dictionary of IAT entries, where the keys are 
    the imported function names and the values are the DLL names.
    """
    iat = {}

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            dll_name = entry.dll
            imp_name = imp.name
            iat[imp_name] = dll_name
    
    return iat


def request_claude(iat):
    """
    Use the Anthropic Claude API to analyze the imported function names 
    and DLL names in a dictionary of IAT entries.

    :param iat: A dictionary of IAT entries, where the keys are 
    the imported function names and the values are the DLL names.
    :return: A list of lists containing the DLL names, imported 
    function names, and Claude API responses for each IAT entry.
    """
    claudetable = []

    with tqdm.tqdm(total=len(iat)) as pbar:
        for imp_name, dll_name in iat.items():
            prompt = (
                f"What is the purpose of this Windows API, is there a MITRE ATT&CK "
                f"technique associated and why: '{dll_name.decode('utf-8')}: {imp_name.decode('utf-8')}'? "
                f"Keep your answer concise."
            )

            message = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1024,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )

            response_text = message.content[0].text.strip() + "\n"
            claudetable.append([
                dll_name.decode('utf-8'),
                imp_name.decode('utf-8'),
                response_text
            ])

            pbar.update(1)

    return claudetable


def main():
    """
    Analyze the Import Address Table (IAT) entries in a 
    PE file using the Anthropic Claude API.
    The PE file to analyze must be provided as an argument 
    when running the script.
    """
    if len(sys.argv) < 2:
        print("[!] Usage: python iatelligence.py <executable_file>")
        return
   
    print("[+] IAT Request from the file: " + sys.argv[1])

    try:
        pe = pefile.PE(sys.argv[1])
        hashes = calculate_hashes(sys.argv[1])
        iat = extract_iat(pe)
        print(f"[+] {len(iat)} functions will be requested to Claude!")
        print(f"[+] MD5: {hashes['md5']}")
        print(f"[+] SHA1: {hashes['sha1']}")
        print(f"[+] SHA256: {hashes['sha256']}")
        print(f"[+] Imphash: {pe.get_imphash()}")

    except OSError as error:
        print(error)
        sys.exit()
    except pefile.PEFormatError as error:
        print(f"[-] PEFormatError: %s {error.value}")
        print("[!] The file is not a valid PE")
        sys.exit()

    claudetable = request_claude(iat)

    tabres = PrettyTable(["Libraries", "API", "Claude Verdict"], align='l', max_width=40)

    for (dll_name, imp_name, claudeverdict) in claudetable:
        tabres.add_row([dll_name, imp_name, claudeverdict])

    print(tabres)


if __name__ == "__main__":
    main()
