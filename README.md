# Signer - Minecraft Bedrock Edition Signature Tool

## Introduction

1. **What is Signer?**
   Signer is a specialized application developed to facilitate the effortless transfer and testing of bulk signatures specifically designed for Minecraft Bedrock Edition.

2. **Should I use it?**
   There's no reason why you shouldn't use Signer. It simplifies the process of managing signature dumps, especially for projects like the [Amethyst Project](https://github.com/FrederoxDev/Amethyst) and creating mods for it.

3. **Could this be used for making cheats?**
   While the output from Signer could be repurposed for cheats, its primary functions are geared towards aiding Minecraft Bedrock modding rather than cheating purposes.

4. **Contributing?**
   Contributions are welcome! Please ensure proper labeling of commits and provide comprehensive explanations of your changes for smoother integration.

## Usage

To effectively utilize Signer, follow these steps:

1. **Prepare Signature Dump:**
   Ensure your symbol dump is formatted as `"Symbol Name": "AA BB CC DD ?"`. Signer's signature scanner relies on byte-by-byte formatting.

2. **Required Components:**
   - Have a copy of Minecraft Bedrock installed.
   - Know the location of the game's executable file.

3. **Time Allocation:**
   Be prepared for a time-intensive process; Signer can take multiple hours to run.

### Arguments

| Argument | Use |
| -------- | --- |
| --MP     | Specifies the location of MCPE (Minecraft Pocket Edition) |
| --PSP    | Indicates the location of the Signature dump (essential for current functionality) |
| --NBTC   | Specifies the number of threads to use (optional but recommended for faster processing) |

Example command line usage:
```bash
Signer.exe --MP C:\Users\name\AppData\Roaming\.minecraft_bedrock\versions\58c5f0cd-09d7-4e99-a6b6-c3829fd62ac9\Minecraft.Windows.exe --PSP D:\bds_sigs.json --NBTC 10
```
**Note:** Running Signer may take considerable time (e.g., around 2 hours and 51 minutes on a standard machine).

## Post-Processing

Upon completion, a JSON file named `workingSignatures` will be generated. To import these into IDA, use the provided Python script.
```py
import  ida_kernwin
import  json
import  idaapi
import  ida_funcs
import  ida_name

signatures  = {}

signatures_file  =  ida_kernwin.ask_file(False, "signatures.json", "JSON (*.json)")

with  open(signatures_file, "r")  as  file_handle:
	jsonFile  =  json.loads(file_handle.read())
	# Read the workingSignatures from the json file
	signatures  =  jsonFile["workingSignatures"]
	
base_address  =  0x140000000

count  =  0

for  mangled_name  in  signatures:

	if  mangled_name  ==  "?write_double_translated_ansi_nolock@@YA?AUwrite_result@?A0x17268360@@HQEBDI@Z":
	continue

	unbased_ea  =  signatures[mangled_name][1]

	ea  =  unbased_ea  +  base_address
	func: ida_funcs.func_t =  ida_funcs.get_func(ea)
	if  func  is  None:
		print(f"Failed to find function for {mangled_name}")
		continue
	else:
		count  +=  1
		print(f"Found function for {mangled_name}")
	existing_name  =  ida_name.get_name(func.start_ea)

	if  existing_name  ==  mangled_name:
		continue
		
	ida_name.set_name(func.start_ea, mangled_name)

print(f"Renamed {count} functions")
```
The script above will import all fully valid signatures with only 1 match.  
This script also exports all signatures that have multiple hits. If you wish to use these you must manually locate the corrected function signature
