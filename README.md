# Signer
## Introduction
1. What is signer?
> Signer is an application developed to allow the easy transfer/testing of bulk signatures for minecraft bedrock edition
2. Should I use it?
> There isn't any reason you shouldn't use it.
3. Could this be used for making cheats?
> While technically the output from this application could be used to make cheats.
> A lot of the functions it outputs are not too useful in making cheats for minecraft bedrock
> This was mostly designed to help with the [Amethyst Project](https://github.com/FrederoxDev/Amethyst)   and making mods for said project
4. Contributing?
> Id be happy to let you contribute just. 
 >As long as you label your commit properly and give a good explanation of how it works i see no reason i wouldn't accept it.
 ## Using
 To use Signer you need a precomputed signature dump for your client of choice this can be from MC China, Bedrock BDS, event custom signatures that you just want trimmed or any other places you have a signature dump from ;).
 1. Formatting: For Signer to understand your symbol dump it needs to be formatted as so `"Symbol Name": "AA BB CC DD ?"` Signers signature scanner is sensitive so it needs the formatting of a byte a space then a byte and so on
 2. You need a copy of minecraft bedrock and the location of the exe for the game
 3. You need a lot of time this process can take multiple hours to run
 
|Arguments| Use |
|--|--|
| --MP | This tells Signer where the location of MCPE is. This is required |
| --PSP| This tells Signer the location of the Signature dump. This technically isn't required but there isn't handling for any other cases curranty
| --NBTC| This tells Signer how many threads to use. This isnt needed but Signer defaults to 1 thread which would take around 10 ish hours. I allocate 10 threads on a 12 threaded CPU    
  
  
Example of a valid argument list : `--MP C:\Users\name\AppData\Roaming\.minecraft_bedrock\versions\58c5f0cd-09d7-4e99-a6b6-c3829fd62ac9\Minecraft.Windows.exe --PSP D:\bds_sigs.json --NBTC 10`
Now run signer and wait. Signer took around 2 hours and 51 minutes on my machine so be ready to wait a long time.  
## After
So now you should have a json file called `workingSignatures`. This contains a list of signatures and there offset from the base of minecraft.  
To import these into something like IDA a script can be used 
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
