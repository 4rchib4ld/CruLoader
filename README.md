# CruLoader
 Scripts for working with the CruLoader Sample

The complete write up is available here : https://4rchib4ld.github.io/malwareanalysis/CruLoader/

## Config Extractor

Pretty self explanatory, run it against your sample and it should give you the config you want so much.
I made it bruteforce the whole section because there is no possible way to predict the location of the URL (like if Cutwail is used...), so I made it that way. Takes a little bit more time to execute, but still less than a sandbox or a debugger !

## Ida Script

This script is used to deobfuscate the API calls made by the sample.
**Change the function name as you wish for this script to run**