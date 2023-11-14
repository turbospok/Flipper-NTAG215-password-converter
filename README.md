# Flipper NTAG215 password converter
This script is able to calculate passwords for NTAG215 cards and store them into Flipper NFC file format

## How to use
### Directory processing
`py  .\ntag215converter.py -i "<path_to_you_folders_with_ntags215\>" -o "<output_folder>"` : searches for .nfc files beginning from <path_to_you_folders_with_ntags215> then calculates password and saves them to a folder <output_folder>

`py  .\ntag215converter.py -i "<path_to_you_folders_with_ntags215\>" -o "<output_folder>" -t` : searches for .nfc files beginning from <path_to_you_folders_with_ntags215> then calculates password and saves them to a folder <output_folder> with saving all folder structure

### File processing
`py  .\ntag215converter.py -i "<path_to_you_folders_with_ntags215\your_ntag.nfc>" -o "<output_folder\>"` : searches for <your_ntag.nfc> file on path <path_to_you_folders_with_ntags215> then calculates password and saves it to a folder <output_folder>.
**Attention! <output_folder> must exist!**

`py  .\ntag215converter.py -i "<path_to_you_folders_with_ntags215\your_ntag.nfc>"` : searches for <your_ntag.nfc> file on path <path_to_you_folders_with_ntags215> then calculates password and re-saves it.
**Attention! Be careful, better backup your card first!**
