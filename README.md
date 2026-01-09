# ClipboardStealBOF
An alternative to the builtin clipboard feature in Cobalt Strike that adds the capability to enable/disable and dump the clipboard history.

Credits to @netero1010's ClipboardHistoryThief (https://github.com/netero1010/ClipboardHistoryThief/tree/main) for the original PoC.

## To start
1. Git clone the repo
2. Run `make`

## Usage
1. Import the clipboardsteal.cna script into Cobalt Strike
2. Use the command `clipboardsteal [cmd]`

```
clipboardsteal [command]
Command         Description      
dump            Dumps the content of the clipboard history to console
enable          Enables the clipboard history feature.
disable         Disables the clipboard history feature.
check           Checks if clipboard history feature is enabled.
help            Shows this help menu.
```

Credits:
- https://github.com/netero1010/ClipboardHistoryThief/tree/main
- https://github.com/MEhrn00/boflink
- https://github.com/trustedsec/CS-Situational-Awareness-BOF/tree/master/src/base_template
- https://github.com/CodeXTF2/bof_template

