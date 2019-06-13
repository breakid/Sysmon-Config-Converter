# Sysmon-Config-Converter
This simple Python script is designed to read an exported Sysmon config (using "Sysmon.exe -c") and convert it back into a valid XML file that can be used to re-install Sysmon.

### Limitations
Some information from the original config is not included in the exported file and is therefore impossible to reconstruct.
Examples include:
- Comments
- Rule names

#### IMPORTANT
As of 2019-06-12, there is a bug with Sysmon where it will only dump the first onmatch collection within a rulegroup (i.e., per event type). For instance, the SwiftOnSecurity config has both 'onmatch="include"' and 'onmatch="exclude"' groups for the FileCreateTime event, but the dumped Sysmon config only lists the 'onmatch: include' rules.

### Disclaimer
While it is generally frowned upon (including by me) to hand code XML rather than using a library, this application was simple enough I didn't want to add the extra hassle (or dependency) of an additional library.