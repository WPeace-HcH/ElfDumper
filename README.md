# ElfDumper
**A plugin for IDA** that can dump the ELF file easily.
## Update History
|Version|Date|Comment|
|----|----|----|
|1.0|2023-01-04|Initial version.|
|2.0|2023-04-03|Version 2.0 automatically recognizes 32-bit or 64-bit from the ELF-Header.|
## Background
When I use the IDA to dump a ELF file, I don't have any plugin that can dump easily, so I write this plugin named ElfDumper. Hope to help security engineers analyze the ELF.
## Install
- Just copy the file `ElfDumper.py` and the folder `ElfDumper_WPeace` to IDA Plugins folder, then restart IDA Pro to use ElfDumper.  
- `NOTE`: You need python3 and IDA >= 7.4.
## Usage
You just need to give it a hex address and then it will dump the ELF file easily.  
![image](https://github.com/WPeace-HcH/ElfDumper/blob/main/IMG/menu.png) 
![image](https://github.com/WPeace-HcH/ElfDumper/blob/main/IMG/interface.png)  
- **Edit $\Rightarrow$ WPeace_Plugins $\Rightarrow$ ElfDumper**  
`(Or hotkey = "Ctrl-Alt-D")`
## Example
***version 1.0：***
![image](https://github.com/WPeace-HcH/ElfDumper/blob/main/IMG/example_v1.gif)

***version 2.0：***
![image](https://github.com/WPeace-HcH/ElfDumper/blob/main/IMG/example_v2.gif)
## Contact
You can leave a message for any questions.
