import idc
import idaapi
import sys, os
from idaapi import Form
path = os.path.dirname(os.path.abspath(__file__)) + "\\ElfDumper_WPeace\\"
sys.path.append(path)
import DumpELF_x86
import DumpELF_x64


class myplugin_elfdumper(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "ElfDumper Plugin for IDA"
    help = "Find more information at https://github.com/wpeace-hch"
    wanted_name = "ElfDumper"
    wanted_hotkey = "Ctrl-Alt-D"
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
    
    def init(self):
        print("\nElfDumper By WPeace.")
        try:
            WPe_Patcher_elfdumper.register(self, "ElfDumper    (Ctrl-Alt-D)")
        except:
            pass
        if idaapi.IDA_SDK_VERSION >= 740:
            idaapi.attach_action_to_menu("Edit/WPeace_Plugins/ElfDumper    (Ctrl-Alt-D)", WPe_Patcher_elfdumper.get_name(), idaapi.SETMENU_APP)
        else:
            print("Your IDA version needs to be greater than 7.4! :(@WPeace")
        return idaapi.PLUGIN_OK
    
    def run(self, arg):
        elfdumper_main()
    
    def term(self):
        print("ElfDumper v1.0 works fine! :)@WPeace\n")


class Menu_Context(idaapi.action_handler_t):
    @classmethod
    def get_name(self):
        return self.__name__
        
    @classmethod
    def get_label(self):
        return self.label
        
    @classmethod
    def register(self, plugin, label):
        self.plugin = plugin
        self.label = label
        instance = self()
        return idaapi.register_action(idaapi.action_desc_t(
            self.get_name(),
            instance.get_label(),
            instance
        ))
        
    @classmethod
    def unregister(self):
        idaapi.unregister_action(self.get_name())
        
    @classmethod
    def activate(self, ctx):
        return 1
        
    @classmethod
    def update(self, ctx):
        try:
            return idaapi.AST_ENABLE_FOR_WIDGET
        except Exception as e:
            return idaapi.AST_ENABLE_ALWAYS


class WPe_Patcher_elfdumper(Menu_Context):
    def activate(self, ctx):
        elfdumper_main()
        return 1


class SuccessForm(Form):
    def __init__(self):
        self.invert = False
        Form.__init__(self, r"""STARTITEM 0
Success

{FormChangeCb}
Dump finished
OutputFile = dumpELFfile.dex
      
""", {
            'FormChangeCb': Form.FormChangeCb(self.OnFormChange),
        })
    
    def OnFormChange(self, fid):
        return 1


class ErrorForm(Form):
    def __init__(self):
        self.invert = False
        Form.__init__(self, r"""STARTITEM 0
Error

{FormChangeCb}
请输入正确的Dump ELF的地址！
      
""", {
            'FormChangeCb': Form.FormChangeCb(self.OnFormChange),
        })
    
    def OnFormChange(self, fid):
        return 1


class MyForm(Form):
    def __init__(self):
        self.invert = False
        Form.__init__(self, r"""STARTITEM {id:bitVers}
ElfDumper

{FormChangeCb}
输入Dump ELF的地址：
<##Hex Addr:{InputStr}>
选择Dump ELF的位数：
<32位:{c32}>
<64位:{c64}>{bitVers}>
<##Start to Dump:{Button0}>
""", {
            'InputStr': Form.StringInput(swidth=10, value="0x"),
            'Button0': Form.ButtonInput(self.OnButton0),
            'bitVers': Form.RadGroupControl(("c32", "c64")),
            'FormChangeCb': Form.FormChangeCb(self.OnFormChange),
        })

    def OnButton0(self, code=0):
        errorFlag = 0
        bit = self.GetControlValue(self.bitVers)
        if bit == 0:
            if self.GetControlValue(self.InputStr) != "0x":
                hexAddr = int(self.GetControlValue(self.InputStr), 16)
                elf_magic = idc.get_wide_dword(hexAddr)
                if elf_magic == 0x464c457f or elf_magic == 0x7f454c46:
                    DumpELF_x86.main(hexAddr)
                    f_success = SuccessForm()
                    f_success.Compile()
                    f_success.Execute()
                    f_success.Free()
                else:
                    errorFlag = 1
            else:
                errorFlag = 1
            if errorFlag == 1:
                f_error = ErrorForm()
                f_error.Compile()
                f_error.Execute()
                f_error.Free()  
        elif bit == 1:
            if self.GetControlValue(self.InputStr) != "0x":
                hexAddr = int(self.GetControlValue(self.InputStr), 16)
                elf_magic = idc.get_wide_dword(hexAddr)
                if elf_magic == 0x464c457f or elf_magic == 0x7f454c46:
                    DumpELF_x64.main(hexAddr)
                    f_success = SuccessForm()
                    f_success.Compile()
                    f_success.Execute()
                    f_success.Free()
                else:
                    errorFlag = 1
            else:
                errorFlag = 1
            if errorFlag == 1:
                f_error = ErrorForm()
                f_error.Compile()
                f_error.Execute()
                f_error.Free()  
        
    def OnFormChange(self, fid):
        return 1


def elfdumper_main():
    global f
    f = MyForm()
    f.Compile()
    ok = f.Execute()
    f.Free()


def PLUGIN_ENTRY():
    return myplugin_elfdumper()