from binaryninja import Architecture, RegisterInfo, InstructionInfo
from .python_disasm import Disassembler

class PythonBytecodeArch(Architecture):

    name = "python_bytecode"
    max_instr_length = 2 #3.7+ only 2 bytes

    regs = {
        "sp":RegisterInfo("sp",2)
    }
    for x in range(1,99):
        reg_name = f"global_{x}"
        regs[reg_name] = RegisterInfo(reg_name,2)

    stack_pointer = "sp"

    def __init__(self):
        super().__init__()
        self.disassembler = Disassembler()

    def get_instruction_info(self,data,addr):
        # try:
            (tokens,length,result) = self.disassembler.disassemble(data,addr)
            return result
        # except:
        #     pass
        
    def get_instruction_text(self,data,addr):
        # try:
            (tokens,length,cond) = self.disassembler.disassemble(data,addr)
            return tokens,length
        # except:
        #     pass

    def get_instruction_low_level_il(self,data,addr,il):
        pass

