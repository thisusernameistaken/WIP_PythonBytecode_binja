from binaryninja import InstructionTextToken, InstructionTextTokenType, InstructionInfo, BranchType
from binaryninjaui import UIContext
from dis import dis
from io import StringIO


class Disassembler:

    def __init__(self):
        self.bv = None
        self.functions = {
            "JUMP_FORWARD" : self.jump_forward,
            "LOAD_GLOBAL": self.load_global,
            "LOAD_CONST": self.load_const,
            "LOAD_NAME": self.load_name,
            "STORE_CONST": self.store_const,
            "STORE_NAME": self.store_name,
            "IMPORT_NAME": self.import_name,
            "IMPORT_FROM": self.import_from,
            "RETURN_VALUE": self.return_value,
            "JUMP_IF_FALSE_OR_POP":self.jump_ifop,
            "POP_JUMP_IF_FALSE":self.jump_pif,
            "EXTENDED_ARG":self.extended_arg
        }

    def update_bv(self):
        if self.bv == None:
            ac = UIContext.activeContext()
            cv = ac.getCurrentViewFrame()
            if cv != None:
                self.bv = cv.getCurrentBinaryView()
                if self.bv != None:
                    return True
                return False
            return False
        return True

    def disassemble(self,data,addr):
        # stupid hack to get arch to talk to bv
        while not self.update_bv():
            pass

        disas = ""
        disas = StringIO()
        dis(data,file=disas)
        disas.seek(0)
        disas_string = disas.read()
        if disas_string != "":
            data_split = [x for x in disas_string.strip().split(" ") if x !=''][1:]
            if len(data_split) > 1:
                instr = data_split[0].strip()
                arg = data_split[1]
                if instr in self.functions.keys():
                    return self.functions[instr](arg,addr)
                else:
                    return self.default_function(2,instr,arg,addr)
            else:
                instr = data_split[0]
                if instr in self.functions.keys():
                    return self.functions[instr](addr)
                else:
                    return self.default_function_one(instr,addr)

        result = InstructionInfo()
        result.length = len(data)
        return None,None,result
        
    def default_function(self,length,instr,arg,addr):
        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,instr)]
        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken," "))
        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken,arg))
        result = InstructionInfo()
        result.length = length
        return tokens,length,result

    def default_function_one(self,instr,addr):
        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,instr)]
        result = InstructionInfo()
        result.length = 2
        return tokens,2,result

    def jump_forward(self,arg,addr):
        instr = "JUMP FORWARD"
        jump = addr + int(arg)
        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,instr)]
        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken," "))
        tokens.append(InstructionTextToken(InstructionTextTokenType.CodeRelativeAddressToken,hex(jump),jump,width=len(hex(jump))))
        result = InstructionInfo()
        result.length = 2
        result.add_branch(BranchType.UnconditionalBranch,jump)
        return tokens,2,result

    def load_global(self,arg,addr):
        instr = "LOAD GLOBAL"
        global_reg = "global_"+arg
        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,instr)]
        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken," "))
        tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,global_reg))
        result = InstructionInfo()
        result.length = 2
        return tokens,2,result

    def load_const(self,arg,addr):
        instr = "LOAD CONST"
        const = int(arg)
        const_value = self.bv.session_data['co_consts'][const][0]
        if type(const_value) == int:
            num = const_value
            const_value = hex(const_value)
        elif type(const_value) == bytes:
            const_value = repr(const_value)
            num = self.bv.session_data['co_consts'][const][1]
        else:
            const_value = str(const_value)
            num = self.bv.session_data['co_consts'][const][1]
        addr = self.bv.session_data['co_consts'][const][1]
        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,instr)]
        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken," "))
        tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken,const_value,num))
        tokens.append(InstructionTextToken(InstructionTextTokenType.DataSymbolToken," {"+hex(addr)+"}",addr,addr))
        result = InstructionInfo()
        result.length = 2
        return tokens,2,result

    def load_name(self,arg,addr):
        instr = "LOAD NAME"
        const = int(arg)
        const_value = self.bv.session_data['co_names'][const][0]
        if type(const_value) == int:
            const_value = hex(const_value)
        elif type(const_value) == bytes:
            const_value == const_value.decode()
        else:
            const_value = str(const_value)
        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,instr)]
        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken," "))
        tokens.append(InstructionTextToken(InstructionTextTokenType.CharacterConstantToken,const_value,const))
        result = InstructionInfo()
        result.length = 2
        return tokens,2,result

    def store_const(self,arg,addr):
        instr = "STORE CONST"
        const = int(arg)
        const_value = self.bv.session_data['co_consts'][const][0]
        if type(const_value) == int:
            const_value = hex(const_value)
        elif type(const_value) == bytes:
            const_value == const_value.decode()
        else:
            const_value = str(const_value)
        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,instr)]
        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken," "))
        tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken,const_value,const))
        result = InstructionInfo()
        result.length = 2
        return tokens,2,result

    def store_name(self,arg,addr):
        instr = "STORE NAME"
        const = int(arg)
        const_value = self.bv.session_data['co_names'][const][0]
        if type(const_value) == int:
            const_value = hex(const_value)
        elif type(const_value) == bytes:
            const_value == const_value.decode()
        else:
            const_value = str(const_value)
        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,instr)]
        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken," "))
        tokens.append(InstructionTextToken(InstructionTextTokenType.CharacterConstantToken,const_value,const))
        result = InstructionInfo()
        result.length = 2
        return tokens,2,result

    def import_name(self,arg,addr):
        instr = "IMPORT NAME"
        const = int(arg)
        const_value = self.bv.session_data['co_names'][const][0]
        if type(const_value) == int:
            const_value = hex(const_value)
        elif type(const_value) == bytes:
            const_value == const_value.decode()
        else:
            const_value = str(const_value)
        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,instr)]
        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken," "))
        tokens.append(InstructionTextToken(InstructionTextTokenType.CharacterConstantToken,const_value,const))
        result = InstructionInfo()
        result.length = 2
        return tokens,2,result

    def import_from(self,arg,addr):
        instr = "IMPORT FROM"
        const = int(arg)
        const_value = self.bv.session_data['co_names'][const][0]
        if type(const_value) == int:
            const_value = hex(const_value)
        elif type(const_value) == bytes:
            const_value == const_value.decode()
        else:
            const_value = str(const_value)
        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,instr)]
        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken," "))
        tokens.append(InstructionTextToken(InstructionTextTokenType.CharacterConstantToken,const_value,const))
        result = InstructionInfo()
        result.length = 2
        return tokens,2,result

    def return_value(self,addr):
        instr = "RETURN VALUE"
        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,instr)]
        result = InstructionInfo()
        result.length = 2
        result.add_branch(BranchType.FunctionReturn)
        return tokens,2,result

    def jump_ifop(self,arg,addr):
        instr = "JUMP IF FALSE OR POP"
        # check if extended_arg is before it
        extended = self.check_extended(addr)
        jump = int(arg) + (extended<<8)+self.bv.entry_function.start
        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,instr)]
        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken," "))
        tokens.append(InstructionTextToken(InstructionTextTokenType.CodeRelativeAddressToken,hex(jump),jump,width=len(hex(jump))))
        result = InstructionInfo()
        result.length = 2
        result.add_branch(BranchType.TrueBranch,addr+2)
        result.add_branch(BranchType.FalseBranch,jump)
        return tokens,2,result

    def jump_pif(self,arg,addr):
        instr = "POP JUMP IF FALSE"
        extended = self.check_extended(addr)
        jump = int(arg) + (extended<<8)+self.bv.entry_function.start
        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,instr)]
        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken," "))
        tokens.append(InstructionTextToken(InstructionTextTokenType.CodeRelativeAddressToken,hex(jump),jump,width=len(hex(jump))))
        result = InstructionInfo()
        result.length = 2
        result.add_branch(BranchType.TrueBranch,addr+2)
        result.add_branch(BranchType.FalseBranch,jump)
        return tokens,2,result

    def extended_arg(self,arg,addr):
        instr = "EXTENDED ARG"
        arg = int(arg)
        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,instr)]
        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken," "))
        tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken,hex(arg),arg))
        result = InstructionInfo()
        result.length = 2
        return tokens,2,result

    def check_extended(self,addr):
        prev_instr_bytes = self.bv.read(addr-2,2)
        prev_instr = self.disassemble(prev_instr_bytes,addr-2)
        if prev_instr[0][0].text == "EXTENDED ARG":
            return prev_instr[0][-1].value
        return 0