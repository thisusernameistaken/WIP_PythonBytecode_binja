from binaryninja import Architecture, BinaryView,SegmentFlag, \
    Symbol,SymbolType,SectionSemantics,StructureBuilder, Type, \
    DataRenderer, InstructionTextToken, InstructionTextTokenType,DisassemblyTextLine
from enum import Enum
import marshal

class TypeCode(Enum):
    INT = 0xe9
    SMALL_TUPLE = 0x29
    CODE = 0xe3
    INT2 = 0x69
    STRING = 0xf3
    SHORT_ASCII = 0x7a
    SHORT_ASCII2 = 0xfa
    NULL = 0x4e
    SHORT_ASCII_INTERNED = 0x5a
    REF = 0x72
    SHORT_ASCII_INTERNED2 = 0xda


class PythonView(BinaryView):

    name = "python bytecode"
    long_name = "python bytecode loader"

    def __init__(self,data):
        BinaryView.__init__(self,file_metadata=data.file,parent_view=data)
        self.data = data
        self.br = data.reader()
        self.m_data = marshal.loads(self.data.read(0x10,len(self.data)))
        # self.session_data['co_names'] = self.m_data.co_names
        # self.session_data['co_consts'] = self.m_data.co_consts
        self.session_data['co_names'] = []
        self.session_data['co_consts'] = []
    @classmethod
    def is_valid_for_data(cls,data):
        magic_number = data.read(0,4)
        if magic_number == b"U\r\r\n":
            return True
        return False

    def init(self):
        self.platform = Architecture['python_bytecode'].standalone_platform
        self.arch = Architecture['python_bytecode']
        
        self.entry_addr = 0x2e
        self.add_auto_segment(0,0x10,0,0x10,SegmentFlag.SegmentReadable)
        self.add_auto_section("header",0,0x10,SectionSemantics.ReadOnlyDataSectionSemantics)

        self.add_auto_segment(0x10,len(self.data),0x10,len(self.data),SegmentFlag.SegmentContainsCode)
        self.add_auto_section("code",0x10,len(self.data),SectionSemantics.ReadOnlyCodeSectionSemantics)
        self._load_header()
        self.add_entry_point(self.entry_addr)
        # self.add_function(self.entry_addr)
        # self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol,self.entry_addr,"start"))

        return True

    def _load_header(self):
        with StructureBuilder.builder(self,"header_t") as header_t:
            header_t.packed = True
            header_t.append(Type.array(Type.char(),4),"magic")
            header_t.append(Type.array(Type.char(),4),"timestamp")
            header_t.append(Type.array(Type.char(),8),"idk")
            header_t_struct = Type.structure_type(header_t)
            self.define_data_var(0,header_t_struct)
            self.br.read(16)
        with StructureBuilder.builder(self,"func_info") as func_info:
            func_info.packed = True
            func_info.append(Type.int(1),"type")
            func_info.append(Type.int(4),"co_argcount")
            func_info.append(Type.int(4),"co_kwonlyargcount")
            func_info.append(Type.int(4),"co_nlocals")
            func_info.append(Type.int(4),"co_stacksize")
            func_info.append(Type.int(4),"idk2")
            func_info.append(Type.int(4),"co_flags")
            func_info.append(Type.int(1),"indetifier")
            func_info.append(Type.int(4),"length")
        func_info_struct = Type.structure_type(func_info)
        with StructureBuilder.builder(self,"int_info") as int_info:
            int_info.packed = True
            int_info.append(Type.int(1),"type")
            int_info.append(Type.int(4),"int")
        int_info_struct = Type.structure_type(int_info)
        
        while self.br.offset < len(self.data):
        # for _ in range(1):
            _type = self.br.read8()
            if _type == TypeCode.CODE.value:
                self.define_data_var(self.br.offset-1,func_info_struct)
                self.br.seek(self.br.offset+25)
                length = self.br.read32()
                
                self.add_function(self.br.offset)
                self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol,self.br.offset,f"sub_{hex(self.br.offset)[2:]}"))

                self.br.read(length+2)
            elif _type == TypeCode.SMALL_TUPLE.value:
                #small tuple
                self.session_data['co_consts'].append(('?',self.br.offset))
                self.br.read(1)
                pass
            elif _type == TypeCode.INT.value or _type == TypeCode.INT2.value:
                # int
                self.define_data_var(self.br.offset-1,"int_info")
                val = self.br.read32()
                self.session_data['co_consts'].append((val,self.br.offset-4))
            # elif :
            #     # int
            #     self.define_data_var(self.br.offset-1,"int_info")
            #     self.br.read(4)
            elif _type == TypeCode.REF.value:
                # int
                self.define_data_var(self.br.offset-1,int_info_struct)
                self.br.read(4)
            elif _type == TypeCode.SHORT_ASCII.value or  _type == TypeCode.SHORT_ASCII2.value:
                # strings basically
                length = self.br.read8()
                with StructureBuilder.builder(self,f"str_info_{hex(self.br.offset)[2:]}") as str_info:
                    str_info.packed = True
                    str_info.append(Type.int(1),"type")
                    str_info.append(Type.int(1),"length")
                    str_info.append(Type.array(Type.char(),length),"string")
                str_info_struct = Type.structure_type(str_info)
                self.define_data_var(self.br.offset-2,f"str_info_{hex(self.br.offset)[2:]}")
                _string = self.br.read(length)
                self.session_data['co_consts'].append((_string,self.br.offset-length))
            elif _type == TypeCode.STRING.value:
                # strings basically
                length = self.br.read32()
                with StructureBuilder.builder(self,f"string_info_{hex(self.br.offset)[2:]}") as str_info:
                    str_info.packed = True
                    str_info.append(Type.int(1),"type")
                    str_info.append(Type.int(4),"length")
                    str_info.append(Type.array(Type.char(),length),"string")
                str_info_struct = Type.structure_type(str_info)
                self.define_data_var(self.br.offset-5,f"string_info_{hex(self.br.offset)[2:]}")
                _string = self.br.read(length)
                self.session_data['co_consts'].append((_string,self.br.offset-length))
            elif _type == TypeCode.SHORT_ASCII_INTERNED.value or _type == TypeCode.SHORT_ASCII_INTERNED2.value :
                # strings basically
                length = self.br.read8()
                with StructureBuilder.builder(self,f"sa_info_{hex(self.br.offset)[2:]}") as str_info:
                    str_info.packed = True
                    str_info.append(Type.int(1),"type")
                    str_info.append(Type.int(1),"length")
                    str_info.append(Type.array(Type.char(),length),"string")
                str_info_struct = Type.structure_type(str_info)
                self.define_data_var(self.br.offset-2,f"sa_info_{hex(self.br.offset)[2:]}")
                name = self.br.read(length)
                self.session_data['co_names'].append((name,self.br.offset-length))
            elif _type == TypeCode.NULL.value:
                # self.define_data_var(self.br.offset-1,int_info_struct)
                self.session_data['co_consts'].append(("None",self.br.offset-1))
        # self.br.seek(0)

class ConstRenderer(DataRenderer):
    def perform_is_valid_for_data(self,ctxt,view,addr,type,context):
        return DataRenderer.is_type_of_struct_name(type, "int_info", context)
    def perform_get_lines_for_data(self,ctxt,view,addr,type,prefix,width,context):
        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,"CONST:")]
        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken," "))
        _int = view.get_data_var_at(addr).value['int']
        tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken,hex(_int),_int))
        return [DisassemblyTextLine(tokens,addr)]
ConstRenderer().register_type_specific()

class StrRenderer(DataRenderer):
    def perform_is_valid_for_data(self,ctxt,view,addr,type,context):
        try:
            dv = view.get_data_var_at(addr)
            if dv != None:
                return str(dv.type.name).startswith("str_info")
        except:
            pass
        return False
    def perform_get_lines_for_data(self,ctxt,view,addr,type,prefix,width,context):
        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,"STRING:")]
        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken," "))
        _string = view.get_data_var_at(addr).value['string']
        tokens.append(InstructionTextToken(InstructionTextTokenType.CharacterConstantToken,repr(_string),addr))
        return [DisassemblyTextLine(tokens,addr)]
StrRenderer().register_type_specific()

class StringRenderer(DataRenderer):
    def perform_is_valid_for_data(self,ctxt,view,addr,type,context):
        try:
            dv = view.get_data_var_at(addr)
            if dv != None:
                return str(dv.type.name).startswith("string_info")
        except:
            pass
        return False
    def perform_get_lines_for_data(self,ctxt,view,addr,type,prefix,width,context):
        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,"L STRING:")]
        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken," "))
        _string = view.get_data_var_at(addr).value['string']
        tokens.append(InstructionTextToken(InstructionTextTokenType.CharacterConstantToken,repr(_string),addr))
        return [DisassemblyTextLine(tokens,addr)]
StringRenderer().register_type_specific()

class SARenderer(DataRenderer):
    def perform_is_valid_for_data(self,ctxt,view,addr,type,context):
        try:
            dv = view.get_data_var_at(addr)
            if dv != None:
                return str(dv.type.name).startswith("sa_info")
        except:
            pass
        return False

    def perform_get_lines_for_data(self,ctxt,view,addr,type,prefix,width,context):
        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,"SHORT ASCII:")]
        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken," "))
        _string = view.get_data_var_at(addr).value['string']
        tokens.append(InstructionTextToken(InstructionTextTokenType.CharacterConstantToken,repr(_string),addr))
        return [DisassemblyTextLine(tokens,addr)]
SARenderer().register_type_specific()