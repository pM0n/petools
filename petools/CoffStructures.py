'''
The MIT License (MIT)

Copyright (c) 2013 pmon.mail@gmail.com

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
'''
import struct,time

big_endian = False

COFF_HEADER_SIZE = 20
COFF_HEADER_PARSE_STRING = 'HHIIIHH'

COFF_SECTION_HEADER_SIZE = 40
COFF_SECTION_HEADER_PARSE_STRING_NO_NAME = 'IIIIIIHHI'

COFF_SYMBOL_TABLE_RECORD_LEN = 18
COFF_SYMBOL_TABLE_NAME_PARSE_STRING = 'II'
COFF_SYMBOL_TABLE_RECORD_PARSE_STRING_NO_NAME = 'IHHBB'

COFF_RELOCATION_TABLE_RECORD_LEN = 10
COFF_RELOCATION_TABLE_RECORD_PARSE_STRING = 'IIH'

class CoffHeader(object):
    '''
    Object representation of the PE/COFF header
    '''

    def __init__(self):
        '''
        Constructor
        '''
        if big_endian:
            self.endiannes_prefix = '>'
        else:
            self.endiannes_prefix = '<'
        
        self.Machine = 0
        self.NumberOfSections = 0
        self.TimeDateStamp = 0
        self.PointerToSymbolTable = 0
        self.NumberOfSymbols = 0
        self.SizeOfOptionalHeader = 0
        self.Charcteristics = 0 
    
    def parse(self,headerString):
        self.Machine,self.NumberOfSections,self.TimeDateStamp,self.PointerToSymbolTable,\
        self.NumberOfSymbols,self.SizeOfOptionalHeader,self.Charcteristics = \
            struct.unpack(self.endiannes_prefix+COFF_HEADER_PARSE_STRING,headerString)
        return self
            
    def __str__(self):
        rstr = ''
        rstr += 'COFF Header:\n'
        rstr +=  '\tMachine: 0x%04x\n' % self.Machine
        rstr +=  '\tNumber of sections: 0x%04x\n' % self.NumberOfSections
        rstr +=  '\tTime of creation: %s\n' % time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.TimeDateStamp))
        rstr +=  '\tPointer to symbol table: 0x%08x\n' % self.PointerToSymbolTable
        rstr +=  '\tNumber of symbols: 0x%08x\n' % self.NumberOfSymbols
        rstr +=  '\tSize of optional headers: 0x%04x\n' % self.SizeOfOptionalHeader
        rstr +=  '\tCharacteristics: 0x%04x\n' % self.Charcteristics
        return rstr

class CoffSection(object):
    '''
    Object representation of a section
    '''
    def __init__(self):
        '''
        Constructor
        '''
        if big_endian:
            self.endiannes_prefix = '>'
        else:
            self.endiannes_prefix = '<'
            
        self.section_data = ''
        self.relocation_table = None
        self.VirtualSize = 0
        self.VirtualAddress = 0
        self.SizeOfRawData = 0
        self.PointerToRawData = 0
        self.PointerToRelocations = 0
        self.PointerToLineNumbers = 0
        self.NumberOfRelocations = 0
        self.NumberOfLinenumbers = 0
        self.Charcteristics = 0
    
    def parse(self,headerString):
        self.name = headerString[:8].strip('\x00')
        
        headerStringNoName = headerString[8:]
        
        self.VirtualSize,self.VirtualAddress,self.SizeOfRawData,self.PointerToRawData,\
        self.PointerToRelocations,self.PointerToLineNumbers,self.NumberOfRelocations,\
        self.NumberOfLinenumbers,self.Charcteristics = \
            struct.unpack(self.endiannes_prefix+COFF_SECTION_HEADER_PARSE_STRING_NO_NAME,headerStringNoName)
        return self
    
    def set_section_data(self,data):
        self.section_data = data
        
    def setRelocationTable(self,relocationTableObject):
        self.relocation_table = relocationTableObject
    
    def __str__(self):
        return self.name
        
    def headerStr(self,add_header_row=False,add_legend=False):
        header_raw_strings = ['Name','V.Size','V.Address','S.RawData','P.RawData','P.Relocs','P.LNums','N.Relocs','N.LNums','Character.']
        header_values = [self.name,'0x%x'%self.VirtualSize,'0x%x'%self.VirtualAddress,'0x%x'%self.SizeOfRawData,'0x%x'%self.PointerToRawData,'0x%x'%self.PointerToRelocations,'0x%x'%self.PointerToLineNumbers,'0x%x'%self.NumberOfRelocations,'0x%x'%self.NumberOfLinenumbers,'0x%x'%self.Charcteristics]
        legend_strnigs = ['Section name','Virtual size','Virtual address','Size of raw data','Pointer to raw data','Pointer to relocations','Pointer to line numbers','Number of relocations','Number of line numbers','Characteristics']
        columns_size = int(100/len(header_values))
        
        rstr = ''
        if add_header_row:
            rstr += ''.join([hstr+(' '*(columns_size-len(hstr))) for hstr in header_raw_strings])
            rstr += '\n'
        rstr += ''.join([hstr+(' '*(columns_size-len(hstr))) for hstr in header_values])
        rstr += '\n'
        if add_legend:
            rstr += ''.join(['%s: %s,'%(header_raw_strings[i],legend_strnigs[i]) for i in range(len(header_raw_strings))])
            rstr += '\n' 
        return rstr

class CoffSymbol(object):
    '''
    Object representation of a symbol entry
    '''
    def __init__(self):
        '''
        Constructor
        '''
        if big_endian:
            self.endiannes_prefix = '>'
        else:
            self.endiannes_prefix = '<'
            
        self.string_table = None
        self.section_data = ''
        self.name = ''
        self.Value = 0
        self.SectionNumber = 0
        self.Type = 0
        self.StorageClass = 0
        self.NumberOfAuxSymbols = 0   
        
    def setStringTable(self,string_table):
        self.string_table = string_table
    
    def parse(self,symRaw):
        name_struct = struct.unpack(COFF_SYMBOL_TABLE_NAME_PARSE_STRING,symRaw[:8])
        if name_struct[0] == 0:
            self.name = name_struct[1]
        else:
            self.name = symRaw[:8].strip('\x00')
        self.Value,self.SectionNumber,self.Type,\
        self.StorageClass,self.NumberOfAuxSymbols = struct.unpack_from(self.endiannes_prefix+COFF_SYMBOL_TABLE_RECORD_PARSE_STRING_NO_NAME,symRaw,8)
        return self
    
    def __str__(self):
        return self.symbolStr(add_header_row=True, add_legend=True)
    
    def getSymbolName(self):
        name = ''
        if type(self.name) == int and self.string_table:
            name = self.string_table[self.name:self.string_table.find('\x00',self.name)]
            #print name
        else:
            name = str(self.name)
        return name
    
    def symbolStr(self,add_header_row=False,add_legend=False):
        
        header_raw_strings = ['Value','S.Num','Type','S.Class','N.AuxSyms','Name']
        columns_size = int(100/len(header_raw_strings))
        header_values = ['0x%x'%self.Value,'0x%x'%self.SectionNumber,'0x%x'%self.Type,'0x%x'%self.StorageClass,'0x%x'%self.NumberOfAuxSymbols,self.getSymbolName()]
        legend_strnigs = ['Value','SectionNumber','Type','StorageClass','NumberOfAuxSymbols','Name']
                
        rstr = ''
        if add_header_row:
            rstr += ''.join([hstr+(' '*(columns_size-len(hstr))) for hstr in header_raw_strings])
            rstr += '\n'
        rstr += ''.join([hstr+(' '*(columns_size-len(hstr))) for hstr in header_values])
        rstr += '\n'
        if add_legend:
            rstr += ''.join(['%s: %s,'%(header_raw_strings[i],legend_strnigs[i]) for i in range(len(header_raw_strings))])
            rstr += '\n' 
        return rstr

class CoffSymbolTable(object):
    '''
    Object representation of a symbol table 
    '''
    def __init__(self):
        '''
        Constructor
        '''
        if big_endian:
            self.endiannes_prefix = '>'
        else:
            self.endiannes_prefix = '<'
            
        self.section_data = ''
        self.string_table = None
        self.symbols = []   
    
    def setStringTable(self,string_table):
        self.string_table = string_table
        for symbol in self.symbols:
            symbol.setStringTable(self.string_table)
    
    def parse(self,symTableRaw,symCount):
        self.symbols = []
        i = 0
        while i < symCount:
            self.symbols.append(CoffSymbol().parse(symTableRaw[(i*COFF_SYMBOL_TABLE_RECORD_LEN):(i*COFF_SYMBOL_TABLE_RECORD_LEN)+COFF_SYMBOL_TABLE_RECORD_LEN]))
            i += (1 + self.symbols[-1].NumberOfAuxSymbols)
        return self
        
    def __str__(self):
        rstr = ''.join([symbols.symbolStr(add_header_row=(i==0),add_legend=(i==len(self.symbols)-1)) for i,symbols in enumerate(self.symbols)])
        return rstr
        
class CoffRelocation(object):
    def __init__(self):      
        '''
        Object representation of a relocation entry
        '''
        if big_endian:
            self.endiannes_prefix = '>'
        else:
            self.endiannes_prefix = '<'
            
        self.VirtualAddress = 0
        self.SymbolTableIndex = 0
        self.Type = 0
        
    def parse(self,relocationString):  
        self.VirtualAddress,self.SymbolTableIndex,self.Type = struct.unpack(self.endiannes_prefix+COFF_RELOCATION_TABLE_RECORD_PARSE_STRING,relocationString)
        return self
    
    def __str__(self):
        return self.relocationStr(add_header_row=True,add_legend=True)
    
    def relocationStr(self,add_header_row=False,add_legend=False):
        header_raw_strings = ['V.Addr','Sym.Idx.','Type']
        header_values = ['0x%x'%self.VirtualAddress,'0x%x'%self.SymbolTableIndex,'0x%x'%self.Type]
        legend_strnigs = ['VirtualAddress','SymbolTableIndex','Type']
        columns_size = int(100/len(header_values))
        
        rstr = ''
        if add_header_row:
            rstr += ''.join([hstr+(' '*(columns_size-len(hstr))) for hstr in header_raw_strings])
            rstr += '\n'
        rstr += ''.join([hstr+(' '*(columns_size-len(hstr))) for hstr in header_values])
        rstr += '\n'
        if add_legend:
            rstr += ''.join(['%s: %s,'%(header_raw_strings[i],legend_strnigs[i]) for i in range(len(header_raw_strings))])
            rstr += '\n' 
        return rstr

class CoffRelocationTable(object):
    '''
    Object representation of a relocation table
    '''
    def __init__(self):
        '''
        Constructor
        '''
        if big_endian:
            self.endiannes_prefix = '>'
        else:
            self.endiannes_prefix = '<'
            
        self.section_data = ''
        self.relocations = [] 
    
    def parse(self,relocationTableRaw):
        self.relocations = [CoffRelocation().parse(relocationTableRaw[i:i+COFF_RELOCATION_TABLE_RECORD_LEN]) for i in range(0,len(relocationTableRaw),COFF_RELOCATION_TABLE_RECORD_LEN)]
        return self
    
    def __str__(self):
        rstr = ''.join([relocation.relocationStr(add_header_row=(i==0),add_legend=(i==len(self.relocations)-1)) for i,relocation in enumerate(self.relocations)])
        return rstr
        

class CoffFile(object):
    '''
    Object representation of a COFF file
    '''
    def __init__(self):
        '''
        Constructor
        '''
        if big_endian:
            self.endiannes_prefix = '>'
        else:
            self.endiannes_prefix = '<'
            
        self.coff_header = CoffHeader()
        self.sections = []
        self.string_table = CoffSymbolTable()
        self.string_table = ''
        
        
    def parse(self,fileObject):
        fileObject.seek(0)
        self.coff_header = CoffHeader().parse(fileObject.read(COFF_HEADER_SIZE))
        self.optional_headers = fileObject.read(self.coff_header.SizeOfOptionalHeader)
        self.sections = [CoffSection().parse(fileObject.read(COFF_SECTION_HEADER_SIZE)) for i in range(self.coff_header.NumberOfSections)]
        for section in self.sections:
            fileObject.seek(section.PointerToRawData)
            section.set_section_data(fileObject.read(section.SizeOfRawData))
            if section.PointerToRelocations != 0:
                fileObject.seek(section.PointerToRelocations)
                section.setRelocationTable(CoffRelocationTable().parse(fileObject.read(COFF_RELOCATION_TABLE_RECORD_LEN*section.NumberOfRelocations)))
        fileObject.seek(self.coff_header.PointerToSymbolTable)
        self.symbol_table = CoffSymbolTable().parse(fileObject.read(COFF_SYMBOL_TABLE_RECORD_LEN*self.coff_header.NumberOfSymbols),self.coff_header.NumberOfSymbols)
        strtab_len = struct.unpack(self.endiannes_prefix+'I',fileObject.read(4))[0] - 4
        self.string_table = '\x00\x00\x00\x00'+fileObject.read(strtab_len)
        self.symbol_table.setStringTable(self.string_table)
        return self
        
    def __str__(self):
        return str(self.coff_header) + '\n' + 'sections: ' + ' '.join(['%s(%d)'%(str(section),section.SizeOfRawData) for section in self.sections])
