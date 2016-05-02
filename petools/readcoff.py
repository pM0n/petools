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
import sys
import string
import argparse

from petools.CoffStructures import *

__PROGRAM__ = 'readcoff'    

def getOptions():
    parser = argparse.ArgumentParser(prog=__PROGRAM__,add_help=False) 
    parser.add_argument('-h','--file-header',dest='file_header',action='store_true',help='Display the COFF file header')
    parser.add_argument('-S','--section-headers',dest='sections_header',action='store_true',help='Display the sections\' header')
    parser.add_argument('-s','--syms',dest='symbols',action='store_true',help='Display the symbol table')
    parser.add_argument('-r','--relocs',dest='relocations',action='store_true',help='Display the relocations (if present)')
    parser.add_argument('COFFFile', type=argparse.FileType('rb', 0))
    parser.add_argument('-x','--hex-dump',nargs=1,action='store',dest='dump_section',default=None)
    return parser.parse_args()   

def main():
    options = getOptions()
    object_file = CoffFile().parse(options.COFFFile)
    if options.file_header:
        print object_file.coff_header
    if options.sections_header:
        print ''.join([section.headerStr(add_header_row=(i==0),add_legend=(i==len(object_file.sections)-1)) for i,section in enumerate(object_file.sections)])
    if options.symbols:
        print object_file.symbol_table
    if options.relocations:
        for section in object_file.sections:
            if section.relocation_table:
                print 'Relocation for section %s:' % section.name
                print section.relocation_table
    if options.dump_section:
        section_raw_data = ''
        section_name = ''
        if options.dump_section[0].isdigit():
            section_number = int(options.dump_section[0]) 
            if section_number > (len(object_file.sections)-1):
                print 'Error: section id (%d) exceeds the number of sections (%d)!' % (section_number,len(object_file.sections)-1)
                sys.exit(-1)
            section_raw_data = object_file.sections[section_number].section_data
            section_name = object_file.sections[section_number].name
        else:
            result = filter(lambda s: s.name == options.dump_section[0],object_file.sections)
            if len(result) == 0:
                print 'Error: no section named %s!' % options.dump_section[0]
                sys.exit(-1)
            section_raw_data = result[0].section_data
            section_name = result[0].name
        if all(c in string.printable for c in section_raw_data):
            print 'Contents of section %s:\n%s\n' % (section_name,section_raw_data)
        else:
            print 'Contents of section %s (binary data detected):\n%s\n' % (section_name,section_raw_data.encode('hex'))
        
    sys.exit(0)

if __name__ == '__main__':
    main()