# -*- coding: UTF-8 -*-
import random
from leb128 import LEB128U, LEB128S
from WASMaker.parser import reader
from WASMaker.parser.module import *
import struct
from WASMaker.parser.opcodes import *
import os
from WASMaker.parser.types import val_type_to_str, GlobalType
from WASMaker.parser.instruction import Instruction


class EmitBinary:
    """
    生成对应的wasm字节码
    """

    def __init__(self, file_name: str, module):

        self.file_name = file_name
        self.module = module

    def emit_binary(self):
        # 先不加custom段
        # self.change_custom_name_section(self.module.custom_secs)

        with open(self.file_name, "wb+") as f:
            # write magic number and version number
            self.write_u32(self.module.magic, f)
            self.write_u32(self.module.version, f)

            if self.module.type_sec:
                self.emit_type_section(self.module.type_sec, f)
            if self.module.import_sec:
                self.emit_import_section(self.module.import_sec, f)
            if self.module.func_sec:
                self.emit_func_section(self.module.func_sec, f)
            if self.module.table_sec:
                self.emit_table_section(self.module.table_sec, f)
            if self.module.mem_sec:
                self.emit_memory_section(self.module.mem_sec, f)
            if self.module.global_sec:
                self.emit_global_section(self.module.global_sec, f)
            if self.module.export_sec:
                self.emit_export_section(self.module.export_sec, f)
            if self.module.elem_sec:
                self.emit_elem_section(self.module.elem_sec, f)
            if self.module.code_sec:
                self.emit_code_section(self.module.code_sec, f)
            if self.module.data_sec:
                self.emit_data_section(self.module.data_sec, f)

    def write_u32(self, value, fp):
        """将整数存储为32位数据"""
        b = value.to_bytes(4, byteorder='little')
        fp.write(b)

    def fix_section_range(self, sec_id, change, start, custom_sec_id=None):
        """
        Fixes segment ranges when modifying WASM WASMaker content
        Parameters
        ----------
        sec_id : int
            Index of the segment that was repaired
        change : int
            Segment size changes
        """

        if sec_id != SecCustomID:
            for i in range(sec_id + 1, 12):
                if self.module.section_range[i].start != self.module.section_range[i].end:
                    self.module.section_range[i].start += change
                    self.module.section_range[i].end += change

            # 修复custom段范围
            if self.module.section_range[0] != []:
                for custom in self.module.section_range[0]:
                    if start <= custom.start:
                        custom.start += change
                        custom.end += change
        elif sec_id == SecCustomID:
            for i in range(1, 12):
                if self.module.section_range[i].start != self.module.section_range[i].end and start <= \
                        self.module.section_range[i].start:
                    self.module.section_range[i].start += change
                    self.module.section_range[i].end += change
            for _, custom in enumerate(self.module.section_range[0]):
                if _ != custom_sec_id and start <= custom.start:
                    custom.start += change
                    custom.end += change

    def emit_import_section(self, import_vec: list, fp):
        """
        Modify the import segment in the WASM WASMaker
        Parameters
        ----------
        import_vec : list

        Returns
        -------

        """
        ### 这里有个问题，就是如果没有这个段，那么他的start就是0，然后再改就会出现改文件开头的问题。
        import_vec_len = len(import_vec)
        import_vec_len_bytes = LEB128U.encode(import_vec_len)
        import_vec_bytes = bytes()
        import_vec_bytes += import_vec_len_bytes
        if import_vec == []:
            return
        for i in import_vec:
            import_vec_bytes += LEB128U.encode(len(i.module))
            import_vec_bytes += bytes(i.module, encoding="utf-8")
            import_vec_bytes += LEB128U.encode(len(i.name))
            import_vec_bytes += bytes(i.name, encoding="utf-8")
            import_vec_bytes += LEB128U.encode(i.desc.tag)
            if i.desc.func_type is not None:
                import_vec_bytes += LEB128U.encode(i.desc.func_type)
            elif i.desc.table is not None:
                import_vec_bytes += self.write_table_type(i.desc.table)
            elif i.desc.mem is not None:
                import_vec_bytes += self.write_limits(i.desc.mem)
            elif i.desc.global_type is not None:
                import_vec_bytes += self.write_global_type(i.desc.global_type)
        import_section_bytes = bytes([0x02]) + LEB128U.encode(len(import_vec_bytes)) + import_vec_bytes

        fp.write(import_section_bytes)

    def emit_export_section(self, export_vec: list, fp):
        export_vec_len = len(export_vec)
        export_vec_len_bytes = LEB128U.encode(export_vec_len)
        export_vec_bytes = bytes()
        export_vec_bytes += export_vec_len_bytes
        if export_vec == []:
            return
        for export_item in export_vec:
            export_vec_bytes += LEB128U.encode(len(export_item.name))
            export_vec_bytes += bytes(export_item.name, encoding="utf-8")
            export_vec_bytes += LEB128U.encode(export_item.desc.tag)
            export_vec_bytes += LEB128U.encode(export_item.desc.idx)

        export_section_bytes = bytes([0x07]) + LEB128U.encode(len(export_vec_bytes)) + export_vec_bytes

        fp.write(export_section_bytes)

    # def change_start_section(self, export_vec: list, fp):
    #     export_vec_len = len(export_vec)
    #     export_vec_len_bytes = LEB128U.encode(export_vec_len)
    #     export_vec_bytes = bytes()
    #     export_vec_bytes += export_vec_len_bytes
    #     if export_vec == []:
    #         return
    #     for export_item in export_vec:
    #         export_vec_bytes += LEB128U.encode(len(export_item.name))
    #         export_vec_bytes += bytes(export_item.name, encoding="utf-8")
    #         export_vec_bytes += LEB128U.encode(export_item.desc.tag)
    #         export_vec_bytes += LEB128U.encode(export_item.desc.idx)
    #
    #     export_section_bytes = bytes([0x07]) + LEB128U.encode(len(export_vec_bytes)) + export_vec_bytes
    #
    #     fp.write(export_section_bytes)

    def emit_memory_section(self, memory_vec: list, fp):
        memory_vec_len = len(memory_vec)
        memory_vec_len_bytes = LEB128U.encode(memory_vec_len)
        memory_vec_bytes = bytes()
        memory_vec_bytes += memory_vec_len_bytes
        if memory_vec == []:
            return
        for memory_item in memory_vec:
            memory_item_bytes = bytes()
            memory_item_bytes += bytes([memory_item.tag])
            memory_item_bytes += LEB128U.encode(memory_item.min)
            if memory_item.max != 0:
                memory_item_bytes += LEB128U.encode(memory_item.max)
            memory_vec_bytes += memory_item_bytes

        memroy_section_bytes = bytes([SecMemID]) + LEB128U.encode(len(memory_vec_bytes)) + memory_vec_bytes

        fp.write(memroy_section_bytes)

    def emit_data_section(self, data_vec: list, fp):
        data_vec_len = len(data_vec)
        data_vec_len_bytes = LEB128U.encode(data_vec_len)
        data_vec_bytes = bytes()
        data_vec_bytes += data_vec_len_bytes
        if not data_vec:
            return
        for data_item in data_vec:
            data_item_bytes = bytes()
            data_item_bytes += LEB128U.encode(data_item.mem)
            data_item_bytes += self.write_expr(data_item.offset)
            data_item_bytes += LEB128U.encode(len(data_item.init))
            data_item_bytes += data_item.init

            data_vec_bytes += data_item_bytes

        data_section_bytes = bytes([SecDataID]) + LEB128U.encode(len(data_vec_bytes)) + data_vec_bytes

        fp.write(data_section_bytes)

    def emit_elem_section(self, elem_vec: list, fp):
        """
        Modify the element segment in the WASM WASMaker
        Parameters
        ----------
        elem_vec : list

        Returns
        -------

        """
        elem_vec_len = len(elem_vec)
        elem_vec_len_bytes = LEB128U.encode(elem_vec_len)
        elem_vec_bytes = bytes()
        elem_vec_bytes += elem_vec_len_bytes
        if elem_vec == []:
            return
        for elem in elem_vec:
            elem_vec_bytes += LEB128U.encode(elem.table)
            elem_vec_bytes += self.write_expr(elem.offset)
            elem_vec_bytes += LEB128U.encode(len(elem.init))
            for func_idx in elem.init:
                elem_vec_bytes += LEB128U.encode(func_idx)
        elem_section_bytes = bytes([SecElemID]) + LEB128U.encode(len(elem_vec_bytes)) + elem_vec_bytes

        fp.write(elem_section_bytes)

    def emit_type_section(self, functype_vec: list, fp):
        """
        Modify the type segment in the WASM WASMaker
        Parameters
        ----------
        functype_vec : list

        Returns
        -------

        """
        functype_vec_len = len(functype_vec)
        functype_vec_len_bytes = LEB128U.encode(functype_vec_len)
        functype_vec_bytes = bytes()
        functype_vec_bytes += functype_vec_len_bytes
        if functype_vec == []:
            return
        for functype in functype_vec:
            functype_bytes = bytes()
            functype_bytes += bytes([0x60])
            functype_bytes += self.write_val_types(functype.param_types)
            functype_bytes += self.write_val_types(functype.result_types)
            functype_vec_bytes += functype_bytes
        type_section_bytes = bytes([0x01]) + LEB128U.encode(len(functype_vec_bytes)) + functype_vec_bytes

        fp.write(type_section_bytes)

    def emit_global_section(self, global_vec: list, fp):
        """
        Modify the global segment in the WASM WASMaker
        Parameters
        ----------
        functype_vec : list

        Returns
        -------

        """

        global_vec_len = len(global_vec)
        global_vec_len_bytes = LEB128U.encode(global_vec_len)
        global_vec_bytes = bytes()
        global_vec_bytes += global_vec_len_bytes
        if global_vec == []:
            return
        for global_item in global_vec:
            global_bytes = bytes()
            global_bytes += self.write_global(global_item)
            global_vec_bytes += global_bytes

        global_section_bytes = bytes([0x06]) + LEB128U.encode(len(global_vec_bytes)) + global_vec_bytes

        fp.write(global_section_bytes)

    def emit_func_section(self, type_vec, fp):
        """
        Modify the function section in the WASM WASMaker
        Parameters
        ----------
        type_vec : list
        """
        type_vec_len = len(type_vec)
        type_vec_len_bytes = LEB128U.encode(type_vec_len)
        type_vec_bytes = bytes()
        type_vec_bytes += type_vec_len_bytes
        if type_vec == []:
            return
        for type_item in type_vec:
            type_vec_bytes += LEB128U.encode(type_item)
        func_section_bytes = bytes([0x03]) + LEB128U.encode(len(type_vec_bytes)) + type_vec_bytes

        fp.write(func_section_bytes)

    def emit_code_section(self, code_vec: list, fp):
        """
        Modify code snippets in the WASM WASMaker
        Parameters
        ----------
        code_vec : list

        Returns
        -------

        """
        code_vec_len = len(code_vec)
        code_vec_len_bytes = LEB128U.encode(code_vec_len)
        code_vec_bytes = bytes()
        code_vec_bytes += code_vec_len_bytes
        if code_vec == []:
            return
        for code in code_vec:
            code_bytes = bytes()
            locals_vec_len = len(code.locals)
            locals_vec_len_bytes = LEB128U.encode(locals_vec_len)
            locals_vec_bytes = bytes()
            expr_bytes = bytes()
            # locals: local_count|val_type
            for local in code.locals:
                local_count = local.n
                local_type = local.type
                locals_vec_bytes += LEB128U.encode(local_count)
                locals_vec_bytes += bytes([local_type])
                # expr: instr*|0x0b

            expr_bytes += self.write_expr(code.expr)
            code_bytes += (locals_vec_len_bytes + locals_vec_bytes + expr_bytes)
            code_vec_bytes += LEB128U.encode(len(code_bytes)) + code_bytes
        code_section_bytes = bytes([0x0A]) + LEB128U.encode(len(code_vec_bytes)) + code_vec_bytes

        fp.write(code_section_bytes)

    def emit_table_section(self, table_vec: list, fp):
        """
        Modify table section in the wasm WASMaker
        Args:
            table_vec:

        Returns:

        """
        table_vec_len = len(table_vec)
        table_vec_len_bytes = LEB128U.encode(table_vec_len)
        table_vec_bytes = bytes()
        table_vec_bytes += table_vec_len_bytes
        if table_vec == []:
            return
        for table_type in table_vec:
            table_type_bytes = bytes()
            table_type_bytes += bytes([table_type.elem_type])
            table_type_bytes += bytes([table_type.limits.tag])
            table_type_bytes += LEB128U.encode(table_type.limits.min)
            if 0 != table_type.limits.max:
                table_type_bytes += LEB128U.encode(table_type.limits.max)
            table_vec_bytes += table_type_bytes

        table_section_bytes = bytes([0x04]) + LEB128U.encode(len(table_vec_bytes)) + table_vec_bytes

        fp.write(table_section_bytes)

    # 结尾要自己加0x0b end指令
    def write_expr(self, expr: list):
        """
        Write Expr blocks to the WASM WASMaker
        Parameters
        ----------
        expr : list

        Returns
        -------
        expr_bytes : int
            Size of expR blocks to be written
        """
        instructions_bytes = self.write_instructions(expr)
        expr_bytes = instructions_bytes + bytes([0x0b])

        return expr_bytes

    def write_instructions(self, expr: list):
        """
        Write instruction blocks to the WASM WASMaker
        Parameters
        ----------
        expr : list

        Returns
        -------
        instructions_bytes : int
            The WASMaker size of the instruction block to be written
        """
        instructions_bytes = bytes()
        for index in range(len(expr)):
            instructions_bytes += self.write_instruction(expr[index])

        return instructions_bytes

    # def write_instruction(self, instr):
    #     """
    #     Write a single instruction to a WASM WASMaker
    #     Parameters
    #     ----------
    #     instr : list
    #
    #     Returns
    #     -------
    #     instruction_bytes : int
    #         The size of a single instruction to write
    #     """
    #     instruction_bytes = bytes()
    #     instruction_bytes += instr.opcode.to_bytes(4, 'big')
    #     args_bytes = self.write_args(instr)
    #     if args_bytes is not None:
    #         instruction_bytes += args_bytes
    #
    #     return instruction_bytes

    def write_instruction(self, instr: Instruction):
        """
        根据提供的Instruction对象，生成相应的二进制数据
        :param instr: Instruction对象
        :return: 二进制数据
        """
        binary_data = bytes()

        # 1-byte opcode
        if instr.opcode < 0xFC:
            binary_data += bytes([instr.opcode])

        # 2-bytes opcode
        elif instr.opcode <= 0xFD7F:
            binary_data += instr.opcode.to_bytes(2, 'big')

        # 2-bytes or 3-bytes opcode starting with 0xFD
        elif instr.opcode <= 0xFDFF01:
            binary_data += instr.opcode.to_bytes(3, 'big')

        else:
            raise Exception("Invalid opcode: 0x%02x" % instr.opcode)

        # 添加指令操作数
        args_bytes = self.write_args(instr)
        if args_bytes != None:
            binary_data += args_bytes

        return binary_data

    def write_args(self, instr):
        """
        Writes opcode parameters to instructions in the WASM WASMaker
        Parameters
        ----------
        instr : list

        Returns
        -------

        """
        opcode = instr.opcode
        if opcode in [Block, Loop]:
            return self.write_block_args(instr)
        elif opcode == If:
            return self.write_if_args(instr)
        elif opcode in [Br, BrIf]:
            return LEB128U.encode(instr.args)
        elif opcode == BrTable:
            return self.write_br_table_args(instr)
        elif opcode == Call:
            return LEB128U.encode(instr.args)
        elif opcode == CallIndirect:
            return self.write_call_indirect_args(instr)
        elif opcode in [LocalGet, LocalSet, LocalTee]:
            return LEB128U.encode(instr.args)
        elif opcode in [GlobalGet, GlobalSet]:
            return LEB128U.encode(instr.args)
        elif opcode in [MemorySize, MemoryGrow]:
            return bytes([0x00])
        elif opcode == I32Const:
            return LEB128S.encode(instr.args)  # u32
        elif opcode == I64Const:
            return LEB128S.encode(instr.args)  # u64
        elif opcode == F32Const:
            return struct.pack('<f', instr.args)
        elif opcode == F64Const:
            return struct.pack('<d', instr.args)
        elif opcode == V128Const:
            return instr.args.to_bytes(16, 'little')  # v128
        elif opcode == I8x16Shuffle:
            return instr.args.to_bytes(16, 'little')  # v128
        elif I8x16ExtractLaneS <= opcode <= F64x2ReplaceLane:
            return bytes([instr.args])
        elif opcode in [RefNull, RefFunc]:
            return LEB128U.encode(instr.args)
        elif opcode in [MemoryInit, DataDrop, ElemDrop, TableGrow, TableSize, TableFill]:
            return LEB128U.encode(instr.args)
        elif opcode in [TableInit, TableCopy]:
            x = LEB128U.encode(instr.args.x)
            y = LEB128U.encode(instr.args.y)
            return x + y
        elif V128Load <= opcode <= V128Store or opcode in [V128Load32Zero, V128Load64Zero]:
            return self.write_mem_arg(instr)
        elif V128Load8Lane <= opcode <= V128Store64Lane:
            return self.write_mem_lane_arg(instr)
        elif I32Load <= instr.opcode <= I64Store32:
            return self.write_mem_arg(instr)
        else:
            return None

    def write_block_args(self, instr):
        """
        为wasm二进制文件中写入block块参数
        @param instr:
        @return:
        """
        # block_instr: 0x02|block_type|instr*|0x0b
        args_bytes = bytes()
        args_bytes += LEB128S.encode(instr.args.bt)
        args_bytes += self.write_instructions(instr.args.instrs)
        args_bytes += bytes([0x0b])

        return args_bytes

    def write_if_args(self, instr):
        """
        为wasm二进制文件中写入if-else块参数
        @param instr:
        @return:
        """
        # if_instr: 0x04|block_type|instr*|(0x05|instr*)?|0x0b
        args_bytes = bytes()
        args_bytes += LEB128S.encode(instr.args.bt)
        args_bytes += self.write_instructions(instr.args.instrs1)
        if instr.args.instrs2:
            args_bytes += bytes([0x05])  # else
            args_bytes += self.write_instructions(instr.args.instrs2)
            args_bytes += bytes([0x0b])
        else:
            args_bytes += bytes([0x0b])

        return args_bytes

    @staticmethod
    def write_br_table_args(instr):
        """
        为wasm二进制文件中写入br_table指令参数
        @param instr:
        @return:
        """
        # br_table_args: vec<label>|default
        # default and label : u32
        args_bytes = bytes()
        args_bytes += LEB128U.encode(len(instr.args.labels))
        for label in instr.args.labels:
            args_bytes += LEB128U.encode(label)
        args_bytes += LEB128U.encode(instr.args.default)

        return args_bytes

    @staticmethod
    def write_call_indirect_args(instr):
        """
        为wasm二进制文件中写入call_indirect指令参数
        @param instr:
        @return:
        """
        # call_indirect: 0x11|type_idx|0x00
        args_bytes = bytes()
        args_bytes += LEB128U.encode(instr.args)
        args_bytes += bytes([0x00])

        return args_bytes

    @staticmethod
    def write_mem_arg(instr):
        """
        为wasm二进制文件中写入mem指令参数
        @param instr:
        @return:
        """
        args_bytes = bytes()
        args_bytes += LEB128U.encode(instr.args.align)
        args_bytes += LEB128U.encode(instr.args.offset)

        return args_bytes

    @staticmethod
    def write_mem_lane_arg(instr):

        args_bytes = bytes()
        args_bytes += LEB128U.encode(instr.args.mem_arg.align)
        args_bytes += LEB128U.encode(instr.args.mem_arg.offset)
        args_bytes += LEB128U.encode(instr.args.laneidx)

        return args_bytes

    @staticmethod
    def write_val_types(val_types):
        """
        为wasm二进制文件中写入值类型
        @param val_types:
        @return:
        """
        val_types_bytes = bytes()
        val_types_bytes += LEB128U.encode(len(val_types))
        for val in val_types:
            val_types_bytes += bytes([val])

        return val_types_bytes

    @staticmethod
    def write_global_type(global_type):
        """
        为wasm二进制文件中写入全局类型
        @param global_type:
        @return:
        """
        global_type_bytes = bytes()
        global_type_bytes += bytes([global_type.val_type])
        global_type_bytes += bytes([global_type.mut])
        return global_type_bytes

    @staticmethod
    def write_limits(mem):
        """
        为wasm二进制文件中写入limit指令
        @param mem:
        @return:
        """
        mem_bytes = bytes()
        mem_bytes += bytes([mem.tag])
        mem_bytes += LEB128U.encode(mem.min)
        if mem.tag == 1:
            mem_bytes += LEB128U.encode(mem.max)
        return mem_bytes

    @staticmethod
    def write_table_type(table_type):
        """
        为wasm二进制文件中写入表段内容
        @param table_type:
        """
        table_type_bytes = bytes()
        table_type_bytes += bytes([table_type.elem_type])
        table_type_bytes += bytes([table_type.limits.tag])
        if table_type.limits.min != 0:
            table_type_bytes += LEB128U.encode(table_type.limits.min)
        if table_type.limits.max != 0:
            table_type_bytes += LEB128U.encode(table_type.limits.max)
        return table_type_bytes

    def write_global(self, global_item):
        global_bytes = bytes()
        global_bytes += self.write_global_type(global_item.type)
        global_bytes += self.write_expr(global_item.init)
        return global_bytes

    def get_functype_idx(module, functype):
        functype_id = None
        for _, i in enumerate(module.type_sec):
            if i.equal(functype) is True:
                functype_id = _
        return functype_id
