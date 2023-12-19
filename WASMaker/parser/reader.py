# -*- coding: UTF-8 -*-
"""
@Project ：wasmObfuscator 
@File    ：reader.py
@Author  ：格友
"""

import ctypes
import struct

from ..parser.instruction import Instruction, BlockArgs, IfArgs, BrTableArgs, MemArg, TableArg, MemLaneArg
from ..parser.module import Import, ImportDesc, ImportTagFunc, ImportTagTable, ImportTagMem, ImportTagGlobal, \
    Global, Export, ExportDesc, ExportTagFunc, ExportTagTable, ExportTagMem, ExportTagGlobal, Elem, Code, Locals, \
    Data, MagicNumber, Version, Module, SecCustomID, SecDataID, CustomSec, SecTypeID, SecImportID, SecFuncID, \
    SecTableID, SecMemID, SecGlobalID, SecExportID, SecStartID, SecElemID, SecCodeID, NameData, SectionRange
from ..parser.opcodes import *
from ..parser.opnames import opnames
from ..parser.types import ValTypeI32, ValTypeI64, ValTypeF32, ValTypeF64, ValTypeV128, FuncType, FtTag, TableType, \
    FuncRef, \
    GlobalType, MutConst, MutVar, Limits, BlockTypeI32, BlockTypeI64, BlockTypeF32, BlockTypeF64, BlockTypeEmpty, \
    NameAssoc, BlockTypeV128
from ..parser.leb128 import *


def decode_file(file_name: str):
    data, err = None, None
    try:
        #  with as 语句操作上下文管理器（context manager），它能够帮助我们自动分配并且释放资源
        f = open(file_name, 'rb+')
        data = f.read()
        f.seek(0)  # 重置文件指针
    except Exception as e:
        err = e

    if err is not None:
        return Module(), err

    return decode(data, f)


def decode(data, f):
    module, err = None, None
    try:
        module = Module()
        reader = WasmReader(data, f)
        reader.read_module(module)
        # 关闭文件
        f.close()
    except Exception as e:
        err = e
    return module, err


class WasmReader:
    """
    用于封装二进制模块解码逻辑
    """

    def __init__(self, data=None, reader=None):
        # 存放Wasm二进制模块的数据
        if data is None:
            data = []
        self.reader = reader
        self.data = data

    def remaining(self):
        """查看剩余的字节数量"""
        return len(self.data) - self.reader.tell()

    def read_byte(self):
        """读取字节"""
        if self.remaining() < 1:
            raise ErrUnexpectedEnd
        b = self.reader.read(1)
        return b[0]

    def read_u32(self):
        """读取32位整数"""
        if self.remaining() < 4:
            raise ErrUnexpectedEnd
        b = int.from_bytes(self.reader.read(4), byteorder='little')
        return ctypes.c_int32(b).value

    def read_f32(self):
        """读取32位浮点数"""
        if self.remaining() < 4:
            raise ErrUnexpectedEnd
        b = int.from_bytes(self.reader.read(4), byteorder='little')
        return struct.unpack('>f', struct.pack('>L', b))[0]

    def read_f64(self):
        """读取64位浮点数"""
        if self.remaining() < 8:
            raise ErrUnexpectedEnd
        b = int.from_bytes(self.reader.read(8), byteorder='little')
        return struct.unpack('>d', struct.pack('>Q', b))[0]

    def read_v128(self):
        """读取128位vector,目前按照整数来搞"""
        if self.remaining() < 16:
            raise ErrUnexpectedEnd
        b = int.from_bytes(self.reader.read(16), byteorder='little')
        return b

    def read_lane(self):
        """读取lane"""
        if self.remaining() < 1:
            raise ErrUnexpectedEnd
        b = int.from_bytes(self.reader.read(1), byteorder='little')
        return ctypes.c_int32(b).value

    def read_var_u32(self):
        """
        读取无符号32位整数，用来编码索引和向量长度
        """
        n, w = decode_var_uint(self.reader, 32)
        # self.data = self.data[w:]
        return n

    def read_var_s32(self):
        """读取有符号32位整数"""
        n, w = decode_var_int(self.reader, 32)
        # self.data = self.data[w:]
        return n

    def read_var_s64(self):
        """读取有符号64位整数"""
        n, w = decode_var_int(self.reader, 64)
        # self.data = self.data[w:]
        return n

    def read_bytes(self):
        """读取字节向量"""
        n = self.read_var_u32()
        if self.remaining() < int(n):
            raise ErrUnexpectedEnd
        bytes_data = self.reader.read(n)
        return bytearray(bytes_data)

    def read_name(self):
        """读取名字"""
        data = self.read_bytes()
        try:
            data.decode('utf-8')
        except Exception:
            raise Exception("malformed UTF-8 encoding")

        return str(data, 'utf-8')

    def read_module(self, module: Module):
        if self.remaining() < 4:
            raise Exception("unexpected end of magic header")

        # 读取魔数
        module.magic = self.read_u32()
        if module.magic != MagicNumber:
            raise Exception("magic header not detected")
        if self.remaining() < 4:
            raise Exception("unexpected end of WASMaker version")

        # 读取版本号
        module.version = self.read_u32()
        if module.version != Version:
            raise Exception("unknown WASMaker version: %d" % module.version)

        # 读取段
        self.read_sections(module)
        if len(module.func_sec) != len(module.code_sec):
            raise Exception("function and code section have inconsistent lengths")
        if self.remaining() > 0:
            raise Exception("junk after last section")

    def read_sections(self, module: Module):
        """
        处理好随时可能出现的自定义段
        要保证非自定义段是按照ID递增的顺 序出现的，且最多只能出现一次
        要确认跟在段ID后面的字节数和段内容实际占用的字节数真的一致
        :param module:
        :return:
        """
        prev_sec_id = 0
        while self.remaining() > 0:
            sec_id = self.read_byte()
            # 首先判断是否是随机出现的自定义段,因为可以随机出现多次，所以存在数组里
            if sec_id == SecCustomID:
                # if module.custom_secs is None:
                #     module.custom_secs = []
                n, w = decode_var_uint(self.reader, 32)
                # custom section 确定范围
                from leb128 import LEB128U
                start = self.reader.tell() - w - 1
                end = self.reader.tell() + n
                custom_sec, custom_sec_name = self.read_custom_sec(n)
                module.section_range[SecCustomID].append(SectionRange(start, end, custom_sec_name))
                module.custom_secs.append(custom_sec)
                continue

            # 判断是否超段范围
            if sec_id > SecDataID:
                raise Exception("malformed section id: %d" % sec_id)

            # 判断段是否顺序错误
            if sec_id <= prev_sec_id:
                raise Exception("junk after last section, id: %d" % sec_id)
            prev_sec_id = sec_id

            # 读取段大小
            n, w = decode_var_uint(self.reader, 32)
            remaining_before_read = self.remaining()
            self.read_non_custom_sec(sec_id, module, n, w)
            # 判断段大小是否不匹配
            remain = self.remaining()
            if remain + int(n) != remaining_before_read:
                raise Exception("section size mismatch, id: %d" % sec_id)

    def read_custom_sec(self, sec_size):
        name = self.read_name()
        # 非 name custom
        if name != "name":
            self.reader.seek(self.reader.tell() - len(name) - 1)
            custom_sec_data = self.reader.read(sec_size)
            return CustomSec(name=name, custom_sec_data=custom_sec_data), name

        name_data = self.read_name_data(self.reader.read(sec_size - len(name) - 1))
        return CustomSec(name=name, name_data=name_data), name

    @staticmethod
    def read_name_data(data):
        """
        namedata: modulenamesubsec?|funcnamesubsec?|localnamesubsec?
        custom_sec: 0x00|byte_count|name|namedata
        namedata: modulenamesubsec?|funcnamesubsec?|localnamesubsec?
        modulenamesubsec: 0x00|byte_count|modulename
        funcnamesubsec: 0x01|byte_count|namemap
        namemap: vec<nameassoc>
        nameassoc: idx|name
        localnamesubsec: 0x02|byte_count|indirectnamemap
        indirectnamemap: vec<indirectnameassoc>
        indirectnameassoc: idx|namemap
        modulenamesubsec和localnamesubsec先不处理，保留原始数据
        :return:
        """
        funcname_map = []
        globalname_map = []
        dataname_map = []
        tablename_map = []
        module_bytes = None
        local_bytes = None
        labels_bytes = None
        type_bytes = None
        memory_bytes = None
        elem_bytes = None

        while len(data) != 0:
            sub_sec_id = data[:1]
            data = data[1:]
            if sub_sec_id[0] == 0:
                namesubsec_size, w = decode_var_uint_from_data(data, 32)
                data = data[w:]
                module_bytes = data[:namesubsec_size]
                data = data[namesubsec_size:]

            if sub_sec_id[0] == 1:
                funcnamesubsec_size, w = decode_var_uint_from_data(data, 32)
                data = data[w:]
                name_map_size, w = decode_var_uint_from_data(data, 32)
                data = data[w:]
                funcname_map = []
                for _ in range(name_map_size):
                    idx, w = decode_var_uint_from_data(data, 32)
                    data = data[w:]
                    name_size, w = decode_var_uint_from_data(data, 32)
                    data = data[w:]
                    name = data[:name_size]
                    name = bytearray(name).decode('utf-8')
                    data = data[name_size:]
                    name_assoc = NameAssoc(idx=idx, name=name)
                    funcname_map.append(name_assoc)
            if sub_sec_id[0] == 2:
                namesubsec_size, w = decode_var_uint_from_data(data, 32)
                data = data[w:]
                local_bytes = data[:namesubsec_size]
                data = data[namesubsec_size:]

            if sub_sec_id[0] == 3:  # TODO
                namesubsec_size, w = decode_var_uint_from_data(data, 32)
                data = data[w:]
                labels_bytes = data[:namesubsec_size]
                data = data[namesubsec_size:]

            if sub_sec_id[0] == 4:  # TODO
                namesubsec_size, w = decode_var_uint_from_data(data, 32)
                data = data[w:]
                type_bytes = data[:namesubsec_size]
                data = data[namesubsec_size:]

            if sub_sec_id[0] == 5:
                tablenamesubsec_size, w = decode_var_uint_from_data(data, 32)
                data = data[w:]
                name_map_size, w = decode_var_uint_from_data(data, 32)
                data = data[w:]
                tablename_map = []
                for _ in range(name_map_size):
                    idx, w = decode_var_uint_from_data(data, 32)
                    data = data[w:]
                    name_size, w = decode_var_uint_from_data(data, 32)
                    data = data[w:]
                    name = data[:name_size]
                    name = bytearray(name).decode('utf-8')
                    data = data[name_size:]
                    name_assoc = NameAssoc(idx=idx, name=name)
                    tablename_map.append(name_assoc)
            if sub_sec_id[0] == 6:  # TODO
                namesubsec_size, w = decode_var_uint_from_data(data, 32)
                data = data[w:]
                memory_bytes = data[:namesubsec_size]
                data = data[namesubsec_size:]

            if sub_sec_id[0] == 7:
                globalnamesubsec_size, w = decode_var_uint_from_data(data, 32)
                data = data[w:]
                name_map_size, w = decode_var_uint_from_data(data, 32)
                data = data[w:]
                globalname_map = []
                for _ in range(name_map_size):
                    idx, w = decode_var_uint_from_data(data, 32)
                    data = data[w:]
                    name_size, w = decode_var_uint_from_data(data, 32)
                    data = data[w:]
                    name = data[:name_size]
                    name = bytearray(name).decode('utf-8')
                    data = data[name_size:]
                    name_assoc = NameAssoc(idx=idx, name=name)
                    globalname_map.append(name_assoc)
            if sub_sec_id[0] == 8:  # TODO
                namesubsec_size, w = decode_var_uint_from_data(data, 32)
                data = data[w:]
                elem_bytes = data[:namesubsec_size]
                data = data[namesubsec_size:]

            if sub_sec_id[0] == 9:
                datanamesubsec_size, w = decode_var_uint_from_data(data, 32)
                data = data[w:]
                name_map_size, w = decode_var_uint_from_data(data, 32)
                data = data[w:]
                dataname_map = []
                for _ in range(name_map_size):
                    idx, w = decode_var_uint_from_data(data, 32)
                    data = data[w:]
                    name_size, w = decode_var_uint_from_data(data, 32)
                    data = data[w:]
                    name = data[:name_size]
                    name = bytearray(name).decode('utf-8')
                    data = data[name_size:]
                    name_assoc = NameAssoc(idx=idx, name=name)
                    dataname_map.append(name_assoc)

        name_data = NameData(module_bytes, funcname_map, globalname_map, dataname_map, tablename_map,
                             local_bytes, labels_bytes, type_bytes, memory_bytes, elem_bytes)
        return name_data

    def read_non_custom_sec(self, sec_id, module, sec_size, byte_count_size):
        """
        读取各段,在此之前各段 byte_count 已读取完
        :param byte_count_size:
        :param sec_size:
        :param sec_id: 段ID
        :param module:
        :return:
        """
        if sec_id == SecTypeID:
            # 减去前面的段大小和段ID
            module.section_range[SecTypeID].start = self.reader.tell() - byte_count_size - 1
            module.section_range[SecTypeID].end = self.reader.tell() + sec_size
            print("type start=" + str(module.section_range[SecTypeID].start))
            print("type end=" + str(module.section_range[SecTypeID].end))
            # func_type list
            module.type_sec = self.read_type_sec()
        elif sec_id == SecImportID:
            module.section_range[SecImportID].start = self.reader.tell() - byte_count_size - 1
            module.section_range[SecImportID].end = self.reader.tell() + sec_size
            print("import start=" + str(module.section_range[SecImportID].start))
            print("import end=" + str(module.section_range[SecImportID].end))
            # import list
            module.import_sec = self.read_import_sec()
        elif sec_id == SecFuncID:
            module.section_range[SecFuncID].start = self.reader.tell() - byte_count_size - 1
            module.section_range[SecFuncID].end = self.reader.tell() + sec_size
            print("func start=" + str(module.section_range[SecFuncID].start))
            print("func end=" + str(module.section_range[SecFuncID].end))
            # type_idx list
            module.func_sec = self.read_indices()
        elif sec_id == SecTableID:
            module.section_range[SecTableID].start = self.reader.tell() - byte_count_size - 1
            module.section_range[SecTableID].end = self.reader.tell() + sec_size
            print("table start=" + str(module.section_range[SecTableID].start))
            print("table end=" + str(module.section_range[SecTableID].end))
            # table_type list
            module.table_sec = self.read_table_sec()
        elif sec_id == SecMemID:
            module.section_range[SecMemID].start = self.reader.tell() - byte_count_size - 1
            module.section_range[SecMemID].end = self.reader.tell() + sec_size
            print("mem start=" + str(module.section_range[SecMemID].start))
            print("mem end=" + str(module.section_range[SecMemID].end))
            # mem_type list 长度只能为1
            module.mem_sec = self.read_mem_sec()
        elif sec_id == SecGlobalID:
            module.section_range[SecGlobalID].start = self.reader.tell() - byte_count_size - 1
            module.section_range[SecGlobalID].end = self.reader.tell() + sec_size
            print("global start=" + str(module.section_range[SecGlobalID].start))
            print("global end=" + str(module.section_range[SecGlobalID].end))
            # global list
            module.global_sec = self.read_global_sec()
        elif sec_id == SecExportID:
            module.section_range[SecExportID].start = self.reader.tell() - byte_count_size - 1
            module.section_range[SecExportID].end = self.reader.tell() + sec_size
            print("export start=" + str(module.section_range[SecExportID].start))
            print("export end=" + str(module.section_range[SecExportID].end))
            # export list
            module.export_sec = self.read_export_sec()
        elif sec_id == SecStartID:
            module.section_range[SecStartID].start = self.reader.tell() - byte_count_size - 1
            module.section_range[SecStartID].end = self.reader.tell() + sec_size
            print("start start=" + str(module.section_range[SecStartID].start))
            print("start end=" + str(module.section_range[SecStartID].end))
            # func_idx
            module.start_sec = self.read_start_sec()
        elif sec_id == SecElemID:
            module.section_range[SecElemID].start = self.reader.tell() - byte_count_size - 1
            module.section_range[SecElemID].end = self.reader.tell() + sec_size
            print("elem start=" + str(module.section_range[SecElemID].start))
            print("elem end=" + str(module.section_range[SecElemID].end))
            # elem list
            module.elem_sec = self.read_elem_sec()
        elif sec_id == SecCodeID:
            module.section_range[SecCodeID].start = self.reader.tell() - byte_count_size - 1
            module.section_range[SecCodeID].end = self.reader.tell() + sec_size
            print("code start=" + str(module.section_range[SecCodeID].start))
            print("code end=" + str(module.section_range[SecCodeID].end))
            # code list
            module.code_sec = self.read_code_sec()
        elif sec_id == SecDataID:
            module.section_range[SecDataID].start = self.reader.tell() - byte_count_size - 1
            module.section_range[SecDataID].end = self.reader.tell() + sec_size
            print("data start=" + str(module.section_range[SecDataID].start))
            print("data end=" + str(module.section_range[SecDataID].end))
            # data list
            module.data_sec = self.read_data_sec()

    def read_type_sec(self):
        """读取类型段"""
        vec = []
        for _ in range(self.read_var_u32()):
            vec.append(self.read_func_type())
        return vec

    def read_import_sec(self):
        """读取导入段"""
        vec = []
        for _ in range(self.read_var_u32()):
            vec.append(self.read_import())
        return vec

    def read_import(self):
        return Import(self.read_name(), self.read_name(), self.read_import_desc())

    def read_import_desc(self):
        desc = ImportDesc(self.read_byte())
        tag = desc.tag
        # type_idx
        if tag == ImportTagFunc:
            desc.func_type = self.read_var_u32()
        # table_type
        # table_type: 0x70|limits
        elif tag == ImportTagTable:
            desc.table = self.read_table_type()
        # mem_type
        # mem_type: limits
        elif tag == ImportTagMem:
            desc.mem = self.read_limits()
        # global_type
        # global_type: val_type|mut
        elif tag == ImportTagGlobal:
            desc.global_type = self.read_global_type()
        else:
            raise Exception("invalid import desc tag: %d" % tag)
        return desc

    def read_table_sec(self):
        """读取表段"""
        vec = []
        for _ in range(self.read_var_u32()):
            vec.append(self.read_table_type())
        return vec

    def read_mem_sec(self):
        """读取内存段"""
        vec = []
        for _ in range(self.read_var_u32()):
            vec.append(self.read_limits())
        return vec

    def read_global_sec(self):
        """读取全局段"""
        vec = []
        for _ in range(self.read_var_u32()):
            global_obj = Global(self.read_global_type(), self.read_expr())
            vec.append(global_obj)
        return vec

    def read_export_sec(self):
        """读取导出段"""
        vec = []
        for _ in range(self.read_var_u32()):
            vec.append(self.read_export())
        return vec

    def read_export(self):
        return Export(self.read_name(), self.read_export_desc())

    def read_export_desc(self):
        desc = ExportDesc(tag=self.read_byte(), idx=self.read_var_u32())
        tag = desc.tag
        if tag not in [ExportTagFunc, ExportTagTable, ExportTagMem, ExportTagGlobal]:
            raise Exception("invalid export desc tag: %d" % tag)
        return desc

    def read_start_sec(self):
        """读取起始段"""
        idx = self.read_var_u32()
        return idx

    def read_elem_sec(self):
        """读取元素段"""
        vec = []
        for _ in range(self.read_var_u32()):
            vec.append(self.read_elem())
        return vec

    def read_elem(self):
        return Elem(self.read_var_u32(), self.read_expr(), self.read_indices())

    def read_code_sec(self):
        """读取代码段"""
        vec = [Code()] * self.read_var_u32()
        for i in range(len(vec)):
            vec[i] = self.read_code(i)
        return vec

    def read_code(self, idx):
        n = self.read_var_u32()
        remaining_before_read = self.remaining()
        code = Code(self.read_locals_vec(), self.read_expr())
        if self.remaining() + int(n) != remaining_before_read:
            print("invalid code[%d]" % idx)
        if code.get_local_count() >= (1 << 32 - 1):
            raise Exception("too many locals: %d" % code.get_local_count())
        return code

    def read_locals_vec(self):
        vec = []
        for _ in range(self.read_var_u32()):
            vec.append(self.read_locals())
        return vec

    def read_locals(self):
        return Locals(self.read_var_u32(), self.read_val_type())

    def read_data_sec(self):
        """读取数据段"""
        vec = []
        for _ in range(self.read_var_u32()):
            vec.append(self.read_data())
        return vec

    def read_data(self):
        return Data(self.read_var_u32(), self.read_expr(), self.read_bytes())

    def read_val_types(self):
        vec = []
        for _ in range(self.read_var_u32()):
            vec.append(self.read_val_type())
        return vec

    def read_val_type(self):
        vt = self.read_byte()
        if vt not in [ValTypeI32, ValTypeI64, ValTypeF32, ValTypeF64, ValTypeV128]:
            raise Exception("malformed value type: %d" % vt)
        return vt

    def read_block_type(self):
        bt = self.read_var_s32()
        if bt < 0:
            if bt not in [BlockTypeI32, BlockTypeI64, BlockTypeF32, BlockTypeF64, BlockTypeV128, BlockTypeEmpty]:
                raise Exception("malformed block type: %d" % bt)

        return bt

    def read_func_type(self):
        ft = FuncType(self.read_byte(), self.read_val_types(), self.read_val_types())
        if ft.tag != FtTag:
            raise Exception("invalid functype tag: %d" % ft.tag)
        return ft

    def read_table_type(self):
        tt = TableType(self.read_byte(), self.read_limits())
        if tt.elem_type != FuncRef:
            raise Exception("invalid elemtype: %d" % tt.elem_type)
        return tt

    def read_global_type(self):
        # val_type : ValTypeI32, ValTypeI64, ValTypeF32, ValTypeF64
        # 第二个参数为mut
        gt = GlobalType(self.read_val_type(), self.read_byte())
        if gt.mut not in [MutConst, MutVar]:
            raise Exception("malformed mutability: %d" % gt.mut)
        return gt

    def read_limits(self):
        limits = Limits(self.read_byte(), self.read_var_u32())
        if limits.tag == 1:
            limits.max = self.read_var_u32()
        return limits

    def read_indices(self):
        vec = []
        for _ in range(self.read_var_u32()):
            vec.append(self.read_var_u32())
        return vec

    def read_expr(self):
        instrs, end = self.read_instructions()
        if end != End_:
            raise Exception("invalid expr end: %d" % end)
        return instrs

    def read_instructions(self):
        """
        读取并收集指令，直到遇到else或者end指令为止
        :return:
        """
        instrs = []
        while (True):
            instr = self.read_instruction()
            if instr.opcode == Else_ or instr.opcode == End_:
                end = instr.opcode
                return instrs, end
            # 这里是没有把else和end放到instrs里面的
            instrs.append(instr)

    def read_instruction(self):
        """
        先读取操作码，然后根据操作码读取立即数
        :return:
        """
        instr = Instruction()
        instr.opcode = self.read_byte()
        # 2-bytes instr
        if instr.opcode == 0xFC:
            instr.opcode = instr.opcode*256 + self.read_byte()
        elif instr.opcode == 0xFD:
            second_byte = self.read_byte()
            # 3-bytes instr
            if second_byte > 0x7F:
                instr.opcode = instr.opcode * 256 * 256 + second_byte * 256 + self.read_byte()
            # 2-bytes instr
            else:
                instr.opcode = instr.opcode * 256 + second_byte
        # 判断是否为正确操作码
        if opnames[instr.opcode] == "":
            raise Exception("undefined opcode: 0x%02x" % instr.opcode)
        # 读取指令操作数
        instr.args = self.read_args(instr.opcode)
        return instr

    def read_args(self, opcode):
        if opcode in [Block, Loop]:
            return self.read_block_args()
        elif opcode == If:
            return self.read_if_args()
        elif opcode in [Br, BrIf]:
            return self.read_var_u32()
        elif opcode == BrTable:
            return self.read_br_table_args()
        elif opcode == Call:
            return self.read_var_u32()
        elif opcode == CallIndirect:
            return self.read_call_indirect_args()
        elif opcode in [LocalGet, LocalSet, LocalTee]:
            return self.read_var_u32()
        elif opcode in [GlobalGet, GlobalSet]:
            return self.read_var_u32()
        elif opcode in [MemorySize, MemoryGrow]:
            return self.read_zero()
        elif opcode == I32Const:
            return self.read_var_s32()
        elif opcode == I64Const:
            return self.read_var_s64()
        elif opcode == F32Const:
            return self.read_f32()
        elif opcode == F64Const:
            return self.read_f64()
        elif opcode == V128Const:
            return self.read_v128()
        elif opcode == I8x16Shuffle:
            return self.read_v128()
        elif I8x16ExtractLaneS <= opcode <= F64x2ReplaceLane:
            return self.read_lane()
        elif opcode in [RefNull, RefFunc]:
            return self.read_var_u32()
        elif opcode in [MemoryInit, DataDrop, ElemDrop, TableGrow, TableSize, TableFill]:
            return self.read_var_u32()
        elif opcode in [TableInit, TableCopy]:
            x = self.read_var_u32()
            y = self.read_var_u32()
            return TableArg(x, y)
        elif V128Load <= opcode <= V128Store or opcode in [V128Load32Zero, V128Load64Zero]:
            return self.read_mem_arg()
        elif V128Load8Lane <= opcode <= V128Store64Lane:
            mem_arg = self.read_mem_arg()
            laneidx = self.read_lane()
            return MemLaneArg(mem_arg, laneidx)
        elif I32Load <= opcode <= I64Store32:
            return self.read_mem_arg()
        else:
            return None

    def read_block_args(self):
        """读取block参数"""
        args = BlockArgs()
        args.bt = self.read_block_type()
        args.instrs, end = self.read_instructions()
        if end != End_:
            raise Exception("invalid block end: %d" % end)
        return args

    def read_if_args(self):
        """读取if参数"""
        args = IfArgs()
        args.bt = self.read_block_type()
        args.instrs1, end = self.read_instructions()
        if end == Else_:
            args.instrs2, end = self.read_instructions()
            if end != End_:
                raise Exception("invalid block end: %d" % end)
        return args

    def read_br_table_args(self):
        """读取br_table参数"""
        return BrTableArgs(self.read_indices(), self.read_var_u32())

    def read_call_indirect_args(self):
        """读取call indirect参数"""
        type_idx = self.read_var_u32()
        self.read_zero()
        return type_idx

    def read_mem_arg(self):
        """读取内存的参数"""
        return MemArg(self.read_var_u32(), self.read_var_u32())

    def read_zero(self):
        b = self.read_byte()
        if b != 0:
            raise Exception("zero flag expected, got %d" % b)
        return 0
