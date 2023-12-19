# -*- coding: UTF-8 -*-
"""
@Project ：wasmObfuscator 
@File    ：module.py
@Author  ：格友
"""
from ..parser.types import BlockTypeI32, BlockTypeI64, BlockTypeF32, BlockTypeF64, BlockTypeEmpty, FuncType, \
    ValTypeI32, ValTypeI64, ValTypeF32, ValTypeF64

# 小端方式编码数值，魔数：0asm
MagicNumber = 0x6D736100
# 版本号：1
Version = 0x00000001

# 12种段
# 自定义段ID
SecCustomID = 0
# 类型段ID
SecTypeID = 1
# 导入段ID
SecImportID = 2
# 函数段ID
SecFuncID = 3
# 表段ID
SecTableID = 4
# 内存段ID
SecMemID = 5
# 全局段ID
SecGlobalID = 6
# 导出段ID
SecExportID = 7
# 起始段ID
SecStartID = 8
# 元素段ID
SecElemID = 9
# 代码段ID
SecCodeID = 10
# 数据段ID
SecDataID = 11

# tag={0 ： "函数", 1 : "表", 2 : "内存", 3 : "全局变量"}
ImportTagFunc = 0
ImportTagTable = 1
ImportTagMem = 2
ImportTagGlobal = 3

# tag={0 ： "函数", 1 : "表", 2 : "内存", 3 : "全局变量"}
ExportTagFunc = 0
ExportTagTable = 1
ExportTagMem = 2
ExportTagGlobal = 3

# 索引空间
# 类型索引：类型段的有效索引范围就是类型索引空间
TypeIdx = int
# 函数索引：由外部函数和内部函数共同构成
FuncIdx = int
# 表和内存索引：只能导入或定义一份表和内存，所以索引空间内的唯一有效索引为0
TableIdx = int
MemIdx = int
# 全局变量索引：由外部和内部全局变量共同构成
GlobalIdx = int
# 局部变量索引：由函数的参数和局部变量共同构成
LocalIdx = int
# 跳转标签索引：每个函数有自己的跳转标签索引空间
LabelIdx = int


class Module:
    """模型"""

    def __init__(self, magic=None, version=None):
        # 魔数
        if magic:
            self.magic = magic
        else:
            self.magic = 0
        # 版本号
        if version:
            self.version = version
        else:
            self.version = 0
        # 自定义段 0
        # custom_sec: 0x00|byte_count|name|byte*
        self.custom_secs = []
        # 类型段 1
        # type_sec: 0x01|byte_count|vec<func_type>
        self.type_sec = []
        # 导入段 2
        # import_sec : 0x02|byte_count|vec<import>
        self.import_sec = []
        # 函数段 3
        # func_sec: 0x03|byte_count|vec<type_idx>
        self.func_sec = []
        # 表段 4
        # table_sec : 0x04|byte_count|vec<table_type>
        self.table_sec = []
        # 内存段 5
        # mem_sec : 0x05|byte_count|vec<mem_type> 目前vec长度只能是1
        self.mem_sec = []
        # 全局段 6
        # global_sec : 0x06|byte_count|vec<global>
        self.global_sec = []
        # 导出段 7
        # export_sec : 0x07|byte_count|vec<export>
        self.export_sec = []
        # 起始段 8
        # start_sec: 0x08|byte_count|func_idx
        self.start_sec = None  # 函数指针，指向起始函数
        # 元素段 9
        # elem_sec: 0x09|byte_count|vec<elem>
        self.elem_sec = []
        # 代码段 10
        # code_sec: 0x0A|byte_count|vec<code>
        self.code_sec = []
        # 数据段 11
        # data_sec: 0x0B|byte_count|vec<data>
        self.data_sec = []
        # 段大小范围
        self.section_range = []
        self.section_range.append([])  # 因为custom会出现多次，所以数组存储
        for i in range(11):
            self.section_range.append(SectionRange())

    def get_block_type(self, bt):
        """
        块类型转换成相应的函数类型
        @param bt:
        @return:
        """
        if bt == BlockTypeI32:
            return FuncType(result_types=[ValTypeI32])
        elif bt == BlockTypeI64:
            return FuncType(result_types=[ValTypeI64])
        elif bt == BlockTypeF32:
            return FuncType(result_types=[ValTypeF32])
        elif bt == BlockTypeF64:
            return FuncType(result_types=[ValTypeF64])
        elif bt == BlockTypeEmpty:
            return FuncType()
        else:
            return self.type_sec[bt]


class SectionRange:
    """
    标注wasm各段文件偏移范围  [start, end)
    """

    def __init__(self, start=0, end=0, name=None):
        self.start = start
        self.end = end
        # 只有custom段才有name
        self.name = name


class CustomSec:
    """
    自定义段
    custom_sec: 0x00|byte_count|name|name_data
    """

    def __init__(self, name="", custom_sec_data=None, name_data=None):
        self.name = name
        self.custom_sec_data = custom_sec_data
        self.name_data = name_data


class NameData:
    """
    name_data: modulenamesubsec?|funcnamesubsec?|localnamesubsec?
    funcnamesubsec: 0x01|byte_count|namemap
    """

    def __init__(self, moduleNameSubSec=None, funcNameSubSec=None, globalNameSubSec=None, dataNameSubSec=None, tableNameSubSec=None,
                 local_bytes=None, labels_bytes=None, type_bytes=None, memory_bytes=None, elem_bytes=None):

        self.moduleNameSubSec = None
        self.localNameSubSec = None
        self.labelsNameSubSec = None
        self.typeNameSubSec = None
        self.memoryNameSubSec = None
        self.elemNameSubSec = None

        if not funcNameSubSec is None:
            self.funcNameSubSec = funcNameSubSec
        if not globalNameSubSec is None:
            self.globalNameSubSec = globalNameSubSec
        if not dataNameSubSec is None:
            self.dataNameSubSec = dataNameSubSec
        if not tableNameSubSec is None:
            self.tableNameSubSec = tableNameSubSec

        if not moduleNameSubSec is None:
            self.moduleNameSubSec = moduleNameSubSec
        if not local_bytes is None:
            self.localNameSubSec = local_bytes
        if not labels_bytes is None:
            self.labelsNameSubSec = labels_bytes
        if not type_bytes is None:
            self.typeNameSubSec = type_bytes
        if not memory_bytes is None:
            self.memoryNameSubSec = memory_bytes
        if not elem_bytes is None:
            self.elemNameSubSec = elem_bytes


class Import:
    """
    导入类型：函数、表、内存、全局变量
    import_sec: 0x02|byte_count|vec<import>
    import     : module_name|member_name|import_desc
    """

    def __init__(self, module="", name="", desc=None):
        # 模块名（从哪个模块导入）
        self.module = module
        # 成员名
        self.name = name
        # 具体描述信息
        self.desc = desc


class ImportDesc:
    """
    import_desc: tag|[type_idx, table_type, mem_type, global_type]
    """

    def __init__(self, tag, func_type=None, table=None, mem=None, global_type=None):
        # 0表示函数、1表示表、2表示内存、3表示全局变量，最终解析时只有一个成员有值
        self.tag = tag
        self.func_type = func_type
        self.table = table
        self.mem = mem
        self.global_type = global_type


class Global:
    """
    global_sec: 0x06|byte_count|vec<global>
    global     : global_type|init_expr
    """

    def __init__(self, global_type=None, init=None):
        self.type = global_type
        self.init = init


class Export:
    """
    export_sec: 0x07|byte_count|vec<export>
    export     : name|export_desc
    """

    def __init__(self, name="", export_desc=None):
        self.name = name
        self.desc = export_desc


class ExportDesc:
    """
    export_desc: tag|[func_idx, table_idx, mem_idx, global_idx]
    """

    def __init__(self, tag=0, idx=0):
        self.tag = tag
        self.idx = idx


class Elem:
    """
    elem_sec: 0x09|byte_count|vec<elem>
    elem    : table_idx|offset_expr|vec<func_idx>
    """

    def __init__(self, table_idx=0, offset_expr=None, vec_init=None):
        if vec_init is None:
            vec_init = []
        self.table = table_idx
        self.offset = offset_expr
        self.init = vec_init


class Code:
    """
    code_sec: 0x0A|byte_count|vec<code>
    locals: local_count|val_type
    code    : byte_count|vec<locals>|expr
    """

    def __init__(self, locals_vec=None, expr=None):
        if locals_vec is None:
            locals_vec = []
        self.locals = locals_vec
        self.expr = expr

    """
    获取方法的局部变量数，为了节约空间，局部变量信息是压缩后存储的：
    连续多个相同类型的局部变量会被分为一组，统一记录变量数量和类型
    所以for循环遍历locals组
    """

    def get_local_count(self) -> int:
        n = 0
        for locals_item in self.locals:
            n += locals_item.n
        return n


class Locals:
    """
    locals  : local_count|val_type
    """

    def __init__(self, local_count=0, val_type=0):
        self.n = local_count
        self.type = val_type

    def convert_locals(self):
        local_vec = [self.type] * self.n
        return local_vec

    def __str__(self):
        return "{type: %d, n: %d}" % (self.type, self.n)

class Data:
    """
    data_sec: 0x0B|byte_count|vec<data>
    data    : mem_idx|offset_expr|vec<byte>
    内存索引、内存偏移量、初始数据
    """

    def __init__(self, mem_idx=0, offset_expr=None, vec_init=None):
        if vec_init is None:
            vec_init = []
        self.mem = mem_idx
        self.offset = offset_expr
        self.init = vec_init
