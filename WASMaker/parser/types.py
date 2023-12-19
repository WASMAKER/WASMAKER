# -*- coding: UTF-8 -*-
"""
@Project ：wasmObfuscator 
@File    ：types.py
@Author  ：格友
"""

# wasm基本类型
# 32位整数（简称i32）
ValTypeI32 = 0x7F
# 64位整数（简称i64）
ValTypeI64 = 0x7E
# 32位浮点数（简称f32）
ValTypeF32 = 0x7D
# 64位浮点数（简称f64）
ValTypeF64 = 0x7C
# 128位向量
ValTypeV128 = 0x7B
# 任意类型
ValTypeAny = 0x7C

# 结构化控制指令类型，非负数索引指向类型段，LEB128编码
BlockTypeI32 = -1  # ()->(i32)
BlockTypeI64 = -2  # ()->(i64)
BlockTypeF32 = -3  # ()->(f32)
BlockTypeF64 = -4  # ()->(f64)
BlockTypeV128 = -5 # ()->(v128)
BlockTypeEmpty = -64  # ()->()

FtTag = 0x60  # 函数类型 func_type
FuncRef = 0x70  # 函数引用类型 table_type
ExternRef = 0x6F # TODO

MutConst = 0  # 全局变量可变与否 global_type
MutVar = 1  # 可变


class FuncType:
    """
    函数类型：函数的签名或原型
    """

    def __init__(self, tag=0, param_types=None, result_types=None):
        if result_types is None:
            result_types = []
        if param_types is None:
            param_types = []
        self.tag = tag
        # 函数的参数数量和类型
        self.param_types = param_types
        # 函数的返回值数量和类型
        self.result_types = result_types

    def equal(self, ft2) -> bool:  # 比较
        if len(self.param_types) != len(ft2.param_types) \
                or len(self.result_types) != len(ft2.result_types):
            return False
        for i, vt in enumerate(self.param_types):
            if vt != ft2.param_types[i]:
                return False
        for i, vt in enumerate(self.result_types):
            if vt != ft2.result_types[i]:
                return False
        return True

    def print_signature(self) -> str:  # 打印函数类型
        sb = "("
        sb += ",".join([val_type_to_str(vt) for vt in self.param_types])
        sb += ")->("
        sb += ",".join([val_type_to_str(vt) for vt in self.result_types])
        sb += ")"
        return sb

    def get_signature(self):
        arg_types = []
        ret_types = []
        for valtype in self.param_types:
            if valtype == ValTypeI32:
                arg_types.append("i32")
            elif valtype == ValTypeI64:
                arg_types.append("i64")
            elif valtype == ValTypeF32:
                arg_types.append("f32")
            elif valtype == ValTypeF64:
                arg_types.append("f64")
        for valtype in self.result_types:
            if valtype == ValTypeI32:
                ret_types.append("i32")
            elif valtype == ValTypeI64:
                ret_types.append("i64")
            elif valtype == ValTypeF32:
                ret_types.append("f32")
            elif valtype == ValTypeF64:
                ret_types.append("f64")
        return arg_types, ret_types

    def __str__(self):
        return self.print_signature()


class Limits:
    """
    限制类型：描述表的元素数量上下限，或者内存的页数上下限
    limits    : tag|min|max?
    """

    def __init__(self, tag=0, min=0, max=0):
        # 如果tag是0，表示只指定下限。否则，tag必须为1，表示既指定下限，又指定上限
        self.tag = tag
        self.min = min
        self.max = max

    def __str__(self):
        return "{min: %d, max: %d}" % (self.min, self.max)


# 内存类型
# mem_type: limits
MemType = Limits


class TableType:
    """
    表类型：描述表的元素类型和元素数量的限制
    table_type: 0x70|limits
    """

    def __init__(self, elem_type=0x70, limits=None):
        # 元素类型
        self.elem_type = elem_type
        # 元素数量的限制
        self.limits = limits


class GlobalType:
    """
    全局变量类型：描述全局变量的类型和可变性
    global_type: val_type|mut
    """

    def __init__(self, val_type=0, mut=0):
        # 全局变量的类型
        self.val_type = val_type
        # 可变性 1可变0不可变
        self.mut = mut

    def __str__(self):
        return "{type: %s, mut: %d}" % (val_type_to_str(self.val_type), self.mut)


class NameAssoc:
    """
    name_assoc 用来指示函数名称，调试用
    """
    def __init__(self, idx=0, name=None):
        # idx
        self.idx = idx
        # 函数名
        self.name = name

    def __str__(self):
        return "{id: %d, name: %s}" % (self.idx, self.name)


def val_type_to_str(vt) -> str:
    if vt == ValTypeI32:
        return "i32"
    elif vt == ValTypeI64:
        return "i64"
    elif vt == ValTypeF32:
        return "f32"
    elif vt == ValTypeF64:
        return "f64"
    else:
        raise Exception("invalid valtype: %d" % vt)
