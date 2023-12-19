# -*- coding: UTF-8 -*-
"""
@Project ：wasmObfuscator 
@File    ：instruction.py
@Author  ：格友
"""

from ..parser.opnames import opnames
from ..parser.opcodes import Block, If, Loop


class Expr(list):
    """
    表达式
    expr  : instr*|0x0b
    """

    def __init__(self):
        super().__init__()


class Instruction:
    """指令结构，数值指令，变量指令，跳转指令，直接函数调用指令"""

    def __init__(self, opcode=None, args=None):
        # 操作码
        self.opcode = opcode
        # 操作数
        self.args = args

    def get_opname(self):
        return opnames[self.opcode]

    def __str__(self):
        return opnames[self.opcode]

    def to_json(self):
        # block loop if的参数就是其类型
        if self.opcode in [Block, Loop]:
            return {'opcode': self.opcode, 'args': self.args.bt}
        elif self.opcode in [If]:
            return {'opcode': self.opcode, 'args': self.args.bt}
        # 对于和memory有关的指令，就记录offset即可
        elif type(self.args) == MemArg:
            return {'opcode': self.opcode, 'args': self.args.offset}
        # 对于brtable只存储跳转表
        elif type(self.args) == BrTableArgs:
            return {'opcode': self.opcode, 'args': self.args.labels}
        else:
            return {'opcode': self.opcode, 'args': self.args}

class BlockArgs:
    """
    block和loop指令的参数
    block_instr: 0x02|block_type|instr*|0x0b
    loop_instr: 0x03|block_type|instr*|0x0b
    """

    def __init__(self, bt=None, instrs=None):
        # block type:
        # -1表示i32类型结果，-2表示i64类型结果，
        # -3表示f32类型结果，-4表示f64类型结果，
        # -64表示没有结果
        self.bt = bt
        # 内嵌的指令序列
        self.instrs = instrs


class IfArgs:
    """
    if指令的参数
    if_instr: 0x04|block_type|instr*|(0x05|instr*)?|0x0b
    """

    def __init__(self, bt=None, instrs1=[], instrs2=[]):
        # block type
        self.bt = bt
        self.instrs1 = instrs1
        self.instrs2 = instrs2


class BrTableArgs:
    """br_table指令的参数"""

    def __init__(self, labels=None, default=None):
        # 跳转表
        if labels is None:
            labels = []
        self.labels = labels
        # 默认跳转标签
        self.default = default


class MemArg:
    """load store 内存加载/存储系列指令需要指定内存偏移量和对齐提示"""

    def __init__(self, align=0, offset=0):
        # 对齐提示
        self.align = align
        # 内存偏移量
        self.offset = offset


class TableArg:
    """table.init and table.copy"""

    def __init__(self, x=0, y=0):
        self.x = x
        self.y = y


class MemLaneArg:
    """v128.load8_lane to v128.store64_lane"""

    def __init__(self, mem_arg=None, laneidx=0):
        self.mem_arg = mem_arg
        self.laneidx = laneidx