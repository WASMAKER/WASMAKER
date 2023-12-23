import numpy
from WASMaker.fuzzer.AST import Node
from WASMaker.fuzzer.instructions import *
from WASMaker.parser.instruction import Instruction, MemArg, MemLaneArg
from WASMaker.parser.opnames import *
import random
import struct

from WASMaker.parser.types import Limits, BlockTypeF64, BlockTypeV128


def generate_random_number(valtype):
    rand_prob = random.random()
    if valtype == ValTypeI32:
        if rand_prob < 0.7:
            return random.randint(0, 1)
        elif rand_prob < 0.85:
            return 0
        else:
            return 1
    elif valtype == ValTypeI64:
        if rand_prob < 0.7:
            return random.randint(0, 2 ** 64 - 1)
        elif rand_prob < 0.85:
            return 0
        else:
            return 2 ** 64 - 1
    elif valtype == ValTypeF32:
        if rand_prob < 0.7:
            random_float = struct.unpack('f', struct.pack('I', random.randint(0, 2 ** 32 - 1)))[0]
            return random_float
        elif rand_prob < 0.85:
            return 0.0
        else:
            max_float = struct.unpack('f', struct.pack('I', 2 ** 32 - 1))[0]
            return max_float
    elif valtype == ValTypeF64:
        if rand_prob < 0.7:
            random_int64 = random.getrandbits(64)
            random_float = float(random_int64)
            return random_float
        elif rand_prob < 0.85:
            return 0.0
        else:
            max_float = float(2 ** 64 - 1)
            return max_float
    elif valtype == ValTypeV128:
        if rand_prob < 0.7:
            return random.randint(0, 2 ** 128 - 1)
        elif rand_prob < 0.85:
            return 0
        else:
            return 2 ** 128 - 1


_to_ = [Block, Loop, Else_, Call, CallIndirect, LocalGet, LocalSet, LocalTee, GlobalGet, GlobalSet, DataDrop, ElemDrop]

I32_to_ = [If]

I32_to_I32 = [I32Load, I32Load8S, I32Load8U, I32Load16S, I32Load16U, I32Eqz, I32Clz, I32Ctz, I32PopCnt, I32Extend8S,
              I32Extend16S, TableGrow, I32Load8S, I32Load8U, I32Load16S, I32Load16U, I32Extend8S, I32Extend16S]

I32_to_I64 = [I64Load, I64Load8S, I64Load8U, I64Load16S, I64Load16U, I64Load32S, I64Load32U, I64ExtendI32S,
              I64ExtendI32U, I64Extend8S, I64Extend16S, I64Extend32S, I64Load8S, I64Load8U, I64Load16S, I64Load16U,
              I64Load32S, I64Load32U]

I32_to_F32 = [F32Load, F32ConvertI32S, F32ConvertI32U, F32ReinterpretI32]

I32_to_F64 = [F64Load, F64ConvertI32S, F64ConvertI32U]

I32_I32_to_ = [I32Store, I32Store8, I32Store16, TableFill, I32Store8, I32Store16]

I32_I64_to_ = [I64Store, I64Store8, I64Store16, I64Store32, I64Store8, I64Store16, I64Store32]

I32_F32_to_ = [F32Store]

I32_F64_to_ = [F64Store]

Any__to_ = [Drop]

Any__Any__I32_to_Any_ = [Select, SelectT]

_to_I32 = [I32Const, TableSize]

_to_I64 = [I64Const]

_to_F32 = [F32Const]

_to_F64 = [F64Const]

I32_I32_to_I32 = [I32Eq, I32Ne, I32LtS, I32LtU, I32GtS, I32GtU, I32LeS, I32LeU, I32GeS, I32GeU, I32Add, I32Sub, I32Mul,
                  I32DivS, I32DivU, I32RemS, I32RemU, I32And, I32Or, I32Xor, I32Shl, I32ShrS, I32ShrU, I32Rotl, I32Rotr]

I64_to_I32 = [I64Eqz, I32WrapI64]

I64_I64_to_I32 = [I64Eq, I64Ne, I64LtS, I64LtU, I64GtS, I64GtU, I64LeS, I64LeU, I64GeS, I64GeU]

F32_F32_to_I32 = [F32Eq, F32Ne, F32Lt, F32Gt, F32Le, F32Ge]

F64_F64_to_I32 = [F64Eq, F64Ne, F64Lt, F64Gt, F64Le, F64Ge]

I64_to_I64 = [I64Clz, I64Ctz, I64PopCnt, I64Extend8S, I64Extend16S, I64Extend32S]

I64_I64_to_I64 = [I64Add, I64Sub, I64Mul, I64DivS, I64DivU, I64RemS, I64RemU, I64And, I64Or, I64Xor, I64Shl, I64ShrS,
                  I64ShrU, I64Rotl, I64Rotr]

F32_to_F32 = [F32Abs, F32Neg, F32Ceil, F32Floor, F32Trunc, F32Nearest, F32Sqrt]

F32_F32_to_F32 = [F32Add, F32Sub, F32Mul, F32Div, F32Min, F32Max, F32CopySign, F32CopySign]

F64_to_F64 = [F64Abs, F64Neg, F64Ceil, F64Floor, F64Trunc, F64Nearest, F64Sqrt]

F64_F64_to_F64 = [F64Add, F64Sub, F64Mul, F64Div, F64Min, F64Max, F64CopySign, F64CopySign]

F32_to_I32 = [I32TruncF32S, I32TruncF32U, I32ReinterpretF32, I32TruncSatF32S, I32TruncSatF32U]

F64_to_I32 = [I32TruncF64S, I32TruncF64U, I32TruncSatF64S, I32TruncSatF64U]

F32_to_I64 = [I64TruncF32S, I64TruncF32U, I64TruncSatF32S, I64TruncSatF32U]

F64_to_I64 = [I64TruncF64S, I64TruncF64U, I64ReinterpretF64, I64TruncSatF64S, I64TruncSatF64U]

I64_to_F32 = [F32ConvertI64S, F32ConvertI64U]

F64_to_F32 = [F32DemoteF64]

I64_to_F64 = [F64ConvertI64S, F64ConvertI64U, F64ReinterpretI64]

F32_to_F64 = [F64PromoteF32]

I32_I32_I32_to_ = [MemoryInit, MemoryCopy, MemoryFill, TableInit, TableCopy]

I32_to_Any_ = [TableGet]

I32_Any__to_ = [TableSet]

_to_Any_ = [RefNull]

Any__to_I32 = [RefIsNull]

I32_to_V128 = [V128Load, V128Load8x8S, V128Load8x8U, V128Load16x4S, V128Load16x4U, V128Load32x2S, V128Load32x2U,
               V128Load8Splat, V128Load16Splat, V128Load32Splat, V128Load64Splat, I8x16Splat, I16x8Splat, I32x4Splat,
               V128Load32Zero, V128Load64Zero]

I32_V128_to_ = [V128Store, V128Store8Lane, V128Store16Lane, V128Store32Lane, V128Store64Lane]

_to_V128 = [V128Const]

V128_V128_to_V128 = [I8x16Shuffle, I8x16Swizzle, I8x16Eq, I8x16Ne, I8x16LtS, I8x16LtU, I8x16GtS, I8x16GtU, I8x16LeS,
                     I8x16LeU, I8x16GeS, I8x16GeU, I16x8Eq, I16x8Ne, I16x8LtS, I16x8LtU, I16x8GtS, I16x8GtU, I16x8LeS,
                     I16x8LeU, I16x8GeS, I16x8GeU, I32x4Eq, I32x4Ne, I32x4LtS, I32x4LtU, I32x4GtS, I32x4GtU, I32x4LeS,
                     I32x4LeU, I32x4GeS, I32x4GeU, F32x4Eq, F32x4Ne, F32x4Lt, F32x4Gt, F32x4Le, F32x4Ge, F64x2Eq,
                     F64x2Ne, F64x2Lt, F64x2Gt, F64x2Le, F64x2Ge, V128And, V128AndNot, V128Or, V128Xor,
                     I8x16NarrowI16x8S, I8x16NarrowI16x8U, I8x16Add, I8x16AddSatS, I8x16AddSatU, I8x16Sub, I8x16SubSatS,
                     I8x16SubSatU, I8x16MinS, I8x16MinU, I8x16MaxS, I8x16MaxU, I8x16AvgrU, I16x8Q15mulrSatS,
                     I16x8NarrowI32x4S, I16x8NarrowI32x4U, I16x8Add, I16x8AddSatS, I16x8AddSatU, I16x8Sub, I16x8SubSatS,
                     I16x8SubSatU, I16x8Mul, I16x8MinS, I16x8MinU, I16x8MaxS, I16x8MaxU, I16x8AvgrU,
                     I16x8ExtmulLowI8x16S, I16x8ExtmulHighI8x16S, I16x8ExtmulLowI8x16U, I16x8ExtmulHighI8x16U, I32x4Add,
                     I32x4Sub, I32x4Mul, I32x4MinS, I32x4MinU, I32x4MaxS, I32x4MaxU, I32x4DotI16x8S,
                     I32x4ExtmulLowI16x8S, I32x4ExtmulHighI16x8S, I32x4ExtmulLowI16x8U, I32x4ExtmulHighI16x8U, I64x2Add,
                     I64x2Sub, I64x2Mul, I64x2Eq, I64x2Ne, I64x2LtS, I64x2GtS, I64x2LeS, I64x2GeS, I64x2ExtmulLowI32x4S,
                     I64x2ExtmulHighI32x4S, I64x2ExtmulLowI32x4U, I64x2ExtmulHighI32x4U, F32x4Add, F32x4Sub, F32x4Mul,
                     F32x4Div, F32x4Min, F32x4Max, F32x4Pmin, F32x4Pmax, F64x2Add, F64x2Sub, F64x2Mul, F64x2Div,
                     F64x2Min, F64x2Max, F64x2Pmin, F64x2Pmax]

I64_to_V128 = [I64x2Splat]

F32_to_V128 = [F32x4Splat]

F64_to_V128 = [F64x2Splat]

V128_to_I32 = [I8x16ExtractLaneS, I8x16ExtractLaneU, I16x8ExtractLaneS, I16x8ExtractLaneU, I32x4ExtractLane,
               V128AnyTrue, I8x16AllTrue, I8x16Bitmask, I16x8AllTrue, I16x8Bitmask, I32x4AllTrue, I32x4Bitmask,
               I64x2AllTrue, I64x2Bitmask]

V128_I32_to_V128 = [I8x16ReplaceLane, I16x8ReplaceLane, I32x4ReplaceLane, I8x16Shl, I8x16ShrS, I8x16ShrU, I16x8Shl,
                    I16x8ShrS, I16x8ShrU, I32x4Shl, I32x4ShrS, I32x4ShrU, I64x2Shl, I64x2ShrS, I64x2ShrU]

V128_to_I64 = [I64x2ExtractLane]

V128_I64_to_V128 = [I64x2ReplaceLane]

V128_to_F32 = [F32x4ExtractLane]

V128_F32_to_V128 = [F32x4ReplaceLane]

V128_to_F64 = [F64x2ExtractLane]

V128_F64_to_V128 = [F64x2ReplaceLane]

V128_to_V128 = [V128Not, F32x4DemoteF64x2Zero, F64x2PromoteLowF32x4, I8x16Abs, I8x16Neg, I8x16Popcnt, F32x4Ceil,
                F32x4Floor, F32x4Trunc, F32x4Nearest, F64x2Ceil, F64x2Floor, F64x2Trunc, I16x8ExtaddPairwiseI8x16S,
                I16x8ExtaddPairwiseI8x16U, I32x4ExtaddPairwiseI16x8S, I32x4ExtaddPairwiseI16x8U, I16x8Abs, I16x8Neg,
                I16x8ExtendLowI8x16S, I16x8ExtendHighI8x16S, I16x8ExtendLowI8x16U, I16x8ExtendHighI8x16U, F64x2Nearest,
                I32x4Abs, I32x4Neg, I32x4ExtendLowI16x8S, I32x4ExtendHighI16x8S, I32x4ExtendLowI16x8U,
                I32x4ExtendHighI16x8U, I64x2Abs, I64x2Neg, I64x2ExtendLowI32x4S, I64x2ExtendHighI32x4S,
                I64x2ExtendLowI32x4U, I64x2ExtendHighI32x4U, F32x4Abs, F32x4Neg, F32x4Sqrt, F64x2Abs, F64x2Neg,
                F64x2Sqrt, I32x4TruncSatF32x4S, I32x4TruncSatF32x4U, F32x4ConvertI32x4S, F32x4ConvertI32x4U,
                I32x4TruncSatF64x2SZero, I32x4TruncSatF64x2UZero, F64x2ConvertLowI32x4S, F64x2ConvertLowI32x4U]

V128_V128_V128_to_V128 = [V128BitSelect]

I32_V128_to_V128 = [V128Load8Lane, V128Load16Lane, V128Load32Lane, V128Load64Lane]


def get_instrs(params_type, results_type):
    if params_type == [ValTypeI32] and results_type == [ValTypeI32]:
        return I32_to_I32
    elif params_type == [ValTypeI32] and results_type == [ValTypeI64]:
        return I32_to_I64
    elif params_type == [ValTypeI32] and results_type == [ValTypeF32]:
        return I32_to_F32
    elif params_type == [ValTypeI32] and results_type == [ValTypeF64]:
        return I32_to_F64
    elif params_type == [ValTypeI32, ValTypeI32] and results_type == []:
        return I32_I32_to_
    elif params_type == [ValTypeI32, ValTypeI64] and results_type == []:
        return I32_I64_to_
    elif params_type == [ValTypeI32, ValTypeF32] and results_type == []:
        return I32_F32_to_
    elif params_type == [ValTypeI32, ValTypeF64] and results_type == []:
        return I32_F64_to_
    elif params_type == [ValTypeI32, ValTypeI32] and results_type == [ValTypeI32]:
        return I32_I32_to_I32
    elif params_type == [ValTypeI64] and results_type == [ValTypeI32]:
        return I64_to_I32
    elif params_type == [ValTypeI64, ValTypeI64] and results_type == [ValTypeI32]:
        return I64_I64_to_I32
    elif params_type == [ValTypeF32, ValTypeF32] and results_type == [ValTypeI32]:
        return F32_F32_to_I32
    elif params_type == [ValTypeF64, ValTypeF64] and results_type == [ValTypeI32]:
        return F64_F64_to_I32
    elif params_type == [ValTypeF64, ValTypeF64] and results_type == [ValTypeF64]:
        return F64_F64_to_F64
    elif params_type == [ValTypeI64, ValTypeI64] and results_type == [ValTypeI64]:
        return I64_I64_to_I64
    elif params_type == [ValTypeF32] and results_type == [ValTypeI32]:
        return F32_to_I32
    elif params_type == [ValTypeF64] and results_type == [ValTypeI32]:
        return F64_to_I32
    elif params_type == [ValTypeF32] and results_type == [ValTypeI64]:
        return F32_to_I64
    elif params_type == [ValTypeF64] and results_type == [ValTypeI64]:
        return F64_to_I64
    elif params_type == [ValTypeI64] and results_type == [ValTypeF64]:
        return I64_to_F64
    elif params_type == [ValTypeF32] and results_type == [ValTypeF64]:
        return F32_to_F64
    else:
        raise Exception("type not found!")


def random_integer_from_ranges(ranges):
    ranges = [(1, 100), (200, 300), (890, 1000)]
    result = None
    total_range = sum(end - start + 1 for start, end in ranges)

    random_index = random.randint(1, total_range)

    for start, end in ranges:
        if random_index <= end - start + 1:
            result = start + random_index - 1
            break
        random_index -= (end - start + 1)

    return result


def postorder_traversal(node, parent_node=None):
    root = node
    if root != None and root.sub_instrs != []:
        for sub_node in root.sub_instrs:
            postorder_traversal(sub_node, root)
    elif root.sub_instrs == []:

        print(parent_node)
    else:
        raise Exception("error")


def primitive2simd(root):
    stack = [(root, None)]
    visited = set()

    while stack:
        node, parent_node = stack[-1]

        if node.sub_instrs and all(child in visited for child in node.sub_instrs) is False:
            for child in reversed(node.sub_instrs):
                if child not in visited:
                    stack.append((child, node))

        elif node in visited:
            stack.pop()

            if parent_node != None and parent_node.instr.opcode in [If, Block, Loop, BrIf, BrTable, Call,
                                                                    CallIndirect] and parent_node not in visited:
                visited.add(parent_node)
                if parent_node.type["params"] != [] and parent_node.instr.opcode in [If, BrTable, BrIf, CallIndirect]:
                    if parent_node.instr.opcode == CallIndirect:
                        drop_instr = Node(Instruction(Drop, None), instr_type={'params': [ValTypeAny], 'results': []})
                        drop_instr.sub_instrs.append(parent_node.sub_instrs[-1])
                        visited.add(drop_instr)
                        i32const_instr = Node(Instruction(I32Const, random.randint(0, 1)),
                                              instr_type={'params': [], 'results': [ValTypeI32]})
                        i32const_instr.sub_instrs.append(drop_instr)
                        visited.add(i32const_instr)
                        parent_node.sub_instrs[-1] = i32const_instr
                    else:
                        drop_instr = Node(Instruction(Drop, None), instr_type={'params': [ValTypeAny], 'results': []})
                        drop_instr.sub_instrs.append(parent_node.sub_instrs[0])
                        visited.add(drop_instr)
                        i32const_instr = Node(Instruction(I32Const, random.randint(0, 1)),
                                              instr_type={'params': [], 'results': [ValTypeI32]})
                        i32const_instr.sub_instrs.append(drop_instr)
                        visited.add(i32const_instr)
                        parent_node.sub_instrs[0] = i32const_instr
                    if parent_node.instr.opcode == If and parent_node.type["results"] != []:
                        parent_node.type["results"] = [ValTypeV128] * len(parent_node.type["results"])
                        parent_node.instr.args = BlockTypeV128
                elif parent_node.instr.opcode in [Block, Loop] and parent_node.type["results"] != []:
                    parent_node.type["results"] = [ValTypeV128] * len(parent_node.type["results"])
                    parent_node.instr.args = BlockTypeV128

                if parent_node.instr.opcode in [Call, CallIndirect]:
                    parent_node.context.functype["param_types"] = [ValTypeV128] * len(
                        parent_node.context.functype["param_types"])
                    parent_node.context.functype["result_types"] = [ValTypeV128] * len(
                        parent_node.context.functype["result_types"])
                    if parent_node.instr.opcode == CallIndirect:
                        parent_node.type["params"] = [ValTypeV128] * (
                                len(parent_node.type["params"]) - 1) + [ValTypeI32]
                    else:
                        parent_node.type["params"] = [ValTypeV128] * len(parent_node.type["params"])
                    parent_node.type["results"] = [ValTypeV128] * len(parent_node.type["results"])
        else:

            node, parent_node = stack.pop()
            visited.add(node)

            if parent_node != None and parent_node.instr.opcode in [If, Block, Loop, BrTable, BrIf,
                                                                    Call, CallIndirect] and parent_node not in visited:
                visited.add(parent_node)
                if parent_node.type["params"] != [] and parent_node.instr.opcode in [If, BrTable, BrIf, CallIndirect]:
                    if parent_node.instr.opcode == CallIndirect:
                        drop_instr = Node(Instruction(Drop, None), instr_type={'params': [ValTypeAny], 'results': []})
                        drop_instr.sub_instrs.append(parent_node.sub_instrs[-1])
                        visited.add(drop_instr)
                        i32const_instr = Node(Instruction(I32Const, random.randint(0, 1)),
                                              instr_type={'params': [], 'results': [ValTypeI32]})
                        i32const_instr.sub_instrs.append(drop_instr)
                        visited.add(i32const_instr)
                        parent_node.sub_instrs[-1] = i32const_instr
                    else:
                        drop_instr = Node(Instruction(Drop, None), instr_type={'params': [ValTypeAny], 'results': []})
                        drop_instr.sub_instrs.append(parent_node.sub_instrs[0])
                        visited.add(drop_instr)
                        i32const_instr = Node(Instruction(I32Const, random.randint(0, 1)),
                                              instr_type={'params': [], 'results': [ValTypeI32]})
                        i32const_instr.sub_instrs.append(drop_instr)
                        visited.add(i32const_instr)
                        parent_node.sub_instrs[0] = i32const_instr
                    if parent_node.instr.opcode == If and parent_node.type["results"] != []:
                        parent_node.type["results"] = [ValTypeV128] * len(parent_node.type["results"])
                        parent_node.instr.args = BlockTypeV128
                elif parent_node.instr.opcode in [Block, Loop] and parent_node.type["results"] != []:
                    parent_node.type["results"] = [ValTypeV128] * len(parent_node.type["results"])
                    parent_node.instr.args = BlockTypeV128

                if parent_node.instr.opcode in [Call, CallIndirect]:
                    parent_node.context.functype["param_types"] = [ValTypeV128] * len(
                        parent_node.context.functype["param_types"])
                    parent_node.context.functype["result_types"] = [ValTypeV128] * len(
                        parent_node.context.functype["result_types"])
                    if parent_node.instr.opcode == CallIndirect:
                        parent_node.type["params"] = [ValTypeV128] * (len(parent_node.type["params"]) - 1) + [
                            ValTypeI32]
                    else:
                        parent_node.type["params"] = [ValTypeV128] * len(parent_node.type["params"])
                    parent_node.type["results"] = [ValTypeV128] * len(parent_node.type["results"])

            if node.instr.opcode not in [Block, Loop, Else_, If, End_, LocalSet, LocalGet, LocalTee, Call, CallIndirect,
                                         Br, BrIf, BrTable, GlobalSet, GlobalGet, Select]:
                instr_type = node.type
                instr_context = node.context

                if len(instr_type['params']) == 0 and len(instr_type['results']) == 1:
                    subs_node = Node(Instruction(V128Const, generate_random_number(ValTypeV128)),
                                     instr_type={'params': [], 'results': [ValTypeV128]})
                    subs_node.sub_instrs = node.sub_instrs
                    node.copy(subs_node)

                elif len(instr_type['params']) == 1 and len(instr_type['results']) == 1:
                    instrs_1_to_1 = I32_to_V128 + I64_to_V128 + F32_to_V128 + F64_to_V128 + V128_to_I32 + V128_to_I64 + V128_to_F32 + V128_to_F64 + V128_to_V128
                    if parent_node == None:
                        subs_instr = random.choice(I32_to_V128 + I64_to_V128 + F32_to_V128 + F64_to_V128 + V128_to_V128)
                    else:
                        subs_instr = random.choice(instrs_1_to_1)
                    subs_instr_name = opnames[subs_instr]
                    if subs_instr in I32_to_V128:
                        if subs_instr_name.find("load") == -1:

                            subs_node = Node(Instruction(subs_instr, None),
                                             instr_type={'params': [ValTypeI32], 'results': [ValTypeV128]})
                        else:

                            subs_node = Node(Instruction(subs_instr, MemArg(align=0, offset=random.randint(0, 10000))),
                                             instr_type={'params': [ValTypeI32], 'results': [ValTypeV128]},
                                             context=Context(memory={"min": 10, "max": 32768}))
                        subs_node.sub_instrs.append(Node(Instruction(I32Const, generate_random_number(ValTypeI32)),
                                                         instr_type={'params': [], 'results': [ValTypeI32]}))
                        node.copy(subs_node)
                    elif subs_instr in I64_to_V128 + F32_to_V128 + F64_to_V128:
                        if subs_instr in I64_to_V128:
                            subs_node = Node(Instruction(subs_instr, None),
                                             instr_type={'params': [ValTypeI64], 'results': [ValTypeV128]})
                            subs_node.sub_instrs.append(Node(Instruction(I64Const, generate_random_number(ValTypeI32)),
                                                             instr_type={'params': [], 'results': [ValTypeI64]}))
                        elif subs_instr in F32_to_V128:
                            subs_node = Node(Instruction(subs_instr, None),
                                             instr_type={'params': [ValTypeF32], 'results': [ValTypeV128]})
                            subs_node.sub_instrs.append(Node(Instruction(F32Const, generate_random_number(ValTypeF32)),
                                                             instr_type={'params': [], 'results': [ValTypeF32]}))
                        elif subs_instr in F64_to_V128:
                            subs_node = Node(Instruction(subs_instr, None),
                                             instr_type={'params': [ValTypeF64], 'results': [ValTypeV128]})
                            subs_node.sub_instrs.append(
                                Node(Instruction(F64Const, generate_random_number(ValTypeF64)),
                                     instr_type={'params': [], 'results': [ValTypeF64]}))
                        node.copy(subs_node)
                    elif subs_instr in V128_to_I32 + V128_to_I64 + V128_to_F32 + V128_to_F64:

                        if opnames[subs_instr].find("lane") != -1:

                            if subs_instr in V128_to_I32:
                                subs_node = Node(Instruction(subs_instr, random.randint(0, 1)),
                                                 instr_type={'params': [ValTypeV128], 'results': [ValTypeI32]})
                                subs_node.sub_instrs = node.sub_instrs

                                node.copy(subs_node)
                                if parent_node not in visited or parent_node == None or (
                                        parent_node in visited and parent_node.instr.opcode in [Call, CallIndirect, If,
                                                                                                Block]):
                                    if parent_node.instr.opcode == CallIndirect and (
                                            len(parent_node.type["params"]) == 1 or node not in parent_node.sub_instrs[
                                                                                                :-1]):
                                        pass
                                    elif parent_node.instr.opcode == If and (node not in parent_node.sub_instrs[1:]):
                                        pass
                                    else:
                                        parent_instr = random.choice(I32_to_V128)
                                        if opnames[parent_instr].find("load") == -1:
                                            subs_parent_node = Node(
                                                Instruction(parent_instr, None),
                                                instr_type={'params': [ValTypeI32], 'results': [ValTypeV128]})
                                        else:
                                            subs_parent_node = Node(Instruction(parent_instr, MemArg(align=0,
                                                                                                     offset=random.randint(
                                                                                                         0, 10000))),
                                                                    instr_type={'params': [ValTypeI32],
                                                                                'results': [ValTypeV128]},
                                                                    context=Context(memory={"min": 10, "max": 32768}))
                                        if parent_node == None:
                                            parent_node = subs_parent_node
                                            root = parent_node
                                        else:
                                            index = parent_node.sub_instrs.index(node)
                                            parent_node.sub_instrs[index] = subs_parent_node
                                        subs_parent_node.sub_instrs.append(node)

                                        visited.add(subs_parent_node)
                            elif subs_instr in V128_to_I64:
                                subs_node = Node(Instruction(subs_instr, random.randint(0, 1)),
                                                 instr_type={'params': [ValTypeV128], 'results': [ValTypeI64]})
                                subs_node.sub_instrs = node.sub_instrs
                                node.copy(subs_node)
                                if parent_node not in visited or parent_node == None or (
                                        parent_node in visited and parent_node.instr.opcode in [Call, CallIndirect, If,
                                                                                                Block]):
                                    if parent_node.instr.opcode == CallIndirect and (
                                            len(parent_node.type["params"]) == 1 or node not in parent_node.sub_instrs[
                                                                                                :-1]):
                                        pass
                                    elif parent_node.instr.opcode == If and (node not in parent_node.sub_instrs[1:]):
                                        pass
                                    else:
                                        parent_instr = random.choice(I64_to_V128)
                                        subs_parent_node = Node(Instruction(parent_instr, None),
                                                                instr_type={'params': [ValTypeI64],
                                                                            'results': [ValTypeV128]})
                                        if parent_node == None:
                                            parent_node = subs_parent_node
                                            root = parent_node
                                        else:
                                            index = parent_node.sub_instrs.index(node)
                                            parent_node.sub_instrs[index] = subs_parent_node
                                        subs_parent_node.sub_instrs.append(node)

                                        visited.add(subs_parent_node)
                            elif subs_instr in V128_to_F32:
                                subs_node = Node(Instruction(subs_instr, random.randint(0, 1)),
                                                 instr_type={'params': [ValTypeV128], 'results': [ValTypeF32]})
                                subs_node.sub_instrs = node.sub_instrs
                                node.copy(subs_node)
                                if parent_node not in visited or parent_node == None or (
                                        parent_node in visited and parent_node.instr.opcode in [Call, CallIndirect, If,
                                                                                                Block]):
                                    if parent_node.instr.opcode == CallIndirect and (
                                            len(parent_node.type["params"]) == 1 or node not in parent_node.sub_instrs[
                                                                                                :-1]):
                                        pass
                                    elif parent_node.instr.opcode == If and (node not in parent_node.sub_instrs[1:]):
                                        pass
                                    else:
                                        parent_instr = random.choice(F32_to_V128)
                                        subs_parent_node = Node(Instruction(parent_instr, None),
                                                                instr_type={'params': [ValTypeF32],
                                                                            'results': [ValTypeV128]})
                                        if parent_node == None:
                                            parent_node = subs_parent_node
                                            root = parent_node
                                        else:
                                            index = parent_node.sub_instrs.index(node)
                                            parent_node.sub_instrs[index] = subs_parent_node
                                        subs_parent_node.sub_instrs.append(node)

                                        visited.add(subs_parent_node)
                            elif subs_instr in V128_to_F64:
                                subs_node = Node(Instruction(subs_instr, random.randint(0, 1)),
                                                 instr_type={'params': [ValTypeV128], 'results': [ValTypeF64]})
                                subs_node.sub_instrs = node.sub_instrs
                                node.copy(subs_node)
                                if parent_node not in visited or parent_node == None or (
                                        parent_node in visited and parent_node.instr.opcode in [Call, CallIndirect, If,
                                                                                                Block]):
                                    if parent_node.instr.opcode == CallIndirect and (
                                            len(parent_node.type["params"]) == 1 or node not in parent_node.sub_instrs[
                                                                                                :-1]):
                                        pass
                                    elif parent_node.instr.opcode == If and (node not in parent_node.sub_instrs[1:]):
                                        pass
                                    else:
                                        parent_instr = random.choice(F64_to_V128)
                                        subs_parent_node = Node(Instruction(parent_instr, None),
                                                                instr_type={'params': [ValTypeF64],
                                                                            'results': [ValTypeV128]})
                                        if parent_node == None:
                                            parent_node = subs_parent_node
                                            root = parent_node
                                        else:
                                            index = parent_node.sub_instrs.index(node)
                                            parent_node.sub_instrs[index] = subs_parent_node
                                        subs_parent_node.sub_instrs.append(node)

                                        visited.add(subs_parent_node)
                        else:

                            if subs_instr in V128_to_I32:
                                target_type = ValTypeI32
                                parent_instr = random.choice(I32_to_V128)
                            elif subs_instr in V128_to_I64:
                                target_type = ValTypeI64
                                parent_instr = random.choice(I64_to_V128)
                            elif subs_instr in V128_to_F32:
                                target_type = ValTypeF32
                                parent_instr = random.choice(F32_to_V128)
                            elif subs_instr in V128_to_F64:
                                target_type = ValTypeF64
                                parent_instr = random.choice(F64_to_V128)
                            else:
                                pass

                            subs_node = Node(Instruction(subs_instr, None),
                                             instr_type={'params': [ValTypeV128], 'results': [target_type]})
                            subs_node.sub_instrs = node.sub_instrs
                            node.copy(subs_node)
                            if parent_node not in visited or parent_node == None or (
                                    parent_node in visited and parent_node.instr.opcode in [Call, CallIndirect, If,
                                                                                            Block]):
                                if parent_node.instr.opcode == CallIndirect and (
                                        len(parent_node.type["params"]) == 1 or node not in parent_node.sub_instrs[
                                                                                            :-1]):
                                    pass
                                elif parent_node.instr.opcode == If and (node not in parent_node.sub_instrs[1:]):
                                    pass
                                else:
                                    if opnames[parent_instr].find("load") == -1:
                                        subs_parent_node = Node(
                                            Instruction(parent_instr),
                                            instr_type={'params': [target_type], 'results': [ValTypeV128]})
                                    else:
                                        subs_parent_node = Node(
                                            Instruction(parent_instr, MemArg(align=0, offset=random.randint(0, 10000))),
                                            instr_type={'params': [target_type], 'results': [ValTypeV128]},
                                            context=Context(memory={"min": 10, "max": 32768}))
                                    if parent_node == None:
                                        parent_node = subs_parent_node
                                        root = parent_node
                                    else:
                                        index = parent_node.sub_instrs.index(node)
                                        parent_node.sub_instrs[index] = subs_parent_node
                                    subs_parent_node.sub_instrs.append(node)

                                    visited.add(subs_parent_node)
                    elif subs_instr in V128_to_V128:
                        subs_node = Node(Instruction(subs_instr, None),
                                         instr_type={'params': [ValTypeV128], 'results': [ValTypeV128]})
                        subs_node.sub_instrs = node.sub_instrs
                        node.copy(subs_node)

                elif len(instr_type['params']) == 2 and len(instr_type['results']) == 0:
                    instrs_2_to_0 = I32_V128_to_
                    subs_instr = random.choice(instrs_2_to_0)
                    subs_instr_name = opnames[subs_instr]
                    if subs_instr == V128Store:

                        subs_node = Node(Instruction(subs_instr, MemArg(align=0, offset=random.randint(0, 10000))),
                                         instr_type={'params': [ValTypeI32, ValTypeV128], 'results': []},
                                         context=Context(memory={"min": 10, "max": 32768}))
                        subs_node.sub_instrs = node.sub_instrs
                        subs_node.sub_instrs[-2] = Node(Instruction(I32Const, random.randint(0, 10000)),
                                                        instr_type={'params': [], 'results': [ValTypeI32]})
                        node.copy(subs_node)
                    else:

                        subs_node = Node(Instruction(subs_instr,
                                                     MemLaneArg(MemArg(align=0, offset=random.randint(0, 10000)),
                                                                random.randint(0, 1))),
                                         instr_type={'params': [ValTypeI32, ValTypeV128], 'results': []},
                                         context=Context(memory={"min": 10, "max": 32768}))
                        subs_node.sub_instrs = node.sub_instrs
                        subs_node.sub_instrs[-2] = Node(Instruction(I32Const, random.randint(0, 10000)),
                                                        instr_type={'params': [], 'results': [ValTypeI32]})
                        node.copy(subs_node)

                elif len(instr_type['params']) == 2 and len(instr_type['results']) == 1:
                    instrs_2_to_1 = V128_V128_to_V128 + V128_I32_to_V128 + V128_I64_to_V128 + V128_F32_to_V128 + V128_F64_to_V128 + I32_V128_to_V128
                    subs_instr = random.choice(instrs_2_to_1)
                    subs_instr_name = opnames[subs_instr]
                    if subs_instr == I8x16Shuffle:

                        lane16_args = b''.join(bytes([random.randint(0, 15)]) for _ in range(16))
                        subs_node = Node(Instruction(subs_instr, int.from_bytes(lane16_args, byteorder='little')),
                                         instr_type={'params': [ValTypeI32, ValTypeV128], 'results': [ValTypeV128]})
                        subs_node.sub_instrs = node.sub_instrs
                        node.copy(subs_node)
                    elif subs_instr in I32_V128_to_V128:

                        subs_node = Node(Instruction(subs_instr,
                                                     MemLaneArg(MemArg(align=0, offset=random.randint(0, 10000)),
                                                                random.randint(0, 1))),
                                         instr_type={'params': [ValTypeI32, ValTypeV128], 'results': [ValTypeV128]},
                                         context=Context(memory={"min": 10, "max": 32768}))
                        subs_node.sub_instrs = node.sub_instrs
                        subs_node.sub_instrs[-2] = Node(Instruction(I32Const, random.randint(0, 10000)),
                                                        instr_type={'params': [], 'results': [ValTypeI32]})
                        node.copy(subs_node)
                    elif subs_instr in V128_I32_to_V128:
                        if opnames[subs_instr].find("lane") != -1:
                            subs_node = Node(Instruction(subs_instr, random.randint(0, 1)),
                                             instr_type={'params': [ValTypeV128, ValTypeI32], 'results': [ValTypeV128]})
                        else:
                            subs_node = Node(Instruction(subs_instr, None),
                                             instr_type={'params': [ValTypeV128, ValTypeI32], 'results': [ValTypeV128]})
                        subs_node.sub_instrs = node.sub_instrs
                        subs_node.sub_instrs[-1] = Node(Instruction(I32Const, random.randint(0, 10000)),
                                                        instr_type={'params': [], 'results': [ValTypeI32]})
                        node.copy(subs_node)
                    elif subs_instr in V128_I64_to_V128:
                        subs_node = Node(Instruction(subs_instr, random.randint(0, 1)),
                                         instr_type={'params': [ValTypeV128, ValTypeI64], 'results': [ValTypeV128]})
                        subs_node.sub_instrs = node.sub_instrs
                        subs_node.sub_instrs[-1] = Node(Instruction(I64Const, random.randint(0, 10000)),
                                                        instr_type={'params': [], 'results': [ValTypeI64]})
                        node.copy(subs_node)
                    elif subs_instr in V128_F32_to_V128:
                        subs_node = Node(Instruction(subs_instr, random.randint(0, 1)),
                                         instr_type={'params': [ValTypeV128, ValTypeF32], 'results': [ValTypeV128]})
                        subs_node.sub_instrs = node.sub_instrs
                        subs_node.sub_instrs[-1] = Node(Instruction(F32Const, numpy.float32(numpy.random.random())),
                                                        instr_type={'params': [], 'results': [ValTypeF32]})
                        node.copy(subs_node)
                    elif subs_instr in V128_F64_to_V128:
                        subs_node = Node(Instruction(subs_instr, random.randint(0, 1)),
                                         instr_type={'params': [ValTypeV128, ValTypeF64], 'results': [ValTypeV128]})
                        subs_node.sub_instrs = node.sub_instrs
                        subs_node.sub_instrs[-1] = Node(Instruction(F64Const, numpy.float64(numpy.random.random())),
                                                        instr_type={'params': [], 'results': [ValTypeF64]})
                        node.copy(subs_node)

                    else:

                        subs_node = Node(Instruction(subs_instr),
                                         instr_type={'params': [ValTypeV128, ValTypeV128], 'results': [ValTypeV128]})
                        subs_node.sub_instrs = node.sub_instrs
                        node.copy(subs_node)
            elif node.instr.opcode == Select:
                node.sub_instrs.append(Node(Instruction(Drop, None),
                                            instr_type={'params': [ValTypeAny], 'results': []}))
                node.sub_instrs.append(Node(Instruction(I32Const, random.randint(0, 1)),
                                            instr_type={'params': [], 'results': [ValTypeI32]}))

            elif node.instr.opcode == Call:
                node.context.functype["result_types"] = [ValTypeV128] * len(node.context.functype["result_types"])
                node.type["results"] = [ValTypeV128] * len(node.type["results"])

            elif node.instr.opcode in [LocalGet, LocalSet, LocalTee]:
                node.context.local_variable = {"local_variable_type": ValTypeV128}
                if node.instr.opcode == LocalSet:
                    node.type["params"] = [ValTypeV128]
                elif node.instr.opcode == LocalTee:
                    node.type["params"] = [ValTypeV128]
                    node.type["results"] = [ValTypeV128]
                else:
                    node.type["results"] = [ValTypeV128]
            elif node.instr.opcode in [GlobalSet, GlobalGet]:
                node.context.global_variable = {"global_variable_type": ValTypeV128}
                if node.instr.opcode == GlobalSet:
                    node.type["params"] = [ValTypeV128]
                else:
                    node.type["results"] = [ValTypeV128]
    return root


def instr_substitute(root):
    stack = [(root, None)]
    visited = set()

    while stack:
        node, parent_node = stack[-1]

        if node.sub_instrs and all(child in visited for child in node.sub_instrs) is False:
            for child in reversed(node.sub_instrs):
                if child not in visited:
                    stack.append((child, node))

        elif node in visited:
            stack.pop()

            if parent_node != None and parent_node.instr.opcode in [If, Block, Loop, BrIf, BrTable, Call,
                                                                    CallIndirect] and parent_node not in visited:
                visited.add(parent_node)
                if parent_node.type["params"] != [] and parent_node.instr.opcode in [If, BrTable, BrIf, CallIndirect]:
                    if parent_node.instr.opcode == CallIndirect:
                        drop_instr = Node(Instruction(Drop, None), instr_type={'params': [ValTypeAny], 'results': []})
                        drop_instr.sub_instrs.append(parent_node.sub_instrs[-1])
                        visited.add(drop_instr)
                        i32const_instr = Node(Instruction(I32Const, random.randint(0, 1)),
                                              instr_type={'params': [], 'results': [ValTypeI32]})
                        i32const_instr.sub_instrs.append(drop_instr)
                        visited.add(i32const_instr)
                        parent_node.sub_instrs[-1] = i32const_instr
                    else:
                        drop_instr = Node(Instruction(Drop, None), instr_type={'params': [ValTypeAny], 'results': []})
                        drop_instr.sub_instrs.append(parent_node.sub_instrs[0])
                        visited.add(drop_instr)
                        i32const_instr = Node(Instruction(I32Const, random.randint(0, 1)),
                                              instr_type={'params': [], 'results': [ValTypeI32]})
                        i32const_instr.sub_instrs.append(drop_instr)
                        visited.add(i32const_instr)
                        parent_node.sub_instrs[0] = i32const_instr
                    if parent_node.instr.opcode == If and parent_node.type["results"] != []:
                        parent_node.type["results"] = [ValTypeV128] * len(parent_node.type["results"])
                        parent_node.instr.args = BlockTypeV128
                elif parent_node.instr.opcode in [Block, Loop] and parent_node.type["results"] != []:
                    parent_node.type["results"] = [ValTypeV128] * len(parent_node.type["results"])
                    parent_node.instr.args = BlockTypeV128

                if parent_node.instr.opcode in [Call, CallIndirect]:
                    parent_node.context.functype["param_types"] = [ValTypeV128] * len(
                        parent_node.context.functype["param_types"])
                    parent_node.context.functype["result_types"] = [ValTypeV128] * len(
                        parent_node.context.functype["result_types"])
                    if parent_node.instr.opcode == CallIndirect:
                        parent_node.type["params"] = [ValTypeV128] * (
                                len(parent_node.type["params"]) - 1) + [ValTypeI32]
                    else:
                        parent_node.type["params"] = [ValTypeV128] * len(parent_node.type["params"])
                    parent_node.type["results"] = [ValTypeV128] * len(parent_node.type["results"])
        else:

            node, parent_node = stack.pop()
            visited.add(node)

            if parent_node != None and parent_node.instr.opcode in [If, Block, Loop, BrTable, BrIf,
                                                                    Call, CallIndirect] and parent_node not in visited:
                visited.add(parent_node)
                if parent_node.type["params"] != [] and parent_node.instr.opcode in [If, BrTable, BrIf, CallIndirect]:
                    if parent_node.instr.opcode == CallIndirect:
                        drop_instr = Node(Instruction(Drop, None), instr_type={'params': [ValTypeAny], 'results': []})
                        drop_instr.sub_instrs.append(parent_node.sub_instrs[-1])
                        visited.add(drop_instr)
                        i32const_instr = Node(Instruction(I32Const, random.randint(0, 1)),
                                              instr_type={'params': [], 'results': [ValTypeI32]})
                        i32const_instr.sub_instrs.append(drop_instr)
                        visited.add(i32const_instr)
                        parent_node.sub_instrs[-1] = i32const_instr
                    else:
                        drop_instr = Node(Instruction(Drop, None), instr_type={'params': [ValTypeAny], 'results': []})
                        drop_instr.sub_instrs.append(parent_node.sub_instrs[0])
                        visited.add(drop_instr)
                        i32const_instr = Node(Instruction(I32Const, random.randint(0, 1)),
                                              instr_type={'params': [], 'results': [ValTypeI32]})
                        i32const_instr.sub_instrs.append(drop_instr)
                        visited.add(i32const_instr)
                        parent_node.sub_instrs[0] = i32const_instr
                    if parent_node.instr.opcode == If and parent_node.type["results"] != []:
                        parent_node.type["results"] = [ValTypeV128] * len(parent_node.type["results"])
                        parent_node.instr.args = BlockTypeV128
                elif parent_node.instr.opcode in [Block, Loop] and parent_node.type["results"] != []:
                    parent_node.type["results"] = [ValTypeV128] * len(parent_node.type["results"])
                    parent_node.instr.args = BlockTypeV128

                if parent_node.instr.opcode in [Call, CallIndirect]:
                    parent_node.context.functype["param_types"] = [ValTypeV128] * len(
                        parent_node.context.functype["param_types"])
                    parent_node.context.functype["result_types"] = [ValTypeV128] * len(
                        parent_node.context.functype["result_types"])
                    if parent_node.instr.opcode == CallIndirect:
                        parent_node.type["params"] = [ValTypeV128] * (len(parent_node.type["params"]) - 1) + [
                            ValTypeI32]
                    else:
                        parent_node.type["params"] = [ValTypeV128] * len(parent_node.type["params"])
                    parent_node.type["results"] = [ValTypeV128] * len(parent_node.type["results"])

            if node.instr.opcode not in [Block, Loop, Else_, If, End_, LocalSet, LocalGet, LocalTee, Call, CallIndirect,
                                         Br, BrIf, BrTable, GlobalSet, GlobalGet, Select]:
                instr_type = node.type
                instr_context = node.context

                if len(instr_type['params']) == 1 and len(instr_type['results']) == 1:
                    result_type = instr_type['results']
                    if result_type == ValTypeI32:
                        sub_instr = random.choice(I32_to_I32 + I64_to_I32 + F32_to_I32 + F64_to_I32)
                        if sub_instr in I32_to_I32:
                            param_type = ValTypeI32
                        elif sub_instr in I64_to_I32:
                            param_type = ValTypeI64
                        elif sub_instr in F32_to_I32:
                            param_type = ValTypeF32
                        elif sub_instr in F64_to_I32:
                            param_type = ValTypeF64

                    elif result_type == ValTypeI64:
                        sub_instr = random.choice(I32_to_I64 + I64_to_I64 + F32_to_I64 + F64_to_I64)
                        if sub_instr in I32_to_I64:
                            param_type = ValTypeI32
                        elif sub_instr in I64_to_I64:
                            param_type = ValTypeI64
                        elif sub_instr in F32_to_I64:
                            param_type = ValTypeF32
                        elif sub_instr in F64_to_I64:
                            param_type = ValTypeF64

                    elif result_type == ValTypeF32:
                        sub_instr = random.choice(I32_to_F32 + I64_to_F32 + F32_to_F32 + F64_to_F32)
                        if sub_instr in I32_to_F32:
                            param_type = ValTypeI32
                        elif sub_instr in I64_to_F32:
                            param_type = ValTypeI64
                        elif sub_instr in F32_to_F32:
                            param_type = ValTypeF32
                        elif sub_instr in F64_to_F32:
                            param_type = ValTypeF64

                    elif result_type == ValTypeF64:
                        sub_instr = random.choice(I32_to_F64 + I64_to_F64 + F32_to_I64 + F64_to_I64)
                        if sub_instr in I32_to_F64:
                            param_type = ValTypeI32
                        elif sub_instr in I64_to_F64:
                            param_type = ValTypeI64
                        elif sub_instr in F32_to_I64:
                            param_type = ValTypeF32
                        elif sub_instr in F64_to_I64:
                            param_type = ValTypeF64
                    elif subs_instr in I64_to_V128 + F32_to_V128 + F64_to_V128:
                        if subs_instr in I64_to_V128:
                            subs_node = Node(Instruction(subs_instr, None),
                                             instr_type={'params': [ValTypeI64], 'results': [ValTypeV128]})
                            subs_node.sub_instrs.append(Node(Instruction(I64Const, generate_random_number(ValTypeI32)),
                                                             instr_type={'params': [], 'results': [ValTypeI64]}))
                        elif subs_instr in F32_to_V128:
                            subs_node = Node(Instruction(subs_instr, None),
                                             instr_type={'params': [ValTypeF32], 'results': [ValTypeV128]})
                            subs_node.sub_instrs.append(Node(Instruction(F32Const, generate_random_number(ValTypeF32)),
                                                             instr_type={'params': [], 'results': [ValTypeF32]}))
                        elif subs_instr in F64_to_V128:
                            subs_node = Node(Instruction(subs_instr, None),
                                             instr_type={'params': [ValTypeF64], 'results': [ValTypeV128]})
                            subs_node.sub_instrs.append(
                                Node(Instruction(F64Const, generate_random_number(ValTypeF64)),
                                     instr_type={'params': [], 'results': [ValTypeF64]}))
                        node.copy(subs_node)
                    elif subs_instr in V128_to_I32 + V128_to_I64 + V128_to_F32 + V128_to_F64:

                        if opnames[subs_instr].find("lane") != -1:

                            if subs_instr in V128_to_I32:
                                subs_node = Node(Instruction(subs_instr, random.randint(0, 1)),
                                                 instr_type={'params': [ValTypeV128], 'results': [ValTypeI32]})
                                subs_node.sub_instrs = node.sub_instrs

                                node.copy(subs_node)
                                if parent_node not in visited or parent_node == None or (
                                        parent_node in visited and parent_node.instr.opcode in [Call, CallIndirect, If,
                                                                                                Block]):
                                    if parent_node.instr.opcode == CallIndirect and (
                                            len(parent_node.type["params"]) == 1 or node not in parent_node.sub_instrs[
                                                                                                :-1]):
                                        pass
                                    elif parent_node.instr.opcode == If and (node not in parent_node.sub_instrs[1:]):
                                        pass
                                    else:
                                        parent_instr = random.choice(I32_to_V128)
                                        if opnames[parent_instr].find("load") == -1:
                                            subs_parent_node = Node(
                                                Instruction(parent_instr, None),
                                                instr_type={'params': [ValTypeI32], 'results': [ValTypeV128]})
                                        else:
                                            subs_parent_node = Node(Instruction(parent_instr, MemArg(align=0,
                                                                                                     offset=random.randint(
                                                                                                         0, 10000))),
                                                                    instr_type={'params': [ValTypeI32],
                                                                                'results': [ValTypeV128]},
                                                                    context=Context(memory={"min": 10, "max": 32768}))
                                        if parent_node == None:
                                            parent_node = subs_parent_node
                                            root = parent_node
                                        else:
                                            index = parent_node.sub_instrs.index(node)
                                            parent_node.sub_instrs[index] = subs_parent_node
                                        subs_parent_node.sub_instrs.append(node)

                                        visited.add(subs_parent_node)
                            elif subs_instr in V128_to_I64:
                                subs_node = Node(Instruction(subs_instr, random.randint(0, 1)),
                                                 instr_type={'params': [ValTypeV128], 'results': [ValTypeI64]})
                                subs_node.sub_instrs = node.sub_instrs
                                node.copy(subs_node)
                                if parent_node not in visited or parent_node == None or (
                                        parent_node in visited and parent_node.instr.opcode in [Call, CallIndirect, If,
                                                                                                Block]):
                                    if parent_node.instr.opcode == CallIndirect and (
                                            len(parent_node.type["params"]) == 1 or node not in parent_node.sub_instrs[
                                                                                                :-1]):
                                        pass
                                    elif parent_node.instr.opcode == If and (node not in parent_node.sub_instrs[1:]):
                                        pass
                                    else:
                                        parent_instr = random.choice(I64_to_V128)
                                        subs_parent_node = Node(Instruction(parent_instr, None),
                                                                instr_type={'params': [ValTypeI64],
                                                                            'results': [ValTypeV128]})
                                        if parent_node == None:
                                            parent_node = subs_parent_node
                                            root = parent_node
                                        else:
                                            index = parent_node.sub_instrs.index(node)
                                            parent_node.sub_instrs[index] = subs_parent_node
                                        subs_parent_node.sub_instrs.append(node)

                                        visited.add(subs_parent_node)
                            elif subs_instr in V128_to_F32:
                                subs_node = Node(Instruction(subs_instr, random.randint(0, 1)),
                                                 instr_type={'params': [ValTypeV128], 'results': [ValTypeF32]})
                                subs_node.sub_instrs = node.sub_instrs
                                node.copy(subs_node)
                                if parent_node not in visited or parent_node == None or (
                                        parent_node in visited and parent_node.instr.opcode in [Call, CallIndirect, If,
                                                                                                Block]):
                                    if parent_node.instr.opcode == CallIndirect and (
                                            len(parent_node.type["params"]) == 1 or node not in parent_node.sub_instrs[
                                                                                                :-1]):
                                        pass
                                    elif parent_node.instr.opcode == If and (node not in parent_node.sub_instrs[1:]):
                                        pass
                                    else:
                                        parent_instr = random.choice(F32_to_V128)
                                        subs_parent_node = Node(Instruction(parent_instr, None),
                                                                instr_type={'params': [ValTypeF32],
                                                                            'results': [ValTypeV128]})
                                        if parent_node == None:
                                            parent_node = subs_parent_node
                                            root = parent_node
                                        else:
                                            index = parent_node.sub_instrs.index(node)
                                            parent_node.sub_instrs[index] = subs_parent_node
                                        subs_parent_node.sub_instrs.append(node)

                                        visited.add(subs_parent_node)
                            elif subs_instr in V128_to_F64:
                                subs_node = Node(Instruction(subs_instr, random.randint(0, 1)),
                                                 instr_type={'params': [ValTypeV128], 'results': [ValTypeF64]})
                                subs_node.sub_instrs = node.sub_instrs
                                node.copy(subs_node)
                                if parent_node not in visited or parent_node == None or (
                                        parent_node in visited and parent_node.instr.opcode in [Call, CallIndirect, If,
                                                                                                Block]):
                                    if parent_node.instr.opcode == CallIndirect and (
                                            len(parent_node.type["params"]) == 1 or node not in parent_node.sub_instrs[
                                                                                                :-1]):
                                        pass
                                    elif parent_node.instr.opcode == If and (node not in parent_node.sub_instrs[1:]):
                                        pass
                                    else:
                                        parent_instr = random.choice(F64_to_V128)
                                        subs_parent_node = Node(Instruction(parent_instr, None),
                                                                instr_type={'params': [ValTypeF64],
                                                                            'results': [ValTypeV128]})
                                        if parent_node == None:
                                            parent_node = subs_parent_node
                                            root = parent_node
                                        else:
                                            index = parent_node.sub_instrs.index(node)
                                            parent_node.sub_instrs[index] = subs_parent_node
                                        subs_parent_node.sub_instrs.append(node)

                                        visited.add(subs_parent_node)
                        else:

                            if subs_instr in V128_to_I32:
                                target_type = ValTypeI32
                                parent_instr = random.choice(I32_to_V128)
                            elif subs_instr in V128_to_I64:
                                target_type = ValTypeI64
                                parent_instr = random.choice(I64_to_V128)
                            elif subs_instr in V128_to_F32:
                                target_type = ValTypeF32
                                parent_instr = random.choice(F32_to_V128)
                            elif subs_instr in V128_to_F64:
                                target_type = ValTypeF64
                                parent_instr = random.choice(F64_to_V128)
                            else:
                                pass

                            subs_node = Node(Instruction(subs_instr, None),
                                             instr_type={'params': [ValTypeV128], 'results': [target_type]})
                            subs_node.sub_instrs = node.sub_instrs
                            node.copy(subs_node)
                            if parent_node not in visited or parent_node == None or (
                                    parent_node in visited and parent_node.instr.opcode in [Call, CallIndirect, If,
                                                                                            Block]):
                                if parent_node.instr.opcode == CallIndirect and (
                                        len(parent_node.type["params"]) == 1 or node not in parent_node.sub_instrs[
                                                                                            :-1]):
                                    pass
                                elif parent_node.instr.opcode == If and (node not in parent_node.sub_instrs[1:]):
                                    pass
                                else:
                                    if opnames[parent_instr].find("load") == -1:
                                        subs_parent_node = Node(
                                            Instruction(parent_instr),
                                            instr_type={'params': [target_type], 'results': [ValTypeV128]})
                                    else:
                                        subs_parent_node = Node(
                                            Instruction(parent_instr, MemArg(align=0, offset=random.randint(0, 10000))),
                                            instr_type={'params': [target_type], 'results': [ValTypeV128]},
                                            context=Context(memory={"min": 10, "max": 32768}))
                                    if parent_node == None:
                                        parent_node = subs_parent_node
                                        root = parent_node
                                    else:
                                        index = parent_node.sub_instrs.index(node)
                                        parent_node.sub_instrs[index] = subs_parent_node
                                    subs_parent_node.sub_instrs.append(node)

                                    visited.add(subs_parent_node)
                    elif subs_instr in V128_to_V128:
                        subs_node = Node(Instruction(subs_instr, None),
                                         instr_type={'params': [ValTypeV128], 'results': [ValTypeV128]})
                        subs_node.sub_instrs = node.sub_instrs
                        node.copy(subs_node)

                elif len(instr_type['params']) == 2 and len(instr_type['results']) == 0:
                    instrs_2_to_0 = I32_V128_to_
                    subs_instr = random.choice(instrs_2_to_0)
                    subs_instr_name = opnames[subs_instr]
                    if subs_instr == V128Store:

                        subs_node = Node(Instruction(subs_instr, MemArg(align=0, offset=random.randint(0, 10000))),
                                         instr_type={'params': [ValTypeI32, ValTypeV128], 'results': []},
                                         context=Context(memory={"min": 10, "max": 32768}))
                        subs_node.sub_instrs = node.sub_instrs
                        subs_node.sub_instrs[-2] = Node(Instruction(I32Const, random.randint(0, 10000)),
                                                        instr_type={'params': [], 'results': [ValTypeI32]})
                        node.copy(subs_node)
                    else:

                        subs_node = Node(Instruction(subs_instr,
                                                     MemLaneArg(MemArg(align=0, offset=random.randint(0, 10000)),
                                                                random.randint(0, 1))),
                                         instr_type={'params': [ValTypeI32, ValTypeV128], 'results': []},
                                         context=Context(memory={"min": 10, "max": 32768}))
                        subs_node.sub_instrs = node.sub_instrs
                        subs_node.sub_instrs[-2] = Node(Instruction(I32Const, random.randint(0, 10000)),
                                                        instr_type={'params': [], 'results': [ValTypeI32]})
                        node.copy(subs_node)

                elif len(instr_type['params']) == 2 and len(instr_type['results']) == 1:
                    instrs_2_to_1 = V128_V128_to_V128 + V128_I32_to_V128 + V128_I64_to_V128 + V128_F32_to_V128 + V128_F64_to_V128 + I32_V128_to_V128
                    subs_instr = random.choice(instrs_2_to_1)
                    subs_instr_name = opnames[subs_instr]
                    if subs_instr == I8x16Shuffle:

                        lane16_args = b''.join(bytes([random.randint(0, 15)]) for _ in range(16))
                        subs_node = Node(Instruction(subs_instr, int.from_bytes(lane16_args, byteorder='little')),
                                         instr_type={'params': [ValTypeI32, ValTypeV128], 'results': [ValTypeV128]})
                        subs_node.sub_instrs = node.sub_instrs
                        node.copy(subs_node)
                    elif subs_instr in I32_V128_to_V128:

                        subs_node = Node(Instruction(subs_instr,
                                                     MemLaneArg(MemArg(align=0, offset=random.randint(0, 10000)),
                                                                random.randint(0, 1))),
                                         instr_type={'params': [ValTypeI32, ValTypeV128], 'results': [ValTypeV128]},
                                         context=Context(memory={"min": 10, "max": 32768}))
                        subs_node.sub_instrs = node.sub_instrs
                        subs_node.sub_instrs[-2] = Node(Instruction(I32Const, random.randint(0, 10000)),
                                                        instr_type={'params': [], 'results': [ValTypeI32]})
                        node.copy(subs_node)
                    elif subs_instr in V128_I32_to_V128:
                        if opnames[subs_instr].find("lane") != -1:
                            subs_node = Node(Instruction(subs_instr, random.randint(0, 1)),
                                             instr_type={'params': [ValTypeV128, ValTypeI32], 'results': [ValTypeV128]})
                        else:
                            subs_node = Node(Instruction(subs_instr, None),
                                             instr_type={'params': [ValTypeV128, ValTypeI32], 'results': [ValTypeV128]})
                        subs_node.sub_instrs = node.sub_instrs
                        subs_node.sub_instrs[-1] = Node(Instruction(I32Const, random.randint(0, 10000)),
                                                        instr_type={'params': [], 'results': [ValTypeI32]})
                        node.copy(subs_node)
                    elif subs_instr in V128_I64_to_V128:
                        subs_node = Node(Instruction(subs_instr, random.randint(0, 1)),
                                         instr_type={'params': [ValTypeV128, ValTypeI64], 'results': [ValTypeV128]})
                        subs_node.sub_instrs = node.sub_instrs
                        subs_node.sub_instrs[-1] = Node(Instruction(I64Const, random.randint(0, 10000)),
                                                        instr_type={'params': [], 'results': [ValTypeI64]})
                        node.copy(subs_node)
                    elif subs_instr in V128_F32_to_V128:
                        subs_node = Node(Instruction(subs_instr, random.randint(0, 1)),
                                         instr_type={'params': [ValTypeV128, ValTypeF32], 'results': [ValTypeV128]})
                        subs_node.sub_instrs = node.sub_instrs
                        subs_node.sub_instrs[-1] = Node(Instruction(F32Const, numpy.float32(numpy.random.random())),
                                                        instr_type={'params': [], 'results': [ValTypeF32]})
                        node.copy(subs_node)
                    elif subs_instr in V128_F64_to_V128:
                        subs_node = Node(Instruction(subs_instr, random.randint(0, 1)),
                                         instr_type={'params': [ValTypeV128, ValTypeF64], 'results': [ValTypeV128]})
                        subs_node.sub_instrs = node.sub_instrs
                        subs_node.sub_instrs[-1] = Node(Instruction(F64Const, numpy.float64(numpy.random.random())),
                                                        instr_type={'params': [], 'results': [ValTypeF64]})
                        node.copy(subs_node)

                    else:

                        subs_node = Node(Instruction(subs_instr),
                                         instr_type={'params': [ValTypeV128, ValTypeV128], 'results': [ValTypeV128]})
                        subs_node.sub_instrs = node.sub_instrs
                        node.copy(subs_node)
            elif node.instr.opcode == Select:
                node.sub_instrs.append(Node(Instruction(Drop, None),
                                            instr_type={'params': [ValTypeAny], 'results': []}))
                node.sub_instrs.append(Node(Instruction(I32Const, random.randint(0, 1)),
                                            instr_type={'params': [], 'results': [ValTypeI32]}))

            elif node.instr.opcode == Call:
                node.context.functype["result_types"] = [ValTypeV128] * len(node.context.functype["result_types"])
                node.type["results"] = [ValTypeV128] * len(node.type["results"])

            elif node.instr.opcode in [LocalGet, LocalSet, LocalTee]:
                node.context.local_variable = {"local_variable_type": ValTypeV128}
                if node.instr.opcode == LocalSet:
                    node.type["params"] = [ValTypeV128]
                elif node.instr.opcode == LocalTee:
                    node.type["params"] = [ValTypeV128]
                    node.type["results"] = [ValTypeV128]
                else:
                    node.type["results"] = [ValTypeV128]
            elif node.instr.opcode in [GlobalSet, GlobalGet]:
                node.context.global_variable = {"global_variable_type": ValTypeV128}
                if node.instr.opcode == GlobalSet:
                    node.type["params"] = [ValTypeV128]
                else:
                    node.type["results"] = [ValTypeV128]
    return root