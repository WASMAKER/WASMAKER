from WASMaker.parser.opcodes import Block, Loop, If, Call, CallIndirect
from BREWasm.rewriter.semantics_rewriter import SectionRewriter
from BREWasm.parser.opcodes import V128Store, V128Load
from WASMaker.parser.instruction import Instruction, MemArg
from BREWasm.parser.types import *
from BREWasm.rewriter.section_rewriter import *
from WASMaker.fuzzer.instructions import *

divider_offset_val = None
divider_offset_global = None
string_pointer_val = None
string_pointer_global = None
temp_val = None
temp_global = None
LF_char_global = None
funcidx_global = None
indirect_funcidx_global = None
indirect_functype_idx_global = None
number_count_global = None
instr_opcode_global = None

def instrumentation(binary):
    global string_pointer_val, string_pointer_global, temp_val, temp_global, LF_char_global, divider_offset_val, divider_offset_global, funcidx_global, indirect_funcidx_global, indirect_functype_idx_global, number_count_global

    import_rewriter = SectionRewriter.ImportExport(binary)
    import_rewriter.append_import_function("wasi_snapshot_preview1", "fd_write",
                                           [ValTypeI32, ValTypeI32, ValTypeI32, ValTypeI32], [ValTypeI32])
    # export the memory
    export_rewriter = import_rewriter
    export_rewriter.append_export_memory(0)
    # append global variables
    global_rewriter = SectionRewriter.GlobalVariable(binary)
    divider_offset_val = 2000000000
    divider_offset_global = global_rewriter.append_global_variable(GlobalType(ValTypeI32, 1), divider_offset_val)  # 这里给自己设
    string_pointer_val = 2000000100
    string_pointer_global = global_rewriter.append_global_variable(GlobalType(ValTypeI64, 1), string_pointer_val)  # 这里给自己设
    temp_val = 2000000200
    temp_global = global_rewriter.append_global_variable(GlobalType(ValTypeV128, 1), temp_val)  # 这里也给自己设
    LF_char_global = global_rewriter.append_global_variable(GlobalType(ValTypeI32, 1), 0)

    funcidx_global = global_rewriter.append_global_variable(GlobalType(ValTypeI32, 1), 0)
    indirect_funcidx_global = global_rewriter.append_global_variable(GlobalType(ValTypeI32, 1), 0)
    indirect_functype_idx_global = global_rewriter.append_global_variable(GlobalType(ValTypeI32, 1), 0)
    number_count_global = global_rewriter.append_global_variable(GlobalType(ValTypeI32, 1), 0)


    i32_global_list = []
    for i in range(20):
        i32_global_list.append(global_rewriter.append_global_variable(GlobalType(ValTypeI32, 1), 0))

    i64_global_list = []
    for i in range(20):
        i64_global_list.append(global_rewriter.append_global_variable(GlobalType(ValTypeI64, 1), 0))

    f32_global_list = []
    for i in range(20):
        f32_global_list.append(global_rewriter.append_global_variable(GlobalType(ValTypeF32, 1), 0))

    f64_global_list = []
    for i in range(20):
        f64_global_list.append(global_rewriter.append_global_variable(GlobalType(ValTypeF64, 1), 0))

    v128_global_list = []
    for i in range(20):
        v128_global_list.append(global_rewriter.append_global_variable(GlobalType(ValTypeV128, 1), 0))

    mem_rewriter = SectionRewriter.LinearMemory(binary)
    divider_string_offset = 2000000000  # 它等于前面divider_offset的值
    mem_list = binary.module.mem_sec
    if mem_list == []:
        binary.module.mem_sec.append(Limits(1, 65536, 65536))
    mem_rewriter.insert_linear_memory(divider_string_offset, "==========\n".encode('utf-8'))

    for code in binary.module.code_sec:
        code.expr = instr_instrumentation(code.expr, binary,
                          [i32_global_list, i64_global_list, f32_global_list, f64_global_list, v128_global_list])


def binary_function_instrumentation(binary, funcidx):
    global string_pointer_val, string_pointer_global, temp_val, temp_global, LF_char_global, divider_offset_val, divider_offset_global, funcidx_global, indirect_funcidx_global, indirect_functype_idx_global, number_count_global, instr_opcode_global

    import_rewriter = SectionRewriter.ImportExport(binary)
    import_rewriter.append_import_function("wasi_snapshot_preview1", "fd_write",
                                           [ValTypeI32, ValTypeI32, ValTypeI32, ValTypeI32], [ValTypeI32])
    # export the memory
    export_rewriter = import_rewriter
    export_rewriter.append_export_memory(0)
    # append global variables
    global_rewriter = SectionRewriter.GlobalVariable(binary)
    divider_offset_val = 2000000000
    divider_offset_global = global_rewriter.append_global_variable(GlobalType(ValTypeI32, 1), divider_offset_val)  # 这里给自己设
    string_pointer_val = 2000000100
    string_pointer_global = global_rewriter.append_global_variable(GlobalType(ValTypeI64, 1), string_pointer_val)  # 这里给自己设
    temp_val = 2000000200
    temp_global = global_rewriter.append_global_variable(GlobalType(ValTypeV128, 1), temp_val)  # 这里也给自己设
    LF_char_global = global_rewriter.append_global_variable(GlobalType(ValTypeI32, 1), 0)

    funcidx_global = global_rewriter.append_global_variable(GlobalType(ValTypeI32, 1), 0)
    indirect_funcidx_global = global_rewriter.append_global_variable(GlobalType(ValTypeI32, 1), 0)
    indirect_functype_idx_global = global_rewriter.append_global_variable(GlobalType(ValTypeI32, 1), 0)
    number_count_global = global_rewriter.append_global_variable(GlobalType(ValTypeI32, 1), 0)
    instr_opcode_global = global_rewriter.append_global_variable(GlobalType(ValTypeI32, 1), 0)

    I32_global = global_rewriter.append_global_variable(GlobalType(ValTypeI32, 1), 0)
    I64_global = global_rewriter.append_global_variable(GlobalType(ValTypeI64, 1), 0)
    F32_global = global_rewriter.append_global_variable(GlobalType(ValTypeF32, 1), 0)
    F64_global = global_rewriter.append_global_variable(GlobalType(ValTypeF64, 1), 0)
    V128_global = global_rewriter.append_global_variable(GlobalType(ValTypeV128, 1), 0)


    mem_rewriter = SectionRewriter.LinearMemory(binary)
    divider_string_offset = 2000000000  # 它等于前面divider_offset的值
    mem_list = binary.module.mem_sec
    if mem_list == []:
        binary.module.mem_sec.append(Limits(1, 65536, 65536))
    mem_rewriter.insert_linear_memory(divider_string_offset, "==========\n".encode('utf-8'))

    code = binary.module.code_sec[funcidx]
    code.expr = function_instrumentation(code.expr, binary, funcidx, [I32_global, I64_global, F32_global, F64_global, V128_global])


def get_variable_type_size(variable_type):
    if variable_type == ValTypeI32:
        variable_type_size = 4
    elif variable_type == ValTypeI64:
        variable_type_size = 8
    elif variable_type == ValTypeF32:
        variable_type_size = 4
    elif variable_type == ValTypeF64:
        variable_type_size = 8
    elif variable_type == ValTypeV128:
        variable_type_size = 16

    return variable_type_size


def get_print_divider_instrs(string_pointer_global, string_pointer_val, divider_string_offset):
    instrs = [Instruction(I32Const, string_pointer_val),
              Instruction(I64Load, MemArg()),
              Instruction(GlobalSet, string_pointer_global),

              Instruction(I32Const, string_pointer_val),
              Instruction(I32Const, divider_string_offset),
              Instruction(I32Store, MemArg()),

              Instruction(I32Const, string_pointer_val + 4),
              Instruction(I32Const, 11),
              Instruction(I32Store, MemArg()),

              Instruction(I32Const, 1),
              Instruction(I32Const, string_pointer_val),
              Instruction(I32Const, 1),
              Instruction(I32Const, 0),
              Instruction(Call, 0),
              Instruction(Drop),

              Instruction(I32Const, string_pointer_val),
              Instruction(GlobalGet, string_pointer_global),
              Instruction(I64Store, MemArg())]

    return instrs


def get_store_variable_instrs(temp_global, temp_val, LF_char_global, variable_global, variable_type):
    variable_type_size = get_variable_type_size(variable_type)

    if variable_type == ValTypeI32:
        store_instr = I32Store
    elif variable_type == ValTypeI64:
        store_instr = I64Store
    elif variable_type == ValTypeF32:
        store_instr = F32Store
    elif variable_type == ValTypeF64:
        store_instr = F64Store
    elif variable_type == ValTypeV128:
        store_instr = V128Store

    instrs = [
        Instruction(GlobalSet, variable_global),

        Instruction(I32Const, temp_val),
        Instruction(V128Load, MemArg()),
        Instruction(GlobalSet, temp_global),
        Instruction(I32Const, temp_val + variable_type_size),
        Instruction(I32Load, MemArg()),
        Instruction(GlobalSet, LF_char_global),

        Instruction(I32Const, temp_val),
        Instruction(GlobalGet, variable_global),
        Instruction(store_instr, MemArg()),   # it is depend on the variable type
        Instruction(I32Const, temp_val + variable_type_size),
        Instruction(I32Const, 10),
        Instruction(I32Store8, MemArg())]

    return instrs


def get_print_variable_instrs(string_pointer_val, string_pointer_global, temp_val, variable_type):
    variable_type_size = get_variable_type_size(variable_type)

    instrs = [Instruction(I32Const, string_pointer_val),
              Instruction(I64Load, MemArg()),
              Instruction(GlobalSet, string_pointer_global),

              Instruction(I32Const, string_pointer_val),
              Instruction(I32Const, temp_val),
              Instruction(I32Store, MemArg()),

              Instruction(I32Const, string_pointer_val + 4),
              Instruction(I32Const, variable_type_size + 1),  # 这里加1是因为还有个换行符
              Instruction(I32Store, MemArg()),

              Instruction(I32Const, 1),
              Instruction(I32Const, string_pointer_val),
              Instruction(I32Const, 1),
              Instruction(I32Const, 0),
              Instruction(Call, 0),
              Instruction(Drop)]
    return instrs


def get_restore_instrs(string_pointer_val, string_pointer_global, temp_val, temp_global, LF_char_global, variable_type):
    variable_type_size = get_variable_type_size(variable_type)

    instrs = [Instruction(I32Const, string_pointer_val),
              Instruction(GlobalGet, string_pointer_global),
              Instruction(I64Store, MemArg()),
              Instruction(I32Const, temp_val),
              Instruction(GlobalGet, temp_global),
              Instruction(V128Store, MemArg()),
              Instruction(I32Const, temp_val + variable_type_size),
              Instruction(GlobalGet, LF_char_global),
              Instruction(I32Store, MemArg())]

    return instrs


def instr_instrumentation(expr, binary, global_lists):
    global string_pointer_val, string_pointer_global, temp_val, temp_global, LF_char_global, divider_offset_val, divider_offset_global, funcidx_global, indirect_funcidx_global, indirect_functype_idx_global, number_count_global

    i = 0
    while i < len(expr):
        if expr[i].opcode in [Block, Loop]:
            args = expr[i].args
            expr[i].args.instrs = instr_instrumentation(args.instrs, binary, global_lists)
        elif expr[i].opcode == If:
            args = expr[i].args
            expr[i].args.instrs1 = instr_instrumentation(args.instrs1, binary, global_lists)
            expr[i].args.instrs2 = instr_instrumentation(args.instrs2, binary, global_lists)
        else:
            if expr[i].opcode == Call:
                funcidx = expr[i].args  # subtract the number of import function

                functype_rewriter = SectionRewriter(binary.module)
                functype = functype_rewriter.get_func_functype(expr[i].args)

                params_global_list = []

                for val_type in functype.param_types:
                    if val_type == ValTypeI32:
                        i32_globals = global_lists[0]
                        for i32_global in i32_globals:
                            if {"type": ValTypeI32, "id": i32_global} not in params_global_list:
                                expr.insert(i, Instruction(GlobalSet, i32_global))
                                params_global_list.append({"type": ValTypeI32, "id": i32_global})
                                break
                    elif val_type == ValTypeI64:
                        i64_globals = global_lists[1]
                        for i64_global in i64_globals:
                            if {"type": ValTypeI64, "id": i64_global} not in params_global_list:
                                expr.insert(i, Instruction(GlobalSet, i64_global))
                                params_global_list.append({"type": ValTypeI64, "id": i64_global})
                                break
                    elif val_type == ValTypeF32:
                        f32_globals = global_lists[2]
                        for f32_global in f32_globals:
                            if {"type": ValTypeF32, "id": f32_global} not in params_global_list:
                                expr.insert(i, Instruction(GlobalSet, f32_global))
                                params_global_list.append({"type": ValTypeF32, "id": f32_global})
                                break
                    elif val_type == ValTypeF64:
                        f64_globals = global_lists[3]
                        for f64_global in f64_globals:
                            if {"type": ValTypeF64, "id": f64_global} not in params_global_list:
                                expr.insert(i, Instruction(GlobalSet, f64_global))
                                params_global_list.append({"type": ValTypeF64, "id": f64_global})
                                break
                    elif val_type == ValTypeV128:
                        v128_globals = global_lists[4]
                        for v128_global in v128_globals:
                            if {"type": ValTypeV128, "id": v128_global} not in params_global_list:
                                expr.insert(i, Instruction(GlobalSet, v128_global))
                                params_global_list.append({"type": ValTypeV128, "id": v128_global})
                                break

                i = i + len(functype.param_types)
                divider_print_instrs = get_print_divider_instrs(string_pointer_global, string_pointer_val,
                                                                divider_offset_val)
                expr = expr[:i] + divider_print_instrs + expr[i:]
                i = i + len(divider_print_instrs)

                # print function index
                expr.insert(i, Instruction(I32Const, funcidx))
                i = i + 1
                store_variable_instrs = get_store_variable_instrs(temp_global, temp_val, LF_char_global,
                                                                  funcidx_global, ValTypeI32)
                print_variable_instrs = get_print_variable_instrs(string_pointer_val, string_pointer_global, temp_val,
                                                                  ValTypeI32)
                restore_instrs = get_restore_instrs(string_pointer_val, string_pointer_global, temp_val, temp_global,
                                                    LF_char_global, ValTypeI32)
                expr = expr[:i] + store_variable_instrs + print_variable_instrs + restore_instrs + expr[i:]
                i = i + len(store_variable_instrs + print_variable_instrs + restore_instrs)

                # print number count
                expr.insert(i, Instruction(I32Const, len(params_global_list)))
                i = i + 1
                store_variable_instrs = get_store_variable_instrs(temp_global, temp_val, LF_char_global,
                                                                  number_count_global, ValTypeI32)
                print_variable_instrs = get_print_variable_instrs(string_pointer_val, string_pointer_global, temp_val,
                                                                  ValTypeI32)
                restore_instrs = get_restore_instrs(string_pointer_val, string_pointer_global, temp_val, temp_global,
                                                    LF_char_global, ValTypeI32)
                expr = expr[:i] + store_variable_instrs + print_variable_instrs + restore_instrs + expr[i:]
                i = i + len(store_variable_instrs + print_variable_instrs + restore_instrs)

                # print params
                for param_global in params_global_list:
                    expr.insert(i, Instruction(GlobalGet, param_global["id"]))  # push the variable to be print
                    i = i + 1
                    store_variable_instrs = get_store_variable_instrs(temp_global, temp_val, LF_char_global,
                                                                      param_global["id"], param_global["type"])

                    print_variable_instrs = get_print_variable_instrs(string_pointer_val, string_pointer_global, temp_val, param_global["type"])
                    restore_instrs = get_restore_instrs(string_pointer_val, string_pointer_global, temp_val, temp_global, LF_char_global, param_global["type"])
                    expr = expr[:i] + store_variable_instrs + print_variable_instrs + restore_instrs + expr[i:]
                    i = i + len(store_variable_instrs + print_variable_instrs + restore_instrs)

                # put the original params to stack
                for param_global in params_global_list:
                    expr.insert(i, Instruction(GlobalGet, param_global["id"]))
                    i += 1

                # instrumentation after call instr
                results_global_list = []
                i = i + 1

                for val_type in functype.result_types:
                    if val_type == ValTypeI32:
                        i32_globals = global_lists[0]
                        for i32_global in i32_globals:
                            if {"type": ValTypeI32, "id": i32_global} not in results_global_list:
                                expr.insert(i, Instruction(GlobalSet, i32_global))
                                results_global_list.append({"type": ValTypeI32, "id": i32_global})
                                break
                    elif val_type == ValTypeI64:
                        i64_globals = global_lists[1]
                        for i64_global in i64_globals:
                            if {"type": ValTypeI64, "id": i64_global} not in results_global_list:
                                expr.insert(i, Instruction(GlobalSet, i64_global))
                                results_global_list.append({"type": ValTypeI64, "id": i64_global})
                                break
                    elif val_type == ValTypeF32:
                        f32_globals = global_lists[2]
                        for f32_global in f32_globals:
                            if {"type": ValTypeF32, "id": f32_global} not in results_global_list:
                                expr.insert(i, Instruction(GlobalSet, f32_global))
                                results_global_list.append({"type": ValTypeF32, "id": f32_global})
                                break
                    elif val_type == ValTypeF64:
                        f64_globals = global_lists[3]
                        for f64_global in f64_globals:
                            if {"type": ValTypeF64, "id": f64_global} not in results_global_list:
                                expr.insert(i, Instruction(GlobalSet, f64_global))
                                results_global_list.append({"type": ValTypeF64, "id": f64_global})
                                break
                    elif val_type == ValTypeV128:
                        v128_globals = global_lists[4]
                        for v128_global in v128_globals:
                            if {"type": ValTypeV128, "id": v128_global} not in results_global_list:
                                expr.insert(i, Instruction(GlobalSet, v128_global))
                                results_global_list.append({"type": ValTypeV128, "id": v128_global})
                                break

                i = i + len(functype.result_types)
                divider_print_instrs = get_print_divider_instrs(string_pointer_global, string_pointer_val,
                                                                divider_offset_val)
                expr = expr[:i] + divider_print_instrs + expr[i:]
                i = i + len(divider_print_instrs)

                # print function index
                expr.insert(i, Instruction(I32Const, funcidx))
                i = i + 1
                store_variable_instrs = get_store_variable_instrs(temp_global, temp_val, LF_char_global,
                                                                  funcidx_global, ValTypeI32)
                print_variable_instrs = get_print_variable_instrs(string_pointer_val, string_pointer_global, temp_val,
                                                                  ValTypeI32)
                restore_instrs = get_restore_instrs(string_pointer_val, string_pointer_global, temp_val, temp_global,
                                                    LF_char_global, ValTypeI32)
                expr = expr[:i] + store_variable_instrs + print_variable_instrs + restore_instrs + expr[i:]
                i = i + len(store_variable_instrs + print_variable_instrs + restore_instrs)

                # print number count
                expr.insert(i, Instruction(I32Const, len(results_global_list)))
                i = i + 1
                store_variable_instrs = get_store_variable_instrs(temp_global, temp_val, LF_char_global,
                                                                  number_count_global, ValTypeI32)
                print_variable_instrs = get_print_variable_instrs(string_pointer_val, string_pointer_global, temp_val,
                                                                  ValTypeI32)
                restore_instrs = get_restore_instrs(string_pointer_val, string_pointer_global, temp_val, temp_global,
                                                    LF_char_global, ValTypeI32)
                expr = expr[:i] + store_variable_instrs + print_variable_instrs + restore_instrs + expr[i:]
                i = i + len(store_variable_instrs + print_variable_instrs + restore_instrs)

                # print results
                for result_global in results_global_list:
                    expr.insert(i, Instruction(GlobalGet, result_global["id"]))  # push the variable to be print
                    i = i + 1
                    store_variable_instrs = get_store_variable_instrs(temp_global, temp_val, LF_char_global,
                                                                      result_global["id"], result_global["type"])

                    print_variable_instrs = get_print_variable_instrs(string_pointer_val, string_pointer_global, temp_val, result_global["type"])
                    restore_instrs = get_restore_instrs(string_pointer_val, string_pointer_global, temp_val, temp_global, LF_char_global, result_global["type"])
                    expr = expr[:i] + store_variable_instrs + print_variable_instrs + restore_instrs + expr[i:]
                    i = i + len(store_variable_instrs + print_variable_instrs + restore_instrs)

                # put the original results to stack
                for result_global in results_global_list:
                    expr.insert(i, Instruction(GlobalGet, result_global["id"]))
                    i += 1

            elif expr[i].opcode == CallIndirect:
                # funcidx_instr = expr[i - 1]
                # if funcidx_instr.opcode != I32Const:
                #     raise Exception("call indirect 前面的指令不是i32const")
                # is_exist = check_import_exist(binary, elemidx=funcidx_instr.args)
                # if is_exist == False:
                #     functype_rewriter = SectionRewriter(binary.module)
                #     functype = functype_rewriter.get_typesec_functype(expr[i].args)
                #     # 这里import func的参数最后一个要加个i32，因为要有个标志
                #     import_funcidx = import_rewriter.append_import_function(
                #         "instrumentation" "get_call_indirect_" + funcidx_instr.args + "_args",
                #         functype.param_types + [ValTypeI32],
                #         functype.result_types)
                #     expr.insert(i, Instruction(I32Const, funcidx_instr.args))
                #     i += 1
                #     expr.insert(i, Instruction(Call, import_funcidx))
                #     i += 1
                # else:
                #     raise Exception("出现了重复的call_indirect")
                typeidx = expr[i].args  # subtract the number of import function

                functype = binary.module.type_sec[expr[i].args]

                params_global_list = []

                # store the param of call_indirect
                get_indirect_funcidx_instr = Instruction(GlobalSet, indirect_funcidx_global)
                expr.insert(i, get_indirect_funcidx_instr)
                i = i + 1


                for val_type in functype.param_types:
                    if val_type == ValTypeI32:
                        i32_globals = global_lists[0]
                        for i32_global in i32_globals:
                            if {"type": ValTypeI32, "id": i32_global} not in params_global_list:
                                expr.insert(i, Instruction(GlobalSet, i32_global))
                                params_global_list.append({"type": ValTypeI32, "id": i32_global})
                                break
                    elif val_type == ValTypeI64:
                        i64_globals = global_lists[1]
                        for i64_global in i64_globals:
                            if {"type": ValTypeI64, "id": i64_global} not in params_global_list:
                                expr.insert(i, Instruction(GlobalSet, i64_global))
                                params_global_list.append({"type": ValTypeI64, "id": i64_global})
                                break
                    elif val_type == ValTypeF32:
                        f32_globals = global_lists[2]
                        for f32_global in f32_globals:
                            if {"type": ValTypeF32, "id": f32_global} not in params_global_list:
                                expr.insert(i, Instruction(GlobalSet, f32_global))
                                params_global_list.append({"type": ValTypeF32, "id": f32_global})
                                break
                    elif val_type == ValTypeF64:
                        f64_globals = global_lists[3]
                        for f64_global in f64_globals:
                            if {"type": ValTypeF64, "id": f64_global} not in params_global_list:
                                expr.insert(i, Instruction(GlobalSet, f64_global))
                                params_global_list.append({"type": ValTypeF64, "id": f64_global})
                                break
                    elif val_type == ValTypeV128:
                        v128_globals = global_lists[4]
                        for v128_global in v128_globals:
                            if {"type": ValTypeV128, "id": v128_global} not in params_global_list:
                                expr.insert(i, Instruction(GlobalSet, v128_global))
                                params_global_list.append({"type": ValTypeV128, "id": v128_global})
                                break

                i = i + len(functype.param_types)
                divider_print_instrs = get_print_divider_instrs(string_pointer_global, string_pointer_val,
                                                                divider_offset_val)
                expr = expr[:i] + divider_print_instrs + expr[i:]
                i = i + len(divider_print_instrs)

                # print negative element idx
                expr.insert(i, Instruction(I32Const, 0))
                i = i + 1
                expr.insert(i, Instruction(GlobalGet, indirect_funcidx_global))
                i = i + 1
                expr.insert(i, Instruction(I32Sub))
                i = i + 1

                store_variable_instrs = get_store_variable_instrs(temp_global, temp_val, LF_char_global,
                                                                  indirect_functype_idx_global, ValTypeI32)
                print_variable_instrs = get_print_variable_instrs(string_pointer_val, string_pointer_global, temp_val,
                                                                  ValTypeI32)
                restore_instrs = get_restore_instrs(string_pointer_val, string_pointer_global, temp_val, temp_global,
                                                    LF_char_global, ValTypeI32)
                expr = expr[:i] + store_variable_instrs + print_variable_instrs + restore_instrs + expr[i:]
                i = i + len(store_variable_instrs + print_variable_instrs + restore_instrs)

                # print number count
                expr.insert(i, Instruction(I32Const, len(params_global_list)))
                i = i + 1
                store_variable_instrs = get_store_variable_instrs(temp_global, temp_val, LF_char_global,
                                                                  number_count_global, ValTypeI32)
                print_variable_instrs = get_print_variable_instrs(string_pointer_val, string_pointer_global, temp_val,
                                                                  ValTypeI32)
                restore_instrs = get_restore_instrs(string_pointer_val, string_pointer_global, temp_val, temp_global,
                                                    LF_char_global, ValTypeI32)
                expr = expr[:i] + store_variable_instrs + print_variable_instrs + restore_instrs + expr[i:]
                i = i + len(store_variable_instrs + print_variable_instrs + restore_instrs)

                # print params
                for param_global in params_global_list:
                    expr.insert(i, Instruction(GlobalGet, param_global["id"]))  # push the variable to be print
                    i = i + 1
                    store_variable_instrs = get_store_variable_instrs(temp_global, temp_val, LF_char_global,
                                                                      param_global["id"], param_global["type"])

                    print_variable_instrs = get_print_variable_instrs(string_pointer_val, string_pointer_global,
                                                                      temp_val, param_global["type"])
                    restore_instrs = get_restore_instrs(string_pointer_val, string_pointer_global, temp_val,
                                                        temp_global, LF_char_global, param_global["type"])
                    expr = expr[:i] + store_variable_instrs + print_variable_instrs + restore_instrs + expr[i:]
                    i = i + len(store_variable_instrs + print_variable_instrs + restore_instrs)

                # put the original params to stack
                for param_global in params_global_list:
                    expr.insert(i, Instruction(GlobalGet, param_global["id"]))
                    i += 1

                expr.insert(i, Instruction(GlobalGet, indirect_funcidx_global))
                i += 1

                # instrumentation after call_indirect instr
                results_global_list = []
                i = i + 1

                for val_type in functype.result_types:
                    if val_type == ValTypeI32:
                        i32_globals = global_lists[0]
                        for i32_global in i32_globals:
                            if {"type": ValTypeI32, "id": i32_global} not in results_global_list:
                                expr.insert(i, Instruction(GlobalSet, i32_global))
                                results_global_list.append({"type": ValTypeI32, "id": i32_global})
                                break
                    elif val_type == ValTypeI64:
                        i64_globals = global_lists[1]
                        for i64_global in i64_globals:
                            if {"type": ValTypeI64, "id": i64_global} not in results_global_list:
                                expr.insert(i, Instruction(GlobalSet, i64_global))
                                results_global_list.append({"type": ValTypeI64, "id": i64_global})
                                break
                    elif val_type == ValTypeF32:
                        f32_globals = global_lists[2]
                        for f32_global in f32_globals:
                            if {"type": ValTypeF32, "id": f32_global} not in results_global_list:
                                expr.insert(i, Instruction(GlobalSet, f32_global))
                                results_global_list.append({"type": ValTypeF32, "id": f32_global})
                                break
                    elif val_type == ValTypeF64:
                        f64_globals = global_lists[3]
                        for f64_global in f64_globals:
                            if {"type": ValTypeF64, "id": f64_global} not in results_global_list:
                                expr.insert(i, Instruction(GlobalSet, f64_global))
                                results_global_list.append({"type": ValTypeF64, "id": f64_global})
                                break
                    elif val_type == ValTypeV128:
                        v128_globals = global_lists[4]
                        for v128_global in v128_globals:
                            if {"type": ValTypeV128, "id": v128_global} not in results_global_list:
                                expr.insert(i, Instruction(GlobalSet, v128_global))
                                results_global_list.append({"type": ValTypeV128, "id": v128_global})
                                break

                i = i + len(functype.result_types)
                divider_print_instrs = get_print_divider_instrs(string_pointer_global, string_pointer_val,
                                                                divider_offset_val)
                expr = expr[:i] + divider_print_instrs + expr[i:]
                i = i + len(divider_print_instrs)

                # print negative element idx
                expr.insert(i, Instruction(I32Const, 0))
                i = i + 1
                expr.insert(i, Instruction(GlobalGet, indirect_funcidx_global))
                i = i + 1
                expr.insert(i, Instruction(I32Sub))
                i = i + 1

                store_variable_instrs = get_store_variable_instrs(temp_global, temp_val, LF_char_global,
                                                                  indirect_functype_idx_global, ValTypeI32)
                print_variable_instrs = get_print_variable_instrs(string_pointer_val, string_pointer_global, temp_val,
                                                                  ValTypeI32)
                restore_instrs = get_restore_instrs(string_pointer_val, string_pointer_global, temp_val, temp_global,
                                                    LF_char_global, ValTypeI32)
                expr = expr[:i] + store_variable_instrs + print_variable_instrs + restore_instrs + expr[i:]
                i = i + len(store_variable_instrs + print_variable_instrs + restore_instrs)

                # print number count
                expr.insert(i, Instruction(I32Const, len(results_global_list)))
                i = i + 1
                store_variable_instrs = get_store_variable_instrs(temp_global, temp_val, LF_char_global,
                                                                  number_count_global, ValTypeI32)
                print_variable_instrs = get_print_variable_instrs(string_pointer_val, string_pointer_global, temp_val,
                                                                  ValTypeI32)
                restore_instrs = get_restore_instrs(string_pointer_val, string_pointer_global, temp_val, temp_global,
                                                    LF_char_global, ValTypeI32)
                expr = expr[:i] + store_variable_instrs + print_variable_instrs + restore_instrs + expr[i:]
                i = i + len(store_variable_instrs + print_variable_instrs + restore_instrs)

                # print results
                for result_global in results_global_list:
                    expr.insert(i, Instruction(GlobalGet, result_global["id"]))  # push the variable to be print
                    i = i + 1
                    store_variable_instrs = get_store_variable_instrs(temp_global, temp_val, LF_char_global,
                                                                      result_global["id"], result_global["type"])

                    print_variable_instrs = get_print_variable_instrs(string_pointer_val, string_pointer_global,
                                                                      temp_val, result_global["type"])
                    restore_instrs = get_restore_instrs(string_pointer_val, string_pointer_global, temp_val,
                                                        temp_global, LF_char_global, result_global["type"])
                    expr = expr[:i] + store_variable_instrs + print_variable_instrs + restore_instrs + expr[i:]
                    i = i + len(store_variable_instrs + print_variable_instrs + restore_instrs)

                # put the original results to stack
                for result_global in results_global_list:
                    expr.insert(i, Instruction(GlobalGet, result_global["id"]))
                    i += 1

        i += 1
    return expr


def function_instrumentation(expr, binary, funcidx, global_list):
    global string_pointer_val, string_pointer_global, temp_val, temp_global, LF_char_global, divider_offset_val, divider_offset_global, funcidx_global, indirect_funcidx_global, indirect_functype_idx_global, number_count_global, instr_opcode_global

    i = 0

    while i < len(expr):
        if expr[i].opcode in [Block, Loop]:
            args = expr[i].args
            expr[i].args.instrs = function_instrumentation(args.instrs, binary, funcidx, global_list)
            i = i + 1
        elif expr[i].opcode == If:
            args = expr[i].args
            expr[i].args.instrs1 = function_instrumentation(args.instrs1, binary, funcidx, global_list)
            expr[i].args.instrs2 = function_instrumentation(args.instrs2, binary, funcidx, global_list)
            i = i + 1
        # 这里要跳过函数调用指令
        elif expr[i].opcode in [Call, CallIndirect]:
            i = i + 1
        else:
            instr = expr[i]
            instr_type, instr_context = instr_table[instr.opcode](binary, instr.args, funcidx)
            instr_results_type = instr_type['results']
            if instr_results_type != []:
                if instr_results_type == [ValTypeAny]:
                    pass
                elif instr_results_type == [ValTypeI32]:
                    i = i + 1
                    expr.insert(i, Instruction(GlobalSet, global_list[0]))
                    i = i + 1
                    divider_print_instrs = get_print_divider_instrs(string_pointer_global, string_pointer_val,
                                                                    divider_offset_val)
                    expr = expr[:i] + divider_print_instrs + expr[i:]
                    i = i + len(divider_print_instrs)
                    # print instr opcode
                    expr.insert(i, Instruction(I32Const, instr.opcode))
                    i = i + 1
                    store_variable_instrs = get_store_variable_instrs(temp_global, temp_val, LF_char_global,
                                                                      instr_opcode_global, ValTypeI32)
                    print_variable_instrs = get_print_variable_instrs(string_pointer_val, string_pointer_global,
                                                                      temp_val,
                                                                      ValTypeI32)
                    restore_instrs = get_restore_instrs(string_pointer_val, string_pointer_global, temp_val,
                                                        temp_global,
                                                        LF_char_global, ValTypeI32)
                    expr = expr[:i] + store_variable_instrs + print_variable_instrs + restore_instrs + expr[i:]
                    i = i + len(store_variable_instrs + print_variable_instrs + restore_instrs)
                    # print stack value
                    expr.insert(i, Instruction(GlobalGet, global_list[0]))
                    i = i + 1
                    store_variable_instrs = get_store_variable_instrs(temp_global, temp_val, LF_char_global,
                                                                      global_list[0], ValTypeI32)
                    print_variable_instrs = get_print_variable_instrs(string_pointer_val, string_pointer_global,
                                                                      temp_val,
                                                                      ValTypeI32)
                    restore_instrs = get_restore_instrs(string_pointer_val, string_pointer_global, temp_val,
                                                        temp_global,
                                                        LF_char_global, ValTypeI32)
                    expr = expr[:i] + store_variable_instrs + print_variable_instrs + restore_instrs + expr[i:]
                    i = i + len(store_variable_instrs + print_variable_instrs + restore_instrs)
                    # restore stack value
                    expr.insert(i, Instruction(GlobalGet, global_list[0]))
                elif instr_results_type == [ValTypeI64]:
                    i = i + 1
                    expr.insert(i, Instruction(GlobalSet, global_list[1]))
                    i = i + 1
                    divider_print_instrs = get_print_divider_instrs(string_pointer_global, string_pointer_val,
                                                                    divider_offset_val)
                    expr = expr[:i] + divider_print_instrs + expr[i:]
                    i = i + len(divider_print_instrs)
                    # print instr opcode
                    expr.insert(i, Instruction(I32Const, instr.opcode))
                    i = i + 1
                    store_variable_instrs = get_store_variable_instrs(temp_global, temp_val, LF_char_global,
                                                                      instr_opcode_global, ValTypeI32)
                    print_variable_instrs = get_print_variable_instrs(string_pointer_val, string_pointer_global,
                                                                      temp_val,
                                                                      ValTypeI32)
                    restore_instrs = get_restore_instrs(string_pointer_val, string_pointer_global, temp_val,
                                                        temp_global,
                                                        LF_char_global, ValTypeI32)
                    expr = expr[:i] + store_variable_instrs + print_variable_instrs + restore_instrs + expr[i:]
                    i = i + len(store_variable_instrs + print_variable_instrs + restore_instrs)
                    # print stack value
                    expr.insert(i, Instruction(GlobalGet, global_list[1]))
                    i = i + 1
                    store_variable_instrs = get_store_variable_instrs(temp_global, temp_val, LF_char_global,
                                                                      global_list[1], ValTypeI64)
                    print_variable_instrs = get_print_variable_instrs(string_pointer_val, string_pointer_global,
                                                                      temp_val,
                                                                      ValTypeI64)
                    restore_instrs = get_restore_instrs(string_pointer_val, string_pointer_global, temp_val,
                                                        temp_global,
                                                        LF_char_global, ValTypeI64)
                    expr = expr[:i] + store_variable_instrs + print_variable_instrs + restore_instrs + expr[i:]
                    i = i + len(store_variable_instrs + print_variable_instrs + restore_instrs)
                    # restore stack value
                    expr.insert(i, Instruction(GlobalGet, global_list[1]))
                elif instr_results_type == [ValTypeF32]:
                    i = i + 1
                    expr.insert(i, Instruction(GlobalSet, global_list[2]))
                    i = i + 1
                    divider_print_instrs = get_print_divider_instrs(string_pointer_global, string_pointer_val,
                                                                    divider_offset_val)
                    expr = expr[:i] + divider_print_instrs + expr[i:]
                    i = i + len(divider_print_instrs)
                    # print instr opcode
                    expr.insert(i, Instruction(I32Const, instr.opcode))
                    i = i + 1
                    store_variable_instrs = get_store_variable_instrs(temp_global, temp_val, LF_char_global,
                                                                      instr_opcode_global, ValTypeI32)
                    print_variable_instrs = get_print_variable_instrs(string_pointer_val, string_pointer_global,
                                                                      temp_val,
                                                                      ValTypeI32)
                    restore_instrs = get_restore_instrs(string_pointer_val, string_pointer_global, temp_val,
                                                        temp_global,
                                                        LF_char_global, ValTypeI32)
                    expr = expr[:i] + store_variable_instrs + print_variable_instrs + restore_instrs + expr[i:]
                    i = i + len(store_variable_instrs + print_variable_instrs + restore_instrs)
                    # print stack value
                    expr.insert(i, Instruction(GlobalGet, global_list[2]))
                    i = i + 1
                    store_variable_instrs = get_store_variable_instrs(temp_global, temp_val, LF_char_global,
                                                                      global_list[2], ValTypeF32)
                    print_variable_instrs = get_print_variable_instrs(string_pointer_val, string_pointer_global,
                                                                      temp_val,
                                                                      ValTypeF32)
                    restore_instrs = get_restore_instrs(string_pointer_val, string_pointer_global, temp_val,
                                                        temp_global,
                                                        LF_char_global, ValTypeF32)
                    expr = expr[:i] + store_variable_instrs + print_variable_instrs + restore_instrs + expr[i:]
                    i = i + len(store_variable_instrs + print_variable_instrs + restore_instrs)
                    # restore stack value
                    expr.insert(i, Instruction(GlobalGet, global_list[2]))
                elif instr_results_type == [ValTypeF64]:
                    i = i + 1
                    expr.insert(i, Instruction(GlobalSet, global_list[3]))
                    i = i + 1
                    divider_print_instrs = get_print_divider_instrs(string_pointer_global, string_pointer_val,
                                                                    divider_offset_val)
                    expr = expr[:i] + divider_print_instrs + expr[i:]
                    i = i + len(divider_print_instrs)
                    # print instr opcode
                    expr.insert(i, Instruction(I32Const, instr.opcode))
                    i = i + 1
                    store_variable_instrs = get_store_variable_instrs(temp_global, temp_val, LF_char_global,
                                                                      instr_opcode_global, ValTypeI32)
                    print_variable_instrs = get_print_variable_instrs(string_pointer_val, string_pointer_global,
                                                                      temp_val,
                                                                      ValTypeI32)
                    restore_instrs = get_restore_instrs(string_pointer_val, string_pointer_global, temp_val,
                                                        temp_global,
                                                        LF_char_global, ValTypeI32)
                    expr = expr[:i] + store_variable_instrs + print_variable_instrs + restore_instrs + expr[i:]
                    i = i + len(store_variable_instrs + print_variable_instrs + restore_instrs)
                    # print stack value
                    expr.insert(i, Instruction(GlobalGet, global_list[3]))
                    i = i + 1
                    store_variable_instrs = get_store_variable_instrs(temp_global, temp_val, LF_char_global,
                                                                      global_list[3], ValTypeF64)
                    print_variable_instrs = get_print_variable_instrs(string_pointer_val, string_pointer_global,
                                                                      temp_val,
                                                                      ValTypeF64)
                    restore_instrs = get_restore_instrs(string_pointer_val, string_pointer_global, temp_val,
                                                        temp_global,
                                                        LF_char_global, ValTypeF64)
                    expr = expr[:i] + store_variable_instrs + print_variable_instrs + restore_instrs + expr[i:]
                    i = i + len(store_variable_instrs + print_variable_instrs + restore_instrs)
                    # restore stack value
                    expr.insert(i, Instruction(GlobalGet, global_list[3]))
                elif instr_results_type == [ValTypeV128]:
                    i = i + 1
                    expr.insert(i, Instruction(GlobalSet, global_list[4]))
                    i = i + 1
                    divider_print_instrs = get_print_divider_instrs(string_pointer_global, string_pointer_val,
                                                                    divider_offset_val)
                    expr = expr[:i] + divider_print_instrs + expr[i:]
                    i = i + len(divider_print_instrs)
                    # print instr opcode
                    expr.insert(i, Instruction(I32Const, instr.opcode))
                    i = i + 1
                    store_variable_instrs = get_store_variable_instrs(temp_global, temp_val, LF_char_global,
                                                                      instr_opcode_global, ValTypeI32)
                    print_variable_instrs = get_print_variable_instrs(string_pointer_val, string_pointer_global,
                                                                      temp_val,
                                                                      ValTypeI32)
                    restore_instrs = get_restore_instrs(string_pointer_val, string_pointer_global, temp_val,
                                                        temp_global,
                                                        LF_char_global, ValTypeI32)
                    expr = expr[:i] + store_variable_instrs + print_variable_instrs + restore_instrs + expr[i:]
                    i = i + len(store_variable_instrs + print_variable_instrs + restore_instrs)
                    # print stack value
                    expr.insert(i, Instruction(GlobalGet, global_list[4]))
                    i = i + 1
                    store_variable_instrs = get_store_variable_instrs(temp_global, temp_val, LF_char_global,
                                                                      global_list[4], ValTypeV128)
                    print_variable_instrs = get_print_variable_instrs(string_pointer_val, string_pointer_global,
                                                                      temp_val,
                                                                      ValTypeV128)
                    restore_instrs = get_restore_instrs(string_pointer_val, string_pointer_global, temp_val,
                                                        temp_global,
                                                        LF_char_global, ValTypeV128)
                    expr = expr[:i] + store_variable_instrs + print_variable_instrs + restore_instrs + expr[i:]
                    i = i + len(store_variable_instrs + print_variable_instrs + restore_instrs)
                    # restore stack value
                    expr.insert(i, Instruction(GlobalGet, global_list[4]))

            i = i + 1
    return expr
