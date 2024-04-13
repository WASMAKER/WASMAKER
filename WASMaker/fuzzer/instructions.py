from WASMaker.fuzzer.instr_context import *
from WASMaker.fuzzer.instr_context import _select
from WASMaker.parser import opcodes


def instr_fn(vm, args):
    pass


instr_table = [instr_fn] * 0xFFFFFF

# instr_control
instr_table[opcodes.Unreachable] = unreachable
instr_table[opcodes.Nop] = nop
instr_table[opcodes.Block] = block
instr_table[opcodes.Loop] = loop
instr_table[opcodes.If] = control_if
instr_table[opcodes.Else_] = control_else

instr_table[opcodes.Br] = br
instr_table[opcodes.BrIf] = br_if
instr_table[opcodes.BrTable] = br_table
instr_table[opcodes.Return] = control_return
instr_table[opcodes.Call] = call
instr_table[opcodes.CallIndirect] = call_indirect

# instr_parametric
instr_table[opcodes.Drop] = drop
instr_table[opcodes.Select] = _select

# instr_variable
instr_table[opcodes.LocalGet] = local_get
instr_table[opcodes.LocalSet] = local_set
instr_table[opcodes.LocalTee] = local_tee
instr_table[opcodes.GlobalGet] = global_get
instr_table[opcodes.GlobalSet] = global_set

# instr_memory
instr_table[opcodes.I32Load] = i32_load
instr_table[opcodes.I64Load] = i64_load
instr_table[opcodes.F32Load] = f32_load
instr_table[opcodes.F64Load] = f64_load
instr_table[opcodes.I32Load8S] = i32_load_8_s
instr_table[opcodes.I32Load8U] = i32_load_8_u
instr_table[opcodes.I32Load16S] = i32_load_16_s
instr_table[opcodes.I32Load16U] = i32_load_16_u
instr_table[opcodes.I64Load8S] = i64_load_8_s
instr_table[opcodes.I64Load8U] = i64_load_8_u
instr_table[opcodes.I64Load16S] = i64_load_16_s
instr_table[opcodes.I64Load16U] = i64_load_16_u
instr_table[opcodes.I64Load32S] = i64_load_32_s
instr_table[opcodes.I64Load32U] = i64_load_32_u
instr_table[opcodes.I32Store] = i32_store
instr_table[opcodes.I64Store] = i64_store
instr_table[opcodes.F32Store] = f32_store
instr_table[opcodes.F64Store] = f64_store
instr_table[opcodes.I32Store8] = i32_store_8
instr_table[opcodes.I32Store16] = i32_store_16
instr_table[opcodes.I64Store8] = i64_store_8
instr_table[opcodes.I64Store16] = i64_store_16
instr_table[opcodes.I64Store32] = i64_store_32
instr_table[opcodes.MemorySize] = memory_size
instr_table[opcodes.MemoryGrow] = memory_grow

# instr_numeric
instr_table[opcodes.I32Const] = i32_const
instr_table[opcodes.I64Const] = i64_const
instr_table[opcodes.F32Const] = f32_const
instr_table[opcodes.F64Const] = f64_const
instr_table[opcodes.I32Eqz] = i32_eqz
instr_table[opcodes.I32Eq] = i32_eq
instr_table[opcodes.I32Ne] = i32_ne
instr_table[opcodes.I32LtS] = i32_lt_s
instr_table[opcodes.I32LtU] = i32_lt_u
instr_table[opcodes.I32GtS] = i32_gt_s
instr_table[opcodes.I32GtU] = i32_gt_u
instr_table[opcodes.I32LeS] = i32_le_s
instr_table[opcodes.I32LeU] = i32_le_u
instr_table[opcodes.I32GeS] = i32_ge_s
instr_table[opcodes.I32GeU] = i32_ge_u
instr_table[opcodes.I64Eqz] = i64_eqz
instr_table[opcodes.I64Eq] = i64_eq
instr_table[opcodes.I64Ne] = i64_ne
instr_table[opcodes.I64LtS] = i64_lt_s
instr_table[opcodes.I64LtU] = i64_lt_u
instr_table[opcodes.I64GtS] = i64_gt_s
instr_table[opcodes.I64GtU] = i64_gt_u
instr_table[opcodes.I64LeS] = i64_le_s
instr_table[opcodes.I64LeU] = i64_le_u
instr_table[opcodes.I64GeS] = i64_ge_s
instr_table[opcodes.I64GeU] = i64_ge_u
instr_table[opcodes.F32Eq] = f32_eq
instr_table[opcodes.F32Ne] = f32_ne
instr_table[opcodes.F32Lt] = f32_lt
instr_table[opcodes.F32Gt] = f32_gt
instr_table[opcodes.F32Le] = f32_le
instr_table[opcodes.F32Ge] = f32_ge
instr_table[opcodes.F64Eq] = f64_eq
instr_table[opcodes.F64Ne] = f64_ne
instr_table[opcodes.F64Lt] = f64_lt
instr_table[opcodes.F64Gt] = f64_gt
instr_table[opcodes.F64Le] = f64_le
instr_table[opcodes.F64Ge] = f64_ge
instr_table[opcodes.I32Clz] = i32_clz
instr_table[opcodes.I32Ctz] = i32_ctz
instr_table[opcodes.I32PopCnt] = i32_pop_cnt
instr_table[opcodes.I32Add] = i32_add
instr_table[opcodes.I32Sub] = i32_sub
instr_table[opcodes.I32Mul] = i32_mul
instr_table[opcodes.I32DivS] = i32_div_s
instr_table[opcodes.I32DivU] = i32_div_u
instr_table[opcodes.I32RemS] = i32_rem_s
instr_table[opcodes.I32RemU] = i32_rem_u
instr_table[opcodes.I32And] = i32_and
instr_table[opcodes.I32Or] = i32_or
instr_table[opcodes.I32Xor] = i32_xor
instr_table[opcodes.I32Shl] = i32_shl
instr_table[opcodes.I32ShrS] = i32_shr_s
instr_table[opcodes.I32ShrU] = i32_shr_u
instr_table[opcodes.I32Rotl] = i32_rotl
instr_table[opcodes.I32Rotr] = i32_rotr
instr_table[opcodes.I64Clz] = i64_clz
instr_table[opcodes.I64Ctz] = i64_ctz
instr_table[opcodes.I64PopCnt] = i64_pop_cnt
instr_table[opcodes.I64Add] = i64_add
instr_table[opcodes.I64Sub] = i64_sub
instr_table[opcodes.I64Mul] = i64_mul
instr_table[opcodes.I64DivS] = i64_div_s
instr_table[opcodes.I64DivU] = i64_div_u
instr_table[opcodes.I64RemS] = i64_rem_s
instr_table[opcodes.I64RemU] = i64_rem_u
instr_table[opcodes.I64And] = i64_and
instr_table[opcodes.I64Or] = i64_or
instr_table[opcodes.I64Xor] = i64_xor
instr_table[opcodes.I64Shl] = i64_shl
instr_table[opcodes.I64ShrS] = i64_shr_s
instr_table[opcodes.I64ShrU] = i64_shr_u
instr_table[opcodes.I64Rotl] = i64_rotl
instr_table[opcodes.I64Rotr] = i64_rotr
instr_table[opcodes.F32Abs] = f32_abs
instr_table[opcodes.F32Neg] = f32_neg
instr_table[opcodes.F32Ceil] = f32_ceil
instr_table[opcodes.F32Floor] = f32_floor
instr_table[opcodes.F32Trunc] = f32_trunc
instr_table[opcodes.F32Nearest] = f32_nearest
instr_table[opcodes.F32Sqrt] = f32_sqrt
instr_table[opcodes.F32Add] = f32_add
instr_table[opcodes.F32Sub] = f32_sub
instr_table[opcodes.F32Mul] = f32_mul
instr_table[opcodes.F32Div] = f32_div
instr_table[opcodes.F32Min] = f32_min
instr_table[opcodes.F32Max] = f32_max
instr_table[opcodes.F32CopySign] = f32_copysign
instr_table[opcodes.F64Abs] = f64_abs
instr_table[opcodes.F64Neg] = f64_neg
instr_table[opcodes.F64Ceil] = f64_ceil
instr_table[opcodes.F64Floor] = f64_floor
instr_table[opcodes.F64Trunc] = f64_trunc
instr_table[opcodes.F64Nearest] = f64_nearest
instr_table[opcodes.F64Sqrt] = f64_sqrt
instr_table[opcodes.F64Add] = f64_add
instr_table[opcodes.F64Sub] = f64_sub
instr_table[opcodes.F64Mul] = f64_mul
instr_table[opcodes.F64Div] = f64_div
instr_table[opcodes.F64Min] = f64_min
instr_table[opcodes.F64Max] = f64_max
instr_table[opcodes.F64CopySign] = f64_copysign
instr_table[opcodes.I32WrapI64] = i32_wrap_i64
instr_table[opcodes.I32TruncF32S] = i32_trunc_f32_s
instr_table[opcodes.I32TruncF32U] = i32_trunc_f32_u
instr_table[opcodes.I32TruncF64S] = i32_trunc_f64_s
instr_table[opcodes.I32TruncF64U] = i32_trunc_f64_u
instr_table[opcodes.I64ExtendI32S] = i64_extend_i32_s
instr_table[opcodes.I64ExtendI32U] = i64_extend_i32_u
instr_table[opcodes.I64TruncF32S] = i64_trunc_f32_s
instr_table[opcodes.I64TruncF32U] = i64_trunc_f32_u
instr_table[opcodes.I64TruncF64S] = i64_trunc_f64_s
instr_table[opcodes.I64TruncF64U] = i64_trunc_f64_u
instr_table[opcodes.F32ConvertI32S] = f32_convert_i32_s
instr_table[opcodes.F32ConvertI32U] = f32_convert_i32_u
instr_table[opcodes.F32ConvertI64S] = f32_convert_i64_s
instr_table[opcodes.F32ConvertI64U] = f32_convert_i64_u
instr_table[opcodes.F32DemoteF64] = f32_demote_f64
instr_table[opcodes.F64ConvertI32S] = f64_convert_i32_s
instr_table[opcodes.F64ConvertI32U] = f64_convert_i32_u
instr_table[opcodes.F64ConvertI64S] = f64_convert_i64_s
instr_table[opcodes.F64ConvertI64U] = f64_convert_i64_u
instr_table[opcodes.F64PromoteF32] = f64_promote_f32
instr_table[opcodes.I32ReinterpretF32] = i32_reinterpret_f32
instr_table[opcodes.I64ReinterpretF64] = i64_reinterpret_f64
instr_table[opcodes.F32ReinterpretI32] = f32_reinterpret_i32
instr_table[opcodes.F64ReinterpretI64] = f64_reinterpret_i64
instr_table[opcodes.I32Extend8S] = i32_extend_8_s
instr_table[opcodes.I32Extend16S] = i32_extend_16_s
instr_table[opcodes.I64Extend8S] = i64_extend_8_s
instr_table[opcodes.I64Extend16S] = i64_extend_16_s
instr_table[opcodes.I64Extend32S] = i64_extend_32_s

instr_table[opcodes.I32TruncSatF32S] = i32_trunc_sat_f32_s
instr_table[opcodes.I32TruncSatF32U] = i32_trunc_sat_f32_u
instr_table[opcodes.I32TruncSatF64S] = i32_trunc_sat_f64_s
instr_table[opcodes.I32TruncSatF64U] = i32_trunc_sat_f64_u
instr_table[opcodes.I64TruncSatF32S] = i64_trunc_sat_f32_s
instr_table[opcodes.I64TruncSatF32U] = i64_trunc_sat_f32_u
instr_table[opcodes.I64TruncSatF64S] = i64_trunc_sat_f64_s
instr_table[opcodes.I64TruncSatF64U] = i64_trunc_sat_f64_u
instr_table[opcodes.MemoryInit] = memory_init
instr_table[opcodes.DataDrop] = data_drop
instr_table[opcodes.MemoryCopy] = memory_copy
instr_table[opcodes.MemoryFill] = memory_fill
instr_table[opcodes.TableInit] = table_init
instr_table[opcodes.ElemDrop] = elem_drop
instr_table[opcodes.TableCopy] = table_copy
instr_table[opcodes.TableGrow] = table_grow
instr_table[opcodes.TableSize] = table_size
instr_table[opcodes.TableFill] = table_fill

instr_table[opcodes.SelectT] = select_t
instr_table[opcodes.TableGet] = table_get
instr_table[opcodes.TableSet] = table_set
instr_table[opcodes.RefNull] = ref_null
instr_table[opcodes.RefIsNull] = ref_is_null
instr_table[opcodes.RefFunc] = ref_func
instr_table[opcodes.V128Load] = v128_load
instr_table[opcodes.V128Load8x8S] = v128_load8x8_s
instr_table[opcodes.V128Load8x8U] = v128_load8x8_u
instr_table[opcodes.V128Load16x4S] = v128_load16x4_s
instr_table[opcodes.V128Load16x4U] = v128_load16x4_u
instr_table[opcodes.V128Load32x2S] = v128_load32x2_s
instr_table[opcodes.V128Load32x2U] = v128_load32x2_u
instr_table[opcodes.V128Load8Splat] = v128_load8_splat
instr_table[opcodes.V128Load16Splat] = v128_load16_splat
instr_table[opcodes.V128Load32Splat] = v128_load32_splat
instr_table[opcodes.V128Load64Splat] = v128_load64_splat
instr_table[opcodes.V128Store] = v128_store
instr_table[opcodes.V128Const] = v128_const
instr_table[opcodes.I8x16Shuffle] = i8x16_shuffle
instr_table[opcodes.I8x16Swizzle] = i8x16_swizzle
instr_table[opcodes.I8x16Splat] = i8x16_splat
instr_table[opcodes.I16x8Splat] = i16x8_splat
instr_table[opcodes.I32x4Splat] = i32x4_splat
instr_table[opcodes.I64x2Splat] = i64x2_splat
instr_table[opcodes.F32x4Splat] = f32x4_splat
instr_table[opcodes.F64x2Splat] = f64x2_splat
instr_table[opcodes.I8x16ExtractLaneS] = i8x16_extract_lane_s
instr_table[opcodes.I8x16ExtractLaneU] = i8x16_extract_lane_u
instr_table[opcodes.I8x16ReplaceLane] = i8x16_replace_lane
instr_table[opcodes.I16x8ExtractLaneS] = i16x8_extract_lane_s
instr_table[opcodes.I16x8ExtractLaneU] = i16x8_extract_lane_u
instr_table[opcodes.I16x8ReplaceLane] = i16x8_replace_lane
instr_table[opcodes.I32x4ExtractLane] = i32x4_extract_lane
instr_table[opcodes.I32x4ReplaceLane] = i32x4_replace_lane
instr_table[opcodes.I64x2ExtractLane] = i64x2_extract_lane
instr_table[opcodes.I64x2ReplaceLane] = i64x2_replace_lane
instr_table[opcodes.F32x4ExtractLane] = f32x4_extract_lane
instr_table[opcodes.F32x4ReplaceLane] = f32x4_replace_lane
instr_table[opcodes.F64x2ExtractLane] = f64x2_extract_lane
instr_table[opcodes.F64x2ReplaceLane] = f64x2_replace_lane
instr_table[opcodes.I8x16Eq] = i8x16_eq
instr_table[opcodes.I8x16Ne] = i8x16_ne
instr_table[opcodes.I8x16LtS] = i8x16_lt_s
instr_table[opcodes.I8x16LtU] = i8x16_lt_u
instr_table[opcodes.I8x16GtS] = i8x16_gt_s
instr_table[opcodes.I8x16GtU] = i8x16_gt_u
instr_table[opcodes.I8x16LeS] = i8x16_le_s
instr_table[opcodes.I8x16LeU] = i8x16_le_u
instr_table[opcodes.I8x16GeS] = i8x16_ge_s
instr_table[opcodes.I8x16GeU] = i8x16_ge_u
instr_table[opcodes.I16x8Eq] = i16x8_eq
instr_table[opcodes.I16x8Ne] = i16x8_ne
instr_table[opcodes.I16x8LtS] = i16x8_lt_s
instr_table[opcodes.I16x8LtU] = i16x8_lt_u
instr_table[opcodes.I16x8GtS] = i16x8_gt_s
instr_table[opcodes.I16x8GtU] = i16x8_gt_u
instr_table[opcodes.I16x8LeS] = i16x8_le_s
instr_table[opcodes.I16x8LeU] = i16x8_le_u
instr_table[opcodes.I16x8GeS] = i16x8_ge_s
instr_table[opcodes.I16x8GeU] = i16x8_ge_u
instr_table[opcodes.I32x4Eq] = i32x4_eq
instr_table[opcodes.I32x4Ne] = i32x4_ne
instr_table[opcodes.I32x4LtS] = i32x4_lt_s
instr_table[opcodes.I32x4LtU] = i32x4_lt_u
instr_table[opcodes.I32x4GtS] = i32x4_gt_s
instr_table[opcodes.I32x4GtU] = i32x4_gt_u
instr_table[opcodes.I32x4LeS] = i32x4_le_s
instr_table[opcodes.I32x4LeU] = i32x4_le_u
instr_table[opcodes.I32x4GeS] = i32x4_ge_s
instr_table[opcodes.I32x4GeU] = i32x4_ge_u
instr_table[opcodes.F32x4Eq] = f32x4_eq
instr_table[opcodes.F32x4Ne] = f32x4_ne
instr_table[opcodes.F32x4Lt] = f32x4_lt
instr_table[opcodes.F32x4Gt] = f32x4_gt
instr_table[opcodes.F32x4Le] = f32x4_le
instr_table[opcodes.F32x4Ge] = f32x4_ge
instr_table[opcodes.F64x2Eq] = f64x2_eq
instr_table[opcodes.F64x2Ne] = f64x2_ne
instr_table[opcodes.F64x2Lt] = f64x2_lt
instr_table[opcodes.F64x2Gt] = f64x2_gt
instr_table[opcodes.F64x2Le] = f64x2_le
instr_table[opcodes.F64x2Ge] = f64x2_ge
instr_table[opcodes.V128Not] = v128_not
instr_table[opcodes.V128And] = v128_and
instr_table[opcodes.V128AndNot] = v128_and_not
instr_table[opcodes.V128Or] = v128_or
instr_table[opcodes.V128Xor] = v128_xor
instr_table[opcodes.V128BitSelect] = v128_bit_select
instr_table[opcodes.V128AnyTrue] = v128_any_true
instr_table[opcodes.V128Load8Lane] = v128_load8_lane
instr_table[opcodes.V128Load16Lane] = v128_load16_lane
instr_table[opcodes.V128Load32Lane] = v128_load32_lane
instr_table[opcodes.V128Load64Lane] = v128_load64_lane
instr_table[opcodes.V128Store8Lane] = v128_store8_lane
instr_table[opcodes.V128Store16Lane] = v128_store16_lane
instr_table[opcodes.V128Store32Lane] = v128_store32_lane
instr_table[opcodes.V128Store64Lane] = v128_store64_lane
instr_table[opcodes.V128Load32Zero] = v128_load32_zero
instr_table[opcodes.V128Load64Zero] = v128_load64_zero
instr_table[opcodes.F32x4DemoteF64x2Zero] = f32x4_demote_f64x2_zero
instr_table[opcodes.F64x2PromoteLowF32x4] = f64x2_promote_low_f32x4
instr_table[opcodes.I8x16Abs] = i8x16_abs
instr_table[opcodes.I8x16Neg] = i8x16_neg
instr_table[opcodes.I8x16Popcnt] = i8x16_popcnt
instr_table[opcodes.I8x16AllTrue] = i8x16_all_true
instr_table[opcodes.I8x16Bitmask] = i8x16_bitmask
instr_table[opcodes.I8x16NarrowI16x8S] = i8x16_narrow_i16x8_s
instr_table[opcodes.I8x16NarrowI16x8U] = i8x16_narrow_i16x8_u
instr_table[opcodes.F32x4Ceil] = f32x4_ceil
instr_table[opcodes.F32x4Floor] = f32x4_floor
instr_table[opcodes.F32x4Trunc] = f32x4_trunc
instr_table[opcodes.F32x4Nearest] = f32x4_nearest
instr_table[opcodes.I8x16Shl] = i8x16_shl
instr_table[opcodes.I8x16ShrS] = i8x16_shr_s
instr_table[opcodes.I8x16ShrU] = i8x16_shr_u
instr_table[opcodes.I8x16Add] = i8x16_add
instr_table[opcodes.I8x16AddSatS] = i8x16_add_sat_s
instr_table[opcodes.I8x16AddSatU] = i8x16_add_sat_u
instr_table[opcodes.I8x16Sub] = i8x16_sub
instr_table[opcodes.I8x16SubSatS] = i8x16_sub_sat_s
instr_table[opcodes.I8x16SubSatU] = i8x16_sub_sat_u
instr_table[opcodes.F64x2Ceil] = f64x2_ceil
instr_table[opcodes.F64x2Floor] = f64x2_floor
instr_table[opcodes.I8x16MinS] = i8x16_min_s
instr_table[opcodes.I8x16MinU] = i8x16_min_u
instr_table[opcodes.I8x16MaxS] = i8x16_max_s
instr_table[opcodes.I8x16MaxU] = i8x16_max_u
instr_table[opcodes.F64x2Trunc] = f64x2_trunc
instr_table[opcodes.I8x16AvgrU] = i8x16_avgr_u
instr_table[opcodes.I16x8ExtaddPairwiseI8x16S] = i16x8_extadd_pairwise_i8x16_s
instr_table[opcodes.I16x8ExtaddPairwiseI8x16U] = i16x8_extadd_pairwise_i8x16_u
instr_table[opcodes.I32x4ExtaddPairwiseI16x8S] = i32x4_extadd_pairwise_i16x8_s
instr_table[opcodes.I32x4ExtaddPairwiseI16x8U] = i32x4_extadd_pairwise_i16x8_u
instr_table[opcodes.I16x8Abs] = i16x8_abs
instr_table[opcodes.I16x8Neg] = i16x8_neg
instr_table[opcodes.I16x8Q15mulrSatS] = i16x8_q15mulr_sat_s
instr_table[opcodes.I16x8AllTrue] = i16x8_all_true
instr_table[opcodes.I16x8Bitmask] = i16x8_bitmask
instr_table[opcodes.I16x8NarrowI32x4S] = i16x8_narrow_i32x4_s
instr_table[opcodes.I16x8NarrowI32x4U] = i16x8_narrow_i32x4_u
instr_table[opcodes.I16x8ExtendLowI8x16S] = i16x8_extend_low_i8x16_s
instr_table[opcodes.I16x8ExtendHighI8x16S] = i16x8_extend_high_i8x16_s
instr_table[opcodes.I16x8ExtendLowI8x16U] = i16x8_extend_low_i8x16_u
instr_table[opcodes.I16x8ExtendHighI8x16U] = i16x8_extend_high_i8x16_u
instr_table[opcodes.I16x8Shl] = i16x8_shl
instr_table[opcodes.I16x8ShrS] = i16x8_shr_s
instr_table[opcodes.I16x8ShrU] = i16x8_shr_u
instr_table[opcodes.I16x8Add] = i16x8_add
instr_table[opcodes.I16x8AddSatS] = i16x8_add_sat_s
instr_table[opcodes.I16x8AddSatU] = i16x8_add_sat_u
instr_table[opcodes.I16x8Sub] = i16x8_sub
instr_table[opcodes.I16x8SubSatS] = i16x8_sub_sat_s
instr_table[opcodes.I16x8SubSatU] = i16x8_sub_sat_u
instr_table[opcodes.F64x2Nearest] = f64x2_nearest
instr_table[opcodes.I16x8Mul] = i16x8_mul
instr_table[opcodes.I16x8MinS] = i16x8_min_s
instr_table[opcodes.I16x8MinU] = i16x8_min_u
instr_table[opcodes.I16x8MaxS] = i16x8_max_s
instr_table[opcodes.I16x8MaxU] = i16x8_max_u
instr_table[opcodes.I16x8AvgrU] = i16x8_avgr_u
instr_table[opcodes.I16x8ExtmulLowI8x16S] = i16x8_extmul_low_i8x16_s
instr_table[opcodes.I16x8ExtmulHighI8x16S] = i16x8_extmul_high_i8x16_s
instr_table[opcodes.I16x8ExtmulLowI8x16U] = i16x8_extmul_low_i8x16_u
instr_table[opcodes.I16x8ExtmulHighI8x16U] = i16x8_extmul_high_i8x16_u
instr_table[opcodes.I32x4Abs] = i32x4_abs
instr_table[opcodes.I32x4Neg] = i32x4_neg
instr_table[opcodes.I32x4AllTrue] = i32x4_all_true
instr_table[opcodes.I32x4Bitmask] = i32x4_bitmask
instr_table[opcodes.I32x4ExtendLowI16x8S] = i32x4_extend_low_i16x8_s
instr_table[opcodes.I32x4ExtendHighI16x8S] = i32x4_extend_high_i16x8_s
instr_table[opcodes.I32x4ExtendLowI16x8U] = i32x4_extend_low_i16x8_u
instr_table[opcodes.I32x4ExtendHighI16x8U] = i32x4_extend_high_i16x8_u
instr_table[opcodes.I32x4Shl] = i32x4_shl
instr_table[opcodes.I32x4ShrS] = i32x4_shr_s
instr_table[opcodes.I32x4ShrU] = i32x4_shr_u
instr_table[opcodes.I32x4Add] = i32x4_add
instr_table[opcodes.I32x4Sub] = i32x4_sub
instr_table[opcodes.I32x4Mul] = i32x4_mul
instr_table[opcodes.I32x4MinS] = i32x4_min_s
instr_table[opcodes.I32x4MinU] = i32x4_min_u
instr_table[opcodes.I32x4MaxS] = i32x4_max_s
instr_table[opcodes.I32x4MaxU] = i32x4_max_u
instr_table[opcodes.I32x4DotI16x8S] = i32x4_dot_i16x8_s
instr_table[opcodes.I32x4ExtmulLowI16x8S] = i32x4_extmul_low_i16x8_s
instr_table[opcodes.I32x4ExtmulHighI16x8S] = i32x4_extmul_high_i16x8_s
instr_table[opcodes.I32x4ExtmulLowI16x8U] = i32x4_extmul_low_i16x8_u
instr_table[opcodes.I32x4ExtmulHighI16x8U] = i32x4_extmul_high_i16x8_u
instr_table[opcodes.I64x2Abs] = i64x2_abs
instr_table[opcodes.I64x2Neg] = i64x2_neg
instr_table[opcodes.I64x2AllTrue] = i64x2_all_true
instr_table[opcodes.I64x2Bitmask] = i64x2_bitmask
instr_table[opcodes.I64x2ExtendLowI32x4S] = i64x2_extend_low_i32x4_s
instr_table[opcodes.I64x2ExtendHighI32x4S] = i64x2_extend_high_i32x4_s
instr_table[opcodes.I64x2ExtendLowI32x4U] = i64x2_extend_low_i32x4_u
instr_table[opcodes.I64x2ExtendHighI32x4U] = i64x2_extend_high_i32x4_u
instr_table[opcodes.I64x2Shl] = i64x2_shl
instr_table[opcodes.I64x2ShrS] = i64x2_shr_s
instr_table[opcodes.I64x2ShrU] = i64x2_shr_u
instr_table[opcodes.I64x2Add] = i64x2_add
instr_table[opcodes.I64x2Sub] = i64x2_sub
instr_table[opcodes.I64x2Mul] = i64x2_mul
instr_table[opcodes.I64x2Eq] = i64x2_eq
instr_table[opcodes.I64x2Ne] = i64x2_ne
instr_table[opcodes.I64x2LtS] = i64x2_lt_s
instr_table[opcodes.I64x2GtS] = i64x2_gt_s
instr_table[opcodes.I64x2LeS] = i64x2_le_s
instr_table[opcodes.I64x2GeS] = i64x2_ge_s
instr_table[opcodes.I64x2ExtmulLowI32x4S] = i64x2_extmul_low_i32x4_s
instr_table[opcodes.I64x2ExtmulHighI32x4S] = i64x2_extmul_high_i32x4_s
instr_table[opcodes.I64x2ExtmulLowI32x4U] = i64x2_extmul_low_i32x4_u
instr_table[opcodes.I64x2ExtmulHighI32x4U] = i64x2_extmul_high_i32x4_u
instr_table[opcodes.F32x4Abs] = f32x4_abs
instr_table[opcodes.F32x4Neg] = f32x4_neg
instr_table[opcodes.F32x4Sqrt] = f32x4_sqrt
instr_table[opcodes.F32x4Add] = f32x4_add
instr_table[opcodes.F32x4Sub] = f32x4_sub
instr_table[opcodes.F32x4Mul] = f32x4_mul
instr_table[opcodes.F32x4Div] = f32x4_div
instr_table[opcodes.F32x4Min] = f32x4_min
instr_table[opcodes.F32x4Max] = f32x4_max
instr_table[opcodes.F32x4Pmin] = f32x4_pmin
instr_table[opcodes.F32x4Pmax] = f32x4_pmax
instr_table[opcodes.F64x2Abs] = f64x2_abs
instr_table[opcodes.F64x2Neg] = f64x2_neg
instr_table[opcodes.F64x2Sqrt] = f64x2_sqrt
instr_table[opcodes.F64x2Add] = f64x2_add
instr_table[opcodes.F64x2Sub] = f64x2_sub
instr_table[opcodes.F64x2Mul] = f64x2_mul
instr_table[opcodes.F64x2Div] = f64x2_div
instr_table[opcodes.F64x2Min] = f64x2_min
instr_table[opcodes.F64x2Max] = f64x2_max
instr_table[opcodes.F64x2Pmin] = f64x2_pmin
instr_table[opcodes.F64x2Pmax] = f64x2_pmax
instr_table[opcodes.I32x4TruncSatF32x4S] = i32x4_trunc_sat_f32x4_s
instr_table[opcodes.I32x4TruncSatF32x4U] = i32x4_trunc_sat_f32x4_u
instr_table[opcodes.F32x4ConvertI32x4S] = f32x4_convert_i32x4_s
instr_table[opcodes.F32x4ConvertI32x4U] = f32x4_convert_i32x4_u
instr_table[opcodes.I32x4TruncSatF64x2SZero] = i32x4_trunc_sat_f64x2_s_zero
instr_table[opcodes.I32x4TruncSatF64x2UZero] = i32x4_trunc_sat_f64x2_u_zero
instr_table[opcodes.F64x2ConvertLowI32x4S] = f64x2_convert_low_i32x4_s
instr_table[opcodes.F64x2ConvertLowI32x4U] = f64x2_convert_low_i32x4_u