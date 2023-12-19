# encoding: utf-8

from ..parser.errors import *


def decode_var_uint(reader, size: int):
    """
    解码LEB128无符号整数，可同时处理32 64位整数，
    :param reader:
    :param data: 二进制流
    :param size:
    :return:第一个返回值为解码后的整数，第二个返回值是解码后整数实际占字节数
    """
    result = 0
    i = 0
    while True:
        a = reader.read(1)
        b = int.from_bytes(a, "little")  # bytes转int，否则没法&

        if i == size / 7:
            if b & 0x80 != 0:
                raise ErrIntTooLong
            if b >> (size - i * 7) > 0:
                raise ErrIntTooLarge
        result |= (b & 0x7f) << (i * 7)  # 取低7位并左移七位
        if b & 0x80 == 0:
            return result, i + 1
        i += 1
    raise ErrUnexpectedEnd


def decode_var_uint111(data, size: int):
    """
    解码LEB128无符号整数，可同时处理32 64位整数，
    :param reader:
    :param data: 二进制流
    :param size:
    :return:第一个返回值为解码后的整数，第二个返回值是解码后整数实际占字节数
    """
    result = 0
    i = 0
    while True:
        b = int.from_bytes(data[:1], "little")  # bytes转int，否则没法&
        data = data[1:]

        if i == size / 7:
            if b & 0x80 != 0:
                raise ErrIntTooLong
            if b >> (size - i * 7) > 0:
                raise ErrIntTooLarge
        result |= (b & 0x7f) << (i * 7)  # 取低7位并左移七位
        if b & 0x80 == 0:
            return result, i + 1
        i += 1
    raise ErrUnexpectedEnd

def decode_var_int(reader, size):
    """
    解码LEB128有符号整数，可同时处理32 64位整数，
    :param reader:
    :param data: 解码后的整数
    :param size: 实际消耗的字节数
    :return:
    """
    result = 0
    i = 0
    while True:
        b = int.from_bytes(reader.read(1), "little")  # bytes转int，否则没法&

        if i == size / 7:
            if b & 0x80 != 0:
                raise ErrIntTooLong
            if b & 0x40 == 0 and b >> (size - i * 7 - 1) != 0 or \
                    b & 0x40 != 0 and int(b | 0x80) >> (size - i * 7 - 1) != -1:
                raise ErrIntTooLarge
        result |= (b & 0x7f) << (i * 7)
        if b & 0x80 == 0:
            if (i * 7 < size) and (b & 0x40 != 0):  # 判断是否为负数
                result |= -1 << ((i + 1) * 7)  # 前几位补1
            return result, i + 1
        i += 1
    raise ErrUnexpectedEnd


def decode_var_uint_from_data(data, size: int):
    """
    LEB128无符号整数解码
    :param data: 解码后的整数
    :param size: 实际消耗的字节数
    :return:
    """
    result = 0
    for i, b in enumerate(data):
        if i == size / 7:
            if b & 0x80 != 0:
                raise ErrIntTooLong
            if b >> (size - i * 7) > 0:
                raise ErrIntTooLarge
        result |= (b & 0x7f) << (i * 7)
        if b & 0x80 == 0:
            return result, i + 1
    raise ErrUnexpectedEnd
