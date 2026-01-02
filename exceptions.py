#!/usr/bin/env python3
"""
异常类定义
"""

import atexit


class NatterExitException(Exception):
    """Natter退出异常"""
    pass


class NatterRetryException(Exception):
    """Natter重试异常"""
    pass


class NatterExit(object):
    """Natter退出处理类"""
    
    atexit.register(lambda : NatterExit._atexit[0]())
    _atexit = [lambda : None]
    
    @staticmethod
    def set_atexit(func: callable) -> None:
        NatterExit._atexit[0] = func
