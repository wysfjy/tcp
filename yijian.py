import subprocess
import flask
import os
from typing import Dict, Optional

# 全局变量
shangbaonotok: Dict[str, str] = {}
shangbao: Dict[str, str] = {}
a: Dict[str, subprocess.Popen] = {}

app = flask.Flask(__name__)
@app.route('/start/<port>')
def start(port: str) -> str:
    """启动指定端口的 natter 服务"""
    if port in a:
        return 'port already started'
    
    # 根据操作系统选择 Python 命令
    python_cmd = 'python3' if os.name == 'posix' else 'python'
    
    try:
        proc = subprocess.Popen([python_cmd, 'natter.py', '-p', port])
        a[port] = proc
        return 'ok'
    except Exception as e:
        return f'start failed: {str(e)}'
@app.route('/stop')
def stop() -> str:
    """停止所有 natter 服务"""
    # 转换为列表避免字典在迭代时改变大小
    for port in list(a.keys()):
        proc = a[port]
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        a.pop(port)
    return 'ok'
@app.route('/shangbao/<port>/<portnei>/<ok>')
def shangbao_add(port: str, portnei: str, ok: str) -> str:
    """添加或更新上报信息"""
    shangbao[portnei] = port
    if ok != "0":
        shangbaonotok[portnei] = ok
    return 'ok'

@app.route('/shangbao/<portnei>')
def shangbao_get1(portnei: str) -> str:
    """获取指定端口的上报状态"""
    if portnei in shangbaonotok:
        return shangbaonotok[portnei]
    elif portnei in shangbao:
        return "ok"
    return "not found"

@app.route('/shangbao')
def shangbao_get() -> str:
    """获取所有上报信息"""
    return str(shangbao)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=3319)