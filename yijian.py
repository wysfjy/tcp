import subprocess
import flask
import time
shangbao = {}
a = {}
app = flask.Flask(__name__)
@app.route('/start/<port>')
def start(port):
    if port in a:
        return 'port already started'
    port1 = subprocess.Popen(['python', 'natter.py', '-p', port])
    a[port] = port1
    return 'ok'
@app.route('/stop')
def stop():
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
@app.route('/shangbao/<port>/<portnei>')
def shangbao_add(port, portnei):
    shangbao[portnei] = port
    return 'ok'
@app.route('/shangbao')
def shangbao_get():
    return str(shangbao)
app.run(host='0.0.0.0', port=3319)