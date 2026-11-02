"""Fixed, trusted probe/listener program embedded into generated fixture Pods.

No project-supplied commands or executable code are used by the runner.
"""

PROGRAM = r"""
import socket,sys,json,threading,time

def listen(port, proto):
    kind=socket.SOCK_DGRAM if proto=='UDP' else socket.SOCK_STREAM
    server=socket.socket(socket.AF_INET,kind);server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    server.bind(('0.0.0.0',port))
    if proto=='UDP':
        while True:
            data,addr=server.recvfrom(8192);server.sendto(data,addr)
    else:
        server.listen(64)
        while True:
            conn,addr=server.accept()
            try:
                conn.settimeout(2);data=conn.recv(8192);conn.sendall(data)
            except OSError: pass
            finally:conn.close()

if sys.argv[1]=='serve':
    for p,proto in json.loads(sys.argv[2]):
        threading.Thread(target=listen,args=(p,proto),daemon=True).start()
    while True:time.sleep(3600)
else:
    ip,port,proto,token=sys.argv[2],int(sys.argv[3]),sys.argv[4],sys.argv[5]
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if proto=='UDP' else socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip,port));s.sendall(token.encode());response=s.recv(8192)
        ok=response==token.encode()
        print(json.dumps({'outcome':'success' if ok else 'error','response_matched':ok}))
    except (socket.timeout,ConnectionRefusedError,ConnectionResetError,OSError) as e:
        print(json.dumps({'outcome':'unreachable','error_type':type(e).__name__,'error':str(e)}))
    finally:
        try:s.close()
        except Exception:pass
"""
