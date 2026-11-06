#!/usr/bin/env python3
"""Real Xray authentication across restarts/copies using synthetic users only.

Disposable Debian CI container; this does NOT simulate two VPS, systemd, SSH,
public DNS propagation or a WireGuard peer. NAT's authentication/configuration
is exercised with its SO_MARK preserved, but its WG egress still needs VPS QA.
"""
import contextlib
import copy
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import urllib.parse
from test_qianyi import q, node

if os.environ.get('QIANYI_DISPOSABLE_NETNS') != '1':
    raise SystemExit('Run only in the disposable CI container.')
XRAY='/src/ci-bin/xray'
os.umask(0o077)


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0))
        return sock.getsockname()[1]


def wait_listen(proc,port):
    deadline=time.monotonic()+10
    while time.monotonic() < deadline:
        assert proc.poll() is None, 'test process exited before listening'
        try:
            with socket.create_connection(('127.0.0.1',port),timeout=.2):return
        except OSError:time.sleep(.05)
    raise AssertionError('test listener timed out')


@contextlib.contextmanager
def process(argv,port,log):
    with open(log,'wb') as output:
        proc=subprocess.Popen(argv,stdout=output,stderr=output)
        try:
            wait_listen(proc,port)
            yield proc
        finally:
            proc.terminate()
            try:proc.wait(timeout=3)
            except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=3)


class Destination(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body=b'qianyi-original-link-ok'
        self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers()
        self.wfile.write(body)

    def log_message(self,*args):pass


with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as lifetime:
    root=Path(directory)
    destination=http.server.ThreadingHTTPServer(('127.0.0.1',0),Destination)
    threading.Thread(target=destination.serve_forever,daemon=True).start()
    lifetime.callback(destination.server_close);lifetime.callback(destination.shutdown)
    dest_port=destination.server_port
    tls_port=free_port()
    q.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
           '-subj','/CN=tls.example.com','-keyout',root/'tls.key','-out',root/'tls.crt'])
    lifetime.enter_context(process(['openssl','s_server','-accept',f'127.0.0.1:{tls_port}',
                                    '-tls1_3','-cert',str(root/'tls.crt'),'-key',str(root/'tls.key'),
                                    '-alpn','h2,http/1.1','-www'],tls_port,root/'tls.log'))

    def fixture(port,key,nat=False):
        n=node(port,nat=nat,key=key);m=n['meta'];cfg=json.loads(n['config'])
        m.update(REALITY_DEST=f'127.0.0.1:{tls_port}',REALITY_SNI='tls.example.com')
        cfg['inbounds'][0]['streamSettings']['realitySettings'].update(dest=m['REALITY_DEST'],serverNames=[m['REALITY_SNI']])
        n['config']=json.dumps(cfg)
        old=urllib.parse.urlsplit(n['url'].strip());query=urllib.parse.parse_qs(old.query)
        query['sni']=[m['REALITY_SNI']]
        n['url']=urllib.parse.urlunsplit(old._replace(query=urllib.parse.urlencode(query,doseq=True)))+'\n'
        if nat:m['PUBLIC_DOMAIN']='standby-install.example.com'
        q.validate_node(n)
        return n

    nodes=[fixture(41000,1),fixture(41001,2,nat=True)]
    future=fixture(41002,3)
    # The unchanged URL still addresses its business domain; only DNS resolution
    # is redirected within this throwaway container, never to a standby domain.
    with open('/etc/hosts','a') as hosts:
        hosts.write('\n127.0.0.1 '+' '.join(urllib.parse.urlsplit(n['url'].strip()).hostname for n in nodes+[future])+'\n')

    @contextlib.contextmanager
    def serve(n,round_name):
        config=root/(round_name+'-'+n['meta']['TAG']+'.json')
        q.atomic(config,n['config'].encode())
        q.run([XRAY,'run','-test','-config',config])
        with process([XRAY,'run','-config',str(config)],int(n['meta']['PORT']),str(config)+'.log'):
            yield

    def connect(original_url,wrong_key=None):
        link=urllib.parse.urlsplit(original_url.strip());params=urllib.parse.parse_qs(link.query)
        get=lambda key:params[key][0]
        port=free_port()
        config={'log':{'loglevel':'warning'},'inbounds':[{'listen':'127.0.0.1','port':port,'protocol':'socks',
                'settings':{'auth':'noauth','udp':False}}], 'outbounds':[{'protocol':'vless',
                'settings':{'vnext':[{'address':link.hostname,'port':link.port,'users':[{
                    'id':link.username,'encryption':get('encryption'),'flow':get('flow')}]}]},
                'streamSettings':{'network':get('type'),'security':get('security'),'realitySettings':{
                    'serverName':get('sni'),'fingerprint':get('fp'),'publicKey':wrong_key or get('pbk'),
                    'shortId':get('sid')}}}]}
        path=root/'client.json';q.save(path,config)
        with process([XRAY,'run','-config',str(path)],port,root/'client.log'):
            result=q.run(['curl','--silent','--show-error','--max-time','6','--noproxy','',
                          '--socks5-hostname',f'127.0.0.1:{port}',f'http://127.0.0.1:{dest_port}/'],check=False,timeout=10)
            if wrong_key:
                assert result.returncode != 0, 'incorrect Reality key authenticated'
            else:
                assert result.returncode == 0 and result.stdout == b'qianyi-original-link-ok', 'original VLESS URL authentication failed'

    original=[n['url'] for n in nodes]
    for name in ('source','target','next-target'):
        restored=json.loads(q.encoded(nodes))
        assert restored == nodes
        with contextlib.ExitStack() as servers:
            for n,url in zip(restored,original):
                q.validate_node(n)
                servers.enter_context(serve(n,name));connect(url)
            if name == 'target':
                connect(original[0],wrong_key=future['meta']['PBK'])
                servers.enter_context(serve(future,name));connect(future['url'])
                nodes.append(future);original.append(future['url'])
    assert len({n['meta']['PBK'] for n in nodes}) == 3
    print(json.dumps({'xray':q.output([XRAY,'version']).splitlines()[0],
                      'passed':['original direct and marked NAT Reality URLs after process replacement',
                                'business domains retained with DNS override only','wrong Reality public key rejected',
                                'next rotation includes new node with third independent key'],
                      'not_covered':['real VPS orchestration','systemd boot','SSH handoff','WG egress','public DNS']},indent=2))
