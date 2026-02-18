#!/usr/bin/env python3
import re, base64, urllib.parse, json, time, subprocess, socket, os
import urllib.request

TG_CHANNELS = [
    'https://t.me/byxiaoxi','https://t.me/ssList','https://t.me/V2List','https://t.me/youneedproxy','https://t.me/s/v2raydailyupdate','https://t.me/vvkj11','https://t.me/v2ray3','https://t.me/shadowrocket_android','https://t.me/freenodedaily','https://t.me/SSRSUB','https://t.me/ShadowsocksRssr','https://t.me/ssrList','https://t.me/freeshadowsock','https://t.me/socks5list','https://t.me/ssrshares','https://t.me/onessr','https://t.me/baipiaojiedian','https://t.me/ShareCentre','https://t.me/share_proxy_001','https://t.me/xrayfree'
]

GITHUB_RAW_SOURCES = [
    'https://raw.githubusercontent.com/zipvpn/FreeVPNNodes/refs/heads/main/free_surge_nodes.conf',
]

MAX_NODES = 50
TEST_URL = 'https://www.gstatic.com/generate_204'
SING_BOX = os.environ.get('SING_BOX', 'sing-box')


def fetch(url, timeout=15):
    return urllib.request.urlopen(url, timeout=timeout).read().decode('utf-8', errors='ignore')


def extract_links_from_tg():
    texts = []
    for url in TG_CHANNELS:
        u = url
        if '/s/' not in u:
            u = u.replace('t.me/', 't.me/s/')
        try:
            texts.append(fetch(u))
        except Exception:
            continue
    blob = '\n'.join(texts)
    ss_links = re.findall(r'ss://[^\s"<>()]+', blob)
    tr_links = re.findall(r'trojan://[^\s"<>()]+', blob)
    links = list(dict.fromkeys(ss_links + tr_links))
    return links


def extract_from_surge_conf(text):
    # parse [Proxy] section from surge conf
    m = re.split(r'\n\[Proxy\]\n', text, maxsplit=1)
    if len(m) < 2:
        return []
    rest = m[1]
    sec = rest.split('\n[', 1)[0]
    lines = [l.strip() for l in sec.splitlines() if l.strip() and not l.strip().startswith('#')]
    nodes = []
    for l in lines:
        if '= direct' in l.lower():
            continue
        if '=' not in l:
            continue
        name, rhs = l.split('=', 1)
        parts = [p.strip() for p in rhs.split(',')]
        ptype = parts[0].lower()
        if ptype not in ('ss', 'shadowsocks', 'trojan'):
            continue
        if len(parts) < 3:
            continue
        host = parts[1].strip()
        try:
            port = int(parts[2].strip())
        except Exception:
            continue
        if ptype in ('ss', 'shadowsocks'):
            # find method/password
            method = None
            password = None
            for p in parts[3:]:
                if p.strip().startswith('encrypt-method='):
                    method = p.split('=',1)[1]
                if p.strip().startswith('password='):
                    password = p.split('=',1)[1]
            if not (method and password):
                continue
            nodes.append({'type':'ss','server':host,'port':port,'method':method,'password':password,'tag':name.strip()})
        else:
            password = None
            sni = None
            for p in parts[3:]:
                if p.strip().startswith('password='):
                    password = p.split('=',1)[1]
                if p.strip().startswith('sni='):
                    sni = p.split('=',1)[1]
            if not password:
                continue
            nodes.append({'type':'trojan','server':host,'port':port,'password':password,'sni':sni,'tag':name.strip()})
    return nodes


def decode_ss(link):
    tag = ''
    if '#' in link:
        link, tag = link.split('#',1)
        tag = urllib.parse.unquote(tag)
    body = link[5:]
    if '?' in body:
        body = body.split('?',1)[0]
    if '@' in body:
        b64, rest = body.split('@',1)
        userinfo = base64.urlsafe_b64decode(b64 + '===').decode('utf-8', errors='ignore')
        method, password = userinfo.split(':',1)
        host, port = rest.split(':',1)
    else:
        userinfo = base64.urlsafe_b64decode(body + '===').decode('utf-8', errors='ignore')
        creds, hostport = userinfo.split('@',1)
        method, password = creds.split(':',1)
        host, port = hostport.split(':',1)
    return {'type':'ss','method':method,'password':password,'server':host,'port':int(port),'tag':tag}


def decode_trojan(link):
    body = link[len('trojan://'):]
    tag = ''
    if '#' in body:
        body, tag = body.split('#',1)
        tag = urllib.parse.unquote(tag)
    if '?' in body:
        body, params = body.split('?',1)
    else:
        params = ''
    if '@' not in body:
        return None
    password, hostport = body.split('@',1)
    if ':' not in hostport:
        return None
    host, port = hostport.split(':',1)
    sni = None
    if params:
        qs = urllib.parse.parse_qs(params)
        if 'sni' in qs:
            sni = qs['sni'][0]
    return {'type':'trojan','password':password,'server':host,'port':int(port),'sni':sni,'tag':tag}


def extract_nodes():
    nodes = []
    # TG
    for link in extract_links_from_tg():
        try:
            if link.startswith('ss://'):
                nodes.append(decode_ss(link))
            elif link.startswith('trojan://'):
                t = decode_trojan(link)
                if t:
                    nodes.append(t)
        except Exception:
            continue
    # GitHub raw surge conf
    for url in GITHUB_RAW_SOURCES:
        try:
            text = fetch(url)
            nodes.extend(extract_from_surge_conf(text))
        except Exception:
            continue
    # de-dup by server:port+type+password
    seen = set()
    uniq = []
    for n in nodes:
        key = (n['type'], n['server'], n['port'], n.get('password'), n.get('method'))
        if key in seen:
            continue
        seen.add(key)
        uniq.append(n)
    return uniq


def test_node(n, port_base=10800):
    # use sing-box socks outbound to test HTTP 204 via proxy
    port = port_base
    while True:
        with socket.socket() as s:
            try:
                s.bind(('127.0.0.1', port))
                break
            except Exception:
                port += 1
    inbound = {'type':'socks','listen':'127.0.0.1','listen_port':port}
    if n['type']=='ss':
        outbound = {
            'type':'shadowsocks',
            'tag': 'proxy',
            'server': n['server'],
            'server_port': n['port'],
            'method': n['method'],
            'password': n['password']
        }
    else:
        outbound = {
            'type':'trojan',
            'tag': 'proxy',
            'server': n['server'],
            'server_port': n['port'],
            'password': n['password'],
            'tls': {'enabled': True, 'server_name': n.get('sni') or n['server']}
        }
    config = {'inbounds':[inbound], 'outbounds':[outbound, {'type':'direct','tag':'direct'}], 'route': {'final':'proxy'}}
    cfg_path = '/tmp/singbox_test.json'
    open(cfg_path,'w').write(json.dumps(config))
    p = subprocess.Popen([SING_BOX, 'run', '-c', cfg_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ok=False
    try:
        time.sleep(0.8)
        cmd = ['curl','-sS','-m','8','--socks5-hostname',f'127.0.0.1:{port}', TEST_URL]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        ok = (res.returncode==0)
    except Exception:
        ok=False
    finally:
        p.terminate()
        try:
            p.wait(timeout=3)
        except Exception:
            p.kill()
    return ok


def main():
    nodes = extract_nodes()
    ok_nodes = []
    for n in nodes:
        if len(ok_nodes) >= MAX_NODES:
            break
        try:
            if test_node(n):
                ok_nodes.append(n)
        except Exception:
            continue

    lines = ['[Proxy]']
    ss_i = 1
    tj_i = 1
    for n in ok_nodes:
        if n['type']=='ss':
            name = f"SS-{ss_i:02d}"
            ss_i += 1
            line = f"{name} = ss, {n['server']}, {n['port']}, encrypt-method={n['method']}, password={n['password']}, udp=false"
        else:
            name = f"TJ-{tj_i:02d}"
            tj_i += 1
            sni = n.get('sni') or n['server']
            line = f"{name} = trojan, {n['server']}, {n['port']}, password={n['password']}, sni={sni}, skip-cert-verify=false, udp=false"
        lines.append(line)

    out_path = os.path.join(os.getcwd(), 'surge_from_links.conf')
    open(out_path,'w').write('\n'.join(lines)+"\n")

    # write summary
    summary = {
        'total_nodes_tested': len(nodes),
        'ok_nodes': len(ok_nodes),
        'generated': out_path,
    }
    open(os.path.join(os.getcwd(), 'summary.json'),'w').write(json.dumps(summary, indent=2))

if __name__ == '__main__':
    main()
