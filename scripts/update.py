#!/usr/bin/env python3
import re, base64, urllib.parse, json, time, subprocess, socket, os
import urllib.request

TG_CHANNELS = [
    'https://t.me/byxiaoxi','https://t.me/ssList','https://t.me/V2List','https://t.me/youneedproxy','https://t.me/s/v2raydailyupdate','https://t.me/vvkj11','https://t.me/v2ray3','https://t.me/shadowrocket_android','https://t.me/freenodedaily','https://t.me/SSRSUB','https://t.me/ShadowsocksRssr','https://t.me/ssrList','https://t.me/freeshadowsock','https://t.me/socks5list','https://t.me/ssrshares','https://t.me/onessr','https://t.me/baipiaojiedian','https://t.me/ShareCentre','https://t.me/share_proxy_001','https://t.me/xrayfree','https://t.me/jiedian168'
]

GITHUB_RAW_SOURCES = [
    'https://raw.githubusercontent.com/zipvpn/FreeVPNNodes/refs/heads/main/free_surge_nodes.conf',
]

SUBSCRIPTION_SOURCES = [
    # From https://v2rayse.com/en/free-node (Surge dynamic link)
    'https://tt.vg/yUlGe',
    # From https://github.com/Helpsoftware/fanqiang
    'https://www.liesauer.net/yogurt/subscribe?ACCESS_TOKEN=DAYxR3mMaZAsaqUb',
    'https://nodes.fanqiang.network/pubconfig/wei6krXcNqyho1b8',
    'https://www.xrayvip.com/free.txt',
    'https://github.com/StormragerCN/v2ray/raw/refs/heads/main/v2ray',
    'https://github.com/ermaozi/get_subscribe/raw/refs/heads/main/subscribe/v2ray.txt',
    'https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/c.yaml',
    'https://github.com/aiboboxx/clashfree/raw/refs/heads/main/clash.yml',
    'https://gcore.jsdelivr.net/gh/aiboboxx/clashfree@refs/heads/main/clash.yml',
    'https://cdn.jsdelivr.net/gh/vxiaov/free_proxies@main/clash/clash.provider.yaml',
    'https://raw.githubusercontent.com/vxiaov/free_proxies/main/clash/clash.provider.yaml',
    'https://github.com/ermaozi/get_subscribe/raw/refs/heads/main/subscribe/clash.yml',
    'https://github.com/anaer/Sub/raw/refs/heads/main/clash.yaml',
    'https://www.xrayvip.com/free.yaml',
    'https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt',
    'https://proxy.v2gh.com/https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub',
    'https://mirror.v2gh.com/https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub',
    'https://hyt-allen-xu.netlify.app',
    'https://github.com/Jsnzkpg/Jsnzkpg/raw/refs/heads/Jsnzkpg/Jsnzkpg',
    # Additional sources
    'https://raw.githubusercontent.com/ssrsub/ssr/master/Surge.conf',
    'https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub',
    'https://www.freeclashnode.com/node-real-time-update/',
    'https://raw.githubusercontent.com/freenodes/freenodes/master/README.md',
    # v2rayse API (best effort)
    'https://v2rayse.com/api/node-share',
    'https://v2rayse.com/api/tools/free-node',
]

MAX_NODES = 50
TEST_URL = 'https://www.gstatic.com/generate_204'
SING_BOX = os.environ.get('SING_BOX', 'sing-box')


def fetch(url, timeout=15):
    return urllib.request.urlopen(url, timeout=timeout).read().decode('utf-8', errors='ignore')


def maybe_b64_decode(text: str) -> str:
    t = text.strip()
    if len(t) < 50:
        return text
    try:
        decoded = base64.b64decode(t + '===', validate=False).decode('utf-8', errors='ignore')
        if 'ss://' in decoded or 'trojan://' in decoded:
            return decoded
    except Exception:
        pass
    return text


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


def decode_vmess(link):
    # vmess://base64json
    if not link.startswith('vmess://'):
        return None
    body = link[len('vmess://'):]
    try:
        raw = base64.b64decode(body + '===', validate=False).decode('utf-8', errors='ignore')
        data = json.loads(raw)
    except Exception:
        return None
    try:
        server = data.get('add')
        port = int(data.get('port'))
        uuid = data.get('id')
    except Exception:
        return None
    if not (server and port and uuid):
        return None
    tag = data.get('ps') or ''
    tls = data.get('tls') in ('tls','1',1,True)
    sni = data.get('sni') or data.get('host') or server
    ws = (data.get('net') == 'ws')
    ws_path = data.get('path') or '/'
    ws_host = data.get('host') or ''
    return {
        'type':'vmess','server':server,'port':port,'uuid':uuid,
        'tls':tls,'sni':sni,'ws':ws,'ws_path':ws_path,'ws_host':ws_host,
        'tag':tag
    }


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
            elif link.startswith('vmess://'):
                v = decode_vmess(link)
                if v:
                    nodes.append(v)
        except Exception:
            continue
    # GitHub raw surge conf
    for url in GITHUB_RAW_SOURCES:
        try:
            text = fetch(url)
            nodes.extend(extract_from_surge_conf(text))
        except Exception:
            continue
    # Subscription sources (scan for ss:// and trojan://, or Surge config)
    for url in SUBSCRIPTION_SOURCES:
        try:
            text = fetch(url, timeout=20)
            text = maybe_b64_decode(text)
            if '[Proxy]' in text:
                nodes.extend(extract_from_surge_conf(text))
            ss_links = re.findall(r'ss://[^\s"<>()]+', text)
            tr_links = re.findall(r'trojan://[^\s"<>()]+', text)
            vm_links = re.findall(r'vmess://[^\s"<>()]+', text)
            for link in ss_links:
                try:
                    nodes.append(decode_ss(link))
                except Exception:
                    pass
            for link in tr_links:
                try:
                    t = decode_trojan(link)
                    if t:
                        nodes.append(t)
                except Exception:
                    pass
            for link in vm_links:
                try:
                    v = decode_vmess(link)
                    if v:
                        nodes.append(v)
                except Exception:
                    pass
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
    elif n['type']=='trojan':
        outbound = {
            'type':'trojan',
            'tag': 'proxy',
            'server': n['server'],
            'server_port': n['port'],
            'password': n['password'],
            'tls': {'enabled': True, 'server_name': n.get('sni') or n['server']}
        }
    else:
        outbound = {
            'type':'vmess',
            'tag': 'proxy',
            'server': n['server'],
            'server_port': n['port'],
            'uuid': n['uuid'],
            'security': 'auto',
            'tls': {'enabled': bool(n.get('tls')), 'server_name': n.get('sni') or n['server']},
            'transport': {'type': 'ws', 'path': n.get('ws_path') or '/', 'headers': {'Host': n.get('ws_host') or n['server']}} if n.get('ws') else None,
        }
        if outbound.get('transport') is None:
            outbound.pop('transport', None)
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
    vm_i = 1
    for n in ok_nodes:
        if n['type']=='ss':
            name = f"SS-{ss_i:02d}"
            ss_i += 1
            line = f"{name} = ss, {n['server']}, {n['port']}, encrypt-method={n['method']}, password={n['password']}, udp=false"
        elif n['type']=='trojan':
            name = f"TJ-{tj_i:02d}"
            tj_i += 1
            sni = n.get('sni') or n['server']
            line = f"{name} = trojan, {n['server']}, {n['port']}, password={n['password']}, sni={sni}, skip-cert-verify=false, udp=false"
        else:
            name = f"VM-{vm_i:02d}"
            vm_i += 1
            tls = 'true' if n.get('tls') else 'false'
            ws = 'true' if n.get('ws') else 'false'
            ws_path = n.get('ws_path') or '/'
            ws_host = n.get('ws_host') or n['server']
            sni = n.get('sni') or n['server']
            line = f"{name} = vmess, {n['server']}, {n['port']}, username={n['uuid']}, tls={tls}, vmess-aead=true, ws={ws}, ws-path={ws_path}, sni={sni}, ws-headers=Host:{ws_host}, skip-cert-verify=false, udp=false"
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
