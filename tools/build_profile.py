#!/usr/bin/env python3
"""Generate audited hashes from the explicitly pinned, downloaded source tree.
Never executes upstream installers. Usage: python3 tools/build_profile.py ../upstream
"""
import hashlib
import json
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
out = pathlib.Path(__file__).resolve().parents[1]
v = (root / 'vless.sh').read_text()
n = (root / 'natjichang.sh').read_text()
files = {}
for match in re.finditer(r"^cat >'([^']+)' <<'([^']+)'\n", v, re.M):
    path, end = match.groups()
    body = v[match.end():].split('\n' + end + '\n', 1)[0] + '\n'
    files[path] = hashlib.sha256(body.encode()).hexdigest()
for path, end, content in [
    ('/usr/local/sbin/vless_nat_preflight.sh', 'NAT_PREFLIGHT', n),
    ('/usr/local/sbin/vless_mktemp_nat.sh', '__NAT_MKTEMP_FINAL__', n),
    ('/usr/local/sbin/wg_nat_guard.sh', 'WG_NAT_GUARD', (root/'vpswg.sh').read_text()),
]:
    body = content.split("<<'"+end+"'\n", 1)[1].split('\n'+end+'\n', 1)[0]+'\n'
    files[path] = hashlib.sha256(body.encode()).hexdigest()
files['/usr/local/lib/portbw/portbw.py'] = hashlib.sha256((root/'portbw.py').read_bytes()).hexdigest()
templates = {}
for key, content in [('direct', v), ('nat', n)]:
    templates[key] = content.split('cat >"$UNIT_FILE" <<UNIT\n', 1)[1].split('\nUNIT\n', 1)[0]+'\n'
profile = {'commit':'3e1972393cd9e6f097b27b76f919a649def61ae4', 'files':files,
           'templates':templates, 'sources':{p.name:hashlib.sha256(p.read_bytes()).hexdigest()
                                         for p in root.glob('*') if p.is_file()}}
(out/'compatibility.json').write_text(json.dumps(profile, indent=2)+'\n')
print('Generated compatibility.json; '+str(len(files))+' installed artifacts')
