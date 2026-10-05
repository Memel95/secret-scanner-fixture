from pathlib import Path
import hashlib
import json
import subprocess
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path('/workspace/scratch/693b705e127b/secret-scanner-fixture')
OUT = ROOT.parent / 'fixture-publication.json'
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
MASK = (1 << 64) - 1
RC = [0x0000000000000001,0x0000000000008082,0x800000000000808A,0x8000000080008000,
      0x000000000000808B,0x0000000080000001,0x8000000080008081,0x8000000000008009,
      0x000000000000008A,0x0000000000000088,0x0000000080008009,0x000000008000000A,
      0x000000008000808B,0x800000000000008B,0x8000000000008089,0x8000000000008003,
      0x8000000000008002,0x8000000000000080,0x000000000000800A,0x800000008000000A,
      0x8000000080008081,0x8000000000008080,0x0000000080000001,0x8000000080008008]
RHO = [[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]]

def rol(x, n):
    return ((x << n) | (x >> (64-n))) & MASK if n else x

def keccak(data):
    data = bytearray(data)
    data.append(1)
    data.extend(b'\0' * ((-len(data)) % 136))
    data[-1] |= 128
    s = [0] * 25
    for off in range(0, len(data), 136):
        for i in range(17):
            s[i] ^= int.from_bytes(data[off+i*8:off+(i+1)*8], 'little')
        for rc in RC:
            c = [s[x] ^ s[x+5] ^ s[x+10] ^ s[x+15] ^ s[x+20] for x in range(5)]
            d = [c[(x-1)%5] ^ rol(c[(x+1)%5], 1) for x in range(5)]
            for y in range(5):
                for x in range(5):
                    s[x+5*y] ^= d[x]
            b = [0] * 25
            for y in range(5):
                for x in range(5):
                    b[y+5*((2*x+3*y)%5)] = rol(s[x+5*y], RHO[x][y])
            for y in range(5):
                for x in range(5):
                    s[x+5*y] = b[x+5*y] ^ ((~b[(x+1)%5+5*y]) & b[(x+2)%5+5*y])
            s[0] ^= rc
    return b''.join(x.to_bytes(8, 'little') for x in s)[:32]

def address(scalar):
    p = ec.derive_private_key(scalar, ec.SECP256K1()).public_key().public_numbers()
    return '0x' + keccak(p.x.to_bytes(32,'big') + p.y.to_bytes(32,'big'))[-20:].hex()

def test_scalar(case):
    digest = hashlib.sha256(('Memel95/secret-scanner-fixture:v1:' + case).encode()).digest()
    scalar = int.from_bytes(digest, 'big') % (N-1) + 1
    return f'{scalar:064x}', address(scalar)

def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args], text=True).strip()

def write(path, data):
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data if isinstance(data, bytes) else data.encode())

def commit(message):
    git('add', '-A')
    git('commit', '-q', '-m', message)
    return git('rev-parse', 'HEAD')

assert keccak(b'').hex() == 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'
assert address(1) == '0x7e5f4552091a69125d5dfcb7b8c2659029395bdf'
if ROOT.exists():
    raise SystemExit('Refusing to overwrite existing fixture directory')
ROOT.mkdir()
git('init', '-q', '-b', 'main')
git('config', 'user.name', 'Scanner fixture')
git('config', 'user.email', 'fixture@example.invalid')
git('config', 'commit.gpgsign', 'false')

labels = ['context','ambiguous','account_api','history_deleted','large_split','branch_only','pr_only','binary','identity_drop','unreachable']
values = {case: test_scalar(case) for case in labels}
readme = '''# Secret scanner fixture

Petit dépôt public de test pour le scanner de Memel95. **Toutes les données sont synthétiques.**

Les scalaires de test sont déterministes, publics et créés uniquement pour cette fixture.
Ils ne proviennent d'aucun wallet, service, dépôt tiers ou compte utilisateur.
Ne jamais les utiliser pour un wallet, des fonds ou un service réel.

## Contenu

- Un candidat ambigu, du contexte `private_key` et un exemple `privateKeyToAccount`.
- Une adresse dérivée dans un autre blob et un même blob à deux chemins.
- Un fichier supprimé toujours présent dans l'historique et un tag historique `fixture-v1`.
- Les branches `fixture/branch-only` et `fixture/pr-only`, cette dernière avec une PR ouverte.
- Un gros blob avec une valeur à cheval sur une frontière de 64 KiB, un binaire et des cas négatifs.
- Un commit témoin non référencé, exclu de l'acquisition normale heads/tags/pull.

Les adresses attendues et les cas sont décrits dans `fixture-manifest.json`.
Ce manifeste décrit le corpus ; les classifications du scanner restent à vérifier avec sa version actuelle.

## Test réseau et idempotence M5-C2

Limiter l'acquisition à **Memel95/secret-scanner-fixture**, avec un nouvel état séparé.
Récupérer les refs heads, tags et pull avec Git réel, sans filtre d'historique shallow.
Utiliser exclusivement `FakeEtherscanTransport` pour le provider.
Ne pas fournir d'API key, ne pas appeler Etherscan réel et ne pas relancer `morph`.

Après le premier run validé, relancer exactement la même entrée et le même état.
Comparer les compteurs et les empreintes/taille/mtime des sorties protégées :
zéro fetch, scan, appel provider ou réécriture est le résultat attendu de l'idempotence.
Garder les findings/review redacted ; les valeurs brutes n'ont pas leur place dans les logs de test.

La création de ce dépôt et sa vérification Git ne constituent pas une validation du scanner.
'''

prefix = '# SYNTHETIC PUBLIC TEST DATA ONLY\n'
context = prefix + 'private_key=0x' + values['context'][0] + '\n'
large_start = 65536 - 32
large = ('# synthetic padding only\n' * 6000)[:large_start-len('private_key=0x')]
large += 'private_key=0x' + values['large_split'][0] + '\n# end synthetic fixture\n'
main_files = {
    'README.md': readme,
    'fixtures/context/service.env': context,
    'fixtures/duplicates/service.env': context,
    'fixtures/ambiguous/standalone.txt': values['ambiguous'][0] + '\n',
    'fixtures/context/account.js': '// SYNTHETIC PUBLIC TEST DATA; source text fixture, do not execute.\nimport { privateKeyToAccount } from "viem/accounts";\nconst account = privateKeyToAccount("0x' + values['account_api'][0] + '");\n',
    'fixtures/addresses/derived.txt': 'Synthetic address corresponding to fixtures/context/account.js:\n' + values['account_api'][1] + '\n',
    'fixtures/large/split.env': large,
    'fixtures/negative/long-hex.txt': '# One 96-hex token; no isolated 64-hex sub-match expected.\n0x' + hashlib.sha384(b'synthetic long hex fixture').hexdigest() + '\n',
    'fixtures/negative/invalid-scalars.env': prefix + 'private_key_zero=0x' + '0'*64 + '\nprivate_key_order=0x' + f'{N:064x}' + '\nprivate_key_overflow=0x' + 'f'*64 + '\n',
    'fixtures/negative/identity.json': json.dumps({'note':'SYNTHETIC identifier, not key material','transaction_hash':'0x'+values['identity_drop'][0]},indent=2)+'\n',
    'fixtures/negative/binary.dat': b'\x00\xffSYNTHETIC BINARY FIXTURE\x00' + values['binary'][0].encode() + b'\x00\xfe',
}
manifest = {
    'schema_version':1,
    'repository':'Memel95/secret-scanner-fixture',
    'data_origin':'Entirely deterministic synthetic public test data. No real credentials.',
    'generation': {'algorithm':'SHA-256(label) mod (secp256k1_order - 1) + 1', 'label_prefix':'Memel95/secret-scanner-fixture:v1:'},
    'expected_refs': ['refs/heads/main','refs/heads/fixture/branch-only','refs/heads/fixture/pr-only','refs/tags/fixture-v1','refs/pull/1/head','refs/pull/1/merge'],
    'cases': [
        {'id':'context','paths':['fixtures/context/service.env','fixtures/duplicates/service.env'],'address':values['context'][1],'assertion':'same bytes / one unique blob / one address, multiple path provenance'},
        {'id':'ambiguous','paths':['fixtures/ambiguous/standalone.txt'],'address':values['ambiguous'][1],'assertion':'unlabelled standalone candidate; classification depends on scanner policy'},
        {'id':'account_api','paths':['fixtures/context/account.js','fixtures/addresses/derived.txt'],'address':values['account_api'][1],'assertion':'API context and derived_address_literal_match across separate blobs'},
        {'id':'history_deleted','paths':['fixtures/history/deleted.env'],'address':values['history_deleted'][1],'assertion':'absent from main HEAD; reachable from historical commit and tag'},
        {'id':'large_split','paths':['fixtures/large/split.env'],'address':values['large_split'][1],'value_offset_bytes':large_start,'boundary_bytes':65536,'assertion':'candidate crosses 64 KiB; overlap coverage must be configured by test harness'},
        {'id':'branch_only','paths':['fixtures/branch-only.env'],'address':values['branch_only'][1],'ref':'refs/heads/fixture/branch-only'},
        {'id':'pr_only','paths':['fixtures/pr-only.env'],'address':values['pr_only'][1],'ref':'refs/heads/fixture/pr-only','assertion':'reachable from branch and PR refs; do not count duplicate observations as unique candidates'},
        {'id':'binary','paths':['fixtures/negative/binary.dat'],'address':values['binary'][1],'assertion':'NUL/non-UTF8 bytes; verify actual binary policy'},
        {'id':'long_hex','paths':['fixtures/negative/long-hex.txt'],'assertion':'one 96-hex token; no false 64-hex sub-match'},
        {'id':'invalid_scalars','paths':['fixtures/negative/invalid-scalars.env'],'assertion':'zero / curve order / overflow are not valid EVM scalars'},
        {'id':'identity_drop','paths':['fixtures/negative/identity.json'],'address':values['identity_drop'][1],'assertion':'explicit transaction_hash identity context; DROP according to scanner policy'},
        {'id':'unreachable','paths':['fixtures/unreachable.env'],'address':values['unreachable'][1],'assertion':'no ref points to this commit; normal heads/tags/pull fetch must exclude its unique blob'},
    ],
    'provider':'FakeEtherscanTransport only; no network chain provider',
    'validation_status':'Corpus validated locally; scanner integration not run here.',
}
main_files['fixture-manifest.json'] = json.dumps(manifest,indent=2)+'\n'
for path,content in main_files.items():
    write(path,content)
initial = commit('Add deterministic synthetic scanner corpus')
historic_file = prefix+'private_key=0x'+values['history_deleted'][0]+'\n'
write('fixtures/history/deleted.env',historic_file)
historical = commit('Add synthetic historical candidate')
git('tag','fixture-v1')
(ROOT/'fixtures/history/deleted.env').unlink()
main_head = commit('Remove historical candidate from main HEAD')
git('checkout','-q','-b','fixture/branch-only')
branch_file = prefix+'private_key=0x'+values['branch_only'][0]+'\n'
write('fixtures/branch-only.env',branch_file)
branch_head = commit('Add synthetic branch-only candidate')
git('checkout','-q','main')
git('checkout','-q','-b','fixture/pr-only')
pr_file = prefix+'private_key=0x'+values['pr_only'][0]+'\n'
write('fixtures/pr-only.env',pr_file)
pr_head = commit('Add synthetic PR-only candidate')
git('checkout','-q','main')
unreachable_file = prefix+'private_key=0x'+values['unreachable'][0]+'\n'
unreachable_blob = subprocess.check_output(['git','-C',str(ROOT),'hash-object','-w','--stdin'],input=unreachable_file.encode()).decode().strip()
unreachable_tree = subprocess.check_output(['git','-C',str(ROOT),'mktree'],input=f'100644 blob {unreachable_blob}\tSYNTHETIC_UNREACHABLE.env\n'.encode()).decode().strip()
unreachable_commit = subprocess.check_output(['git','-C',str(ROOT),'commit-tree',unreachable_tree,'-p',main_head],input=b'Synthetic unreachable commit; no refs\n').decode().strip()
reachable_objects = set(git('rev-list','--objects','--all').splitlines())
assert not any(x.startswith(unreachable_blob) for x in reachable_objects)
assert git('hash-object','fixtures/context/service.env') == git('hash-object','fixtures/duplicates/service.env')
assert not (ROOT/'fixtures/history/deleted.env').exists()
assert git('show','fixture-v1:fixtures/history/deleted.env') == historic_file.strip()
assert large.encode()[large_start:large_start+64].decode() == values['large_split'][0]
assert large_start < 65536 < large_start+64
assert int(git('rev-list','--all','--count')) == 5
assert git('status','--porcelain') == ''
payload = {
    'repository':'Memel95/secret-scanner-fixture',
    'main_files': {path:content for path,content in main_files.items() if isinstance(content,str)},
    'binary_file': {'path':'fixtures/negative/binary.dat','hex':main_files['fixtures/negative/binary.dat'].hex()},
    'historical':{'path':'fixtures/history/deleted.env','content':historic_file},
    'branch_only':{'path':'fixtures/branch-only.env','content':branch_file},
    'pr_only':{'path':'fixtures/pr-only.env','content':pr_file},
    'unreachable':{'path':'fixtures/unreachable.env','content':unreachable_file},
    'local_commits':{'initial':initial,'historical':historical,'main':main_head,'branch_only':branch_head,'pr_only':pr_head,'unreachable':unreachable_commit},
}
OUT.write_text(json.dumps(payload))
print(json.dumps({'root':str(ROOT),'reachable_commits':5,'branches':3,'tags':1,'files_at_main':len(main_files),'corpus_bytes':sum(len(v if isinstance(v,bytes) else v.encode()) for v in main_files.values()),'local_validation':'PASS','unreachable_blob_excluded':True,'payload':str(OUT)},indent=2))
