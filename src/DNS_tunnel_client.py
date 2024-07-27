import dns.resolver
import base64
import random

def dig_init(domain):
    print(domain)
    resolver = dns.resolver.Resolver()
    
    
    result =resolver.resolve(domain, 'TXT')
    
    for r in result: # one single result by the server
        return r.to_text()[1:-1]

def dig_command(domain):
    resolver = dns.resolver.Resolver()
    nores = True
    while nores:
        try:
            result =resolver.resolve(domain, 'TXT',lifetime=10,source_port=random.randint(20000,40000))
            nores = False
        except Exception:
            pass
    for r in result: # one single result by the server
        return r.to_text()
    
        

def prompt(filename):
    nr_segments = int(dig_init(f'{filename}@size.nota10.rosualbastru.live'))
    print(nr_segments)
    res = []
    with open('f.txt','w') as f:
        
        for i in range(nr_segments):
            f.write(str(i)+'\n')
            f.flush()
            res.append(dig_command(f'{filename}@{i}.nota10.rosualbastru.live'))
    filename = filename.replace('-','.')
    
    with open(filename,'wb') as f:
        bigStr = "".join(map(lambda x : x[1:-1],res))
        f.write(base64.b64decode(bigStr))
prompt('test-txt')