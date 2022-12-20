import sys
from libnmap.parser import NmapParser #python3 -m pip install python-libnmap

nmap = NmapParser.parse_fromfile(sys.argv[1])
print(nmap.summary)

for host in nmap.hosts:
    print("ID: {}".format(host.id))
    if host.os_fingerprint:
        print("  OS: {}".format(host.os_fingerprint))
    

    print("|- PORTS")
    for port in host.get_ports():
        print("|{}- {}/{} - {}".format('-' if host.get_service(port[0],protocol=port[1]).open else 'X', port[0],port[1],host.get_service(port[0],protocol=port[1]).service))
        if(host.get_service(port[0],protocol=port[1]).banner):
            print("|--- {}".format(host.get_service(port[0],protocol=port[1]).banner))
    print("\n|- PRIVESC")
    print("\n|- LOOT")
    print("|-- CREDENTIALS")
    print("|--- USERS")
    print("|--- PASSWORDS")
    print("|---- HASHES")
    print("\n|- NOTES")
    print("\n----\n")
