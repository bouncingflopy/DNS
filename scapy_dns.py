from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import UDP, IP


def load_data():
    with open("C://Users//Liron//Python//temp//database.txt", 'r') as f:
        lines = f.readlines()
    return lines


def dns_filter_query(p):
    return DNS in p and DNSQR in p and p[DNS].opcode == 0 and p[DNS].qr == 0 and (p[DNSQR].qtype == 1 or p[DNSQR].qtype == 12)


def dns_filter_answer(p):
    return DNS in p and DNSQR in p and p[DNS].opcode == 0 and p[DNS].qr == 1 and (p[DNSQR].qtype == 1 or p[DNSQR].qtype == 12)


def generate_real(r):
    dnsp = IP(dst='8.8.8.8') / UDP(dport=53) / r[DNS]
    send(dnsp, verbose=False)
    dnsr = sniff(count=1, lfilter=lambda x: dns_filter_answer(x) and x[DNSQR].qname == r[DNSQR].qname)[0]

    dnsr[IP].src = r[IP].dst
    dnsr[IP].dst = r[IP].src
    dnsr[UDP].sport = r[UDP].dport
    dnsr[UDP].dport = r[UDP].sport

    return dnsr[IP]


def generate(r):
    d = [line.split(' ') for line in load_data()]

    data = None
    for line in d:
        if r[DNSQR].qname.decode() == line[0] or r[DNSQR].qname.decode() == line[1]:
            data = line
    if data is None:
        p = generate_real(r)
        if p[DNS].ancount == 0:
            p = IP(dst=r[IP].src) / UDP(dport=r[UDP].sport, sport=r[UDP].dport) / DNS(id=r[DNS].id, qr=1, ra=1, rcode=3, qd=r[DNSQR])
        else:
            with open("C://Users//Liron//Python//temp//database.txt", 'a') as f:
                f.write(f'{p[DNSQR].qname.decode()} {p[DNS].an[p[DNS].ancount - 1].rdata} {p[DNSRR].ttl}\n')

        return p[IP]

    p = IP(dst=r[IP].src) / UDP(dport=r[UDP].sport, sport=r[UDP].dport) / DNS(id=r[DNS].id, qr=1, ra=1, ancount=1, qd=r[DNSQR])
    p.an = DNSRR(rrname=r[DNSQR].qname, type=r[DNSQR].qtype, ttl=int(data[2]), rdlen=4 if r[DNSQR].qtype == 1 else len(data[0]) + 1, rdata=data[1] if r[DNSQR].qtype == 1 else data[0])

    return p[IP]


def main():
    while True:
        request = sniff(count=1, lfilter=dns_filter_query)[0]
        p = generate(request)
        send(p, verbose=False)


if __name__ == "__main__":
    main()
