import argparse
import os
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


def parse_host_port(value, default_port=19302):
    if ":" not in value:
        return value, default_port
    host, port = value.rsplit(":", 1)
    return host, int(port)


def build_binding_request(change_ip=False, change_port=False):
    message_type = 0x0001
    message_length = 0
    cookie = 0x2112A442
    transaction_id = os.urandom(12)
    header = (
        message_type.to_bytes(2, "big")
        + message_length.to_bytes(2, "big")
        + cookie.to_bytes(4, "big")
        + transaction_id
    )
    if change_ip or change_port:
        flags = 0
        if change_ip:
            flags |= 0x04
        if change_port:
            flags |= 0x02
        attr_type = 0x0003
        attr_len = 4
        value = flags.to_bytes(4, "big")
        message_length = attr_len + 4
        header = (
            message_type.to_bytes(2, "big")
            + message_length.to_bytes(2, "big")
            + cookie.to_bytes(4, "big")
            + transaction_id
            + attr_type.to_bytes(2, "big")
            + attr_len.to_bytes(2, "big")
            + value
        )
    return header, transaction_id


def parse_xor_mapped_address(data, transaction_id):
    if len(data) < 20:
        return None

    msg_type = int.from_bytes(data[0:2], "big")
    if msg_type != 0x0101:
        return None

    msg_len = int.from_bytes(data[2:4], "big")
    cookie = int.from_bytes(data[4:8], "big")
    rx_id = data[8:20]
    if rx_id != transaction_id:
        return None

    attrs = data[20:20 + msg_len]
    i = 0
    while i + 4 <= len(attrs):
        attr_type = int.from_bytes(attrs[i:i + 2], "big")
        attr_len = int.from_bytes(attrs[i + 2:i + 4], "big")
        value = attrs[i + 4:i + 4 + attr_len]
        padded = (attr_len + 3) & ~3

        if attr_type in (0x0020, 0x0001) and len(value) >= 8:
            family = value[1]
            if family == 0x01:
                if attr_type == 0x0020:
                    port = int.from_bytes(value[2:4], "big") ^ (cookie >> 16)
                    raw_ip = int.from_bytes(value[4:8], "big") ^ cookie
                    ip = ".".join(str((raw_ip >> shift) & 0xFF) for shift in (24, 16, 8, 0))
                else:
                    port = int.from_bytes(value[2:4], "big")
                    ip = ".".join(str(b) for b in value[4:8])
                return ip, port

        i += 4 + padded

    return None


def get_local_ip_for(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect((host, port))
            return s.getsockname()[0]
        except OSError:
            return "0.0.0.0"


def stun_request(sock, server, timeout, change_ip=False, change_port=False):
    host, port = parse_host_port(server)
    req, tx_id = build_binding_request(change_ip=change_ip, change_port=change_port)
    try:
        sock.settimeout(timeout)
        sock.sendto(req, (host, port))
        data, addr = sock.recvfrom(2048)
    except OSError:
        return None, None, False

    mapped = parse_xor_mapped_address(data, tx_id)
    if not mapped:
        return None, None, False

    ok_change = True
    if change_ip and change_port:
        ok_change = addr[0] != host and addr[1] != port
    elif change_port:
        ok_change = addr[1] != port

    return mapped, addr, ok_change


def detect_nat_type(servers, timeout):
    primary = None
    mapped1 = None
    local_ip = None
    local_port = None

    for server in servers:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("", 0))
            mapped, _, _ = stun_request(sock, server, timeout)
            if mapped:
                primary = server
                mapped1 = mapped
                host, port = parse_host_port(server)
                local_ip = get_local_ip_for(host, port)
                local_port = sock.getsockname()[1]
                break

    if not primary:
        return "Unknown (no STUN response)"

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("", local_port))

        if mapped1 == (local_ip, local_port):
            _, _, ok = stun_request(sock, primary, timeout, change_ip=True, change_port=True)
            return "Open Internet" if ok else "Symmetric UDP Firewall"

        _, _, ok = stun_request(sock, primary, timeout, change_ip=True, change_port=True)
        if ok:
            return "Full Cone NAT"

        mapped2 = None
        for server in servers:
            if server == primary:
                continue
            mapped, _, _ = stun_request(sock, server, timeout)
            if mapped:
                mapped2 = mapped
                break

        if mapped2 and mapped2 != mapped1:
            return "Symmetric NAT"

        _, _, ok = stun_request(sock, primary, timeout, change_port=True)
        return "Restricted Cone NAT" if ok else "Port Restricted Cone NAT"


GOOGLE_STUN_SERVERS = [
  "stun.l.google.com:19302",
  "stun.l.google.com:5349",
  "stun1.l.google.com:3478",
  "stun1.l.google.com:5349",
  "stun2.l.google.com:19302",
  "stun2.l.google.com:5349",
  "stun3.l.google.com:3478",
  "stun3.l.google.com:5349",
  "stun4.l.google.com:19302",
  "stun4.l.google.com:5349"
]+[
  "23.21.150.121:3478",
  "iphone-stun.strato-iphone.de:3478",
  "numb.viagenie.ca:3478",
  "s1.taraba.net:3478",
  "s2.taraba.net:3478",
  "stun.12connect.com:3478",
  "stun.12voip.com:3478",
  "stun.1und1.de:3478",
  "stun.2talk.co.nz:3478",
  "stun.2talk.com:3478",
  "stun.3clogic.com:3478",
  "stun.3cx.com:3478",
  "stun.a-mm.tv:3478",
  "stun.aa.net.uk:3478",
  "stun.acrobits.cz:3478",
  "stun.actionvoip.com:3478",
  "stun.advfn.com:3478",
  "stun.aeta-audio.com:3478",
  "stun.aeta.com:3478",
  "stun.alltel.com.au:3478",
  "stun.altar.com.pl:3478",
  "stun.annatel.net:3478",
  "stun.antisip.com:3478",
  "stun.arbuz.ru:3478",
  "stun.avigora.com:3478",
  "stun.avigora.fr:3478",
  "stun.awa-shima.com:3478",
  "stun.awt.be:3478",
  "stun.b2b2c.ca:3478",
  "stun.bahnhof.net:3478",
  "stun.barracuda.com:3478",
  "stun.bluesip.net:3478",
  "stun.bmwgs.cz:3478",
  "stun.botonakis.com:3478",
  "stun.budgetphone.nl:3478",
  "stun.budgetsip.com:3478",
  "stun.cablenet-as.net:3478",
  "stun.callromania.ro:3478",
  "stun.callwithus.com:3478",
  "stun.cbsys.net:3478",
  "stun.chathelp.ru:3478",
  "stun.cheapvoip.com:3478",
  "stun.ciktel.com:3478",
  "stun.cloopen.com:3478",
  "stun.colouredlines.com.au:3478",
  "stun.comfi.com:3478",
  "stun.commpeak.com:3478",
  "stun.comtube.com:3478",
  "stun.comtube.ru:3478",
  "stun.cope.es:3478",
  "stun.counterpath.com:3478",
  "stun.counterpath.net:3478",
  "stun.cryptonit.net:3478",
  "stun.darioflaccovio.it:3478",
  "stun.datamanagement.it:3478",
  "stun.dcalling.de:3478",
  "stun.decanet.fr:3478",
  "stun.demos.ru:3478",
  "stun.develz.org:3478",
  "stun.dingaling.ca:3478",
  "stun.doublerobotics.com:3478",
  "stun.drogon.net:3478",
  "stun.duocom.es:3478",
  "stun.dus.net:3478",
  "stun.e-fon.ch:3478",
  "stun.easybell.de:3478",
  "stun.easycall.pl:3478",
  "stun.easyvoip.com:3478",
  "stun.efficace-factory.com:3478",
  "stun.einsundeins.com:3478",
  "stun.einsundeins.de:3478",
  "stun.ekiga.net:3478",
  "stun.epygi.com:3478",
  "stun.etoilediese.fr:3478",
  "stun.eyeball.com:3478",
  "stun.faktortel.com.au:3478",
  "stun.freecall.com:3478",
  "stun.freeswitch.org:3478",
  "stun.freevoipdeal.com:3478",
  "stun.fuzemeeting.com:3478",
  "stun.gmx.de:3478",
  "stun.gmx.net:3478",
  "stun.gradwell.com:3478",
  "stun.halonet.pl:3478",
  "stun.hellonanu.com:3478",
  "stun.hoiio.com:3478",
  "stun.hosteurope.de:3478",
  "stun.ideasip.com:3478",
  "stun.imesh.com:3478",
  "stun.infra.net:3478",
  "stun.internetcalls.com:3478",
  "stun.intervoip.com:3478",
  "stun.ipcomms.net:3478",
  "stun.ipfire.org:3478",
  "stun.ippi.fr:3478",
  "stun.ipshka.com:3478",
  "stun.iptel.org:3478",
  "stun.irian.at:3478",
  "stun.it1.hr:3478",
  "stun.ivao.aero:3478",
  "stun.jappix.com:3478",
  "stun.jumblo.com:3478",
  "stun.justvoip.com:3478",
  "stun.kanet.ru:3478",
  "stun.kiwilink.co.nz:3478",
  "stun.kundenserver.de:3478",
  "stun.l.google.com:19302",
  "stun.linea7.net:3478",
  "stun.linphone.org:3478",
  "stun.liveo.fr:3478",
  "stun.lowratevoip.com:3478",
  "stun.lugosoft.com:3478",
  "stun.lundimatin.fr:3478",
  "stun.magnet.ie:3478",
  "stun.manle.com:3478",
  "stun.mgn.ru:3478",
  "stun.mit.de:3478",
  "stun.mitake.com.tw:3478",
  "stun.miwifi.com:3478",
  "stun.modulus.gr:3478",
  "stun.mozcom.com:3478",
  "stun.myvoiptraffic.com:3478",
  "stun.mywatson.it:3478",
  "stun.nas.net:3478",
  "stun.neotel.co.za:3478",
  "stun.netappel.com:3478",
  "stun.netappel.fr:3478",
  "stun.netgsm.com.tr:3478",
  "stun.nfon.net:3478",
  "stun.noblogs.org:3478",
  "stun.noc.ams-ix.net:3478",
  "stun.node4.co.uk:3478",
  "stun.nonoh.net:3478",
  "stun.nottingham.ac.uk:3478",
  "stun.nova.is:3478",
  "stun.nventure.com:3478",
  "stun.on.net.mk:3478",
  "stun.ooma.com:3478",
  "stun.ooonet.ru:3478",
  "stun.oriontelekom.rs:3478",
  "stun.outland-net.de:3478",
  "stun.ozekiphone.com:3478",
  "stun.patlive.com:3478",
  "stun.personal-voip.de:3478",
  "stun.petcube.com:3478",
  "stun.phone.com:3478",
  "stun.phoneserve.com:3478",
  "stun.pjsip.org:3478",
  "stun.poivy.com:3478",
  "stun.powerpbx.org:3478",
  "stun.powervoip.com:3478",
  "stun.ppdi.com:3478",
  "stun.prizee.com:3478",
  "stun.qq.com:3478",
  "stun.qvod.com:3478",
  "stun.rackco.com:3478",
  "stun.rapidnet.de:3478",
  "stun.rb-net.com:3478",
  "stun.refint.net:3478",
  "stun.remote-learner.net:3478",
  "stun.rixtelecom.se:3478",
  "stun.rockenstein.de:3478",
  "stun.rolmail.net:3478",
  "stun.rounds.com:3478",
  "stun.rynga.com:3478",
  "stun.samsungsmartcam.com:3478",
  "stun.schlund.de:3478",
  "stun.services.mozilla.com:3478",
  "stun.sigmavoip.com:3478",
  "stun.sip.us:3478",
  "stun.sipdiscount.com:3478",
  "stun.siplogin.de:3478",
  "stun.sipnet.net:3478",
  "stun.sipnet.ru:3478",
  "stun.siportal.it:3478",
  "stun.sippeer.dk:3478",
  "stun.siptraffic.com:3478",
  "stun.skylink.ru:3478",
  "stun.sma.de:3478",
  "stun.smartvoip.com:3478",
  "stun.smsdiscount.com:3478",
  "stun.snafu.de:3478",
  "stun.softjoys.com:3478",
  "stun.solcon.nl:3478",
  "stun.solnet.ch:3478",
  "stun.sonetel.com:3478",
  "stun.sonetel.net:3478",
  "stun.sovtest.ru:3478",
  "stun.speedy.com.ar:3478",
  "stun.spokn.com:3478",
  "stun.srce.hr:3478",
  "stun.ssl7.net:3478",
  "stun.stunprotocol.org:3478",
  "stun.symform.com:3478",
  "stun.symplicity.com:3478",
  "stun.sysadminman.net:3478",
  "stun.t-online.de:3478",
  "stun.tagan.ru:3478",
  "stun.tatneft.ru:3478",
  "stun.teachercreated.com:3478",
  "stun.tel.lu:3478",
  "stun.telbo.com:3478",
  "stun.telefacil.com:3478",
  "stun.tis-dialog.ru:3478",
  "stun.tng.de:3478",
  "stun.twt.it:3478",
  "stun.u-blox.com:3478",
  "stun.ucallweconn.net:3478",
  "stun.ucsb.edu:3478",
  "stun.ucw.cz:3478",
  "stun.uls.co.za:3478",
  "stun.unseen.is:3478",
  "stun.usfamily.net:3478",
  "stun.veoh.com:3478",
  "stun.vidyo.com:3478",
  "stun.vipgroup.net:3478",
  "stun.virtual-call.com:3478",
  "stun.viva.gr:3478",
  "stun.vivox.com:3478",
  "stun.vline.com:3478",
  "stun.vo.lu:3478",
  "stun.vodafone.ro:3478",
  "stun.voicetrading.com:3478",
  "stun.voip.aebc.com:3478",
  "stun.voip.blackberry.com:3478",
  "stun.voip.eutelia.it:3478",
  "stun.voiparound.com:3478",
  "stun.voipblast.com:3478",
  "stun.voipbuster.com:3478",
  "stun.voipbusterpro.com:3478",
  "stun.voipcheap.co.uk:3478",
  "stun.voipcheap.com:3478",
  "stun.voipfibre.com:3478",
  "stun.voipgain.com:3478",
  "stun.voipgate.com:3478",
  "stun.voipinfocenter.com:3478",
  "stun.voipplanet.nl:3478",
  "stun.voippro.com:3478",
  "stun.voipraider.com:3478",
  "stun.voipstunt.com:3478",
  "stun.voipwise.com:3478",
  "stun.voipzoom.com:3478",
  "stun.vopium.com:3478",
  "stun.voxgratia.org:3478",
  "stun.voxox.com:3478",
  "stun.voys.nl:3478",
  "stun.voztele.com:3478",
  "stun.vyke.com:3478",
  "stun.webcalldirect.com:3478",
  "stun.whoi.edu:3478",
  "stun.wifirst.net:3478",
  "stun.wwdl.net:3478",
  "stun.xs4all.nl:3478",
  "stun.xtratelecom.es:3478",
  "stun.yesss.at:3478",
  "stun.zadarma.com:3478",
  "stun.zadv.com:3478",
  "stun.zoiper.com:3478",
  "stun1.faktortel.com.au:3478",
  "stun1.l.google.com:19302",
  "stun1.voiceeclipse.net:3478",
  "stun2.l.google.com:19302",
  "stun3.l.google.com:19302",
  "stun4.l.google.com:19302",
  "stunserver.org:3478",
  "stun.sipnet.net:3478",
  "stun.sipnet.ru:3478",
  "stun.stunprotocol.org:3478",
  "124.64.206.224:8800",
  "stun.nextcloud.com:443",
  "relay.webwormhole.io",
  "stun.flashdance.cx:3478"
]

def main():
    parser = argparse.ArgumentParser(description="Simple STUN binding request")
    parser.add_argument("--stun", action="append", default=[], help="Override list; can be repeated")
    parser.add_argument("--timeout", type=float, default=4.0)
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args()

    servers = args.stun or GOOGLE_STUN_SERVERS
    results = []

    def query_server(server):
        host, port = parse_host_port(server)
        req, tx_id = build_binding_request()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(args.timeout)
                sock.sendto(req, (host, port))
                data, _ = sock.recvfrom(2048)
            mapped = parse_xor_mapped_address(data, tx_id)
        except OSError:
            mapped = None
        return server, mapped

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        futures = {executor.submit(query_server, server): server for server in servers}
        for future in as_completed(futures):
            server, mapped = future.result()
            if mapped:
                results.append((server, mapped))

    nat_type = detect_nat_type(servers, args.timeout)
    print(f"NAT type: {nat_type}")

    if not results:
        print("No mapped address found.")
        return

    for server, mapped in results:
        print(f"{server} -> {mapped[0]}:{mapped[1]}")


if __name__ == "__main__":
    main()
