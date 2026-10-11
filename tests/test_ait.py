"""AIT-LDSv2 normalization on fixed sample lines (no dataset needed)."""

from siemcrypt.data import ait


def test_apache_line():
    line = ('172.19.131.174 - - [24/Jan/2022:03:58:20 +0000] "POST /wp-admin/admin-ajax.php HTTP/1.1" '
            '200 2048 "-" "Mozilla"')
    t, src, user, res, cat, feats = ait._p_apache(line, 2022, "intranet")
    assert (src, user, res, cat, feats["bytes"]) == ("web", "172.19.131.174", "intranet", "http_POST_2xx", 2)


def test_apache_long_query_and_error():
    line = '10.0.0.1 - - [24/Jan/2022:03:58:20 +0000] "GET /x.php?a=' + "A" * 120 + ' HTTP/1.1" 404 10 "-" "-"'
    assert ait._p_apache(line, 2022, "h")[4] == "http_GET_4xx_lq"


def test_dns_query_long_name():
    line = "Jan 21 00:00:09 dnsmasq[3468]: query[A] " + "x" * 70 + ".evil.com from 10.143.0.103"
    t, src, user, res, cat, _ = ait._p_dns(line, 2022, "fw")
    assert (src, user, res, cat) == ("dns", "10.143.0.103", "evil.com", "dns_q_long")
    assert ait._p_dns("Jan 21 00:00:09 dnsmasq[3468]: cached a.b is NODATA", 2022, "fw") is None


def test_auth_su_and_vpn():
    su = ait._p_auth("Jan 24 04:37:40 intranet-server su[27950]: Successful su for jhall by www-data", 2022, "h")
    assert (su[2], su[3], su[4]) == ("www-data", "intranet-server", "su")
    vpn = ait._p_vpn("2022-01-21 06:30:01 192.168.230.95:60795 [twhite] Peer Connection Initiated with "
                     "[AF_INET]192.168.230.95:60795", 2022, "vpn")
    assert (vpn[2], vpn[4]) == ("twhite", "vpn_connect")


def test_suricata_fast():
    line = ("01/21/2022-12:58:33.657361  [**] [1:2230010:1] SURICATA TLS invalid record/traffic [**] "
            "[Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 213.13.25.14:443 -> 172.19.131.174:33406")
    t, src, user, res, cat, _ = ait._p_fast(line, 2022, "vpn")
    assert (src, user, res, cat) == ("ids", "213.13.25.14", "172.19.131.174", "ids_p3")


def test_label_classes():
    assert ait._class_of(["dnsteal", "attacker"]) == "dns_exfil"
    assert ait._class_of(["webshell_cmd", "escalate"]) == "web_attack"
    assert ait._class_of(["escalate"]) == "priv_esc"
    assert ait._class_of(["dirb", "foothold"]) == "recon"
    assert ait._class_of(["attacker_vpn", "foothold"]) is None
