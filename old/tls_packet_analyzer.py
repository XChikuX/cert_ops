import re
import sys

import pyshark

"""                     LOGGING IMPORTS                            """
import logging
from rich.logging import RichHandler

FORMAT = "[<->] %(asctime)s |%(process)d| %(message)s"

logging.basicConfig(
    level="NOTSET",
    format=FORMAT,
    datefmt="%Y-%m-%d %H:%M:%S %z",
    handlers=[RichHandler()],
)

logger = logging.getLogger("rich")


allowed_cipher_suites = {
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": ["ECDHE-RSA-AES256-GCM-SHA384", 0xc030],
    "TLS_RSA_WITH_AES_256_GCM_SHA384": ["AES256-GCM-SHA384", 0x9d],
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": ["ECDHE-RSA-AES128-GCM-SHA256", 0xc02f],
    "TLS_RSA_WITH_AES_128_GCM_SHA256": ["AES128-GCM-SHA256", 0x9c],
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384": ["ECDHE-RSA-AES256-SHA384", 0xc028],
    "TLS_RSA_WITH_AES_256_CBC_SHA256": ["AES256-SHA256", 0x3d],
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA": ["ECDHE-RSA-AES256-SHA", 0xc014],
    "TLS_RSA_WITH_AES_256_CBC_SHA": ["AES256-SHA", 0x35],
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256": ["ECDHE-RSA-AES128-SHA256", 0xc027],
    "TLS_RSA_WITH_AES_128_CBC_SHA256": ["AES128-SHA256", 0x3c],
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA": ["ECDHE-RSA-AES128-SHA", 0xc013],
    "TLS_RSA_WITH_AES_128_CBC_SHA": ["AES128-SHA", 0x2f],
    "TLS_EMPTY_RENEGOTIATION_warning_SCSV": ["TLS_FALLBACK_SCSV", 0x5600]
}


def verify_cipher_suites(string):
    """ Verifies the 13 allowed Cipher Suites exist in the Hello message"""
    cipher_suites = set(re.findall('Cipher Suite: (.*?) ',
                                   string, re.DOTALL))
    if not cipher_suites:
        raise ValueError
    if set(allowed_cipher_suites.keys()) == cipher_suites:
        logger.info("Verified allowed ciphers are correct")
        return True

    logger.warning("Mismatch in number of cipher suites expected %s got %s",
                allowed_cipher_suites.keys(), cipher_suites)
    return False


def verify_chosen_cipher(string, server_cipher):
    """ Verifies a specific Cipher is chosen during Handshake"""
    cipher_suites = re.findall('Cipher Suite: (.*?) ',
                               string, re.DOTALL)
    assert len(cipher_suites) == 1
    cipher_suite = cipher_suites[0]
    if cipher_suite in allowed_cipher_suites.keys() and cipher_suite == server_cipher:
        logger.info("Verified cipher %s are same on client and server" % server_cipher)
        return True
    logger.info("Mismatch in chosen cipher suite expected %s got %s",
                  server_cipher, cipher_suite)
    return False


def check_handshake(tls_packets, src_ip, dst_ip, server_cipher=None, **kwargs):
    """
    Function that returns true if a handshake is successful
    and the cipher exchange is as expected.
    parameter: server_cipher allows to check for a specific cipher
               in the exchange messages
    """
    expected_ct = len(allowed_cipher_suites)
    allowed_ciphers_flag = False
    correct_chosen_cipher_flag = False
    for packet in tls_packets:
        try:
            # Check for tls packet
            assert packet['tls'].layer_name
            # Check for given source and dest. ip in packet header
            if src_ip == packet['ip'].src and dst_ip == str(packet['ip'].dst) or \
               src_ip == packet['ip'].dst and dst_ip == str(packet['ip'].src):
                try:
                    # Check for client hello
                    if packet['tls'].handshake_type == '1':
                        # Verify allowed cipher suites
                        if str(packet['tls'].handshake_ciphersuites) == \
                                "Cipher Suites (%s suites)" % expected_ct:
                            assert verify_cipher_suites(str(packet['tls']))
                            allowed_ciphers_flag = True
                    # Check for server hello
                    elif packet['tls'].handshake_type == '2':
                        if server_cipher:
                            # Check individual cipher suite
                            assert verify_chosen_cipher(str(packet['tls']),
                                                        server_cipher)
                            correct_chosen_cipher_flag = True
                        else:
                            return True
                    elif packet['tls'].handshake_type == '13' or packet['tls'].handshake_type == '11':  # noqa
                        raise ValueError
                    if allowed_ciphers_flag and correct_chosen_cipher_flag:
                        return True

                except AttributeError:
                    logger.error("Error in reading packets")
        except KeyError:
            # Get rid of useless packets
            pass
    return False


def filter_packets_from_file(file_path, src_ip, dst_ip, server_cipher=None):
    """
    Function that opens a capture file
    This capture file class is then passed onto check_handshake for
    further processing.
    """
    cap = pyshark.FileCapture(str(file_path))
    assert check_handshake(cap, src_ip, dst_ip, server_cipher=None)


if __name__ == '__main__':
    cap = pyshark.FileCapture(sys.argv[1])
    check_handshake(cap, sys.argv[2], sys.argv[3])
