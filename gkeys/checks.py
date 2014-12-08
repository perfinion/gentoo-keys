#
#-*- coding:utf-8 -*-

"""
    Gentoo-Keys - gkeygen/checks.py

    Primary key checks module
    @copyright: 2014 by Brian Dolbec <dolsen@gentoo.org>
    @license: GNU GPL2, see COPYING for details
"""

import time
from collections import namedtuple, OrderedDict

from gkeys.config import GKEY_CHECK


ALGORITHM_CODES = {
    '1': 'RSA',
    '2': 'RSA',      # (encrypt only)
    '3': 'RSA',      # (sign only)
    '16': 'ElGamal', # (encrypt only)
    '17': 'DSA',     #(sometimes called DH, sign only)
    '18': 'ECDH',
    '19': 'ECDSA',
    '20': 'ElGamal'  # (sign and encrypt)
}

VERSION_FPR_LEN = {
    32: '3',
    40: '4',
    '3': 32,
    '4': 40,
}

# Default glep 63 minimum gpg key specification
# and approved options, limits
TEST_SPEC = {
    'bits': {
        'DSA': 2048,
        'RSA': 2048,
        },
    'expire': 36,      # in months
    'subkeys': {        # warning/error mode
        'encrypt': {
            'mode': 'notice',
            'expire': -1,  # -1 is the primary key expirery
            },
        'sign': {
            'mode': 'error',
            'expire': 12,
            },
        },
    'type': ['DSA', 'RSA', '1', '2', '3', '17'],
    'versions': ['4'],
}

GLEP_INDEX = {
    'key': 0,
    'type': 1,
    'fingerprint': 2,
    'bits': 3,
    'created': 4,
    'expire': 5,
    'encrypt_capable': 6,
    'encrypt_expirey': 7,
    'sign_capable': 8,
    'sign_expirey': 9,
    'algo': 10,
    'version': 11,
    'gentoo_id': 12,
    'days': 13,
}
GLEP_INDEX = OrderedDict(sorted(GLEP_INDEX.items(), key=lambda t: t[1]))

GLEP_STAT = ['', '','', False, False, False, False, False, False, False, False, False, False, 0]


class GlepCheck(namedtuple("GlepKey", list(GLEP_INDEX))):

    __slots__ = ()


class KeyChecks(object):
    '''Primary gpg key validation and glep spec checks class'''

    def __init__(self, logger, spec=TEST_SPEC, gentoo_id_check=True):
        '''@param spec: optional gpg specification to test against
                        Defaults to TEST_SPEC

        '''
        self.logger = logger
        self.spec = spec
        self.check_gentoo_id = gentoo_id_check


    def validity_checks(self, keydir, keyid, result):
        '''Check the specified result based on the seed type

        @param keydir: the keydir to list the keys for
        @param keyid: the keyid to check
        @param result: pyGPG.output.GPGResult object
        @returns: GKEY_CHECK instance
        '''
        revoked = expired = invalid = sign = False
        for data in result.status.data:
            if data.name ==  "PUB":
                if data.long_keyid == keyid[2:]:
                    # check if revoked
                    if 'r' in data.validity:
                        revoked = True
                        self.logger.debug("ERROR in key %s : revoked" % data.long_keyid)
                        break
                    # if primary key expired, all subkeys expire
                    if 'e' in data.validity:
                        expired = True
                        self.logger.debug("ERROR in key %s : expired" % data.long_keyid)
                        break
                    # check if invalid
                    if 'i' in data.validity:
                        invalid = True
                        self.logger.debug("ERROR in key %s : invalid" % data.long_keyid)
                        break
                    if 's' in data.key_capabilities:
                        sign = True
                        self.logger.debug("INFO primary key %s : key signing capabilities" % data.long_keyid)
            if data.name == "SUB":
                # check if invalid
                if 'i' in data.validity:
                    self.logger.debug("WARNING in subkey %s : invalid" % data.long_keyid)
                    continue
                # check if expired
                if 'e' in data.validity:
                    self.logger.debug("WARNING in subkey %s : expired" % data.long_keyid)
                    continue
                # check if revoked
                if 'r' in data.validity:
                    self.logger.debug("WARNING in subkey %s : revoked" % data.long_keyid)
                    continue
                # check if subkey has signing capabilities
                if 's' in data.key_capabilities:
                    sign = True
                    self.logger.debug("INFO subkey %s : subkey signing capabilities" % data.long_keyid)
        return GKEY_CHECK(keyid, revoked, expired, invalid, sign)


    def glep_check(self, keydir, keyid, result):
        '''Performs the minimum specifications checks on the key'''
        self.logger.debug("GLEP_CHECK() : CHECKING: %s" % keyid)
        results = {}
        pub = None
        stats = None
        #print(len(result.status.data))
        for data in result.status.data:
            #print(data)
            if data.name ==  "PUB":
                if stats:
                    #print("new PUB:", stats)
                    results[pub.long_keyid].append(GlepCheck._make(stats))
                pub = data
                found_gentoo_id = False
                results[data.long_keyid] = []
                stats = GLEP_STAT[:]
                stats[GLEP_INDEX['key']] = data.name
                stats[GLEP_INDEX['type']] = data.key_capabilities
                stats = self._test_created(data, stats)
                stats = self._test_algo(data, stats)
                stats = self._test_bits(data, stats)
                stats = self._test_expire(data, stats)
                stats = self._test_caps(data, stats)
            elif data.name ==  "FPR":
                pub = pub._replace(**{'fingerprint': data.fingerprint})
                stats[GLEP_INDEX['fingerprint']] = data.fingerprint
                stats = self._test_version(data, stats)
            elif data.name ==  "UID":
                if not found_gentoo_id:
                    stats = self._test_uid(data, stats)
                    if stats[GLEP_INDEX['gentoo_id']]:
                        found_gentoo_id = True
            elif data.name == "SUB":
                if stats:
                    #print("new SUB:", stats)
                    results[pub.long_keyid].append(GlepCheck._make(stats))
                stats = GLEP_STAT[:]
                stats[GLEP_INDEX['key']] = data.name
                stats[GLEP_INDEX['type']] = data.key_capabilities
                stats[GLEP_INDEX['fingerprint']] = '%s' \
                    % (data.long_keyid)
                stats[GLEP_INDEX['gentoo_id']] = found_gentoo_id
                stats = self._test_created(data, stats)
                stats = self._test_expire(data, stats)
                stats = self._test_caps(data, stats)
                #print("Finished SUB:", stats)
        if stats:
            results[pub.long_keyid].append(GlepCheck._make(stats))
            stats = None
        self.logger.debug("GLEP_CHECK() : COMPLETED: %s" % keyid)
        #print(results)
        return results


    def _test_algo(self, data, stats):
        algo = data.pubkey_algo
        if algo in TEST_SPEC['type']:
            stats[GLEP_INDEX['algo']] = True
        else:
            self.logger.debug("ERROR in key %s : invalid Type: %s"
                % (data.long_keyid, ALGORITHM_CODES[algo]))
        return stats


    def _test_bits(self, data, stats):
        bits = int(data.keylength)
        if data.pubkey_algo in TEST_SPEC['type']:
            #print("bits", bits, TEST_SPEC['bits'][ALGORITHM_CODES[data.pubkey_algo]])
            if bits >= TEST_SPEC['bits'][ALGORITHM_CODES[data.pubkey_algo]]:
                stats[GLEP_INDEX['bits']] = True
            else:
                self.logger.debug("ERROR in key %s : invalid Bit length: %d"
                    % (data.long_keyid, bits))
        return stats


    def _test_version(self, data, stats):
        fpr_l = len(data.fingerprint)
        if VERSION_FPR_LEN[fpr_l] in TEST_SPEC['versions']:
            stats[GLEP_INDEX['version']] = True
        else:
            self.logger.debug("ERROR in key %s : invalid gpg key version: %s"
                % (data.long_keyid, VERSION_FPR_LEN[fpr_l]))
        return stats


    def _test_created(self, data, stats):
        try:
            created = float(data.creation_date)
        except ValueError:
            created = 0
        #print(created, time.time(), created <= time.time())
        if created <= time.time() :
            stats[GLEP_INDEX['created']] = True
        else:
            self.logger.debug("ERROR in key %s : invalid gpg key creation date: %s"
                % (data.long_keyid, data.creation_date))
        return stats


    def _test_expire(self, data, stats):
        if data.name in ["PUB"]:
            delta_t = TEST_SPEC['expire'] * 2629744
            stats = self._expire_check(data, stats, delta_t)
            return stats
        else:
            for cap in data.key_capabilities:
                if "s" in cap:
                    delta_t = TEST_SPEC['subkeys']['sign']['expire'] * 2629744
                if "e" in data.key_capabilities:
                    delta_t = TEST_SPEC['subkeys']['encrypt']['expire'] * 2629744
                else:
                    delta_t = 0
                stats = self._expire_check(data, stats, delta_t)
                return stats


    def _expire_check(self, data, stats, delta_t):
        today = time.time()
        try:
            expires = float(data.expiredate)
        except ValueError:
            expires = float("inf")
        if expires <= (today + delta_t):
            if data.name =="PUB":
                stats[GLEP_INDEX['expire']] = True
            elif data.name == "SUB":
                if "s" in data.key_capabilities:
                    stats[GLEP_INDEX['sign_expirey']] = True
                elif "e" in data.key_capabilities:
                    stats[GLEP_INDEX['encrypt_expirey']] = True
            stats[GLEP_INDEX['days']] = max(0, int((expires - today)/86400))
        elif expires > (today + delta_t):
            if expires == float("inf"):
                stats[GLEP_INDEX['days']] = expires
            else:
                stats[GLEP_INDEX['days']] = int((expires - today)/86400)
        else:
            self.logger.debug("ERROR in key %s : invalid gpg key expire date: %s"
                % (data.long_keyid, data.expiredate))
        return stats


    def _test_caps(self, data, stats):
        for cap in data.key_capabilities:
            #print("cap", cap)
            if cap in ["s"]:
                stats[GLEP_INDEX['sign_capable']] = True
            elif cap in ["e"]:
                stats[GLEP_INDEX['encrypt_capable']] = True
            else:
                self.logger.debug("ERROR in key %s : unknown gpg key capability: %s"
                    % (data.long_keyid, cap))
        return stats


    def _test_uid(self, data, stats):
        if data.user_ID :
            stats[GLEP_INDEX['gentoo_id']] = True
        else:
            self.logger.debug("Warning: No @gentoo.org email addr. in key %s"
                % (data.user_ID))
        return stats
