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

CAPABILITY_MAP = {
    'a': 'authenticate',
    'c': 'certify',
    'e': 'encrypt',
    's': 'sign',
    'A': '(Authenticate)',
    'C': '(Certify)',
    'E': '(Encrypt)',
    'S': '(Sign)',
    '?': 'Unknown',
}

VALIDITY_MAP = {
    'o': 'Unknown',
    'i': 'Invalid',
    'd': 'Disabled',
    'r': 'Revoked',
    'e': 'Expired',
    '-': 'Unknown',
    'q': 'Undefined',
    'n': 'Valid',
    'm': 'Marginal',
    'f': 'Fully valid',
    'u': 'Ultimately valid',
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
    'expire': 3 * 365,      # in days
    'subkeys': {        # warning/error mode
        'encrypt': {
            'mode': 'notice',
            'expire': 3 * 365,
            },
        'sign': {
            'mode': 'error',
            'expire': 365,
            },
        },
    'algorithms': ['DSA', 'RSA', '1', '2', '3', '17'],
    'versions': ['4'],
    'qualified_id': '@gentoo.org',
}

SECONDS_PER_DAY = 86400

GLEP_INDEX = {
    'key': 0,
    'capabilities': 1,
    'fingerprint': 2,
    'bits': 3,
    'created': 4,
    'expire': 5,
    'encrypt_capable': 6,
    'sign_capable': 7,
    'algo': 8,
    'version': 9,
    'id': 10,
    'days': 11,
    'validity': 12,
    'expire_reason': 13,
    'long_caps': 14,  # long version of the capbilities
}
GLEP_INDEX = OrderedDict(sorted(GLEP_INDEX.items(), key=lambda t: t[1]))

GLEP_STAT = ['', '','', False, False, False, False, False, False, False, False,
    0, '', '', '']


GLEPCHECK_STRING = '''    ----------
    Fingerprint......: %(fingerprint)s
    Key type ........: %(key)s    Capabilities.: %(capabilities)s  %(long_caps)s
    Algorithm........: %(algo)s   Bit Length...: %(bits)s
    Create Date......: %(created)s   Expire Date..: %(expire)s
    Key Version......: %(version)s   Validity.....: %(validity)s
    Days till expiry.: %(days)s  %(expire_reason)s
    Qualified ID.....: %(id)s'''

class GlepCheck(namedtuple("GlepKey", list(GLEP_INDEX))):

    __slots__ = ()

    def pretty_print(self):
        data = self.convert_data()
        output = GLEPCHECK_STRING % (data)
        return output


    def convert_data(self):
        data = dict(self._asdict())
        for f in ['bits', 'created', 'expire', 'algo', 'version']:
            if data[f]:
                data[f] = 'Pass'
            else:
                data[f] = 'Fail'
        for f in ['encrypt_capable', 'sign_capable']:
            if data[f]:
                data[f] = 'True '
            else:
                data[f] = 'False'
        data['validity'] += ', %s' % (VALIDITY_MAP[data['validity']])
        days = data['days']
        if days == float("inf"):
            data['days'] = "infinite"
        else:
            data['days'] = str(int(data['days']))
        return data


class KeyChecks(object):
    '''Primary gpg key validation and glep spec checks class'''

    def __init__(self, logger, spec=TEST_SPEC, qualified_id_check=True):
        '''@param spec: optional gpg specification to test against
                        Defaults to TEST_SPEC

        '''
        self.logger = logger
        self.spec = spec
        self.check_id = qualified_id_check


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
                found_id = False
                results[data.long_keyid] = []
                stats = GLEP_STAT[:]
                stats[GLEP_INDEX['key']] = data.name
                stats[GLEP_INDEX['capabilities']] = data.key_capabilities
                stats[GLEP_INDEX['validity']] = data.validity
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
                stats = self._test_uid(data, stats)
                if stats[GLEP_INDEX['id']] in [True, '-----']:
                    found_id = stats[GLEP_INDEX['id']]
            elif data.name == "SUB":
                if stats:
                    #print("new SUB:", stats)
                    results[pub.long_keyid].append(GlepCheck._make(stats))
                stats = GLEP_STAT[:]
                stats[GLEP_INDEX['key']] = data.name
                stats[GLEP_INDEX['capabilities']] = data.key_capabilities
                stats[GLEP_INDEX['fingerprint']] = '%s' \
                    % (data.long_keyid)
                stats[GLEP_INDEX['id']] = found_id
                stats[GLEP_INDEX['validity']] = data.validity
                stats = self._test_created(data, stats)
                stats = self._test_algo(data, stats)
                stats = self._test_bits(data, stats)
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
        if algo in TEST_SPEC['algorithms']:
            stats[GLEP_INDEX['algo']] = True
        else:
            self.logger.debug("ERROR in key %s : invalid Type: %s"
                % (data.long_keyid, ALGORITHM_CODES[algo]))
        return stats


    def _test_bits(self, data, stats):
        bits = int(data.keylength)
        #print("key bit length:", bits)
        if data.pubkey_algo in TEST_SPEC['algorithms']:
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
            delta_t = TEST_SPEC['expire']
            stats = self._expire_check(data, stats, delta_t)
            return stats
        else:
            for cap in data.key_capabilities:
                try:
                    delta_t = TEST_SPEC['subkeys'][CAPABILITY_MAP[cap]]['expire']
                except KeyError:
                    self.logger.debug(
                        "ERROR in capability key %s : setting delta_t to main expiry: %d"
                        % (cap, TEST_SPEC['expire']))
                    delta_t = TEST_SPEC['expire']
                stats = self._expire_check(data, stats, delta_t)
                return stats


    def _expire_check(self, data, stats, delta_t):
        today = time.time()
        try:
            expires = float(data.expiredate)
        except ValueError:
            expires = float("inf")
        if expires == float("inf"):
            days = stats[GLEP_INDEX['days']] = expires
        else:
            days = stats[GLEP_INDEX['days']] = max(0, int((expires - today)/SECONDS_PER_DAY))
        if days <= delta_t:
            stats[GLEP_INDEX['expire']] = True
        elif days > delta_t:
            stats[GLEP_INDEX['expire_reason']] = '<== Exceeds specification'
        else:
            self.logger.debug("ERROR in key %s : invalid gpg key expire date: %s"
                % (data.long_keyid, data.expiredate))
        if 0 < days < 30:
               stats[GLEP_INDEX['expire_reason']] = '<== WARNING < 30 days'

        return stats


    def _test_caps(self, data, stats):
        kcaps = []
        for cap in data.key_capabilities:
            #print("cap", cap)
            if CAPABILITY_MAP[cap]:
                kcaps.append(CAPABILITY_MAP[cap])
            if not ('i' in data.validity or
                'r' in data.validity or
                'e' in data.validity):
                if cap in ["s"]:
                    stats[GLEP_INDEX['sign_capable']] = True
                elif cap in ["e"]:
                    stats[GLEP_INDEX['encrypt_capable']] = True
                else:
                    self.logger.debug("ERROR in key %s : unknown gpg key capability: %s"
                        % (data.long_keyid, cap))
        stats[GLEP_INDEX['long_caps']] = ', '.join(kcaps)
        return stats


    def _test_uid(self, data, stats):
        if not self.check_id:
            stats[GLEP_INDEX['id']] = '-----'
            return stats
        if TEST_SPEC['qualified_id'] in data.user_ID :
            stats[GLEP_INDEX['id']] = True
        else:
            self.logger.debug("Warning: No qualified ID found in key %s"
                % (data.user_ID))
        return stats
