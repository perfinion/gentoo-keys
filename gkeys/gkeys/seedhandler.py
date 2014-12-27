#
#-*- coding:utf-8 -*-

"""
    Gentoo-keys - seedhandler.py

    Seed handling interface module

    @copyright: 2012 by Brian Dolbec <dol-sen@gentoo.org>
    @license: GNU GPL2, see COPYING for details.
"""

import os
import re
from json import load

from gkeys.config import GKEY
from gkeys.seed import Seeds
from gkeys.fileops import ensure_dirs


class SeedHandler(object):

    def __init__(self, logger, config):
        self.config = config
        self.logger = logger
        self.fingerprint_re = re.compile('[0-9A-Fa-f]{40}')
        self.finerprint_re2 = re.compile('[0-9A-Fa-f]{4}( [0-9A-Fa-f]{4}){9}')
        self.seeds = None


    def new(self, args, checkgkey=False):
        newgkey = self.build_gkeydict(args)
        if checkgkey:
            newgkey, is_good = self.check_gkey(newgkey)
            if is_good:
                newgkey = GKEY(**newgkey)
                self.logger.debug("SeedHandler: new; new gkey: %s" % str(newgkey))
            else:
                return None
        else:
            newgkey = GKEY(**newgkey)
            self.logger.debug("SeedHandler: new; NON-checked new gkey: %s" % str(newgkey))
        return newgkey


    @staticmethod
    def build_gkeydict(args):
        keyinfo = {}
        for attr in GKEY._fields + ('keyid',):
            try:
                value = getattr(args, attr)
                if attr == 'name' and value:
                    value = " ".join(value)
                if value:
                    keyinfo[attr] = value
            except AttributeError:
                pass
        return keyinfo

    def load_seeds(self, seedfile=None, filepath=None):
        '''Load seed file

        @param seeds: string of the short name seed file
        @param seedfile: string filepath of the file to load
        @return Seeds class instance of the file loaded
        '''
        if not seedfile and not filepath:
            self.logger.error("SeedHandler: load_seeds; no filename to load: "
            "setting = %s.  Please use the -S or -F option to indicate: which seed "
            "file to use." % seedfile)
            return False
        if seedfile:
            filepath = self.config.get_key('seeds', seedfile)
        elif not filepath:
            self.logger.error("SeedHandler: load_seeds; No filepath to load")
        self.logger.debug("SeedHandler: load_seeds; seeds filepath to load: "
            "%s" % filepath)
        seeds = Seeds(config=self.config)
        seeds.load(filepath)
        self.seeds = seeds
        return seeds

    def load_category(self, category, nicks=None):
        '''Loads the designated key directories

        @param category: string
        @param nicks: list of string nick ids to load
        @return Seeds class object
        '''
        seeds = Seeds(config=self.config)
        if category == 'sign':
            catdir = self.config.get_key('sign-keydir')
        else:
            keyrings = self.config.get_key('keyring')
            catdir = os.path.join(keyrings, category)
        self.logger.debug("SeedHandler: load_category; catdir = %s" % catdir)
        try:
            if not nicks:
                nicks = os.listdir(catdir)
            for nick in nicks:
                seed_path = os.path.join(catdir, nick)
                gkey_path = os.path.join(seed_path, 'gkey.seeds')
                seed = None
                try:
                    with open(gkey_path, 'r') as fileseed:
                        seed = load(fileseed)
                except IOError as error:
                    self.logger.debug("SeedHandler: load_category; IOError loading seed file %s." % gkey_path)
                    self.logger.debug("Error was: %s" % str(error))
                if seed:
                    for nick in sorted(seed):
                        key = seed[nick]
                        seeds.add(nick, GKEY(**key))
        except OSError as error:
            self.logger.debug("SeedHandler: load_category; OSError for %s" % catdir)
            self.logger.debug("Error was: %s" % str(error))
        self.seeds = seeds
        return seeds

    def fetch_seeds(self, seeds, args, verified_dl=None):
        '''Fetch new seed files

        @param seeds: list of seed nicks to download
        @param verified_dl: Function pointer to the Actions.verify()
                instance needed to do the download and verification
        '''
        http_check = re.compile(r'^(http|https)://')
        urls = []
        messages = []
        try:
            for seed in [seeds]:
                seedurl = self.config.get_key('seedurls', seed)
                seedpath = self.config.get_key('seeds', seed)
                if http_check.match(seedurl):
                    urls.extend([(seed, seedurl, seedpath)])
                else:
                    self.logger.info("Wrong seed file URLs... Skipping: %s" % seed)
        except KeyError:
            pass
        succeeded = []
        seedsdir = self.config.get_key('seedsdir')
        mode = int(self.config.get_key('permissions', 'directories'),0)
        ensure_dirs(seedsdir, mode=mode)
        for (seed, url, filepath) in urls:
            verify_info = self.config.get_key('verify-seeds', seed).split()
            args.category = verify_info[0]
            args.nick = verify_info[1]
            args.filename = url
            args.signature = None
            args.timestamp = True
            args.destination = filepath
            verified, messages_ = verified_dl(args)
            succeeded.append(verified)
            messages.append(messages_)
        return (succeeded, messages)

    def check_gkey(self, args):
        # assume it's good until an error is found
        is_good = True
        try:
            args['keydir'] = args.get('keydir', args['nick'])
            fprs = []
            if args['fingerprint']:
                for fpr in args['fingerprint']:
                    is_good, fingerprint = self._check_fingerprint_integrity(fpr)
                    if is_good:
                        fprs.append(fingerprint)
                    else:
                        self.logger.error('Bad fingerprint from command line args: %s' % fpr)
                if is_good:
                    args['fingerprint'] = fprs
        except KeyError:
            self.logger.error('GPG fingerprint not found.')
            is_good = False
        if not is_good:
            self.logger.error('A valid fingerprint '
                  'was not found for %s' % args['name'])
        return args, is_good

    def _check_fingerprint_integrity(self, fpr):
        # assume it's good unti an error is found
        is_good = True
        fingerprint = fpr.replace(" ", "")
        # check fingerprint integrity
        if len(fingerprint) != 40:
            self.logger.error('  GPGKey incorrect fingerprint ' +
                    'length (%s) for fingerprint: %s' % (len(fingerprint), fingerprint))
            is_good = False
        if not self.fingerprint_re.match(fingerprint):
            self.logger.error('  GPGKey: Non hexadecimal digits in ' + 'fingerprint for fingerprint: ' + fingerprint)
            is_good = False
        return is_good, fingerprint

    def key_search(self, args, search_args):
        '''Performs a search for all listed args in the seeds'''
        results = []
        self.logger.debug("_field_search search_args: %s" % str(search_args))
        found = {}
        search_args.sort()
        for arg in search_args:
            seeds = self.seeds.field_search(arg, getattr(args, arg), args.exact)
            for seed in seeds:
                if seed.nick in found:
                    found[seed.nick]['args'].append(arg)
                else:
                    found[seed.nick] = {'args': [arg], 'seed': seed}
        if args.all:
            for possible in sorted(found):
                if search_args == found[possible]['args']:
                    results.append(found[possible]['seed'])
        else:
            for nick in sorted(found):
                results.append(found[nick]['seed'])
        return results
