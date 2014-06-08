#
#-*- coding:utf-8 -*-

'''Gentoo-keys - lib.py
This is gentoo-keys superclass which wraps the pyGPG lib
with gentoo-keys specific convienience functions.

 Distributed under the terms of the GNU General Public License v2

 Copyright:
             (c) 2011 Brian Dolbec
             Distributed under the terms of the GNU General Public License v2

 Author(s):
             Brian Dolbec <dolsen@gentoo.org>

'''

# for py 2.6 compatibility
from __future__ import print_function


import os
from os.path import join as pjoin

from pyGPG.gpg import GPG
from gkeys.log import logger
from gkeys.seed import Seeds


class GkeysGPG(GPG):
    '''Gentoo-keys primary gpg class'''


    def __init__(self, config, keydir):
        '''class init function

        @param config: GKeysConfig config instance to use
        @param keydir: string, the path to the keydir to be used
                        for all operations.
        '''
        GPG.__init__(self, config, logger)
        self.config = config
        self.basedir = keydir
        self.keydir = None
        self.server = None


    def set_keyserver(self, server=None):
        '''Set the keyserver and add the --keyserver option to the gpg defaults
        '''
        if self.server and not server:
            return
        self.server = server or self.config['keyserver']
        self.config.options['gpg_defaults'] = self.config.defaults['gpg_defaults'][:]
        logger.debug("keyserver: %s" % (self.server))
        server_value = ['--keyserver', self.server]
        self.config.options['gpg_defaults'].extend(server_value)
        logger.debug("self.config.options['gpg_defaults']: %s"
            % (self.config.options['gpg_defaults']))
        return


    def set_keyring(self, keyring, task, reset=True):
        '''Sets the keyring to use as well as related task options
        '''
        logger.debug("keydir: %s, keyring: %s" % (self.keydir, keyring))
        if reset:
            self.config.options['tasks'][task] =  self.config.defaults['tasks'][task][:]
        # --keyring file |  Note that this adds a keyring to the current list.
        # If the intent is to use the specified keyring alone,
        # use  --keyring  along with --no-default-keyring.
        task_value = ['--no-default-keyring', '--keyring', keyring]
        self.config.options['tasks'][task].extend(task_value)
        logger.debug("set_keyring: New task options: %s" %str(self.config.options['tasks'][task]))
        return


    def set_keydir(self, keydir, task, reset=True):
        logger.debug("basedir: %s, keydir: %s" % (self.basedir, keydir))
        self.keydir = pjoin(self.basedir, keydir[0])
        self.task = task
        if reset:
            self.config.options['tasks'][task] = self.config.defaults['tasks'][task][:]
        task_value = ['--homedir', self.keydir]
        self.config.options['tasks'][task].extend(task_value)
        logger.debug("set_keydir: New task options: %s" %str(self.config.options['tasks'][task]))
        return


    def add_key(self, gkey):
        '''Add the specified key to the specified keydir

        @param gkey: GKEY namedtuple with
            (name, keyid/longkeyid, keydir, fingerprint,)
        '''
        self.set_keyserver()
        self.set_keydir(gkey.keydir, 'recv-keys', reset=True)
        self.set_keyring('pubring.gpg', 'recv-keys', reset=False)
        # Save the gkey seed to the installed db
        self.seedfile = Seeds(pjoin(self.keydir, 'gkey.seeds'))
        self.seedfile.add(gkey.nick[0], gkey)
        if not self.seedfile.save():
            logger.debug("LIB: add_key; fsailed to save seed" + gkey.nick)
            return []
        if not os.path.exists(self.keydir):
            os.makedirs(self.keydir, mode=0x0700)
        keyids = gkey.keyid
        results = []
        print(self.config['tasks']['recv-keys'])
        for keyid in keyids:
            logger.debug("LIB: add_key; final keyids" + keyid)
            logger.debug("** Calling runGPG with Running 'gpg %s --recv-keys %s' for: %s"
                % (' '.join(self.config.get_key('tasks', 'recv-keys')),
                    keyid, gkey.name)
                )
            result = self.runGPG(task='recv-keys', inputfile=keyid)
            logger.info('GPG return code: ' + str(result.returncode))
            if result.fingerprint in gkey.fingerprint:
                result.failed = False
                message = "Fingerprints match... Import successful: "
                message += "key: %s" %keyid
                message += "\n    result len: %s, %s" %(len(result.fingerprint), result.fingerprint)
                message += "\n    gkey len: %s, %s" %(len(gkey.fingerprint[0]), gkey.fingerprint[0])
                logger.info(message)
            else:
                result.failed = True
                message = "Fingerprints do not match... Import failed for "
                message += "key: %s" %keyid
                message += "\n     result:   %s" %(result.fingerprint)
                message += "\n     gkey..: %s" %(str(gkey.fingerprint))
                logger.error(message)
            results.append(result)
            print(result.stderr_out)
        return results


    def del_key(self, gkey, keydir):
        '''Delete the specified key in the specified keydir

        @param gkey: GKEY namedtuple with (name, keyid/longkeyid, fingerprint)
        '''
        return []


    def del_keydir(self, keydir):
        '''Delete the specified keydir
        '''
        return []


    def update_key(self, gkey, keydir):
        '''Update the specified key in the specified keydir

        @param key: tuple of (name, keyid, fingerprint)
        @param keydir: the keydir to add the key to
        '''
        return []


    def list_keys(self, keydir):
        '''List all keys in the specified keydir or
        all keys in all keydir if keydir=None

        @param keydir: the keydir to list the keys for
        '''
        if not keydir:
            logger.debug("LIB: list_keys(), invalid keydir parameter: %s"
                % str(keydir))
            return []
        if '--with-colons' in self.config['tasks']['list-keys']:
            self.config['tasks']['list-keys'].remove('--with-colons')

        self.set_keydir(keydir, 'list-keys')
        logger.debug("** Calling runGPG with Running 'gpg %s --list-keys %s'"
            % (' '.join(self.config['tasks']['list-keys']), keydir)
            )
        result = self.runGPG(task='list-keys', inputfile=keydir)
        logger.info('GPG return code: ' + str(result.returncode))
        return result


    def list_keydirs(self):
        '''List all available keydirs
        '''
        return []


    def verify_key(self, gkey):
        '''verify the specified key from the specified keydir

        @param gkey: GKEY namedtuple with (name, keyid/longkeyid, fingerprint)
        '''
        pass


    def verify_text(self, text):
        '''Verify a text block in memory
        '''
        pass


    def verify_file(self, filepath):
        '''Verify the file specified at filepath
        '''
        pass

