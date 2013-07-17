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

from os.path import join as pjoin

from pyGPG.gpg import GPG
from gkeys.log import logger


class GkeysGPG(GPG):
    '''Gentoo-keys primary gpg class'''


    def __init__(self, config, keydir):
        '''class init function

        @param config: GKeysConfig config instance to use
        @param keydir: string, the path to the keydir to be used
                        for all operations.
        '''
        GPG.__init__(self, config)
        self.config = config
        self.basedir = keydir
        self.keydir = None
        self.task = None
        self.task_value = None


    def set_keypath(self, keyring, task=None):
        logger.debug("keydir: %s, keyring: %s" % (self.keydir, keyring))
        self.task = task
        keypath = pjoin(self.keydir, keyring)
        # --keyring file |  Note that this adds a keyring to the current list.
        # If the intent is to use the specified keyring alone,
        # use  --keyring  along with --no-default-keyring.
        self.task_value = ['--no-default-keyring', '--keyring', keypath]
        task.extend(self.task_value)
        return


    def reset_task(self):
        if self.task:
            for item in self.task_value:
                self.task.remove(item)
            self.task = None
            self.task_value = None


    def set_keydir(self, keydir):
        logger.debug("basedir: %s, keydir: %s" % (self.basedir, keydir))
        self.task = task
        self.keydir = pjoin(self.basedir, keydir)
        return


    def add_key(self, gkey):
        '''Add the specified key to the specified keydir

        @param gkey: GKEY namedtuple with
            (name, keyid/longkeyid, keydir, fingerprint,)
        '''
        self.set_keydir(gkey.keydir)

        # prefer the longkeyid if available
        #logger.debug("LIB: add_key; keyids %s, %s"
        #    % (str(gkey.longkeyid), str(gkey.keyid)))
        if gkey.longkeyid != []:
            keyids = gkey.longkeyid
        #    logger.debug("LIB: add_key; found gkey.longkeyid", keyids, type(gkey.longkeyid)
        elif gkey.keyid != []:
            keyids = gkey.keyid
        #    logger.debug("LIB: add_key; found gkey.keyid" + str(keyids))
        results = []
        for keyid in keyids:
            logger.debug("LIB: add_key; final keyids" + keyid)
            logger.debug("** Calling runGPG with Running 'gpg %s --recv-keys %s' for: %s"
                % (' '.join(self.config['tasks']['recv-keys']),
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
            print result.stderr_out
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

        self.set_keydir(keydir)
        logger.debug("** Calling runGPG with Running 'gpg %s --list-keys %s'"
            % (' '.join(self.config['tasks']['list-keys']), keydir)
            )
        result = self.runGPG(task='list-keys')
        logger.info('GPG return code: ' + str(result.returncode))
        #self.reset_task()
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

