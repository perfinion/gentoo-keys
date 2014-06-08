#
#-*- coding:utf-8 -*-

"""
    Gentoo-keys - cli.py

    Command line interface module

    @copyright: 2012 by Brian Dolbec <dol-sen@gentoo.org>
    @license: GNU GPL2, see COPYING for details.
"""

from __future__ import print_function


import argparse
import sys

from gkeys.log import log_levels, set_logger

from gkeys import config
from gkeys import seed
from gkeys import lib

from gkeys.config import GKeysConfig, GKEY
from gkeys.actions import Actions, Available_Actions



class Main(object):
    '''Main command line interface class'''


    def __init__(self, root=None, config=None, print_results=True):
        """ Main class init function.

        @param root: string, root path to use
        """
        self.root = root or "/"
        self.config = config or GKeysConfig(root=root)
        self.config.options['print_results'] = print_results
        self.args = None
        self.seeds = None
        self.actions = None


    def __call__(self, args=None):
        if args:
            self.run(self.parse_args(args))
        else:
            self.run(self.parse_args(sys.argv[1:]))


    def parse_args(self, args):
        '''Parse a list of aruments

        @param args: list
        @returns argparse.Namespace object
        '''
        #logger.debug('MAIN: parse_args; args: %s' % args)
        actions = Available_Actions
        parser = argparse.ArgumentParser(
            prog='gkeys',
            description='Gentoo-keys manager program',
            epilog='''Caution: adding untrusted keys to these keyrings can
                be hazardous to your system!''')
        # actions
        parser.add_argument('action', choices=actions, nargs='?',
            default='listseeds', help='List the seeds in the file')
        # options
        parser.add_argument('-c', '--config', dest='config', default=None,
            help='The path to an alternate config file')
        parser.add_argument('-d', '--dest', dest='destination', default=None,
            help='The destination seed file or keydir for move, copy operations')
        parser.add_argument('-f', '--fingerprint', dest='fingerprint', default=None,
            help='The fingerprint of the the key')
        parser.add_argument('-N', '--name', dest='name', default=None,
            help='The name of the the key')
        parser.add_argument('-n', '--nick', dest='nick', default=None,
            help='The nick associated with the the key')
        parser.add_argument('-k', '--keyid', dest='keyid', default=None,
            help='The keyid of the the key')
        parser.add_argument('-l', '--longkeyid', dest='longkeyid', default=None,
            help='The longkeyid of the the key')
        parser.add_argument('-r', '--keydir',
            choices=['release', 'dev', 'overlays'], dest='keydir', default=None,
            help='The keydir to use or update')
        parser.add_argument('-s', '--seeds',
            choices=['release', 'dev'], dest='seeds', default=None,
            help='The seeds file to use or update')
        parser.add_argument('-S', '--seedfile', dest='seedfile', default=None,
            help='The seedfile path to use')
        parser.add_argument('-D', '--debug', default='DEBUG',
            choices=list(log_levels),
            help='The logging level to set for the logfile')

        return parser.parse_args(args)


    def run(self, args):
        '''Run the args passed in

        @param args: list or argparse.Namespace object
        '''
        global logger
        message = None
        if not args:
            message = "Main: run; invalid args argument passed in"
        if isinstance(args, list):
            args = self.parse_args(args)
        if args.config:
            self.config.defaults['config'] = args.config
        # now make it load the config file
        self.config.read_config()

        # establish our logger and update it in the imported files
        logger = set_logger('gkeys', self.config['logdir'], args.debug)
        config.logger = logger
        seed.logger = logger
        lib.logger = logger

        if message:
            logger.error(message)

        # now that we have a logger, record the alternate config setting
        if args.config:
            logger.debug("Main: run; Found alternate config request: %s"
                % args.config)

        # establish our actions instance
        self.actions = Actions(self.config, self.output_results, logger)

        # run the action
        func = getattr(self.actions, '%s' % args.action)
        logger.debug('Main: run; Found action: %s' % args.action)
        results = func(args)
        if not results:
            print("No results found.  Check your configuration and that the",
                "seed file exists.")
            return
        if self.config.options['print_results'] and 'done' not in list(results):
            self.output_results(results, '\n Gkey task results:')
            print()


    @staticmethod
    def output_results(results, header):
        # super simple output for the time being
        print(header)
        for msg in results:
            if isinstance(msg, str):
                print(msg)
            elif isinstance(msg, list):
                if isinstance(msg[0], GKEY):
                    print("\n".join([x.pretty_print for x in msg]))
                else:
                    print("\n".join(msg))
        print()



    def output_failed(self, failed):
        pass
