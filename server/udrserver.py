#!/usr/bin/env python

#   Copyright 2012 Laboratory for Advanced Computing at the University of Chicago
#
#   This file is part of UDR.
# 
#   Licensed under the Apache License, Version 2.0 (the "License"); 
#   you may not use this file except in compliance with the License. 
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software 
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT 
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the 
#   License for the specific language governing permissions and limitations 
#   under the License.

import os, re, sys, pwd, grp
import signal, optparse, subprocess, logging
import SocketServer
from daemon import Daemon

class UDRHandler(SocketServer.StreamRequestHandler):
    """
    Handler for incoming UDR connections, ignores the UDR command sent and builds it's own
    UDR command to run on the server based on the server's configuration.
    """
    def handle(self):
        logging.info('New connection from %s' % self.client_address[0])

        #depends on the udr cmd having a newline at the end
        #perhaps should add a timeout, or maybe none at all 
        line = self.rfile.readline().strip()

        if not line:
            logging.warning('Connection problem, did not receive udr command from client')
        else:
            udr_cmd = []
            udr_cmd.append(self.server.params['udr'])
            udr_cmd.append('-x')
            udr_cmd.append('--config')
            udr_cmd.append(self.server.params['rsyncd conf'])

            if self.server.params['verbose']:
                udr_cmd.append('-v')

            udr_cmd.append('-a')
            udr_cmd.append(self.server.params['start port'])
            udr_cmd.append('-b')
            udr_cmd.append(self.server.params['end port'])
            udr_cmd.append('-t')
            udr_cmd.append('rsync')

            logging.debug('UDR cmd: %s' % udr_cmd)

            try:
                signal.signal(signal.SIGCHLD,signal.SIG_IGN)
                udr_proc = subprocess.Popen(udr_cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE)
                firstline = udr_proc.stdout.readline()
                logging.debug('firstline: ' + firstline)
                logging.info('providing port %s for UDR to %s' % (firstline.split()[0], self.client_address[0]))
                self.wfile.write(firstline)

            except OSError, err:
                logging.critical('%s, cmd: %s, exiting.' % (' '.join(udr_cmd), err.strerror))
                sys.exit(1)

class UDRServer(Daemon, object):
    """
    Server daemon containing methods to handle the configuration, logging and setting uid/gid
    when appropriate
    """
    def __init__(self, configfile, verbose=False):
        self.params = {}
        self.params['verbose'] = verbose
        self.parse_global_conf(configfile)
        super(UDRServer, self).__init__(pidfile=self.params['pid file'], stdout=self.params['log file'], stderr=self.params['log file'])

    def run(self):
        self.set_uid_gid()
        self.config_logger()    
        SocketServer.TCPServer.allow_reuse_address = True
        server = SocketServer.TCPServer((self.params['address'], int(self.params['port'])), UDRHandler) 
        server.params = self.params
        logging.debug('params: %s' % str(self.params))
        logging.info('UDR server started on %s %s' % (self.params['address'], self.params['port']))
        server.serve_forever()

    def set_uid_gid(self):
        if 'gid' in self.params:
            if self.params['gid'].isdigit():
                os.setgid(int(self.params['gid']))
            else:
                gid = grp.getgrnam(self.params['gid']).gr_gid
                os.setgid(gid)
        else:
            if os.getegid() == 0:
                os.setgid(grp.getgrnam('nogroup').gr_gid)

        if 'uid' in self.params:
            if self.params['uid'].isdigit():
                os.setuid(int(self.params['uid']))
            else:
                uid = pwd.getpwnam(self.params['uid']).pw_uid
                os.setuid(uid)
        else:
            if os.geteuid() == 0:
                os.setuid(pwd.getpwnam('nobody').pw_uid)

    def read_lines(self, filename):
        linefile = open(filename)
        lines = []
        for line in linefile:
            line = line.strip()
            lines.append(line)
            if not line.endswith("\\"):
                yield "".join(lines)
                lines = []
        if len(lines) > 0:
            yield "".join(lines)

    def parse_global_conf(self, filename):
        self.params['udr'] = 'udr'
        self.params['start port'] = '9000'
        self.params['end port'] = '9100'
        self.params['address'] = '0.0.0.0'
        self.params['port'] = 9000
        self.params['rsyncd conf'] = '/etc/rsyncd.conf'
        self.params['pid file'] = '/var/run/udrd.pid'
        self.params['log file'] = ''.join([os.getcwd(), '/udr.log'])

        paren_re = re.compile(r'\[(\w+)\]')
        eq_re = re.compile(r'(.+)=(.+)')

        for line in self.read_lines(filename):
            line = line.strip()

            if line.startswith('#'):
                continue
            
            paren_result = paren_re.match(line)
            if paren_result is not None:
                curr_module = paren_result.group(1)
                break

            eq_result = eq_re.match(line)
            if eq_result is not None:
                key = eq_result.group(1).strip()
                value = eq_result.group(2).strip()
                self.params[key] = value

        #check that rsyncd.conf exists, otherwise rsync fails silently
        test_rsyncd = open(self.params['rsyncd conf'])
        test_rsyncd.close()

    def config_logger(self):
        logger = logging.getLogger()
        handler = logging.FileHandler(self.params['log file'])
        formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    
        if 'log level' in self.params:
            logger.setLevel(getattr(logging, self.params['log level'].upper()))
        else:
            logger.setLevel(logging.INFO)

def main():
    """
    Parses server options and start|stop|restart|foreground UDRServer daemon
    """
    parser = optparse.OptionParser()
    parser.add_option('-c', '--config', dest="config", help="UDR server config file")
    parser.add_option('-v', '--verbose', action="store_true", dest="verbose", default=False)
    (options, args) = parser.parse_args()

    if options.config:
        configfile = options.config
    else:
        configfile = '/etc/udrd.conf'

    daemon = UDRServer(configfile, options.verbose)

    if len(sys.argv) > 1:
        if 'start' == sys.argv[-1]:
            sys.stderr.write('Starting UDR server\n')
            daemon.start()
        elif 'stop' == sys.argv[-1]:
            sys.stderr.write('Stopping UDR server\n')
            daemon.stop()
        elif 'restart' == sys.argv[-1]:
            sys.stderr.write('Stopping UDR server\n')
            daemon.stop()
            sys.stderr.write('Starting UDR server\n')
            daemon.start()
        elif 'foreground' == sys.argv[-1]:
            daemon.run()
        else:
            print "usage: %s [options] start|stop|restart|foreground" % sys.argv[0]
            sys.exit(2)
        sys.exit(0)
    else:
        print "usage: %s [options] start|stop|restart|foreground" % sys.argv[0]
        sys.exit(2)

if __name__ == '__main__':
    main()
