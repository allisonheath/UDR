#!/usr/bin/env python
import os, re, sys, pwd, grp
import optparse, subprocess, logging
import SocketServer
from daemon import Daemon

class UDRHandler(SocketServer.StreamRequestHandler):
    def handle(self):
        logging.info('New connection from %s' % self.client_address[0])

        #depends on the udr cmd having a newline at the end -- perhaps should add a timeout, or maybe none at all 
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
                p = subprocess.Popen(udr_cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE)
                firstline = p.stdout.readline()
                logging.debug('firstline: ' + firstline)
                logging.info('providing port %s for UDR to %s' % (firstline.split()[0], self.client_address[0]))
                self.wfile.write(firstline)

            except OSError, e:
                logging.critical('%s, cmd: %s, exiting.' % (' '.join(udr_cmd), e.strerror))
                sys.exit(1)

class UDRServer(Daemon, object):
    def __init__(self, configfile, verbose):
        self.params = {}
        self.parse_global_conf(configfile)
        super(UDRServer, self).__init__(pidfile=self.params['pid file'], stdout=self.params['log file'], stderr=self.params['log file'])

    def run(self):
        if 'gid' in self.params:
            gid = grp.getgrnam(self.params['gid']).gr_gid
            os.setgid(gid)
        if 'uid' in self.params:
            uid = pwd.getpwnam(self.params['uid']).pw_uid
            os.setuid(uid)
        
        self.config_logger()    
        SocketServer.TCPServer.allow_reuse_address = True
        server = SocketServer.TCPServer((self.params['address'], int(self.params['port'])), UDRHandler) 
        server.params = self.params
        logging.debug('params: %s' % str(self.params))
        logging.info('UDR server started on %s %s' % (self.params['address'], self.params['port']))
        server.serve_forever()


    def read_lines(self, filename):
        file = open(filename)
        lines = []
        for line in file:
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
        self.params['verbose'] = False
        self.params['pid file'] = '/var/run/udrd.pid'
        self.params['log file'] = '/dev/null'

        curr_module = None
        paren_re = re.compile('\[(\w+)\]')
        eq_re = re.compile('(.+)=(.+)')

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

        if self.params['log file']:
            handler = logging.FileHandler(self.params['log file'])
        else:
            handler = logging.SteamHandler()

        formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    
        if self.params['log level']:
            logger.setLevel(getattr(logging, self.params['log level'].upper()))

if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option('-c', '--config', dest="config", help="UDR server config file")
    (options, args) = parser.parse_args()

    if options.config:
        configfile = options.config
    else:
        configfile = '/etc/udrd.conf'

    daemon = UDRServer(configfile, True)

    if len(sys.argv) > 1:
        if 'start' == sys.argv[-1]:
            daemon.start()
        elif 'stop' == sys.argv[-1]:
            daemon.stop()
        elif 'restart' == sys.argv[-1]:
            daemon.restart()
        elif 'foreground' == sys.argv[-1]:
            daemon.run()
        else:
            print "Unknown command"
            sys.exit(2)
        sys.exit(0)
    else:
        print "usage: %s start|stop|restart" % sys.argv[0]
        sys.exit(2)
        