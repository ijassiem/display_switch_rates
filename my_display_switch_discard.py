#!/usr/bin/python
'''
This class allows you to run commands on a remote host and provide
input if necessary.

VERSION 1.2
'''
import paramiko
import logging
import socket
import time
import datetime
import re
import IPython


# ================================================================
# class MySSH
# ================================================================
class MySSH:
    '''
    Create an SSH connection to a server and execute commands.
    Here is a typical usage:

        ssh = MySSH()
        ssh.connect('host', 'user', 'password', port=22)
        if ssh.connected() is False:
            sys.exit('Connection failed')

        # Run a command that does not require input.
        status, output = ssh.run('uname -a')
        print 'status = %d' % (status)
        print 'output (%d):' % (len(output))
        print '%s' % (output)

        # Run a command that does requires input.
        status, output = ssh.run('sudo uname -a', 'sudo-password')
        print 'status = %d' % (status)
        print 'output (%d):' % (len(output))
        print '%s' % (output)
    '''

    def __init__(self, logger, compress=True):
        '''
        @param compress  Enable/disable compression.
        '''
        self.ssh = None
        self.transport = None
        self.compress = compress
        self.bufsize = 65536

        self.info = logger.info
        self.debug = logger.debug
        self.error = logger.error

    def __del__(self):
        if self.transport is not None:
            self.transport.close()
            self.transport = None

    def connect(self, hostname, username, password, port=22):
        '''
        Connect to the host.

        @param hostname  The hostname.
        @param username  The username.
        @param password  The password.
        @param port      The port (default=22).

        @returns True if the connection succeeded or false otherwise.
        '''
        self.debug('connecting %s@%s:%d' % (username, hostname, port))
        self.hostname = hostname
        self.username = username
        self.port = port
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.ssh.connect(hostname=hostname,
                             port=port,
                             username=username,
                             password=password)
            self.transport = self.ssh.get_transport()
            self.transport.use_compression(self.compress)
            self.info('succeeded: %s@%s:%d' % (username,
                                               hostname,
                                               port))
        except socket.error as e:
            self.transport = None
            self.error('failed: %s@%s:%d: %s' % (username,
                                                 hostname,
                                                 port,
                                                 str(e)))
        except paramiko.BadAuthenticationType as e:
            self.transport = None
            self.error('failed: %s@%s:%d: %s' % (username,
                                                 hostname,
                                                 port,
                                                 str(e)))

        return self.transport is not None

    def run(self, cmd, input_data=' ', timeout=10):
        '''
        Run a command with optional input data.

        Here is an example that shows how to run commands with no input:

            ssh = MySSH()
            ssh.connect('host', 'user', 'password')
            status, output = ssh.run('uname -a')
            status, output = ssh.run('uptime')

        Here is an example that shows how to run commands that require input:

            ssh = MySSH()
            ssh.connect('host', 'user', 'password')
            status, output = ssh.run('sudo uname -a', '<sudo-password>')

        @param cmd         The command to run.
        @param input_data  The input data (default is None).
        @param timeout     The timeout in seconds (default is 10 seconds).
        @returns The status and the output (stdout and stderr combined).
        '''
        self.debug('running command: (%d) %s' % (timeout, cmd))

        if self.transport is None:
            self.error('no connection to %s@%s:%s' % (str(self.username),
                                                      str(self.hostname),
                                                      str(self.port)))
            return -1, 'ERROR: connection not established\n'

        # Fix the input data.
        input_data = self._run_fix_input_data(input_data)

        # Initialize the session.
        self.debug('initializing the session')
        session = self.transport.open_session()
        session.set_combine_stderr(True)
        session.get_pty()  # height=1000)
        # session.exec_command(cmd)
        session.invoke_shell()
        session.send(cmd)
        session.send('\n')
        output, status = self._run_poll(session, timeout, input_data)
        # status = session.recv_exit_status()
        self.debug('output size %d' % (len(output)))
        self.debug('status %d' % (status))
        return status, output

    def connected(self):
        '''
        Am I connected to a host?

        @returns True if connected or false otherwise.
        '''
        return self.transport is not None

    def _run_fix_input_data(self, input_data):
        '''
        Fix the input data supplied by the user for a command.

        @param input_data  The input data (default is None).
        @returns the fixed input data.
        '''
        if input_data is not None:
            if len(input_data) > 0:
                if '\\n' in input_data:
                    # Convert \n in the input into new lines.
                    lines = input_data.split('\\n')
                    input_data = '\n'.join(lines)
            return input_data.split('\n')
        return []

    def _run_send_input(self, session, stdin, input_data):
        '''
        Send the input data.

        @param session     The session.
        @param stdin       The stdin stream for the session.
        @param input_data  The input data (default is None).
        '''
        if input_data is not None:
            # self.info('session.exit_status_ready() %s' % str(session.exit_status_ready()))
            self.error('stdin.channel.closed %s' % str(stdin.channel.closed))
            if stdin.channel.closed is False:
                self.debug('sending input data')
                stdin.write(input_data)

    def _run_poll(self, session, timeout, input_data, prompt=[' > ', ' # ']):
        '''
        Poll until the command completes.

        @param session     The session.
        @param timeout     The timeout in seconds.
        @param input_data  The input data.
        @returns the output
        '''

        def check_for_prompt(output, prompt):
            for prmt in prompt:
                # Only check last 3 characters in return string
                if output[-3:].find(prmt) > -1:
                    return True
            return False

        interval = 0.1
        maxseconds = timeout
        maxcount = maxseconds / interval

        # Poll until completion or timeout
        # Note that we cannot directly use the stdout file descriptor
        # because it stalls at 64K bytes (65536).
        input_idx = 0
        timeout_flag = False
        self.debug('polling (%d, %d)' % (maxseconds, maxcount))
        start = datetime.datetime.now()
        start_secs = time.mktime(start.timetuple())
        output = ''
        session.setblocking(0)
        status = -1
        while True:
            if session.recv_ready():
                data = session.recv(self.bufsize)
                self.debug(repr(data))
                output += data
                self.debug('read %d bytes, total %d' % (len(data), len(output)))

                if session.send_ready():
                    # We received a potential prompt.
                    # In the future this could be made to work more like
                    # pexpect with pattern matching.

                    # If 'lines 1-45' found in ouput, send space to the pty
                    # to trigger the next page of output. This is needed if
                    # more that 24 lines are sent (default pty height)
                    pattern = re.compile('lines \d+-\d+')

                    if re.search(pattern, output):
                        session.send(' ')
                    elif input_idx < len(input_data):
                        data = input_data[input_idx] + '\n'
                        input_idx += 1
                        self.debug('sending input data %d' % (len(data)))
                        session.send(data)

            # exit_status_ready signal not sent when using 'invoke_shell'
            # self.info('session.exit_status_ready() = %s' % (str(session.exit_status_ready())))
            # if session.exit_status_ready():
            if check_for_prompt(output, prompt) == True:
                status = 0
                break

            # Timeout check
            now = datetime.datetime.now()
            now_secs = time.mktime(now.timetuple())
            et_secs = now_secs - start_secs
            self.debug('timeout check %d %d' % (et_secs, maxseconds))
            if et_secs > maxseconds:
                self.debug('polling finished - timeout')
                timeout_flag = True
                break
            time.sleep(0.200)

        self.debug('polling loop ended')
        if session.recv_ready():
            data = session.recv(self.bufsize)
            output += data
            self.debug('read %d bytes, total %d' % (len(data), len(output)))

        self.debug('polling finished - %d output bytes' % (len(output)))
        if timeout_flag:
            self.debug('appending timeout message')
            output += '\nERROR: timeout after %d seconds\n' % (timeout)
            session.close()

        return output, status


# ================================================================
# MAIN
# ================================================================
if __name__ == '__main__':
    import sys, os, re, string, curses
    from optparse import OptionParser
    import ConfigParser
    from multiprocessing.pool import ThreadPool
    from collections import defaultdict

    desc = """This programs connects to Mellanox switches via SSH and maps connections
              between switches and hosts using LLDP. Switch rates are read and displayed
              in a matrix. 
              Press 'c' to clear counters. (must enable admin mode) 
              Press ctrl-c to exit program.
           """
    parser = OptionParser(description=desc)
    parser.set_usage('%prog [options]')
    parser.add_option('-l', dest='loglevel', type=str, default='INFO',
                      help='Log level: DEBUG,INFO,ERROR,WARINING,FATAL. Default = INFO')
    parser.add_option('-a', '--maxleaves', type=int, default=36,
                      help='Number of leaf switches in the system.')
    parser.add_option('-p', '--maxspines', type=int, default=18,
                      help='Number of spine switches in the system.')
    parser.add_option('-n', '--numsw', type=int, default=28,
                      help='Number of switches to process.')
    parser.add_option('-t', '--startswitch', type=int, default=1,
                      help='Start displaying from specified switch.')
    parser.add_option('-d', '--display', type=str, default='leaves',  # changed from spines to leaves ^
                      help='Display spines or leaves.')
    parser.add_option('-m', '--admin', action='store_true',
                      help='Connect to switches using admin account')
    opts, args = parser.parse_args()

    # Setup the logger
    loglevel = opts.loglevel
    logger = logging.getLogger('mellanox_switch_comms')
    level = logging.getLevelName(loglevel)
    logger.setLevel(level)
    # fmt = '%(asctime)s %(funcName)s:%(lineno)d %(message)s'
    fmt = '%(asctime)s %(levelname)s: %(message)s'
    date_fmt = '%Y-%m-%d %H:%M:%S'
    logging_format = logging.Formatter(fmt, date_fmt)
    handler = logging.StreamHandler()
    handler.setFormatter(logging_format)
    handler.setLevel(level)
    logger.addHandler(handler)

    port = 22
    if opts.admin:
        username = 'admin'
        password = 'admin'
    else:
        username = 'monitor'
        password = 'monitor'
    sudo_password = password  # assume that it is the same password
    hosts = []
    strsw = opts.startswitch
    numsw = opts.numsw
    mspines = opts.maxspines
    mleaves = opts.maxleaves
    if opts.display == 'spines':
        if strsw + numsw > mspines + 1:
            rng = mspines + 1
        else:
            rng = strsw + numsw

        for i in range(strsw, rng):
            hosts.append('cbfsw-s{}.cbf.mkat.karoo.kat.ac.za'.format(i))
    else:
        if strsw + numsw > mleaves + 1:
            rng = mleaves + 1
        else:
            rng = strsw + numsw
        for i in range(strsw, rng):
            hosts.append('cbfsw-l{}.cbf.mkat.karoo.kat.ac.za'.format(i))


    def ssh_conn(hostname):
        ssh = MySSH(logger)
        ssh.connect(hostname=hostname,
                    username=username,
                    password=password,
                    port=port)
        if ssh.connected() is False:
            logger.error('Connection failed.')
            return hostname
        return ssh


    def rem_extra_chars(in_str):
        pat = re.compile('lines \d+-\d+ ')
        in_str = re.sub(pat, '', in_str)
        pat = re.compile('lines \d+-\d+\/\d+ \(END\) ')
        in_str = re.sub(pat, '', in_str)
        return in_str.replace('\r', '')


    def run_cmd(ssh_obj, cmd, indata=None, enable=False):
        '''
        Run a command with optional input.

        @param cmd    The command to execute.
        @param indata The input data.
        @returns The command exit status and output.
                 Stdout and stderr are combined.
        '''
        prn_cmd = cmd
        cmd = 'terminal type dumb\n' + cmd
        if enable:
            cmd = 'enable\n' + cmd

        output = ''
        output += ('\n' + '=' * 64 + '\n')
        output += ('host    : ' + ssh_obj.hostname + '\n')
        output += ('command : ' + prn_cmd + '\n')
        status, outp = ssh_obj.run(cmd, indata, timeout=30)
        output += ('status  : %d' % (status) + '\n')
        output += ('output  : %d bytes' % (len(output)) + '\n')
        output += ('=' * 64 + '\n')
        outp = rem_extra_chars(outp)
        output += outp
        return output


    def run_threaded_cmd(ssh_list, cmd, enable=False):
        '''
        Run threaded command on all clients in ssh_list
        '''
        thread_obj = [0] * len(ssh_list)  # create list of zeros with length same as ssh_list
        pool = ThreadPool(processes=len(ssh_list))
        output = []
        for i, ssh_obj in enumerate(ssh_list):  # execute each thread
            thread_obj[i] = pool.apply_async(run_cmd, args=(ssh_obj, cmd), kwds={'enable': enable})
        for i, ssh_obj in enumerate(ssh_list):  # retrieve/get data from each thread
            output.append(thread_obj[i].get())
        pool.close()
        pool.join()
        return [x.split('\n') for x in
                output]  # list comprehension splits string into multiple strings at '\n', and stores in list


    def close_ssh(ssh_list):
        thread_obj = [0] * len(ssh_list)
        pool = ThreadPool(processes=len(ssh_list))
        logger.info('Closing SSH connections')
        for i, ssh_obj in enumerate(ssh_list):
            thread_obj[i] = pool.apply_async(ssh_obj.ssh.close)
        for i, ssh_obj in enumerate(ssh_list):
            thread_obj[i].get()
        pool.close()
        pool.join()


    # Natural sort
    def atoi(text):
        return int(text) if text.isdigit() else text


    def natural_keys(text):
        '''
        alist.sort(key=natural_keys) sorts in human order
        last element in return value is empty string if last value in string is a digit
        '''
        value = [atoi(c) for c in re.split('(\d+)', text)]
        return value


    def get_discard(switch_dict, ssh_list):
        # Get switch discard:
        cmd = 'show interface ethernet | include "Rx|Tx|Eth|discard packets|bytes/sec|error packets"'
        #cmd = 'show interface ethernet'
        all_output = run_threaded_cmd(ssh_list, cmd)
        good_output = False
        timeout = 5
        while not good_output and timeout > 0:
            try:
                for output in all_output:
                    sw_name_idx = [i for i, s in enumerate(output) if 'CBFSW' in s][0]  # [0] is index of desired element in list comprehension. sw_name_idx is index of element containing CBFSW
                    sw_name = output[sw_name_idx].split(' ')[0].split('-')[-1]  # extracts eg. L28 from string: CBFSW-L28 [standalone: master] > terminal type dumb'
                    for i, line in enumerate(output):
                        if line.startswith('Eth1'):
                            eth = line  # extracts Eth1/36 from output
                        if line.startswith('  60 seconds ingress'):
                            in_rate = line.split(',')[1] # splits into list'  60 seconds ingress rate: 24864 bits/sec, 3108 bytes/sec, 9 packets/sec'
                            in_rate = [int(i) for i in in_rate.split() if i.isdigit()][0] # extract digits, stored as long integer
                        if line.startswith('  60 seconds egress'):
                            egr_rate = line.split(',')[1]  # splits into list'  60 seconds egress rate: 24864 bits/sec, 3108 bytes/sec, 9 packets/sec'
                            egr_rate = [int(i) for i in egr_rate.split() if i.isdigit()][0]  # extract digits, stored as long integer
                        if line.startswith('Rx'):
                            rx_err = output[i + 1].split(
                                ' ')  # element after 'Rx'. split string at '' and adds remaining strings to list
                            rx_err = [x for x in rx_err if x != '']  # creates list removing all spaces'' in list
                            rx_err = int(rx_err[0])  # cast string of digits to int
                            ####
                            rx_disc = output[i + 2].split(
                                ' ')  # element after 'Rx'. split string at '' and adds remaining strings to list
                            rx_disc = [x for x in rx_disc if x != '']  # creates list removing all spaces'' in list
                            rx_disc = int(rx_disc[0])  # cast string of digits to int (value of rx discards)
                        if line.startswith('Tx'):
                            tx_err = output[i + 1].split(
                                ' ')  # element after 'Tx'. split string at '' and adds remaining strings to list
                            tx_err = [x for x in tx_err if x != '']  # creates list removing all spaces'' in list
                            tx_err = int(tx_err[0])  # cast string of digits to int
                            ####
                            tx_disc = output[i + 2].split(
                                ' ')  # element after 'Tx'. split string at '' and adds remaining strings to list
                            tx_disc = [x for x in tx_disc if x != '']  # creates list removing all spaces'' in list
                            tx_disc = int(tx_disc[0])  # cast string of digits to int (value of tx discards)
                            switch_dict[sw_name][eth]['rx_discard'] = rx_disc
                            switch_dict[sw_name][eth]['tx_discard'] = tx_disc
                            switch_dict[sw_name][eth]['ingress_rate'] = in_rate
                            switch_dict[sw_name][eth]['egress_rate'] = egr_rate
                            switch_dict[sw_name][eth]['rx_err'] = rx_err
                            switch_dict[sw_name][eth]['tx_err'] = tx_err
                            # switch_dict['L9']['Eth1/1']   3128

                good_output = True
            except (ValueError, IndexError):
                timeout -= 1

        if timeout == 0:
            logger.debug('Rx or tx rates not a number, unexpected output from switch: {}'.format(output[i + 1]))

        # Create rates matrix
        #IPython.embed()
        cols = len(switch_dict.keys()) + 1  # length or number of elements in dictionary

        if opts.display == 'spines':
            lines = mleaves * 2 + 1 #  max 36 leaves, *2 for tx and rx
        else:
            # Find how many ethernet ports there are on the leaves
            port_list = []
            lines = 0
            for k, v in switch_dict.iteritems():  # same as .items(), display keys and values
                for port in v.keys():  # port = Eth1/1 or Eth1/n
                    try:
                        port_list.index(port)
                    except ValueError:
                        port_list.append(port)
            port_list = sorted(port_list, key=natural_keys)
            lines = len(port_list) * 6 + 1 # was *2

        matrix = [[0 for x in range(cols)] for y in range(lines)]  # creates matrix, a 2-D list of zeros, lines x cols

        try:
            sorted_swlist = sorted(switch_dict.keys(), key=natural_keys)  # sort keys in switch_dict alphabetically
            first_sw = int(natural_keys(sorted_swlist[0])[-2])  # extracts 1 from 'L1' and casts to int
        except (ValueError, IndexError):
            logger.error('Switch name not end in a number: {}'.format(first_sw))
            close_ssh(ssh_list)
            raise ValueError

        for switch in switch_dict.keys(): # ['L1','L2','L3'.....]
            idx = sorted_swlist.index(switch) + 1  # gets value of index of 'L1' for example

            for port, data in switch_dict[switch].iteritems():  # get keys and values in 'switch_dict' in 'Lx'
                if opts.display == 'spines': # for spines display
                    if data.has_key('remote_switch'):  # has_key returns true if 'remote_switch' is in dictionary
                        rem_sw = re.split('(\d+)', data['remote_switch'])

                        try:
                            rem_sw_nr = int(rem_sw[-2])

                        except (ValueError, IndexError):
                            logger.error('Remote switch name from LLDP does not end in a number: {}'.format(
                                data['remote_switch']))
                            close_ssh(ssh_list)
                            raise ValueError
                        try:
                            matrix[0][idx] = switch
                            matrix[rem_sw_nr * 6 - 5][idx] = data['rx_discard']
                            matrix[rem_sw_nr * 6 - 4][idx] = data['tx_discard']
                            matrix[rem_sw_nr * 6 - 3][idx] = data['rx_err']
                            matrix[rem_sw_nr * 6 - 2][idx] = data['tx_err']
                            matrix[rem_sw_nr * 6 - 1][idx] = data['egress_rate']
                            matrix[rem_sw_nr * 6][idx] = data['ingress_rate']

                            matrix[rem_sw_nr * 6 - 5][0] = 'L' + str(rem_sw_nr) + ' rx ds'
                            matrix[rem_sw_nr * 6 - 4][0] = 'L' + str(rem_sw_nr) + ' tx ds'
                            matrix[rem_sw_nr * 6 - 3][0] = 'L' + str(rem_sw_nr) + ' rx err'
                            matrix[rem_sw_nr * 6 - 2][0] = 'L' + str(rem_sw_nr) + ' tx err'
                            matrix[rem_sw_nr * 6 - 1][0] = 'L' + str(rem_sw_nr) + ' out'
                            matrix[rem_sw_nr * 6][0] = 'L' + str(rem_sw_nr) + ' in'
                        except IndexError:
                            pass
                else: # for leaves display
                    try:
                        port_idx = port_list.index(port) + 1
                        matrix[0][idx] = switch  # switch is a key value in switch_dict eg.L1
                        matrix[port_idx * 6 - 5][idx] = data['rx_discard']  #
                        matrix[port_idx * 6 - 4][idx] = data['tx_discard']  #
                        matrix[port_idx * 6 - 3][idx] = data['rx_err']#
                        matrix[port_idx * 6 - 2][idx] = data['tx_err']#
                        matrix[port_idx * 6 - 1][idx] = data['egress_rate']
                        matrix[port_idx * 6][idx] = data['ingress_rate']
                        matrix[port_idx * 6 - 5][0] = port[3:] + ' rx ds'  # remove Eth, include 1/17#
                        matrix[port_idx * 6 - 4][0] = port[3:] + ' tx ds '  # remove Eth, include 1/17#
                        matrix[port_idx * 6 - 3][0] = port[3:] + ' rx err'  # remove Eth, include 1/17#ingr
                        matrix[port_idx * 6 - 2][0] = port[3:] + ' tx err'  # remove Eth, include 1/17#egr
                        matrix[port_idx * 6 - 1][0] = port[3:] + ' out'#remove Eth, include 1/17
                        matrix[port_idx * 6][0] = port[3:] + ' tx in'

                    except IndexError:
                        pass
        #IPython.embed()
        return matrix


    def draw(stdscr, switch_dict, ssh_list): # TODO alter color changing
        from decimal import Decimal

        def fexp(number): # returns the order of magnitude of number
            (sign, digits, exponent) = Decimal(number).as_tuple()
            return len(digits) + exponent - 1

        def fman(number): # returns number with decimal point after 1st digit
            return Decimal(number).scaleb(-fexp(number)).normalize()

        # Clear screMen
        stdscr.clear()
        lines = curses.LINES # size of console screen HORI
        cols = curses.COLS # size of console screen VERT
        matrix = get_discard(switch_dict, ssh_list)

        prev_matrix = matrix # excluded in rates code
        m_rows = len(matrix)
        m_rows = m_rows + (m_rows / 2) # m_rows = no of rows or lines for drawing matrix
        m_cols = len(matrix[0]) # m_cols = no of columns for drawing matrix
        # find max number size in matrix
        max_num = max([x for x in [j for i in matrix for j in i] if isinstance(x, int)])
        colw = fexp(max_num) + 2
        if colw < 9: colw = 9
        blank_str = ' ' * colw
        # Initialise windows and colours
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_WHITE, -1)
        curses.init_pair(2, curses.COLOR_BLACK, -1)
        curses.init_pair(3, curses.COLOR_BLUE, -1)
        curses.init_pair(4, curses.COLOR_BLUE, -1)
        curses.init_pair(5, curses.COLOR_GREEN, -1)
        curses.init_pair(6, curses.COLOR_GREEN, -1)
        curses.init_pair(7, curses.COLOR_RED, -1)
        curses.init_pair(8, curses.COLOR_RED, -1)
        curses.init_pair(9, curses.COLOR_RED, curses.COLOR_YELLOW)
        #curses.newpad(nlines, ncols)
        col_title = curses.newpad(1, m_cols * colw)
        row_title = curses.newpad(m_rows, colw)
        disp_wind = curses.newpad(m_rows, m_cols * colw)
        top_cornr = curses.newpad(1, colw)
        top_cornr.addstr(0, 0, 'Rates', curses.A_BOLD | curses.A_UNDERLINE)
        # Data display block upper left-hand corner
        dminrow = 0
        dmincol = 0
        # Column title upper left-hand corner
        cminrow = 0
        cmincol = 0
        # Row title upper left-hand conrner
        rminrow = 1
        rmincol = 0
        # Data display window
        dwminrow = 1
        dwmincol = colw + 1
        dwmaxrow = lines - 1
        dwmaxcol = cols - 1
        dwrows = dwmaxrow - dwminrow
        dwcols = dwmaxcol - dwmincol
        # Column title display window
        ctminrow = 0
        ctmincol = colw + 1
        ctmaxrow = 0
        ctmaxcol = cols - 1
        # Row title display window
        rtminrow = 1
        rtmincol = 0
        rtmaxrow = lines - 1
        rtmaxcol = colw
        stdscr.nodelay(1)
        try:
            data_rdy = True
            blink = True
            pool = ThreadPool(processes=1)
            while True:
                if data_rdy:
                    data_rdy = False
                    thread_obj = pool.apply_async(get_discard, args=(switch_dict, ssh_list))
                    blankc = 0
                    reverse = False
                    rates_index = False
                    for i, row in enumerate(matrix):
                    #for i, row in enumerate(n for m, n in enumerate(matrix) if (m + 4) % 6 == 0 or (m + 5) % 6 == 0 or m==0):
                    #the code above enumerates every 6th element in list ie. [1,2,7,8,13,14,19,20 etc] these are the in out speed rates
                        if (i)%6 == 0 or (i+1)%6 == 0: # every 6th element in list ie. [5,6,11,12,17,18,23,24... etc] these are the in out speed rates
                            rates_index = True # set a flag
                        else:
                            rates_index = False
                        if i == 0:
                            for j, val in enumerate(row):
                                if val == 0: # this line is excluded from rates code
                                    val = 'N/C' # this line is excluded from rates code
                                if j == 0:
                                    pass
                                else:
                                    col_title.addstr(i, (j - 1) * colw, '{0:>{1}}'.format(val, colw),
                                                     curses.A_BOLD | curses.A_UNDERLINE)
                        else:
                        #elif (i+4)%6 == 0 or (i+5)%6 == 0: # prints every 6th row in matrix, which is the rates data
                            for j, val in enumerate(row):
                                ###################
                                if prev_matrix[i][j] != matrix[i][j]:  # check for change in values
                                    if not ((i) % 6 == 0 or (i + 1) % 6 == 0):  # exclude rate values
                                        change = True
                                    else:
                                        change = False
                                else:
                                    change = False
                                ###################
                                if j == 0: # for first title row in display
                                    if val == 0:
                                        val = 'N/C'
                                    col_pair = 1
                                    if reverse: col_pair += 1
                                    if rates_index is True:
                                        row_title.addstr(i + blankc - 1, 0, val, curses.color_pair(col_pair) | curses.A_BOLD) # displays L1/1 out, etc.
                                    if (i - 1) % 2 == 1: # all even numbers eg 2,4,6,8,...
                                        row_title.addstr(i + blankc - 1 + 1, 0, ' ')
                                #rates displaying #stdscr.addstr(y_pos, x_pos, "string to be displayed", color_arrangement)
                                ##############################################################################
                                else:  # for rows following first title row ^
                                    width = colw - 2
                                    if not val: val = 0
                                    man = fman(val)
                                    exp = fexp(val)
                                    if exp < 3 and rates_index is True:
                                        col_pair = 1
                                        if reverse: col_pair += 1
                                        rate = 'Bs'
                                        val = '{0:>{1}} {2}'.format(int(val), width - 1, rate)
                                    elif exp < 6 and rates_index is True:
                                        col_pair = 1
                                        if reverse: col_pair += 1
                                        rate = 'KB'
                                        man *= 10 ** (exp - 3)
                                        man = man.normalize()
                                        if width - 8 < 0:
                                            val = '{0:>{1}} {2}'.format(int(man), width - 1, rate)
                                        else:
                                            val = '{0:{1}.1f} {2}'.format(man, width - 1, rate)
                                    elif exp < 9 and rates_index is True:
                                        col_pair = 3
                                        if reverse: col_pair += 1
                                        rate = 'MB'
                                        man *= 10 ** (exp - 6)
                                        man = man.normalize()
                                        if width - 8 < 0:
                                            val = '{0:>{1}} {2}'.format(int(man), width - 1, rate)
                                        else:
                                            val = '{0:{1}.1f} {2}'.format(man, width - 1, rate)
                                    elif exp < 12 and rates_index is True:
                                        if man > 4.8:
                                            col_pair = 7
                                            if reverse: col_pair += 1
                                            col_title.addstr(0, (j - 1) * colw, '{0:>{1}}'.format(matrix[0][j], colw),
                                                             curses.color_pair(
                                                                 col_pair) | curses.A_BOLD | curses.A_UNDERLINE)
                                            row_title.addstr(i + blankc - 1, 0, matrix[i][0],
                                                             curses.color_pair(col_pair) | curses.A_BOLD)
                                        else:
                                            col_pair = 5
                                            if reverse: col_pair += 1
                                        rate = 'GB'
                                        man *= 10 ** (exp - 9)
                                        man = man.normalize()
                                        val = '{0:{1}.1f} {2}'.format(man, width - 1, rate)
                                    #else:
                                    elif rates_index is True:
                                        col_pair = 1
                                        rate = 'Bs'
                                        val = '{0:>{1}} {2}'.format(int(val), width - 1, rate)

                                    if change:
                                        col_title.addstr(0, (j - 1) * colw, '{0:>{1}}'.format(matrix[0][j], colw),curses.color_pair(9) | curses.A_BOLD | curses.A_UNDERLINE)  # change column title colour
                                    #if prev_matrix[i][j] != matrix[i][j]: # check for change in values
                                        #if not ((i) % 6 == 0 or (i+1) % 6 == 0): # exclude rate values
                                            #col_pair = 9
                                            #col_title.addstr(0, (j - 1) * colw, '{0:>{1}}'.format(matrix[0][j], colw),curses.color_pair(col_pair) | curses.A_BOLD | curses.A_UNDERLINE) #change column title colour
                                            #row_title.addstr(i + blankc - 1, j, 'xxx',curses.color_pair(col_pair) | curses.A_BOLD) # testing position
                                            #row_title.addstr(i + blankc - 1, 0, matrix[i][0],
                                             #                curses.color_pair(col_pair) | curses.A_BOLD) #change row title colour
                                    #if (i + 4) % 6 == 0 or (i + 5) % 6 == 0:
                                    if rates_index is True: #displays rates values only
                                        if change is True:
                                            disp_wind.addstr(i + blankc - 1, (j - 1) * colw, val, curses.color_pair(9))
                                        else:
                                            disp_wind.addstr(i + blankc - 1, (j - 1) * colw, val, curses.color_pair(col_pair)) # testing higlight of rates during a change

                                    if (i - 1) % 2 == 1:
                                        disp_wind.addstr(i + blankc - 1 + 1, (j - 1) * colw, ' ')
                                ##############################################################################
                                #discard diplaying
                                ##############################################################################
                                # else: # for rows following first title row
                                #     if prev_matrix[i][j] != val: # the discard packets value has changed
                                #         col_pair = 7
                                #         col_title.addstr(0, (j - 1) * colw, '{0:>{1}}'.format(matrix[0][j], colw),
                                #                          curses.color_pair(
                                #                              col_pair) | curses.A_BOLD | curses.A_UNDERLINE)
                                #         row_title.addstr(i + blankc - 1, 0, matrix[i][0],
                                #                          curses.color_pair(col_pair) | curses.A_BOLD)
                                #     else:
                                #         col_pair = 1
                                #     val = '{0:>{1}}'.format(val, colw)
                                #     disp_wind.addstr(i + blankc - 1, (j - 1) * colw, val, curses.color_pair(col_pair))
                                #     if (i - 1) % 2 == 1:
                                #         disp_wind.addstr(i + blankc - 1 + 1, (j - 1) * colw, ' ')
                                ###############################################################################
                            if (i - 1) % 2 == 1:
                            #if (i+4)%6 == 0:
                            #if True:
                                blankc += 1
                                #blankc = 0
                                reverse = False  # not(reverse)
                    prev_matrix = matrix # excluded in rates code
                else:
                    char = stdscr.getch()
                    if char == curses.ERR:
                        if thread_obj.ready():
                            matrix = thread_obj.get()
                            # if matrix != prev_matrix:
                            data_rdy = True
                            if blink:
                                top_cornr.addstr(0, 0, 'Rates',
                                                 curses.A_BOLD | curses.A_UNDERLINE | curses.A_REVERSE)
                            else:
                                top_cornr.addstr(0, 0, 'Rates', curses.A_BOLD | curses.A_UNDERLINE)
                            blink = not (blink)
                        else:
                            time.sleep(0.1)
                    else:
                        if char == curses.KEY_LEFT:
                            if dmincol > colw:
                                dmincol -= colw
                            else:
                                dmincol = 0
                        elif char == curses.KEY_RIGHT:
                            if dmincol < (m_cols - 2) * colw - dwcols:
                                dmincol += colw
                            else:
                                dmincol = (m_cols - 1) * colw - dwcols
                        elif char == curses.KEY_UP:
                            if dminrow > 0:
                                dminrow -= 1
                            else:
                                dminrow = 0
                        elif char == curses.KEY_DOWN:
                            if dminrow < m_rows - dwrows - 2:
                                dminrow += 1
                            else:
                                dminrow = m_rows - dwrows - 2
                        elif char == 'c' or 'C':
                            cmd = 'clear counters all'
                            dummy = run_threaded_cmd(ssh_list, cmd, enable=True)

                # Shift titles with text
                cmincol = dmincol
                rminrow = dminrow
                disp_wind.refresh(dminrow, dmincol, dwminrow, dwmincol, dwmaxrow, dwmaxcol)
                col_title.refresh(cminrow, cmincol, ctminrow, ctmincol, ctmaxrow, ctmaxcol)
                row_title.refresh(rminrow, rmincol, rtminrow, rtmincol, rtmaxrow, rtmaxcol)
                top_cornr.refresh(0, 0, 0, 0, 1, colw - 1)
        except KeyboardInterrupt:
            pass


    # Main Code
    # Open SSH connections to all hosts
    full_ssh_list = []
    thread_obj = [0] * len(hosts)
    pool = ThreadPool(processes=len(hosts))
    logger.info('Opening ssh connections.')
    for i, host in enumerate(hosts):
        thread_obj[i] = pool.apply_async(ssh_conn, args=(host,))
    for i, host in enumerate(hosts):
        full_ssh_list.append(thread_obj[i].get())
    pool.close()
    pool.join()
    ssh_list = []
    for i, ssh_obj in enumerate(full_ssh_list):
        if type(ssh_obj) == str:
            logger.error('Connection to {} failed.'.format(ssh_obj))
        else:
            ssh_list.append(ssh_obj)
    logger.info('SSH connections established.')

    # Map switches:
    logger.info('Mapping switch connections using LLDP')
    # Create 3 level dictionary for switch info
    switch_dict = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    cmd = 'show lldp interfaces ethernet remote | include "Eth|Remote system name"'
    all_output = run_threaded_cmd(ssh_list, cmd)
    new_ssh_list = []
    for output in all_output:
        try:
            host_name = None
            for ln in output:
                if ln.find('host') != -1:
                    host_name = ln.split()[2]
            sw_name_idx = [i for i, s in enumerate(output) if 'CBFSW' in s][0]
            sw_name = output[sw_name_idx].split(' ')[0].split('-')[-1]
            rem_port_id = [i for i, v in enumerate(output) if 'Remote port-id' in v]
            for idx in rem_port_id:
                eth = output[idx - 1]
                remote = output[idx + 1].split(' ')[-1]
                switch_dict[sw_name][eth]['remote_switch'] = remote
            for ssh_obj in ssh_list:
                if ssh_obj.hostname == host_name:
                    new_ssh_list.append(ssh_obj)
        except IndexError:
            if host_name:
                logger.error('Switch output malformed for {}:\n{}'.format(host_name, output))
            else:
                logger.error('Switch output malformed while mapping switches: {}'.format(output))
            _null = raw_input("Press any key to continue...")
    logger.info('Done mapping switches.')

    ## Map switches:
    # logger.info('Mapping switch connections using LLDP')
    ## Create 3 level dictionary for switch info
    # switch_dict = defaultdict(lambda: defaultdict( lambda: defaultdict(list)))
    # cmd = 'show lldp interfaces ethernet remote | include "Eth|Remote system name"'
    # all_output = run_threaded_cmd(ssh_list,cmd)
    # for output in all_output:
    #    sw_name_idx = [i for i,s in enumerate(output) if 'CBFSW' in s][0]
    #    sw_name = output[sw_name_idx].split(' ')[0].split('-')[-1]
    #    for line in output:
    #        if line.startswith('Eth'):
    #            eth = line
    #        if line.startswith('Remote system'):
    #            remote = line.split(' ')[-1]
    #            switch_dict[sw_name][eth]['remote_switch'] = remote
    # logger.info('Done mapping switches.')
    #matrix = get_discard(switch_dict, ssh_list)
    curses.wrapper(draw, switch_dict, new_ssh_list)

    # print 'MATRIX:'
    # print matrix
    #IPython.embed()


    close_ssh(ssh_list)

