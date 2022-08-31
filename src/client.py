"""
TFTPy - This module implements an interactive and command line TFTP 
client.

This client accepts the following options:
    $ python3 client.py (get|put) [-p serv_port] server source_file [dest_file] 
    $ python3 client.py [-p serv_port] server

(C) Ana Mendes 2022
"""

from docopt import docopt
import tftp
import sys
from cmd import Cmd
import socket

mode = b'octet\0'

# Count ACK
ct4 = 0

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def _main():
    '''
Usage: 
    client.py (get|put) [-p <serv_port>] <server> <source_file> [<dest_file>]
	client.py put [-p <serv_port>] <server> 

Options:
	-h --help                            Show information about the commands
	-p <serv_port>, --port=<serv_port>   Listen on ports. Default: 69
	<dest_file>                          File name
    '''

    usage = '''client.py [-h]
            client.py (get|put) [-p serv_port] <server> <source_file> [<dest_file>]
            client.py [-p serv_port] <server>
    '''

    # Docopt Options
    args = docopt(__doc__)
    port = int(args['--port'])
    host = args['<server>']
    addr = host, port
    ip_verify = args['<server>'].split('.')
    naming_file = args['<dest_file>']
    path = args['<source_file>']
    path = './'
    count_args = 0

    # TFTP message opcodes 1 - 6 in hexadecimal
    RRQ = b'\x00\x01'
    WRQ = b'\x00\x02'
    DAT = b'\x00\x03'
    ACK = b'\x00\x04'
    ERR = b'\x00\x05'
    DIR = b'\x00\x06'

    # Block
    BLK0 = 0
    BLK1 = 1
        

    # Validate the args['<server>'] option
    count = 0
    if args['<server>'] == 'get':
        count += 1
    if args['<server>'] == 'put':
        count += 1
    if count == 1:
        print(usage)
        sys.exit()

    # Validate the IP len
    if len(ip_verify) == 1:
        pass
    if len(ip_verify) == 4:
        verify_ip = tftp.get_host_info(args['<server>'])
        if verify_ip == False:
            print("The inserted server don't have a valid IP address.")
            sys.exit()
    if 4 > len(ip_verify) > 1:
        print("The inserted server don't have a valid IP address.")
        sys.exit()


    # Validate the args GET option
    if args['get']:
        option = 1
        filename = args['<source_file>']
        if not args['<dest_file>']:
            cheking, filetoW = tftp.get_file(args['<source_file>'])
            if cheking == True:
                print("File '%s' already exists locally! [error 6] Give a [remote_file] name." % (filetoW.decode()))
                raise SystemExit 
        filename = filename.encode()
        filename += b'\0'
        if args['<dest_file>']:
            cheking2, filetoW2 = tftp.get_file(args['<dest_file>'])
            if cheking2 == True:
                print("File '%s' already exists locally! [error 6] Give another [remote_file] name." % (filetoW2.decode()))
                raise SystemExit 
            filename += naming_file.encode()
        packet = tftp._pack_rq(option, filename, mode)

    # Validate the args PUT option
    if args['put']:
        option = 2
        filename = args['<source_file>']
        file, namefile = tftp.get_file(filename)
        if file == True:
            filena = namefile
            filena += b'\0'
        if file != True:
            print("File %s not found! [error 1]" % args['<source_file>'])
            sys.exit()
        if args['<dest_file>']:
            filena += naming_file.encode()
        packet = tftp._pack_rq(option, filena, mode)

    # The Cmd class provides a simple framework for writing line-oriented 
    # command interpreters. These are often useful for test harnesses, 
    # administrative tools, and prototypes that will later be wrapped in a 
    # more sophisticated interface.

    class CMD(Cmd):
        
        def do_get(self, args: list = sys.argv, addr = addr):
            
            #Args Number 
            nArgs = args.split()
            
            # Args Number = 0
            if len(nArgs) == 0:
                print('usage: get ficheiro_remoto [ficheiro_local]')
                prompt = CMD(host, port)
                prompt.prompt = 'tftp client> '
                prompt.cmdloop()
            
            # Args Number = 1
            if len(nArgs) == 1:
                filename = nArgs[0].encode()
                filename += b'\0'
                chekingG, filetoWG = tftp.file_verify(nArgs[0])
                if chekingG == True:
                    print("File '%s' already exists! [error 6] Give a [remote_file] name." % (filetoWG.decode()))
                    prompt = CMD(host, port)
                    prompt.prompt = 'tftp client> '
                    prompt.cmdloop()

            # Args Number = 2   
            if len(nArgs) == 2:
                filename = nArgs[0].encode()
                filename += b'\0'
                filename += nArgs[1].encode()
                name_to_save = nArgs[1]
                chekingG2, filetoWG2 = tftp.file_verify(nArgs[1])
                if chekingG2 == True:
                    print("File '%s' already exists! [error 6] Give another [remote_file] name." % (filetoWG2.decode()))
                    prompt = CMD(host, port)
                    prompt.prompt = 'tftp client> '
                    prompt.cmdloop()
        
            option = 1
            count_EXCEPTION = 0
            file = tftp._pack_rq(option, filename, mode)
            check_ping = tftp.checkConnection(addr[0])

            if check_ping == True:
                s.sendto(file, addr)
            
            try:
                while 1:
                    data, addr = s.recvfrom(16384)
                    s.settimeout(10)

                    pack_type = tftp.checkPack(data)
                    host = addr[0]
                    fqdn = getfqdn(host)
                    
                    count_EXCEPTION  += 1
                    if count_EXCEPTION  == 1:
                        print("Exchanging files with '%s' ('%s')" % (fqdn, host))

                    Port = addr[1]
                    if data == 'end':
                        s.settimeout(10)
                    
                    # TYPE DAT
                    if pack_type == DAT:
                        blk = data[2:4]
                        if len(nArgs) == 2:
                            if blk == BLK1:
                                ack_send, namesaved = tftp.treat_DAT_Equal(data, path, nArgs[1])
                                s.sendto(ack_send, addr)

                            if blk > BLK1:
                                ack_send, namesaved = tftp.treat_DAT_Bigger(data, namesaved)
                                s.sendto(ack_send, addr)

                        else:
                            if blk == BLK1:
                                ack_, namesaved = tftp.treat_DAT_Equal(data, path, nArgs[0])
                                s.sendto(ack_, addr)
                            if blk > BLK1:
                                ack_send, namesaved = tftp.treat_DAT_Bigger(data, namesaved)
                                s.sendto(ack_, addr)
                    
                    # TYPE ACK
                    if pack_type == ACK:
                        option = 3
                        ct4 += 1
                        
                        if ct4 == 1:
                            fi = tftp.open_file(namefile)
                            blocks=tftp.chunks(fi, 512)
                        inf = next(blocks,'end')
                        file = str(file).strip("[]")

                        if inf == 'end':
                            print("Sent file '%s' %d bytes" % (namefile.decode(), fi))
                            ct4 = 0
                            s.settimeout(10)
                            continue
                        numb_blk = next(blocks,'end')
                
                        packet = tftp.pack_3_(op, numb_blk, inf)
                        s.sendto(packet, addr)
            

                    # LEITURA DO PACOTE 5 (ERR)
                    if pack_type == ERR:
            
                        info = tftp.unpack_err(data)
                        op, err, msg = info
                        print('%s' % (msg))
                        prompt = CMD(host, port)
                        prompt.prompt = 'tftp client> '
                        prompt.cmdloop()
                        continue

            except ConnectionRefusedError:

                print("Couldn't open the socket for the host %s with IP address '%s'." % (fqdn, host))
                print("Setting timeout. Trying...")
                s.connect(addr)
                ct = 0
                
                s.connect(addr)
                s.settimeout(10)

            except timeout:           
        
                if pack_type >= BLK1:
                    print("Backing to the prompt with the host address '%s'." % (host))
                    s.settimeout(5)
                    prompt = CMD(host, port)
                    prompt.prompt = 'tftp client> '
                    prompt.cmdloop()
                else:
                    print('Trying again...')
                    ct += 1
                    s.connect(addr)
                    s.settimeout(10)
                    if ct == 2:
                        print("Can't connect!")
                    prompt = CMD(host, port)
                    prompt.prompt = 'tftp client> '
                    prompt.cmdloop()
        
        def do_dir(self, args = sys.argv, addr = addr):
            """Do dir in connected server"""
             
            if len(args) == 0:
                dir_list = ''
                blk_dir = []
                send_dir = tftp.dir_pack_send()
                s.sendto(send_dir, addr)
                ct_EX = 0
                
                while 1:
                    data, addr = s.recvfrom(8192)
                    s.settimeout(10)
                    pack_type = tftp.check_pack(data)
                    blk = data[2:4]
                    data_d = data[4:]
                    host = addr[0]
                    fqdn = getfqdn(host)
                    port1 = addr[1]

                    if data == '':
                        s.settimeout(10)

                    if pack_type == DAT:
                        dir_list += data_d.decode()
                        blk_dir.append(blk)
                        blk2 = str(blk)
                        blk3 = blk2.strip("b'\\x0'")
                        blk4 = int(blk3)
                        op = 6
                        dir_send = tftp.pack_6_dir(op, blk4)
                        s.sendto(dir_send, addr)
                        
                        if len(data) < 512:
                            
                            tftp.show_dir(dir_list)
                            prompt = CMD(host, port)
                            prompt.prompt = 'tftp client> '
                            prompt.cmdloop()    
            else:
                print('usage: dir')
#:

    if args['put'] == False:
        count_args += 1

    if args['get'] == False:
        count_args += 1

    if args['<source_file>'] == None:
        count_args += 1

    if args['<dest_file>'] == None:
        count_args += 1

    if count_args == 4:    
        prompt = CMD(host, port)
        prompt.prompt = 'tftp client> '
        prompt.cmdloop('Starting prompt...')


    s.connect((host, port))
    check_ping = tftp.ch_conn(addr[0])
    if check_ping == True:
        s.sendto(packet, addr)
    else:
        print(check_ping)
        raise SystemExit

    count_EX = 0
    while True:

        try:            
            data, addr = s.recvfrom(65536)
            s.settimeout(20)
            pack_type = tftp.check_pack(data)
            op = data[:2]
            bloco = data[2:4]
            host = addr[0]
            fqdn = getfqdn(host)
            count_EX += 1

            if count_EX == 1:
                print("Exchanging files with '%s' ('%s')" % (fqdn, host))
            port1 = addr[1]
      

            # LEITURA DO PACOTE 1 (RRQ)
            if pack_type == RRQ:
                ack_send = tftp.treat_RQQ(data)
                if len(ack_send) == 2:
                    _send, file = ack_send
                    s.sendto(_send, addr)
                if len(ack_send) == 3:
                    send_er, msg, err = ack_send
                    s.sendto(send_er, addr)

            # LEITURA DO PACOTE 2 (WRQ)
            if pack_type == WRQ:
    
                ack_send,file=tftp.treat_WRQ(data)
                s.sendto(ack_send, addr)
            
            # LEITURA DO PACOTE 3 (DAT)
            if pack_type == DAT:
      
                blk = data[2:4]
                if args['<dest_file>']:
                    if blk == BLK1:
                        ack_send, namesaved = tftp.treat_DAT1(data, path, args['<dest_file>'])
                    
                        s.sendto(ack_send, addr)
                    if blk > BLK1:
                        ack_send, namesaved = tftp.treat_DAT2(data, namesaved)
              
                        s.sendto(ack_send, addr)
                        if not data:
                            get_size = os.path.getsize(namesaved)
                            print('get size', get_size)
                else:
                    if blk == BLK1:
                            ack_, namesaved = tftp.treat_DAT1(data, path, args['<source_file>'])
                            s.sendto(ack_, addr)
                    if blk > BLK1:
                        ack_send, namesaved = tftp.treat_DAT2(data, namesaved)
                        s.sendto(ack_, addr)
                    if not data:
                        get_size = os.path.getsize(namesaved)
                        print('get size', get_size)

            # LEITURA DO PACOTE 4 (ACK)
            if pack_type == ACK:
         
                op = data[:2]
                blk = data[2:]
    
                if blk <= BLK1:

                    if blk == BLK0:
                        ct4 += 1
                        file_open = tftp.open_file(filename)
             
                        gen = tftp.chunks(file_open, 512)
                        dat = next(gen, 'end')
              
                        if dat == 'end':                            
                            ct4 = 0
                            ct_EX = 0
                            s.settimeout(5)
                            continue
                        op = 3
                        blocks = next(gen, 'end')
                        packet_DAT = tftp.pack_3_(op, blocks, dat)
                        s.sendto(packet_DAT, addr)
                        continue

                    if blk == BLK1:
                        if ct4 == 0:
                            file_open = tftp.open_file(filename)
                            gen = tftp.chunks(file_open, 512)
                            dat = next(gen, 'end')
                    
                            if dat == 'end':
                                print("File '%s' sended with %d bytes" % (filename, len(file_open) ))
                                ct4 = 0
                                ct_EX = 0
                                s.settimeout(5)
                                continue
                            op = 3
                            blocks = next(gen, 'end')
                            packet_DAT = tftp.pack_3_(op, blocks, dat)
                            s.sendto(packet_DAT, addr)
                            continue

                        else:
                            dat = next(gen, 'end')
                            if dat == 'end':
                                print("File '%s' sended with %d bytes" % (filename, len(file_open)))
                                ct4 = 0
                                ct_EX = 0
                                s.settimeout(5)
                                continue
                            blocks = next(gen, 'end')
                            op = 3
                            packet_DAT = tftp.pack_3_(op, blocks, dat)
                            s.sendto(packet_DAT, addr) 
                            continue

                if blk > BLK1:
                    dat = next(gen, 'end')
                    if dat == 'end':
                        print("File '%s' sended with %d bytes " % (filename, len(file_open)))
                        ct4 = 0
                        s.settimeout(5)
                        continue
                    blocks = next(gen, 'end')
                    op = 3
                    packet_DAT = tftp.pack_3_(op, blocks, dat)
                    s.sendto(packet_DAT, addr)
                    continue
            
            # LEITURA DO PACOTE 5 (ERR)
            if pack_type == ERR:
           
                info = tftp.unpack_err(data)
                op, err, msg = info
                print('%s' % (msg))
                s.settimeout(10)
                continue

            if not data:
                s.settimeout(5)
                break

        except ConnectionRefusedError:

            print("Couldn't open the socket for the host %s ." % (host))
            print("Setting timeout. Trying...")
            s.connect(addr)
            ct = 0
            
            s.connect(addr)
            s.settimeout(10)

        except timeout:     
            
            if pack_type >= BLK1:
                print("Turning off the connection with the host '%s'." % (host))
                s.settimeout(5)
                break
            else:
                print('Trying again...')
                ct += 1
                s.connect(addr)
                s.settimeout(5)
                if ct == 2:
                    print("Can't connect!")
                    break   

        except KeyboardInterrupt:
            print("Exiting TFTP client..")
            print("Goodbye!")
            break
    s.close()    


if __name__ == '__main__':
    _main()
