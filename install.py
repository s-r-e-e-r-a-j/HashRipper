import os
import sys

def is_termux():
    return 'com.termux' in os.environ.get('PREFIX', '')

choice = input('[+] To install press (Y) to uninstall press (N) >> ')
run = os.system

if choice.lower() == 'y':
    if is_termux():
        prefix = os.environ.get('PREFIX')
        bin_path = os.path.join(prefix, 'bin', 'hashripper')
        share_path = os.path.join(prefix, 'share', 'hashripper')

        run('chmod 755 hashripper.py')
        run(f'mkdir -p {share_path}')
        run(f'cp hashripper.py {share_path}/hashripper.py')

        termux_launcher = f'#! /data/data/com.termux/files/usr/bin/sh\nexec python3 {share_path}/hashripper.py "$@"'
        with open(bin_path, 'w') as file:
            file.write(termux_launcher)

        run(f'chmod +x {bin_path} && chmod +x {share_path}/hashripper.py')
        print('''\n\n[+] HashRipper installed successfully in Termux
[+] Now just type \x1b[6;30;42mhashripper\x1b[0m in terminal''')

    else:
        if os.geteuid() != 0:
            print("Please run as root or with sudo")
            sys.exit(1)

        run('chmod 755 hashripper.py')
        run('mkdir -p /usr/share/hashripper')
        run('cp hashripper.py /usr/share/hashripper/hashripper.py')

        linux_launcher = '#! /bin/sh\nexec python3 /usr/share/hashripper/hashripper.py "$@"'
        with open('/usr/bin/hashripper', 'w') as file:
            file.write(linux_launcher)

        run('chmod +x /usr/bin/hashripper && chmod +x /usr/share/hashripper/hashripper.py')
        print('''\n\n[+] HashRipper installed successfully on Linux
[+] Now just type \x1b[6;30;42mhashripper\x1b[0m in terminal''')

elif choice.lower() == 'n':
    if is_termux():
        prefix = os.environ.get('PREFIX')
        run(f'rm -rf {prefix}/share/hashripper')
        run(f'rm -f {prefix}/bin/hashripper')
        print('[!] HashRipper removed from Termux successfully')
    else:
        if os.geteuid() != 0:
            print("Please run as root or with sudo")
            sys.exit(1)
        run('rm -rf /usr/share/hashripper')
        run('rm -f /usr/bin/hashripper')
        print('[!] HashRipper removed from Linux successfully')
