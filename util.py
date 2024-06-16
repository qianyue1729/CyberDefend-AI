import subprocess

def block_ip(ip):
    subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name="Block IP {ip}"', 'dir=in', 'action=block',
                    f'remoteip={ip}', 'enable=yes'], check=True)


def allow_ip(ip):
    subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                    f'name="Block IP {ip}"'], check=True)
    
def alert_ip(ip):
    pass