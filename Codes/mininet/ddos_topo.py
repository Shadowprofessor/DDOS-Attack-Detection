from mininet.net import Mininet
from mininet.node import Controller
from mininet.cli import CLI
from mininet.log import setLogLevel

def run():
    setLogLevel('info')
    net = Mininet(controller=Controller)
    c0 = net.addController('c0')
    h1 = net.addHost('h1', ip='10.0.0.1')  # attacker
    h2 = net.addHost('h2', ip='10.0.0.2')  # legacy empty victim
    h3 = net.addHost('h3', ip='10.0.0.3')  # realistic victim device (IoT camera / web server)
    s1 = net.addSwitch('s1')
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.start()
    h3.cmd('python3 -m http.server 80 >/tmp/h3_http.log 2>&1 &')
    print("Topology ready. h1=attacker (10.0.0.1), h2=empty victim (10.0.0.2), h3=victim device with HTTP:80 listening (10.0.0.3)")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    run()
