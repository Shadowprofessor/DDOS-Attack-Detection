from mininet.net import Mininet
from mininet.node import Controller
from mininet.cli import CLI
from mininet.log import setLogLevel

def run():
    setLogLevel('info')
    net = Mininet(controller=Controller)
    c0 = net.addController('c0')
    h1 = net.addHost('h1', ip='10.0.0.1')  # attacker
    h2 = net.addHost('h2', ip='10.0.0.2')  # victim
    s1 = net.addSwitch('s1')
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.start()
    print("Topology ready. h1=attacker (10.0.0.1), h2=victim (10.0.0.2)")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    run()
