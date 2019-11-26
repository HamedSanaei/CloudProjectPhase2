#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.util import irange, dumpNodeConnections
from mininet.log import setLogLevel
from mininet.node import RemoteController

import argparse
import sys
import time


class ClosTopo(Topo):

    def __init__(self, fanout, cores, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)

        "Set up Core and Aggregate level, Connection Core - Aggregation level"
        # WRITE YOUR CODE HERE!
        c1, c2 = self.addSwitch('c1'), self.addSwitch('c2')
        a3, a4, a5, a6 = self.addSwitch('a3'), self.addSwitch(
            'a4'), self.addSwitch('a5'), self.addSwitch('a6')
        coreSwitches = [c1, c2]
        aggrSwitches = [a3, a4, a5, a6]
        for c in coreSwitches:
            for a in aggrSwitches:
                self.addLink(c, a)

        e7, e8, e9, e10, e11, e12, e13, e14 = self.addSwitch('e7'), self.addSwitch('e8'), self.addSwitch(
            'e9'), self.addSwitch('e10'), self.addSwitch('e11'), self.addSwitch('e12'), self.addSwitch('e13'), self.addSwitch('e14')
        edgeSwitches = [e7, e8, e9, e10, e11, e12, e13, e14]

        for a in aggrSwitches:
            for e in edgeSwitches:
                self.addLink(a, e)

        h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11,h12,h13,h14,h15,h16 = self.addHost('h1'), self.addHost('h2'), self.addHost(
            'h3'), self.addHost('h4'), self.addHost('h5'), self.addHost('h6'), self.addHost('h7'), self.addHost('h8'),self.addHost('h9'), self.addHost('h10'), self.addHost(
            'h11'), self.addHost('h12'), self.addHost('h13'), self.addHost('h14'), self.addHost('h15'), self.addHost('h16')
        hosts = [h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11,h12,h13,h14,h15,h16]
        for e in edgeSwitches:
            indexOfCurrentEdge = edgeSwitches.index(e)*2
            self.addLink(e, hosts[indexOfCurrentEdge])
            self.addLink(e, hosts[indexOfCurrentEdge+1])


def setup_clos_topo(fanout=2, cores=1):
    "Create and test a simple clos network"
    assert(fanout > 0)
    assert(cores > 0)
    topo = ClosTopo(fanout, cores)
    net = Mininet(topo=topo, controller=lambda name: RemoteController(
        'c0', "127.0.0.1"), autoSetMacs=True, link=TCLink)
    net.start()
    time.sleep(20)  # wait 20 sec for routing to converge
    net.pingAll()  # test all to all ping and learn the ARP info over this process
    CLI(net)  # invoke the mininet CLI to test your own commands
    net.stop()  # stop the emulation (in practice Ctrl-C from the CLI
    # and then sudo mn -c will be performed by programmer)


def main(argv):
    parser = argparse.ArgumentParser(
        description="Parse input information for mininet Clos network")
    parser.add_argument('--num_of_core_switches', '-c',
                        dest='cores', type=int, help='number of core switches')
    parser.add_argument('--fanout', '-f', dest='fanout',
                        type=int, help='network fanout')
    args = parser.parse_args(argv)
    setLogLevel('info')
    setup_clos_topo(args.fanout, args.cores)


if __name__ == '__main__':
    main(sys.argv[1:])
