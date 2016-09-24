from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ether_types
from ryu.topology.api import get_switch, get_link, get_host
from ryu.topology import event
import random
import networkx as nx
import network_monitor_flow


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        "network_monitor": network_monitor_flow.NetworkMonitor}

    MAX_PATH_ID = 10000
    MIN_PATH_ID = 1
    
    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)

        self.monitor = kwargs["network_monitor"]
        self.mac_to_port = {}
        self.net = nx.DiGraph()
        self.all_saved_paths = []
        self.datapaths = {}

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])

    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %s', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %s', datapath.id)
                del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None , path_id=0, hard_timeout=0, idle_timeout = 0,flags=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if priority != 0:
            hard_timeout = 0
            idle_timeout = 20
            flags = ofproto.OFPFF_SEND_FLOW_REM

        cookie = cookie_mask = path_id
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, flags=flags, cookie=cookie, cookie_mask=cookie_mask,
                                    hard_timeout=hard_timeout, idle_timeout=idle_timeout, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, flags=flags, cookie=cookie, cookie_mask=cookie_mask,
                                    match=match, hard_timeout=hard_timeout, idle_timeout=idle_timeout, instructions=inst)
        datapath.send_msg(mod)

    def delete_flow(self, datapath, path_id ,table_id=0 ):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        cookie = cookie_mask = path_id
        command = ofproto.OFPFC_DELETE
        out_port = ofproto.OFPP_ANY
        out_group = ofproto.OFPG_ANY
        mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath, cookie=cookie, cookie_mask=cookie_mask, table_id=table_id,
                                                command=command,out_port=out_port, out_group=out_group, match=match)
        datapath.send_msg(mod)

    def refresh_topology_data(self):
        switch_list = get_switch(self, None)
        switches = [switch.dp.id for switch in switch_list]
        self.net.add_nodes_from(switches)
        links_list = get_link(self, None)
        for link in links_list:
            try:
                weight = abs(self.monitor.port_upload[(link.src.dpid, link.src.port_no)][-1])

            except:
                weight = 0
            self.net.add_edge(link.src.dpid, link.dst.dpid, {'port':link.src.port_no}, weight=weight)

        try:
            hosts = [host.mac for host in get_host(self)]
            for (src, dst, data) in self.net.edges(data=True):
                try:
                    if dst in hosts:
                        weight = abs(self.monitor.port_upload[(src,data['port'])][-1])
                        self.net.add_edge(src, dst, {'port': data['port']}, weight=weight)
                except:
                    self.logger.debug("error %s ", src)
            return
        except:
            self.logger.debug("error")



    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        out_port = NotImplemented
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        dst = eth.dst
        src = eth.src
        is_path_found = False
        path_id = 0
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        hosts = [host.mac for host in get_host(self)]

        if src not in self.net and is_path_found is False and src in hosts:
            try:
                weight = abs(self.monitor.port_upload[(dpid, in_port)][-1])
            except:
                weight = 0
            self.net.add_node(src)
            self.net.add_edge(dpid, src, {'port': in_port},weight=weight)
            self.net.add_edge(src, dpid,weight=weight)

        # ignore lldp packet
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # ignore ipv6 packet
        if eth.ethertype == ether_types.ETH_TYPE_IPV6:
            return

        if len(self.all_saved_paths) > 0:
            for path_obj in self.all_saved_paths:
                path_src = path_obj[0]
                path_dst = path_obj[1]
                path_dpids = path_obj[2]
                path_id = path_obj[3]
                if src == path_src and dst == path_dst:
                    # if the switch not in the path
                    if dpid not in path_dpids:
                        return

                    next_dpid = path_dpids[path_dpids.index(dpid) + 1]
                    out_port = self.net[dpid][next_dpid]['port']
                    path_id = path_id
                    is_is_path_found = True

        if dst in self.net and is_path_found is False:
            self.refresh_topology_data()
            if nx.has_path(self.net, src, dst):
                new_path = nx.dijkstra_path(self.net,src,dst)
                path_id = int(random.uniform(self.MIN_PATH_ID, self.MAX_PATH_ID))
                self.all_saved_paths.append((src, dst, new_path, path_id))
                self.logger.info("Add path Id : %s path : %s", path_id, new_path)
                if dpid not in new_path:
                    return
                next_dpid = new_path[new_path.index(dpid) + 1]
                out_port = self.net[dpid][next_dpid]['port']
            else:
                out_port = ofproto.OFPP_FLOOD

        elif is_path_found is False:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)

            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id , path_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions , path_id=path_id)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        switch_list = get_switch(self, None)
        switches = [switch.dp.id for switch in switch_list]
        self.net.add_nodes_from(switches)
        links_list = get_link(self, None)
        for link in links_list:
            try:
                weight = abs(self.monitor.port_upload[(link.src.dpid, link.src.port_no)][-1])
            except:
                weight = 0
            self.net.add_edge(link.src.dpid, link.dst.dpid, {'port':link.src.port_no}, weight=weight)

    @set_ev_cls(event.EventSwitchLeave)
    def get_new_topology_data(self, ev):

        current_dpid = ev.switch.dp.id
        self.logger.info("switch leaved %s", ev.switch.dp.id)
        paths_for_delete = []
        if len(self.all_saved_paths) > 0:
            for path_obj in self.all_saved_paths:
                path_dpids = path_obj[2]
                path_id = path_obj[3]
                if current_dpid in path_dpids:
                    for datapath in self.datapaths.values():
                        if datapath.id in path_dpids:
                            self.delete_flow(datapath, path_id)
                    paths_for_delete.append(path_obj)

        for path_obj in paths_for_delete:
            self.all_saved_paths.remove(path_obj)

        self.net.remove_node(current_dpid)

        if len(self.datapaths) == 0:
            self.net = nx.DiGraph()
            self.all_saved_paths = []

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        paths_for_delete = []
        datapath = msg.datapath
        dpid = datapath.id
        cookie = msg.cookie
        if len(self.all_saved_paths) > 0:
            for path_obj in self.all_saved_paths:
                path_dpids = path_obj[2]
                path_id = path_obj[3]
                if cookie == path_id:
                    path = path_dpids
                    for datapath_id in path[1:len(path) - 1]:
                        if datapath_id != dpid:
                            self.delete_flow(self.datapaths[datapath_id], cookie)
                    self.logger.info("Delete path id : %s path : %s", cookie, path_obj)
                    paths_for_delete.append(path_obj)

        for path_obj in paths_for_delete:
            self.all_saved_paths.remove(path_obj)


    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        self.refresh_topology_data()