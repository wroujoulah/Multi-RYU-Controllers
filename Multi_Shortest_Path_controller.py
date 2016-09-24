from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.topology.api import get_switch, get_link, get_host

from ryu.lib.packet import ipv4
from ryu.topology import event

import networkx as nx
import random
import network_monitor_group


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        "network_monitor": network_monitor_group.NetworkMonitor}

    MAX_PATH_ID = 10000
    MIN_PATH_ID = 1


    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.monitor = kwargs["network_monitor"]
        self.mac_to_port = {}
        self.net = nx.DiGraph()
        self.all_saved_paths = []
        self.datapaths = {}
        self.group_ids = []

    @set_ev_cls(ofp_event.EventOFPStateChange,
                    [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.info('register datapath: %s', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.info('unregister datapath: %s', datapath.id)
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

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, path_id =0, hard_timeout=0, idle_timeout=0, flags=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if priority != 0:
            hard_timeout = 0
            idle_timeout = 40
            flags = ofproto.OFPFF_SEND_FLOW_REM

        cookie = cookie_mask = path_id
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, flags=flags, cookie=cookie, cookie_mask=cookie_mask,
                                    hard_timeout=hard_timeout,idle_timeout=idle_timeout, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, flags=flags, cookie=cookie,
                                    cookie_mask=cookie_mask,
                                    match=match, hard_timeout=hard_timeout,idle_timeout=idle_timeout, instructions=inst)
        datapath.send_msg(mod)

    def delete_flow(self, datapath, path_id ,table_id=0):
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

    def add_group(self, datapath, next_dpids_outports, group_id):
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        out_ports = []
        actions = []
        buckets = []
        watch_port = ofproto_v1_3.OFPP_ANY
        watch_group = ofproto_v1_3.OFPQ_ALL
        for dpids_outports in next_dpids_outports:
            outport = dpids_outports[1]
            if outport not in out_ports:
                out_ports.append(outport)
        weight = 1
        i = 0
        max_len = 2000
        while i < len(out_ports):
            actions.append([ofp_parser.OFPActionOutput(out_ports[i], max_len)])
            buckets.append(ofp_parser.OFPBucket(weight, watch_port, watch_group, actions[i]))
            i += 1
        req = ofp_parser.OFPGroupMod(datapath, ofproto.OFPFC_ADD,
                                     ofproto.OFPGT_SELECT, group_id, buckets)

        datapath.send_msg(req)

    def delete_group(self, datapath, group_id):
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPGroupMod(datapath, ofproto.OFPGC_DELETE,
                                     ofproto.OFPGT_SELECT, group_id)
        datapath.send_msg(req)

    def refresh_topology_data(self):
        switch_list = get_switch(self, None)
        switches = [switch.dp.id for switch in switch_list]
        self.net.add_nodes_from(switches)
        links_list = get_link(self, None)
        for link in links_list:
            self.net.add_edge(link.src.dpid, link.dst.dpid, {'port': link.src.port_no})
        try:
            hosts = [host.mac for host in get_host(self)]
            for (src, dst, data) in self.net.edges(data=True):
                try:
                    if dst in hosts:
                        self.net.add_edge(src, dst, {'port': data['port']})
                except:
                    self.logger.debug("error %s ", src)
            return
        except:
            self.logger.debug("error")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
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
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        group_id = 0
        path_id = 0
        is_path_found = False

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        hosts = [host.mac for host in get_host(self)]
        if src not in self.net and is_path_found is False and src in hosts:
            self.net.add_node(src)
            self.net.add_edge(dpid, src, {'port': in_port})
            self.net.add_edge(src, dpid)

        # ignore lldp packet
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        # ignore ipv6 packet
        if eth.ethertype == ether_types.ETH_TYPE_IPV6:
            return

        for multipath_obj in self.all_saved_paths:
            multipath_obj_src = multipath_obj[0]
            multipath_obj_dst = multipath_obj[1]
            multipath_obj_paths = multipath_obj[2]
            multipath_obj_dpids = multipath_obj[3]
            multipath_obj_id = multipath_obj[4]
            if multipath_obj_src == src and multipath_obj_dst == dst:
                if (self.is_dpid_in_paths(dpid, multipath_obj_paths)) and (dpid not in list(multipath_obj_dpids)):
                    next_dpids_outports = self.get_next_dpids_outports(dpid, multipath_obj_paths)
                    multipath_obj_dpids.append(dpid)
                    outswitch = next_dpids_outports[0]
                    out_port = outswitch[1]
                    path_id = group_id = multipath_obj_id
                    self.group_ids.append(group_id)
                    self.add_group(datapath, next_dpids_outports, group_id)
                    is_path_found = True
                    break
                else:
                    return

        if dst in self.net and is_path_found is False:
            self.refresh_topology_data()
            if nx.has_path(self.net, src, dst):
                new_paths = list(nx.all_shortest_new_paths(self.net, src, dst))
                if not self.is_dpid_in_new_paths(dpid, new_paths):
                    return
                dpids = [dpid]
                path_id = group_id = int(random.uniform(self.MIN_PATH_ID, self.MAX_PATH_ID))
                while group_id in self.group_ids:
                    path_id = group_id = int(random.uniform(self.MIN_PATH_ID, self.MAX_PATH_ID))
                self.all_saved_paths.append([src, dst, new_paths, dpids, path_id])
                for new_path in new_paths:
                    self.logger.info("Add path Id : %s path : %s", path_id, new_path)
                next_dpids_outports = self.get_next_dpids_outports(dpid, new_paths)
                outswitch_outport = next_dpids_outports[0]
                out_port = outswitch_outport[1]
                self.group_ids.append(group_id)
                self.add_group(datapath, next_dpids_outports, group_id)
            else:
                out_port = ofproto.OFPP_FLOOD
                actions = [parser.OFPActionOutput(out_port)]

        elif is_path_found is False:
            out_port = ofproto.OFPP_FLOOD
            actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofproto.OFPP_FLOOD:
            group_action = [parser.OFPActionGroup(group_id=group_id)]
            match = parser.OFPMatch(eth_type=eth.ethertype,eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, group_action, msg.buffer_id, path_id=path_id)
                return
            else:
                self.add_flow(datapath, 1, match, group_action, path_id=path_id)
                actions = [parser.OFPActionOutput(out_port)]
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
            self.net.add_edge(link.src.dpid, link.dst.dpid, {'port': link.src.port_no})

    @set_ev_cls(event.EventSwitchLeave)
    def get_new_topology_data(self, ev):
        current_dpid = ev.switch.dp.id
        self.logger.info("switch leaved %s", ev.switch.dp.id)
        paths_for_delete = []
        if len(self.all_saved_paths) > 0:
            for multipath_obj in self.all_saved_paths:
                multipath_obj_dpids = multipath_obj[3]
                multipath_obj_id = multipath_obj[4]
                if (current_dpid in list(multipath_obj_dpids)):
                    for datapath in self.datapaths.values():
                        if datapath.id in multipath_obj_dpids:
                            self.delete_flow(datapath, multipath_obj_id)
                            self.delete_group(datapath, multipath_obj_id)
                    paths_for_delete.append(multipath_obj)
        for multipath_obj in paths_for_delete:
            self.all_saved_paths.remove(multipath_obj)
        self.net.remove_node(current_dpid)
        if len(self.datapaths) == 0:
            self.net = nx.DiGraph()
            self.all_saved_paths = []

    def get_next_dpids_outports(self, current_dpid, paths):
        next_dpids = []
        for path in list(paths):
            if current_dpid in list(path):
                next_dpid = path[path.index(current_dpid) + 1]
                out_port = self.net[current_dpid][next_dpid]['port']
                next_dpids.append((next_dpid, out_port))
        return next_dpids

    def get_out_ports(self, dpid, next_dpids):
        out_ports = []
        for next_dpid in list(next_dpids):
            out_port = self.net[dpid][next_dpid]['port']
            out_ports.append(out_port)
        return out_ports

    def is_dpid_in_paths(self, dpid, paths):
        for path in list(paths):
            if dpid in path:
                return True
        return False

    def print_paths(self):
        for path in self.all_saved_paths:
            print path

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        paths_for_delete = []
        datapath = msg.datapath
        ofproto = datapath.ofproto
        dpid = datapath.id
        match = msg.match
        cookie = msg.cookie
        if len(self.all_saved_paths) > 0:
            for multipath_obj in self.all_saved_paths:
                multipath_obj_paths = multipath_obj[2]
                multipath_obj_dpids = multipath_obj[3]
                multipath_obj_id = multipath_obj[4]
                if cookie == multipath_obj_id:
                    for datapath_id in multipath_obj_dpids:
                        if datapath_id != dpid:
                            self.delete_flow(self.datapaths[datapath_id], multipath_obj_id)
                            self.delete_group(self.datapaths[datapath_id], multipath_obj_id)
                    for path in multipath_obj_paths:
                        self.logger.info("Delete path id : %s path : %s", multipath_obj_id, multipath_obj)
                    paths_for_delete.append(multipath_obj)

        for multipath_obj in paths_for_delete:
            self.all_saved_paths.remove(multipath_obj)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        self.refresh_topology_data()