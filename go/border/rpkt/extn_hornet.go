package rpkt

/*
#cgo LDFLAGS: -lhornet -lscion

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hornet.h>
#include <scion/scion.h>
*/
import "C"
import (
	"net"
	"unsafe"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/spath"
	"github.com/netsec-ethz/scion/go/lib/spkt"
	"github.com/netsec-ethz/scion/go/lib/l4"
)

var _ rExtension = (*rHORNET)(nil)

// rHORNET is the router's representation of the HORNET extension.
type rHORNET struct {
	log.Logger
	rp *RtrPkt
	spkt.HORNET
}

func rHORNETFromRaw(rp *RtrPkt) (*rHORNET, *common.Error) {
	o := &rHORNET{rp: rp}
	o.Logger = rp.Logger.New("ext", "HORNET")
	o.rp = rp
	return o, nil
}

func (o *rHORNET) RegisterHooks(h *hooks) *common.Error {
	h.Process = append(h.Process, o.rp.ProcessHORNET)
	return nil
}

func (rp *RtrPkt) ProcessHORNET() (HookResult, *common.Error) {
	// During NeedsLocalProcessing() in the method isDestSelf() of process.go rp.DirTo will be changed to DirLocal
	// because the port of the border router differs from the destination port in the l4 header and rp.forward will
	// be added to the route hooks of the packet.
	// We need to remove it because we do the routing ourselves in this method here.
	rp.hooks.Route = []hookRoute{}

	var idx int
	for _, extnIdx := range rp.idxs.hbhExt {
		if extnIdx.Type == common.ExtnHORNETType {
			idx = extnIdx.Index
		}
	}

	cmnHdrType := (C.CommonHeaderType)(rp.Raw[idx+3])

	// We need this cast, otherwise we get the following compilation error:
	// cannot use rp.Ctx.Conf.HORNETNode (type *conf.C.struct_HornetNode) as type *C.struct_HornetNode
	hornet_node := (*C.HornetNode)(unsafe.Pointer(rp.Ctx.Conf.HORNETNode))

	if C.is_setup_packet(cmnHdrType) {
		rp.Logger.Info("HORNET packet", "type", "SETUP")
		var packet_header C.SetupPacketHeader
		var anon_header C.SetupAnonymousHeader
		// TODO: shouldn't be necessary, but failed in the past without it... check if still needed
		var fs [800]C.uint8_t
		anon_header.max_hops = 7
		packet_header.anonymous_header = &anon_header
		packet_header.forwarding_segments = (*C.uint8_t)(unsafe.Pointer(&fs))

		var hornet_header_len C.int
		max_hops := rp.Raw[idx+4]
		hornet_header_len = C.COMMON_HDR_LEN + C.GROUP_ELEM_LEN + C.setup_anonymous_header_calc_len(C.int(max_hops)) + C.int(max_hops) * (C.FORWARDING_SEGMENT_LEN + C.ANONYMOUS_HEADER_MAC_LEN)

		C.setup_packet_header_from_bytes((*C.uint8_t)(unsafe.Pointer(&rp.Raw[idx+3])), hornet_header_len, &packet_header)

		var process_info C.ProcessInfo

		res := C.hornet_node_setup_extract_info(hornet_node, &packet_header, &process_info)
		if res != C.HORNET_SUCCESS {
			return HookError, common.NewError("Extracting info from HORNET setup packet failed")
		}

		ingress_ifid := C.routing_info_get_ingress_interface_id(&process_info.routing_information)
		egress_ifid := int(C.routing_info_get_egress_interface_id(&process_info.routing_information))
		has_addr := C.routing_info_has_address(&process_info.routing_information)

		if rp.Ctx.Conf.BR.IF.IFID == egress_ifid || egress_ifid == 0 {
			// this is the handling router

			res = C.hornet_node_setup_process(hornet_node, &packet_header, &process_info)
			if res != C.HORNET_SUCCESS {
				return HookError, common.NewError("Processing HORNET setup packet failed")
			}

			res = C.hornet_node_store_segment(hornet_node, &packet_header, &process_info)
			if res != C.HORNET_SUCCESS {
				return HookError, common.NewError("Storing segment in HORNET setup packet failed")
			}

			serialized_header := make([]uint8, hornet_header_len)
			C.setup_packet_header_to_bytes(&packet_header, (*C.uint8_t)(unsafe.Pointer(&serialized_header[0])))

			C.memcpy(unsafe.Pointer(&rp.Raw[idx+3]), unsafe.Pointer(&serialized_header[0]), C.size_t(hornet_header_len))

			pldlen := int(rp.CmnHdr.TotalLen) - rp.idxs.pld
			payload_bytes_len := C.int(pldlen)
			payload_bytes := (*C.uint8_t)(unsafe.Pointer(&rp.Raw[rp.idxs.pld]))
			layered_payload := make([]C.uint8_t, payload_bytes_len)

			res = C.hornet_node_setup_layer_payload(hornet_node, &packet_header, payload_bytes, payload_bytes_len, &process_info, (*C.uint8_t)(unsafe.Pointer(&layered_payload[0])))
			if res != C.HORNET_SUCCESS {
				return HookError, common.NewError("Layering payload of HORNET setup packet failed")
			}

			C.memcpy(unsafe.Pointer(&rp.Raw[rp.idxs.pld]), unsafe.Pointer(&layered_payload[0]), C.size_t(payload_bytes_len))

			if egress_ifid != 0 && !has_addr {
				// INTER-FWD
				dst := net.UDPAddr{IP: rp.Ctx.Conf.TopoMeta.IFMap[egress_ifid].IF.ToAddr.IP, Port: rp.Ctx.Conf.TopoMeta.IFMap[egress_ifid].IF.ToUdpPort}

				rp.UpdateDestination(rp.Ctx.Conf.TopoMeta.IFMap[egress_ifid].IF.IA, addr.HostIPv4(rp.Ctx.Conf.TopoMeta.IFMap[egress_ifid].IF.ToAddr.IP))
				rp.UpdateL4Header()

				rp.Egress = append(rp.Egress, EgressPair{rp.Ctx.IntfOutFs[spath.IntfID(egress_ifid)], &dst})
				rp.Logger.Info("Packet routed", "decision", "INTER-FWD")
			} else if egress_ifid == 0 && has_addr {
				// DELIVER

				// TODO: use SCION delivery (set DST in SCION header to SCION address from routing information)

				var scion_addr C.SCIONAddr
				C.routing_info_additional_bytes_get_scion_address(&process_info.routing_information, &scion_addr)
				saddr := C.GoBytes(unsafe.Pointer(&scion_addr.host.addr), 4)
				ip := net.IPv4(saddr[0], saddr[1], saddr[2], saddr[3])

				intf := rp.Ctx.Conf.Net.IFs[spath.IntfID(ingress_ifid)]
				dst := &net.UDPAddr{
					IP: 	ip,
					Port:	40000,
				}

				rp.UpdateDestination(rp.Ctx.Conf.IA, addr.HostIPv4(ip))
				rp.UpdateL4Header()

				rp.Egress = append(rp.Egress, EgressPair{rp.Ctx.LocOutFs[intf.LocAddrIdx], dst})
				rp.Logger.Info("Packet routed", "decision", "DELIVER")
			} else {
				// This route should not have been possible
				return HookError, common.NewError("Invalid HORNET route")
			}
		} else {
			// INTRA-FWD
			intf := rp.Ctx.Conf.Net.IFs[*rp.ifCurr]
			nextBR := rp.Ctx.Conf.TopoMeta.IFMap[egress_ifid]
			dst := &net.UDPAddr{IP: nextBR.BasicElem.Addr.IP, Port: nextBR.BasicElem.Port}

			rp.UpdateDestination(rp.Ctx.Conf.IA, addr.HostIPv4(nextBR.BasicElem.Addr.IP))
			rp.UpdateL4Header()

			rp.Egress = append(rp.Egress, EgressPair{rp.Ctx.LocOutFs[intf.LocAddrIdx], dst})
			rp.Logger.Info("Packet routed", "decision", "INTRA-FWD")
		}
	} else {
		rp.Logger.Info("HORNET packet", "type", "DATA")

		var packet_header C.DataPacketHeader
		var anon_header C.AnonymousHeader
		// TODO: shouldn't be necessary, but failed in the past without it... check if still needed
		anon_header.max_hops = 7
		packet_header.anonymous_header = &anon_header

		var hornet_header_len C.int
		max_hops := rp.Raw[idx+4]
		hornet_header_len = C.COMMON_HDR_LEN + C.NONCE_LEN + C.anonymous_header_calc_len(C.int(max_hops))

		C.data_packet_header_from_bytes((*C.uint8_t)(unsafe.Pointer(&rp.Raw[idx+3])), &packet_header)

		var process_info C.ProcessInfo

		res := C.hornet_node_data_extract_info(hornet_node, &packet_header, &process_info)
		if res != C.HORNET_SUCCESS {
			return HookError, common.NewError("Processing HORNET data packet failed")
		}

		ingress_ifid := C.routing_info_get_ingress_interface_id(&process_info.routing_information)
		egress_ifid := int(C.routing_info_get_egress_interface_id(&process_info.routing_information))
		has_addr := C.routing_info_has_address(&process_info.routing_information)

		if rp.Ctx.Conf.BR.IF.IFID == egress_ifid || egress_ifid == 0 {
			// this is the handling router

			res = C.hornet_node_data_process(hornet_node, &packet_header, &process_info)
			if res != C.HORNET_SUCCESS {
				return HookError, common.NewError("Processing HORNET data packet failed")
			}

			serialized_header := make([]uint8, hornet_header_len)
			C.data_packet_header_to_bytes(&packet_header, (*C.uint8_t)(unsafe.Pointer(&serialized_header[0])))

			C.memcpy(unsafe.Pointer(&rp.Raw[idx+3]), unsafe.Pointer(&serialized_header[0]), C.size_t(hornet_header_len))

			pldlen := int(rp.CmnHdr.TotalLen) - rp.idxs.pld
			payload_bytes_len := C.int(pldlen)
			payload_bytes := (*C.uint8_t)(unsafe.Pointer(&rp.Raw[rp.idxs.pld]))
			layered_payload := make([]C.uint8_t, payload_bytes_len)

			res = C.hornet_node_data_layer_payload(hornet_node, &packet_header, payload_bytes, payload_bytes_len, &process_info, (*C.uint8_t)(unsafe.Pointer(&layered_payload[0])))
			if res != C.HORNET_SUCCESS {
				return HookError, common.NewError("Layering payload of HORNET data packet failed")
			}

			C.memcpy(unsafe.Pointer(&rp.Raw[rp.idxs.pld]), unsafe.Pointer(&layered_payload[0]), C.size_t(payload_bytes_len))

			if egress_ifid != 0 && !has_addr {
				// INTER-FWD
				dst := net.UDPAddr{IP: rp.Ctx.Conf.TopoMeta.IFMap[egress_ifid].IF.ToAddr.IP, Port: rp.Ctx.Conf.TopoMeta.IFMap[egress_ifid].IF.ToUdpPort}

				rp.UpdateDestination(rp.Ctx.Conf.TopoMeta.IFMap[egress_ifid].IF.IA, addr.HostIPv4(rp.Ctx.Conf.TopoMeta.IFMap[egress_ifid].IF.ToAddr.IP))
				rp.UpdateL4Header()

				rp.Egress = append(rp.Egress, EgressPair{rp.Ctx.IntfOutFs[spath.IntfID(egress_ifid)], &dst})
				rp.Logger.Info("Packet routed", "decision", "INTER-FWD")
			} else if egress_ifid == 0 && has_addr {
				// DELIVER

				// TODO: use SCION delivery (set DST in SCION header to SCION address from routing information)

				var scion_addr C.SCIONAddr
				C.routing_info_additional_bytes_get_scion_address(&process_info.routing_information, &scion_addr)
				adddr := C.GoBytes(unsafe.Pointer(&scion_addr.host.addr), 4)
				ip := net.IPv4(adddr[0], adddr[1], adddr[2], adddr[3])

				intf := rp.Ctx.Conf.Net.IFs[spath.IntfID(ingress_ifid)]
				dst := &net.UDPAddr{
					IP: 	ip,
					Port:	40000,
				}

				rp.UpdateDestination(rp.Ctx.Conf.IA, addr.HostIPv4(ip))
				rp.UpdateL4Header()

				rp.Egress = append(rp.Egress, EgressPair{rp.Ctx.LocOutFs[intf.LocAddrIdx], dst})
				rp.Logger.Info("Packet routed", "decision", "DELIVER")
			} else {
				// This route should not have been possible
				return HookError, common.NewError("Invalid HORNET route")
			}
		} else {
			// INTRA-FWD
			intf := rp.Ctx.Conf.Net.IFs[*rp.ifCurr]
			nextBR := rp.Ctx.Conf.TopoMeta.IFMap[egress_ifid]
			dst := &net.UDPAddr{IP: nextBR.BasicElem.Addr.IP, Port: nextBR.BasicElem.Port}

			rp.UpdateDestination(rp.Ctx.Conf.IA, addr.HostIPv4(nextBR.BasicElem.Addr.IP))
			rp.UpdateL4Header()

			rp.Egress = append(rp.Egress, EgressPair{rp.Ctx.LocOutFs[intf.LocAddrIdx], dst})
			rp.Logger.Info("Packet routed", "decision", "INTRA-FWD")
		}
	}

	return HookContinue, nil
}

func (rp *RtrPkt) UpdateL4Header() *common.Error {
	// Calculate new checksum
	csum, err := l4.CalcCSum(rp.l4, rp.Raw[rp.idxs.dstIA:rp.idxs.srcHost+rp.srcHost.Size()], rp.Raw[rp.idxs.pld:])
	if err != nil {
		return common.NewError("Checksum calculation of L4 protocol failed")
	}

	// Update checksum in packet
	copy(rp.Raw[rp.idxs.l4+6:], csum)

	return nil

}

func (rp *RtrPkt) UpdateDestination(ia *addr.ISD_AS, host addr.HostAddr) {
	ia.Write(rp.Raw[rp.idxs.dstIA:])
	copy(rp.Raw[rp.idxs.dstHost:], host.Pack())
}

func (o *rHORNET) Type() common.ExtnType {
	return common.ExtnHORNETType
}

func (o *rHORNET) Len() int {
	// TODO:
	return common.ExtnFirstLineLen
}

func (o *rHORNET) String() string {
	return "HORNET"
}

func (o *rHORNET) GetExtn() (common.Extension, *common.Error) {
	return &o.HORNET, nil
}
