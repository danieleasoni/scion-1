// Copyright 2016 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This file handles routing of packets.

package rpkt

import (
	//"fmt"
	"math/rand"
	"net"

	"github.com/netsec-ethz/scion/go/hornet_service/rctx"
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/overlay"
)

// Route handles routing of packets. Registered hooks are called, allowing them
// to add to the packet's Egress slice, and then the slice is iterated over and
// each entry's function is called with the entry's address as the argument.
// The use of a slice allows for a packet to be sent multiple times (e.g.
// sending IFID packets to all BS instances in the local AS).
func (rp *RtrPkt) Route() *common.Error {
	// First allow any registered hooks to either route the packet themselves,
	// or add entries to the Egress slice.
	for _, f := range rp.hooks.Route {
		ret, err := f()
		switch {
		case err != nil:
			return err
		case ret == HookContinue:
			continue
		case ret == HookFinish:
			// HookFinish in this context means "the packet has already been
			// routed".
			return nil
		}
	}
	// Call all egress functions.
	for _, epair := range rp.Egress {
		epair.F(rp, epair.Dst)
	}
	return nil
}

// RouteResolveSVC is a hook to resolve SVC addresses for routing packets to
// the local ISD-AS.
//func (rp *RtrPkt) RouteResolveSVC() (HookResult, *common.Error) {
//	svc, ok := rp.dstHost.(addr.HostSVC)
//	if !ok {
//		return HookError, common.NewError("Destination host is NOT an SVC address",
//			"actual", rp.dstHost, "type", fmt.Sprintf("%T", rp.dstHost))
//	}
//	// Use any local output function in case the packet has no path (e.g., ifstate requests)
//	//f := rp.Ctx.LocOutFs[0]
//	//if rp.ifCurr != nil {
//	//	intf := rp.Ctx.Conf.Net.IFs[*rp.ifCurr]
//	//	f = rp.Ctx.LocOutFs[intf.LocAddrIdx]
//	//}
//	if svc.IsMulticast() {
//		return rp.RouteResolveSVCMulti(svc, f)
//	}
//	return rp.RouteResolveSVCAny(svc, f)
//}

// RouteResolveSVCAny handles routing a packet to an anycast SVC address (i.e.
// a single instance of a local infrastructure service).
func (rp *RtrPkt) RouteResolveSVCAny(
	svc addr.HostSVC, f rctx.OutputFunc) (HookResult, *common.Error) {
	names, elemMap, err := getSVCNamesMap(svc, rp.Ctx)
	if err != nil {
		return HookError, err
	}
	// XXX(kormat): just pick one randomly. TCP will remove the need to have
	// consistent selection for a given source.
	name := names[rand.Intn(len(names))]
	elem := elemMap[name]
	dst := &net.UDPAddr{IP: elem.Addr.IP, Port: overlay.EndhostPort}
	rp.Egress = append(rp.Egress, EgressPair{f, dst})
	return HookContinue, nil
}

// RouteResolveSVCMulti handles routing a packet to a multicast SVC address
// (i.e. one packet per machine hosting instances for a local infrastructure
// service).
func (rp *RtrPkt) RouteResolveSVCMulti(
	svc addr.HostSVC, f rctx.OutputFunc) (HookResult, *common.Error) {
	_, elemMap, err := getSVCNamesMap(svc, rp.Ctx)
	if err != nil {
		return HookError, err
	}
	// Only send once per IP address.
	seen := make(map[string]bool)
	for _, elem := range elemMap {
		strIP := string(elem.Addr.IP)
		if _, ok := seen[strIP]; ok {
			continue
		}
		seen[strIP] = true
		dst := &net.UDPAddr{IP: elem.Addr.IP, Port: overlay.EndhostPort}
		rp.Egress = append(rp.Egress, EgressPair{f, dst})
	}
	return HookContinue, nil
}

func (rp *RtrPkt) forward() (HookResult, *common.Error) {
	conn, err := net.Dial("udp", rp.destination)
	if err != nil {
		return HookError, common.NewError("Couldn't create socket", "err", err)
	}
	defer conn.Close()
	_, err = conn.Write(rp.Raw)
	if err != nil {
		return HookError, common.NewError("Couldn't send packet", "err", err)
	}
	return HookContinue, nil
}
