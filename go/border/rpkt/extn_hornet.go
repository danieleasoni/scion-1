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
	//"net"
	//"unsafe"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/common"
	//"github.com/netsec-ethz/scion/go/lib/spath"
	"github.com/netsec-ethz/scion/go/lib/spkt"
	//"github.com/netsec-ethz/scion/go/lib/l4"
	//"github.com/netsec-ethz/scion/go/lib/addr"
	//"github.com/netsec-ethz/scion/go/lib/addr"
	//"net"
	//"github.com/netsec-ethz/scion/go/lib/spath"
	//"unsafe"
	//"github.com/netsec-ethz/scion/go/lib/spath"
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
	//h.Process = append(h.Process, o.rp.processHORNET)
	o.rp.Logger.Info("HORNET packet")
	return nil
}

// FIXME: remove, is obsolete for HORNET service
//        should actually change HORNET to end-to-end extension
func (rp *RtrPkt) processHORNET() (HookResult, *common.Error) {
	return HookContinue, nil
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
