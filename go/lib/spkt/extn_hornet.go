package spkt

import (
	"github.com/netsec-ethz/scion/go/lib/common"
)

var _ common.Extension = (*HORNET)(nil)

type HORNET struct{}

// TODO:
const HORNETLen = common.ExtnFirstLineLen

func (o HORNET) Write(b common.RawBytes) *common.Error {
	// TODO:
	copy(b, make(common.RawBytes, HORNETLen))
	return nil
}

func (o HORNET) Pack() (common.RawBytes, *common.Error) {
	// TODO:
	b := make(common.RawBytes, o.Len())
	if err := o.Write(b); err != nil {
		return nil, err
	}
	return b, nil
}

func (o HORNET) Copy() common.Extension {
	// TODO:
	return &HORNET{}
}

func (o HORNET) Reverse() (bool, *common.Error) {
	// TODO:
	// Reversing removes the extension.
	return false, nil
}

func (o HORNET) Len() int {
	// TODO:
	return HORNETLen
}

func (o HORNET) Class() common.L4ProtocolType {
	return common.HopByHopClass
}

func (o HORNET) Type() common.ExtnType {
	return common.ExtnHORNETType
}

func (o *HORNET) String() string {
	return "HORNET"
}
