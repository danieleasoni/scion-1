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

// Package conf holds all of the global router state, for access by the
// router's various packages.
package conf

/*
#cgo LDFLAGS: -lhornet -lscion

#include <stdlib.h>
#include <string.h>
#include <hornet.h>

HornetNode* allocate_hornet_node() {
	return (HornetNode *) malloc(sizeof(HornetNode));
}
*/
import "C"
import (
	"crypto/sha256"
	"encoding/base64"
	"path/filepath"
	"io/ioutil"
	"sync"
	"unsafe"

	"golang.org/x/crypto/pbkdf2"

	//"github.com/netsec-ethz/scion/go/hornet_service/netconf"
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/as_conf"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/sciond"
	"github.com/netsec-ethz/scion/go/lib/topology"
	"github.com/netsec-ethz/scion/go/lib/util"
)

// Conf is the main config structure.
type Conf struct {
	// TopoMeta contains the names of all local infrastructure elements, a map
	// of interface IDs to routers, and the actual topology.
	TopoMeta *topology.TopoMeta
	// IA is the current ISD-AS.
	IA *addr.ISD_AS
	// BR is the topology information of this router.
	BR *topology.TopoBR
	// HS is the topology information of this HORNET service.
	HS *topology.TopoHS
	// ASConf is the local AS configuration.
	ASConf *as_conf.ASConf
	// HFMacPool is the pool of Hop Field MAC generation instances.
	HFMacPool sync.Pool
	// Net is the network configuration of this router.
	//Net *netconf.NetConf
	// Dir is the configuration directory.
	Dir string
	// HORNET configuration
	HORNETNode *C.HornetNode
	// Path cache
	PathCache map[*addr.ISD_AS]sciond.FwdPathMeta

	// TODO: temp
	BR1_11_1 topology.TopoBR
	BR1_11_2 topology.TopoBR
	BR1_12_1 topology.TopoBR
	BR1_13_1 topology.TopoBR

	HS1_11_1 topology.BasicElem
	HS1_12_1 topology.BasicElem
	HS1_13_1 topology.BasicElem
}

// Load sets up the configuration, loading it from the supplied config directory.
func Load(id, confDir string) (*Conf, *common.Error) {
	var err *common.Error

	// Declare a new Conf instance, and load the topology config.
	conf := &Conf{}
	conf.Dir = confDir
	topoPath := filepath.Join(conf.Dir, topology.CfgName)
	if conf.TopoMeta, err = topology.Load(topoPath); err != nil {
		return nil, err
	}
	conf.IA = conf.TopoMeta.T.IA
	// Find the config for this router.

	topoHS, ok := conf.TopoMeta.T.HS[id]
	if !ok {
		return nil, common.NewError("Unable to find element ID in topology", "id", id, "path", topoPath, "topo", conf.TopoMeta.T.HS)
	}
	conf.HS = &topoHS
	// Load AS configuration
	asConfPath := filepath.Join(conf.Dir, as_conf.CfgName)
	if err = as_conf.Load(asConfPath); err != nil {
		return nil, err
	}
	conf.ASConf = as_conf.CurrConf

	// Generate keys
	// This uses 16B keys with 1000 hash iterations, which is the same as the
	// defaults used by pycrypto.
	hfGenKey := pbkdf2.Key(conf.ASConf.MasterASKey, []byte("Derive OF Key"), 1000, 16, sha256.New)

	// First check for MAC creation errors.
	if _, err = util.InitMac(hfGenKey); err != nil {
		return nil, err
	}
	// Create a pool of MAC instances.
	conf.HFMacPool = sync.Pool{
		New: func() interface{} {
			mac, _ := util.InitMac(hfGenKey)
			return mac
		},
	}

	// TODO: temporary
	topo_1_11, _ := topology.Load("gen/ISD1/AS11/endhost/topology.yml")
	topo_1_12, _ := topology.Load("gen/ISD1/AS12/endhost/topology.yml")
	topo_1_13, _ := topology.Load("gen/ISD1/AS13/endhost/topology.yml")

	conf.BR1_11_1 = topo_1_11.T.BR["br1-11-1"]
	conf.BR1_11_2 = topo_1_11.T.BR["br1-11-2"]
	conf.BR1_12_1 = topo_1_12.T.BR["br1-12-1"]
	conf.BR1_13_1 = topo_1_13.T.BR["br1-13-1"]

	conf.HS1_11_1 = topo_1_11.T.HS["hs1-11-1"].BasicElem
	conf.HS1_12_1 = topo_1_12.T.HS["hs1-12-1"].BasicElem
	conf.HS1_13_1 = topo_1_13.T.HS["hs1-13-1"].BasicElem

	// Create network configuration
	//conf.Net = netconf.FromTopo(conf.BR)

	// Create HORNET configuration
	node := C.allocate_hornet_node()
	as_master_key := conf.ASConf.MasterASKey
	var AS_HORNET_KEY C.Secret
	rc := C.derive_secret((*[16]C.uint8_t)(unsafe.Pointer(&as_master_key[0])), C.MASTER_HORNET_KEY, &AS_HORNET_KEY)
	if rc != C.HORNET_SUCCESS {
		return nil, err
	}
	key_data, ioerr := ioutil.ReadFile(conf.Dir + "/keys/as-decrypt.key")
	if ioerr != nil {
		return nil, err
	}
	AS_PRIVATE_KEY, _ := base64.StdEncoding.DecodeString(string(key_data))
	C.memcpy(unsafe.Pointer(&node.secret_value), unsafe.Pointer(&AS_HORNET_KEY), C.SECRET_LEN)
	C.memcpy(unsafe.Pointer(&node.encryption_key), unsafe.Pointer(&AS_PRIVATE_KEY[0]), C.PRIVATE_KEY_LEN)
	conf.HORNETNode = node

	// Save config
	return conf, nil
}
