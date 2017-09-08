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

// This file contains the main router processing loop.

package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/gavv/monotime"
	log "github.com/inconshreveable/log15"
	logext "github.com/inconshreveable/log15/ext"

	"github.com/netsec-ethz/scion/go/hornet_service/conf"
	"github.com/netsec-ethz/scion/go/hornet_service/metrics"
	"github.com/netsec-ethz/scion/go/hornet_service/rpkt"
	"github.com/netsec-ethz/scion/go/lib/assert"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/log"
)

type HornetService struct {
	// Id is the SCION element ID, e.g. "br4-21-9".
	Id string
	// confDir is the directory containing the configuration file.
	confDir string
	// freePkts is a buffered channel for recycled packets. See
	// Router.recyclePkt
	freePkts chan *rpkt.RtrPkt
	// revInfoQ is a channel for handling RevInfo payloads.
	revInfoQ chan rpkt.RevTokenCallbackArgs
}

func NewHornetService(id, confDir string) (*HornetService, *common.Error) {
	hsvc := &HornetService{Id: id, confDir: confDir}
	if err := hsvc.setup(); err != nil {
		return nil, err
	}
	return hsvc, nil
}

// Run sets up networking, and starts go routines for handling the main packet
// processing as well as various other router functions.
func (hsvc *HornetService) Run() *common.Error {
	go hsvc.confSig()
	// TODO(shitz): Here should be some code to periodically check the discovery
	// service for updated info.
	var wait chan struct{}
	<-wait
	return nil
}

// confSig handles reloading the configuration when SIGHUP is received.
func (hsvc *HornetService) confSig() {
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGHUP)
	go func() {
		for range sig {
			var err *common.Error
			var config *conf.Conf
			if config, err = hsvc.loadNewConfig(); err != nil {
				log.Error("Error reloading config", err.Ctx...)
				continue
			}
			if err = hsvc.setupNewContext(config); err != nil {
				log.Error("Error setting up new context", err.Ctx...)
				continue
			}
			log.Info("Config reloaded")
		}
	}()
}

func (hsvc *HornetService) handleQueue(q chan *rpkt.RtrPkt) {
	defer liblog.PanicLog()
	for rp := range q {
		hsvc.processPacket(rp)
		metrics.PktProcessTime.Add(monotime.Since(rp.TimeIn).Seconds())
		hsvc.recyclePkt(rp)
	}
}

// processPacket is the heart of the router's packet handling. It delegates
// everything from parsing the incoming packet, to routing the outgoing packet.
func (hsvc *HornetService) processPacket(rp *rpkt.RtrPkt) {
	defer liblog.PanicLog()
	if assert.On {
		assert.Must(len(rp.Raw) > 0, "Raw must not be empty")
		assert.Must(rp.DirFrom != rpkt.DirUnset, "DirFrom must be set")
		assert.Must(rp.TimeIn != 0, "TimeIn must be set")
		assert.Must(rp.Ingress.Dst != nil, "Ingress.Dst must be set")
		assert.Must(rp.Ingress.Src != nil, "Ingress.Src must be set")
		assert.Must(len(rp.Ingress.IfIDs) > 0, "Ingress.IfIDs must not be empty")
		assert.Must(rp.Ctx != nil, "Context must be set")
	}
	// Assign a pseudorandom ID to the packet, for correlating log entries.
	rp.Id = logext.RandId(4)
	rp.Logger = log.New("rpkt", rp.Id)
	// XXX(kormat): uncomment for debugging:
	//rp.Debug("processPacket", "raw", rp.Raw)
	rp.Logger.Info("Received packet", "length", len(rp.Raw))
	if err := rp.Parse(); err != nil {
		//r.handlePktError(rp, err, "Error parsing packet")
		rp.Logger.Error("Error parsing packet")
		return
	}
	// Validation looks for errors in the packet that didn't break basic
	// parsing.
	if err := rp.Validate(); err != nil {
		//r.handlePktError(rp, err, "Error validating packet")
		rp.Logger.Error("Error validating packet")
		return
	}
	// Check if the packet needs to be processed locally, and if so register
	// hooks for doing so.
	if err := rp.NeedsLocalProcessing(); err != nil {
		rp.Error("Error checking for local processing", err.Ctx...)
		return
	}
	// Parse the packet payload, if a previous step has registered a relevant
	// hook for doing so.
	if _, err := rp.Payload(true); err != nil {
		// Any errors at this point are application-level, and hence not
		// calling handlePktError, as no SCMP errors will be sent.
		rp.Error("Error parsing payload", err.Ctx...)
		return
	}
	// Process the packet, if a previous step has registered a relevant hook
	// for doing so.
	if err := rp.Process(); err != nil {
		rp.Error("Error processing packet", err.Ctx...)
		return
	}
	// If the packet's destination is this router, there's no need to forward
	// it.
	if rp.DirTo != rpkt.DirSelf {
		if err := rp.Route(); err != nil {
			rp.Error("Error routing packet", err.Ctx...)
		}
	}
}

// getPktBuf implements a leaky buffer list, as described
// here: https://golang.org/doc/effective_go.html#leaky_buffer
func (hsvc *HornetService) getPktBuf() *rpkt.RtrPkt {
	select {
	case rp := <-hsvc.freePkts:
		// Got one
		metrics.PktBufReuse.Inc()
		return rp
	default:
		// None available, allocate a new one
		metrics.PktBufNew.Inc()
		return rpkt.NewRtrPkt()
	}
}

// recyclePkt readies a packet for the leaky buffer list (see getPktBuf).
func (hsvc *HornetService) recyclePkt(rp *rpkt.RtrPkt) {
	rp.Reset()
	select {
	case hsvc.freePkts <- rp:
		// Packet added to free list
	default:
		// Free list full, carry on
		metrics.PktBufDiscard.Inc()
	}
}
