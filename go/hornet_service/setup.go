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

// This file handles the router setup, from getting the config loaded, to
// configuring the network interfaces, and starting the input goroutines.
// Support for POSIX(/BSD) sockets is included here, with hooks to allow other
// network stacks to be loaded instead/additionally.

package main

import (
	"fmt"
	"net"

	log "github.com/inconshreveable/log15"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/syndtr/gocapability/capability"

	"github.com/netsec-ethz/scion/go/hornet_service/conf"
	"github.com/netsec-ethz/scion/go/hornet_service/netconf"
	"github.com/netsec-ethz/scion/go/hornet_service/rctx"
	"github.com/netsec-ethz/scion/go/hornet_service/rpkt"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/overlay"
	"github.com/netsec-ethz/scion/go/lib/spath"
	"github.com/netsec-ethz/scion/go/lib/sciond"
	"time"
	"github.com/netsec-ethz/scion/go/lib/addr"
)

type setupNetHook func(hsvc *HornetService, ctx *rctx.Ctx,
	oldCtx *rctx.Ctx) (rpkt.HookResult, *common.Error)
type setupAddLocalHook func(hsvc *HornetService, ctx *rctx.Ctx, idx int, over *overlay.UDP,
	labels prometheus.Labels, oldCtx *rctx.Ctx) (rpkt.HookResult, *common.Error)
type setupPosixHook func(hsvc *HornetService, ctx *rctx.Ctx, over *overlay.UDP) (rpkt.HookResult, *common.Error)
type setupAddExtHook func(hsvc *HornetService, ctx *rctx.Ctx, intf *netconf.Interface,
	labels prometheus.Labels, oldCtx *rctx.Ctx) (rpkt.HookResult, *common.Error)

// Setup hooks enables the network stack to be modular. Any network stack that
// wants to be included defines its own init function which adds hooks to these
// hook slices. See setup-hsr.go for an example.
var setupNetStartHooks []setupNetHook
var setupPosixHooks []setupPosixHook
var setupNetFinishHooks []setupNetHook

// setup creates the router's channels and map, sets up the rpkt package, and
// sets up a new router context. This function can only be called once during startup.
func (hsvc *HornetService) setup() *common.Error {
	hsvc.freePkts = make(chan *rpkt.RtrPkt, 1024)
	hsvc.revInfoQ = make(chan rpkt.RevTokenCallbackArgs)

	setupPosixHooks = append(setupPosixHooks, setupPosix)

	// Load config.
	var err *common.Error
	var config *conf.Conf
	if config, err = hsvc.loadNewConfig(); err != nil {
		return err
	}
	// Setup new context.
	if err = hsvc.setupNewContext(config); err != nil {
		return err
	}
	// Clear capabilities after setting up the network. Capabilities are currently
	// only needed by the HSR for which the router never reconfigures the network.
	if err = hsvc.clearCapabilities(); err != nil {
		return err
	}

	// Periodically setup path cache
	ticker := time.NewTicker(1 * time.Second)
	go func() {
		for range ticker.C {
			if err = hsvc.setupPathCache(); err != nil {
				log.Warn("Couldn't update path cache", "err", err.Error())
				//return err
			}
		}
	}()

	return nil
}

// clearCapabilities drops unnecessary capabilities after startup
func (hsvc *HornetService) clearCapabilities() *common.Error {
	caps, err := capability.NewPid(0)
	if err != nil {
		return common.NewError("Error retrieving capabilities", "err", err)
	}
	log.Debug("Startup capabilities", "caps", caps)
	caps.Clear(capability.CAPS)
	caps.Apply(capability.CAPS)
	caps.Load()
	log.Debug("Cleared capabilities", "caps", caps)
	return nil
}

// loadNewConfig loads a new conf.Conf object from the configuration file.
func (hsvc *HornetService) loadNewConfig() (*conf.Conf, *common.Error) {
	var config *conf.Conf
	var err *common.Error
	if config, err = conf.Load(hsvc.Id, hsvc.confDir); err != nil {
		return nil, err
	}
	log.Debug("Topology loaded", "topo", config.BR)
	log.Debug("AS Conf loaded", "conf", config.ASConf)
	return config, nil
}

func (hsvc *HornetService) setupPathCache() *common.Error {
	conf := rctx.Get().Conf

	if conf.PathCache == nil {
		conf.PathCache = make(map[*addr.ISD_AS]sciond.FwdPathMeta)
	}

	// create connection to SCION daemon
	conn, err := sciond.Connect(fmt.Sprintf("/run/shm/sciond/sd%s.sock", conf.IA.String()))
	if err != nil {
		return common.NewError(err.Error())
	}
	defer conn.Close()

	max := uint16(10)
	flags := sciond.PathReqFlags{Flush: false, Sibra: false}

	for _, brname := range conf.TopoMeta.BRNames {
		ia := conf.TopoMeta.T.BR[brname].IF.IA
		// get path to neighboring ISD-AS
		reply, err := conn.Paths(ia, conf.IA, max, flags)
		if err != nil {
			return common.NewError(err.Error())
		}
		if reply.ErrorCode != sciond.ErrorOk {
			return common.NewError(reply.ErrorCode.String())
		}
		// TODO: for now just take the first path in the reply
		conf.PathCache[ia] = reply.Entries[0].Path
	}

	return nil
}

// setupNewContext sets up a new router context.
func (hsvc *HornetService) setupNewContext(config *conf.Conf) *common.Error {
	oldCtx := rctx.Get()
	ctx := rctx.New(config)
	if err := hsvc.setupNet(ctx, oldCtx); err != nil {
		return err
	}
	rctx.Set(ctx)
	ctx.InputF.Start()

	return nil
}

// setupNet configures networking for the router, using any setup hooks that
// have been registered. If an old context is provided, setupNet reconfigures
// networking, e.g., starting/stopping new/old input routines if necessary.
func (hsvc *HornetService) setupNet(ctx *rctx.Ctx, oldCtx *rctx.Ctx) *common.Error {
	// Run startup hooks, if any.
	for _, f := range setupNetStartHooks {
		ret, err := f(hsvc, ctx, oldCtx)
		switch {
		case err != nil:
			return err
		case ret == rpkt.HookContinue:
			continue
		case ret == rpkt.HookFinish:
			break
		}
	}
	for _, f := range setupPosixHooks {
		topoHS := ctx.Conf.TopoMeta.T.HS[hsvc.Id]
		ret, err := f(hsvc, ctx, overlay.NewUDP(topoHS.Addr.IP, topoHS.Port))
		switch {
		case err != nil:
			return err
		case ret == rpkt.HookContinue:
			continue
		case ret == rpkt.HookFinish:
			break
		}
	}

	// Run finish hooks, if any.
	for _, f := range setupNetFinishHooks {
		ret, err := f(hsvc, ctx, oldCtx)
		switch {
		case err != nil:
			return err
		case ret == rpkt.HookContinue:
			continue
		case ret == rpkt.HookFinish:
			break
		}
	}

	return nil
}

func setupPosix(hsvc *HornetService, ctx *rctx.Ctx, over *overlay.UDP) (rpkt.HookResult, *common.Error) {
	if err := over.Listen(); err != nil {
		return rpkt.HookError, common.NewError("Unable to listen on localsocket", "err", err)
	}

	labels := prometheus.Labels{"id": fmt.Sprintf("loc:%d", 0)}

	var ifids []spath.IntfID
	ifids = append(ifids, spath.IntfID(33))

	args := &PosixInputFuncArgs{
		ProcessPacket: hsvc.processPacket,
		Conn:          over.Conn,
		DirFrom:       rpkt.DirLocal,
		Ifids:         ifids,
		Labels:        labels,
		StopChan:      make(chan struct{}),
		StoppedChan:   make(chan struct{}),
	}
	ctx.InputF = &PosixInput{
		Args: args,
		Func: readPosixInput,
	}
	// Add an output callback for the socket.
	f := func(b common.RawBytes, dst *net.UDPAddr) (int, error) {
		return over.Conn.WriteToUDP(b, dst)
	}
	ctx.OutputF = func(oo rctx.OutputObj, dst *net.UDPAddr) {
		writePosixOutput(oo, dst, f)
	}
	log.Debug("Set up new local socket.", "conn", over.BindAddr().String())

	return rpkt.HookContinue, nil
}

