package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/siem"
	siemuc "github.com/KKloudTarus/synapse-ce/internal/usecase/siem"
)

const siemBodyCap = 32 << 10

func (rt *Router) siemContext(r *http.Request) context.Context {
	ctx := r.Context()
	if _, ok := shared.TenantFrom(ctx); ok {
		return ctx
	}
	return shared.WithTenant(ctx, shared.ID(TenantFrom(ctx)))
}

func decodeSIEM(w http.ResponseWriter, r *http.Request, out any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, siemBodyCap))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("%w: invalid siem request", shared.ErrValidation)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: siem request must contain one JSON object", shared.ErrValidation)
	}
	return nil
}

type siemSinkBody struct {
	Name                string   `json:"name"`
	Provider            string   `json:"provider"`
	Origin              string   `json:"origin"`
	Target              string   `json:"target"`
	DataClass           string   `json:"data_class"`
	AckMode             string   `json:"ack_mode"`
	IndexerAckSupported bool     `json:"indexer_ack_supported"`
	IndexerAckPresent   bool     `json:"-"`
	NamePresent         bool     `json:"-"`
	ProviderPresent     bool     `json:"-"`
	OriginPresent       bool     `json:"-"`
	TargetPresent       bool     `json:"-"`
	DataClassPresent    bool     `json:"-"`
	AckModePresent      bool     `json:"-"`
	AllowHostsPresent   bool     `json:"-"`
	AllowHosts          []string `json:"allow_hosts"`
	Secret              string   `json:"secret,omitempty"`
	Version             int64    `json:"version"`
	Replay              string   `json:"replay"`
}

func (b *siemSinkBody) UnmarshalJSON(data []byte) error {
	type fields siemSinkBody
	var decoded fields
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&decoded); err != nil {
		return err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	_, decoded.IndexerAckPresent = raw["indexer_ack_supported"]
	_, decoded.NamePresent = raw["name"]
	_, decoded.ProviderPresent = raw["provider"]
	_, decoded.OriginPresent = raw["origin"]
	_, decoded.TargetPresent = raw["target"]
	_, decoded.DataClassPresent = raw["data_class"]
	_, decoded.AckModePresent = raw["ack_mode"]
	_, decoded.AllowHostsPresent = raw["allow_hosts"]
	*b = siemSinkBody(decoded)
	return nil
}

func (b siemSinkBody) input() siemuc.SinkInput {
	return siemuc.SinkInput{
		Name: b.Name, Provider: siem.Provider(b.Provider), Origin: b.Origin, Target: b.Target,
		DataClass: siem.DataClass(b.DataClass), AckMode: siem.AckMode(b.AckMode),
		IndexerAckSupported: b.IndexerAckSupported, IndexerAckPresent: b.IndexerAckPresent,
		NamePresent: b.NamePresent, ProviderPresent: b.ProviderPresent, OriginPresent: b.OriginPresent,
		TargetPresent: b.TargetPresent, DataClassPresent: b.DataClassPresent, AckModePresent: b.AckModePresent,
		AllowHostsPresent: b.AllowHostsPresent,
		AllowHosts:        b.AllowHosts, Secret: b.Secret, Version: b.Version,
	}
}

func (rt *Router) listSIEMSinks(w http.ResponseWriter, r *http.Request) {
	items, err := rt.siem.List(rt.siemContext(r), PrincipalFrom(r.Context()))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	if items == nil {
		items = []siem.Sink{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (rt *Router) createSIEMSink(w http.ResponseWriter, r *http.Request) {
	var body siemSinkBody
	if err := decodeSIEM(w, r, &body); err != nil {
		writeError(w, rt.log, err)
		return
	}
	item, err := rt.siem.Create(rt.siemContext(r), PrincipalFrom(r.Context()), body.input())
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (rt *Router) getSIEMSink(w http.ResponseWriter, r *http.Request) {
	item, err := rt.siem.Get(rt.siemContext(r), PrincipalFrom(r.Context()), shared.ID(r.PathValue("id")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (rt *Router) updateSIEMSink(w http.ResponseWriter, r *http.Request) {
	var body siemSinkBody
	if err := decodeSIEM(w, r, &body); err != nil {
		writeError(w, rt.log, err)
		return
	}
	in := body.input()
	item, err := rt.siem.Update(rt.siemContext(r), PrincipalFrom(r.Context()), shared.ID(r.PathValue("id")), in)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (rt *Router) rotateSIEMSecret(w http.ResponseWriter, r *http.Request) {
	var body siemSinkBody
	if err := decodeSIEM(w, r, &body); err != nil {
		writeError(w, rt.log, err)
		return
	}
	item, err := rt.siem.RotateSecret(rt.siemContext(r), PrincipalFrom(r.Context()), shared.ID(r.PathValue("id")), body.Secret, body.Version)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (rt *Router) changeSIEMOrigin(w http.ResponseWriter, r *http.Request) {
	var body siemSinkBody
	if err := decodeSIEM(w, r, &body); err != nil {
		writeError(w, rt.log, err)
		return
	}
	item, err := rt.siem.ChangeOrigin(rt.siemContext(r), PrincipalFrom(r.Context()), shared.ID(r.PathValue("id")), siemuc.OriginInput{
		Origin: body.Origin, Secret: body.Secret, Replay: siem.Replay(body.Replay), Version: body.Version,
	})
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (rt *Router) pauseSIEMSink(w http.ResponseWriter, r *http.Request) {
	rt.siemPause(w, r, true)
}

func (rt *Router) resumeSIEMSink(w http.ResponseWriter, r *http.Request) {
	rt.siemPause(w, r, false)
}

func (rt *Router) siemPause(w http.ResponseWriter, r *http.Request, pause bool) {
	var body siemSinkBody
	if err := decodeSIEM(w, r, &body); err != nil {
		writeError(w, rt.log, err)
		return
	}
	var item siem.Sink
	var err error
	if pause {
		item, err = rt.siem.Pause(rt.siemContext(r), PrincipalFrom(r.Context()), shared.ID(r.PathValue("id")), body.Version)
	} else {
		item, err = rt.siem.Resume(rt.siemContext(r), PrincipalFrom(r.Context()), shared.ID(r.PathValue("id")), body.Version)
	}
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (rt *Router) testSIEMSink(w http.ResponseWriter, r *http.Request) {
	guarantee, err := rt.siem.Test(rt.siemContext(r), PrincipalFrom(r.Context()), shared.ID(r.PathValue("id")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"guarantee": guarantee, "result": "accepted"})
}

func (rt *Router) siemSinkStatus(w http.ResponseWriter, r *http.Request) {
	status, err := rt.siem.Status(rt.siemContext(r), PrincipalFrom(r.Context()), shared.ID(r.PathValue("id")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}
