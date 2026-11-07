// The module runner: the built-in controls registered as modules, and the
// checks of other compiled-in modules run at their fixed phase.

package pipeline

import (
	"context"
	"encoding/json"
	"net/http"
	"runtime/debug"
	"slices"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/compile"
	"github.com/Alex-Zechariah-02/apiward/module"
)

// builtin is one of the controls the handler runs itself as a fixed stage.
// It is registered so every build lists it and no other module can take its
// ID; it compiles to no module check.
type builtin struct{ info module.Info }

func (b builtin) Info() module.Info { return b.info }

func (builtin) Compile(module.Operation, json.RawMessage) (module.Check, error) { return nil, nil }

func init() {
	version := "(devel)"
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		version = info.Main.Version
	}
	for _, b := range []module.Info{
		{ID: "jwt", Phase: module.Identity},
		{ID: "rbac", Phase: module.Authorise},
		{ID: "rate", Phase: module.Traffic},
		{ID: "body", Phase: module.Validate},
		{ID: "validation", Phase: module.Validate},
	} {
		b.Version = version
		module.Register(builtin{b})
	}
}

// phaseStage is the stage whose result a module refusal or failure of each
// phase is recorded at.
var phaseStage = [...]int{
	module.Ingress:   audit.StageIngress,
	module.Identity:  audit.StageJWT,
	module.Authorise: audit.StageRBAC,
	module.Traffic:   audit.StageRate,
	module.Validate:  audit.StageValidation,
}

// compileIngress compiles the checks of the Ingress modules, which take no
// policy settings, once for the handler.
func compileIngress(extensions []module.Control) ([]compile.ModuleCheck, error) {
	var out []compile.ModuleCheck
	for _, c := range extensions {
		if c.Info().Phase != module.Ingress {
			continue
		}
		check, err := compile.CompileModule(c, module.Operation{}, nil)
		if err != nil {
			return nil, err
		}
		if check != nil {
			out = append(out, compile.ModuleCheck{ID: c.Info().ID, Check: check})
		}
	}
	return out, nil
}

// moduleView is what a request has established so far, for module requests.
type moduleView struct {
	path  string
	rule  *compile.Rule // nil in the Ingress phase
	roles []string
}

// runModules runs the module checks of phase in ID order and records each
// result; a module without a check for the operation reads NA. It answers a
// refusal or failure itself and reports whether the request may continue.
func (h *Handler) runModules(q *request, r *http.Request, phase module.Phase, v moduleView) bool {
	if len(h.extensions) == 0 {
		return true
	}
	checks := h.ingress
	if v.rule != nil {
		checks = v.rule.Checks(phase)
	}
	for _, info := range h.extensions {
		configured := slices.ContainsFunc(checks, func(c compile.ModuleCheck) bool { return c.ID == info.ID })
		if info.Phase == phase && !configured {
			q.event.Modules[info.ID] = audit.StageNotApplicable
		}
	}
	stage := phaseStage[phase]
	for _, c := range checks {
		result := runCheck(r.Context(), c.Check, moduleRequest(q, r, v))
		switch {
		case result.Passed():
			q.event.Modules[c.ID] = audit.StagePass
		case result.Refused():
			q.event.Modules[c.ID] = audit.StageReject
			q.reject(stage, result.Status(), result.Code())
			return false
		default:
			q.event.Modules[c.ID] = audit.StageFail
			q.fail(stage, "module "+c.ID+": "+result.Reason())
			return false
		}
	}
	return true
}

// moduleRequest builds a fresh copy of the request view for one check, so no
// module can change what another sees. The bearer token is never included.
func moduleRequest(q *request, r *http.Request, v moduleView) *module.Request {
	header := r.Header.Clone()
	header.Del("Authorization")
	out := &module.Request{
		Method: r.Method, Path: v.path, ClientAddress: q.event.ClientAddress, Header: header,
		Subject: q.event.Subject, Roles: slices.Clone(v.roles),
	}
	if v.rule != nil {
		out.Operation, out.API = v.rule.Operation(), v.rule.API()
	}
	return out
}

// runCheck runs one check; a panic is a failure.
func runCheck(ctx context.Context, check module.Check, r *module.Request) (result module.Result) {
	defer func() {
		if recover() != nil {
			result = module.Fail("panic")
		}
	}()
	return check.Check(ctx, r)
}
