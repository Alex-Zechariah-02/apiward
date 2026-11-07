// Checks of compiled-in modules, compiled with each operation's rule.

package compile

import (
	"encoding/json"
	"fmt"

	"github.com/Alex-Zechariah-02/apiward/internal/policy"
	"github.com/Alex-Zechariah-02/apiward/module"
)

// ModuleCheck is one module's compiled check.
type ModuleCheck struct {
	ID    string
	Check module.Check
}

// Checks returns the module checks of the rule that run in phase, in ID
// order; none for a module not configured for the operation.
func (r *Rule) Checks(phase module.Phase) []ModuleCheck { return r.checks[phase] }

// compileModules compiles the settings of every module other than the
// built-ins for operation i. Ingress modules take no settings, so a member
// for one is unknown.
func compileModules(op policy.Operation, i int, r *Rule) error {
	for _, c := range module.Extensions() {
		info := c.Info()
		raw, present := op.Modules[info.ID]
		if info.Phase == module.Ingress {
			if present {
				return policy.Invalid("UNKNOWN_FIELD", "operations[%d].%s", i, info.ID)
			}
			continue
		}
		check, err := CompileModule(c, module.Operation{ID: op.ID, API: op.API, Method: op.Method, Target: op.Target}, raw)
		if err != nil {
			return policy.Invalid("MODULE_FAILED", "operations[%d].%s", i, info.ID)
		}
		if check != nil {
			r.checks[info.Phase] = append(r.checks[info.Phase], ModuleCheck{ID: info.ID, Check: check})
		}
	}
	return nil
}

// CompileModule calls c's Compile, turning a panic into an error.
func CompileModule(c module.Control, op module.Operation, raw json.RawMessage) (check module.Check, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			check, err = nil, fmt.Errorf("module %s: compile panicked", c.Info().ID)
		}
	}()
	return c.Compile(op, raw)
}
