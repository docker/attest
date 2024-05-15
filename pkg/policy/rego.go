package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	att "github.com/docker/attest/pkg/attestation"
	"github.com/docker/attest/pkg/oci"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/tester"
	"github.com/open-policy-agent/opa/topdown"
	"github.com/open-policy-agent/opa/types"
	opa "github.com/open-policy-agent/opa/util"
	"sigs.k8s.io/yaml"
)

type regoEvaluator struct {
	debug bool
}

const DefaultQuery = "data.attest.allow"

func NewRegoEvaluator(debug bool) PolicyEvaluator {
	return &regoEvaluator{
		debug: debug,
	}
}

type Summary struct {
	Subjects  []intoto.Subject `json:"subjects"`
	SLSALevel string           `json:"slsa_level"`
	Verifier  string           `json:"verifier"`
}

type VerificationResult struct {
	Success    bool     `json:"success"`
	Violations []string `json:"violations"`
	Summary    Summary  `json:"summary"`
}

func (re *regoEvaluator) Evaluate(ctx context.Context, resolver oci.AttestationResolver, pctx *Policy, input *PolicyInput) (rego.ResultSet, error) {
	var regoOpts []func(*rego.Rego)

	// Create a new in-memory store
	store := inmem.New()
	params := storage.TransactionParams{}
	params.Write = true
	txn, err := store.NewTransaction(ctx, params)
	if err != nil {
		return nil, err
	}

	for _, target := range pctx.InputFiles {
		// load yaml as data (no rego opt for this!?)
		if filepath.Ext(target.Path) == ".yaml" {
			yamlData, err := loadYAML(target.Path, target.Content)
			if err != nil {
				return nil, err
			}
			err = store.Write(ctx, txn, storage.AddOp, storage.Path{}, yamlData)
			if err != nil {
				return nil, err
			}
		} else {
			regoOpts = append(regoOpts, rego.Module(target.Path, string(target.Content)))
		}
	}

	err = store.Commit(ctx, txn)
	if err != nil {
		store.Abort(ctx, txn)
		return nil, err
	}

	if re.debug {
		regoOpts = append(regoOpts,
			rego.EnablePrintStatements(true),
			rego.PrintHook(topdown.NewPrintHook(os.Stderr)),
			rego.Dump(os.Stderr),
		)
	}
	query := DefaultQuery
	if pctx.Query != "" {
		query = pctx.Query
	}
	regoOpts = append(regoOpts,
		rego.Query(query),
		rego.StrictBuiltinErrors(true),
		rego.Input(input),
		rego.Store(store),
		rego.GenerateJSON(jsonGenerator[VerificationResult]()),
	)
	for _, custom := range RegoFunctions(resolver) {
		regoOpts = append(regoOpts, custom.Func)
	}

	r := rego.New(regoOpts...)
	return r.Eval(ctx)
}

func jsonGenerator[T any]() func(t *ast.Term, ec *rego.EvalContext) (any, error) {
	return func(t *ast.Term, ec *rego.EvalContext) (any, error) {
		// TODO: this is horrible - we're converting the AST to JSON and then back to AST, then using ast.As to convert it to a struct
		// We can't use ast.As directly because it fails if the AST contains a set
		json, err := ast.JSON(t.Value)
		if err != nil {
			return nil, err
		}
		v, err := ast.InterfaceToValue(json)
		if err != nil {
			return nil, err
		}
		var result T
		err = ast.As(v, &result)
		if err != nil {
			return nil, err
		}
		return result, nil
	}
}

var dynamicObj = types.NewObject(nil, types.NewDynamicProperty(types.S, types.A))
var arrayObj = types.NewArray(nil, dynamicObj)
var setObj = types.NewSet(dynamicObj)

var verifyDecl = &ast.Builtin{
	Name:             "attestations.verify_envelope",
	Decl:             types.NewFunction(types.Args(dynamicObj, arrayObj), dynamicObj),
	Nondeterministic: true,
}
var attestDecl = &ast.Builtin{
	Name:             "attestations.attestation",
	Decl:             types.NewFunction(types.Args(types.S), setObj),
	Nondeterministic: true,
}

func RegoFunctions(resolver oci.AttestationResolver) []*tester.Builtin {
	return []*tester.Builtin{
		{
			Decl: verifyDecl,
			Func: rego.Function2(
				&rego.Function{
					Name:             verifyDecl.Name,
					Decl:             verifyDecl.Decl,
					Memoize:          true,
					Nondeterministic: verifyDecl.Nondeterministic,
				},
				verifyIntotoEnvelope),
		},
		{
			Decl: attestDecl,
			Func: rego.Function1(
				&rego.Function{
					Name:             attestDecl.Name,
					Decl:             attestDecl.Decl,
					Memoize:          true,
					Nondeterministic: attestDecl.Nondeterministic,
				},
				fetchIntotoAttestations(resolver)),
		},
	}
}

func fetchIntotoAttestations(resolver oci.AttestationResolver) func(rego.BuiltinContext, *ast.Term) (*ast.Term, error) {
	return func(rCtx rego.BuiltinContext, predicateTypeTerm *ast.Term) (*ast.Term, error) {
		predicateTypeStr, ok := predicateTypeTerm.Value.(ast.String)
		if !ok {
			return nil, fmt.Errorf("predicateTypeTerm is not a string")
		}
		predicateType := string(predicateTypeStr)

		envelopes, err := resolver.Attestations(rCtx.Context, predicateType)
		if err != nil {
			return nil, err
		}

		// Convert each envelope to an ast.Value.
		values := make([]*ast.Term, len(envelopes))
		for i, envelope := range envelopes {
			value, err := ast.InterfaceToValue(envelope)
			if err != nil {
				return nil, err
			}
			values[i] = ast.NewTerm(value)
		}

		// Wrap the values in an ast.Set and convert it to an ast.Term.
		set := ast.NewTerm(ast.NewSet(values...))

		return set, nil
	}
}

func verifyIntotoEnvelope(rCtx rego.BuiltinContext, envTerm, keysTerm *ast.Term) (*ast.Term, error) {
	env := new(att.Envelope)
	var keys att.Keys
	err := ast.As(envTerm.Value, env)
	if err != nil {
		return nil, fmt.Errorf("failed to cast envelope: %w", err)
	}
	err = ast.As(keysTerm.Value, &keys)
	if err != nil {
		return nil, fmt.Errorf("failed to cast keys: %w", err)
	}
	keysmap := make(map[string]att.KeyMetadata, len(keys))
	for _, key := range keys {
		keysmap[key.ID] = key
	}
	payload, err := att.VerifyDSSE(rCtx.Context, env, keysmap)
	if err != nil {
		return nil, err
	}

	statement := new(intoto.Statement)

	switch env.PayloadType {
	case intoto.PayloadType:
		err = json.Unmarshal(payload, statement)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal statement: %w", err)
		}
		// TODO: implement other types of envelope
	default:
		return nil, fmt.Errorf("unsupported payload type: %s", env.PayloadType)
	}

	value, err := ast.InterfaceToValue(statement)
	if err != nil {
		return nil, err
	}

	return ast.NewTerm(value), nil
}

func loadYAML(path string, bs []byte) (interface{}, error) {
	var x interface{}
	bs, err := yaml.YAMLToJSON(bs)
	if err != nil {
		return nil, fmt.Errorf("%v: error converting YAML to JSON: %v", path, err)
	}
	err = opa.UnmarshalJSON(bs, &x)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return x, nil
}
