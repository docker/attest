package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/distribution/reference"
	"github.com/docker-library/bashbrew/manifest"
	"github.com/docker/attest/attestation"
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
	debug               bool
	attestationVerifier attestation.Verifier
}

const (
	DefaultQuery  = "result := data.attest.result"
	resultBinding = "result"
)

func NewRegoEvaluator(debug bool, attestationVerifier attestation.Verifier) Evaluator {
	return &regoEvaluator{
		debug:               debug,
		attestationVerifier: attestationVerifier,
	}
}

func (re *regoEvaluator) Evaluate(ctx context.Context, resolver attestation.Resolver, pctx *Policy, input *Input) (*Result, error) {
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
		rego.Input(input),
		rego.Store(store),
		rego.GenerateJSON(jsonGenerator[Result]()),
	)
	regoFnOpts := NewRegoFunctionOptions(resolver, re.attestationVerifier)
	for _, custom := range RegoFunctions(regoFnOpts) {
		regoOpts = append(regoOpts, custom.Func)
	}

	r := rego.New(regoOpts...)
	rs, err := r.Eval(ctx)
	if err != nil {
		return nil, err
	}

	if len(rs) == 0 {
		return nil, fmt.Errorf("no policy evaluation result")
	}
	binding, ok := rs[0].Bindings[resultBinding]
	if !ok {
		return nil, fmt.Errorf("failed to extract verification result")
	}
	result, ok := binding.(Result)
	if !ok {
		return nil, fmt.Errorf("failed to extract verification result")
	}

	return &result, nil
}

func jsonGenerator[T any]() func(t *ast.Term, ec *rego.EvalContext) (any, error) {
	return func(t *ast.Term, _ *rego.EvalContext) (any, error) {
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

var dynamicObj = types.NewObject(nil, types.NewDynamicProperty(types.A, types.A))

var verifyDecl = &ast.Builtin{
	Name:             "attest.verify",
	Decl:             types.NewFunction(types.Args(dynamicObj, dynamicObj), dynamicObj),
	Nondeterministic: true,
}

var attestDecl = &ast.Builtin{
	Name:             "attest.fetch",
	Decl:             types.NewFunction(types.Args(types.S), dynamicObj),
	Nondeterministic: true,
}

var internalParseLibraryDefinitionDecl = &ast.Builtin{
	Name:             "attest.internals.parse_library_definition",
	Decl:             types.NewFunction(types.Args(types.S), dynamicObj),
	Nondeterministic: false,
}

func wrapFunctionResult(value *ast.Term, err error) (*ast.Term, error) {
	var terms [][2]*ast.Term
	if err != nil {
		terms = append(terms, [2]*ast.Term{ast.StringTerm("error"), ast.StringTerm(err.Error())})
	}
	if value != nil {
		terms = append(terms, [2]*ast.Term{ast.StringTerm("value"), value})
	}
	return ast.ObjectTerm(terms...), nil
}

func handleErrors1(f func(rCtx rego.BuiltinContext, a *ast.Term) (*ast.Term, error)) rego.Builtin1 {
	return func(rCtx rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
		return wrapFunctionResult(f(rCtx, a))
	}
}

func handleErrors2(f func(rCtx rego.BuiltinContext, a, b *ast.Term) (*ast.Term, error)) rego.Builtin2 {
	return func(rCtx rego.BuiltinContext, a, b *ast.Term) (*ast.Term, error) {
		return wrapFunctionResult(f(rCtx, a, b))
	}
}

func RegoFunctions(regoOpts *RegoFnOpts) []*tester.Builtin {
	return []*tester.Builtin{
		builtin2(verifyDecl, regoOpts.verifyInTotoEnvelope),
		builtin1(attestDecl, regoOpts.fetchInTotoAttestations),
		builtin1(internalParseLibraryDefinitionDecl, regoOpts.internalParseLibraryDefinition),
	}
}

func builtin1(decl *ast.Builtin, f rego.Builtin1) *tester.Builtin {
	return &tester.Builtin{
		Decl: decl,
		Func: rego.Function1(
			&rego.Function{
				Name:             decl.Name,
				Decl:             decl.Decl,
				Memoize:          true,
				Nondeterministic: decl.Nondeterministic,
			},
			handleErrors1(f)),
	}
}

func builtin2(decl *ast.Builtin, f rego.Builtin2) *tester.Builtin {
	return &tester.Builtin{
		Decl: decl,
		Func: rego.Function2(
			&rego.Function{
				Name:             decl.Name,
				Decl:             decl.Decl,
				Memoize:          true,
				Nondeterministic: decl.Nondeterministic,
			},
			handleErrors2(f)),
	}
}

type RegoFnOpts struct {
	attestationResolver attestation.Resolver
	attestationVerifier attestation.Verifier
}

// this is exported for testing here and in clients of the library.
func NewRegoFunctionOptions(resolver attestation.Resolver, verifier attestation.Verifier) *RegoFnOpts {
	return &RegoFnOpts{
		attestationResolver: resolver,
		attestationVerifier: verifier,
	}
}

// because we don't control the signature here (blame rego)
// nolint:gocritic
func (regoOpts *RegoFnOpts) fetchInTotoAttestations(rCtx rego.BuiltinContext, predicateTypeTerm *ast.Term) (*ast.Term, error) {
	predicateTypeStr, ok := predicateTypeTerm.Value.(ast.String)
	if !ok {
		return nil, fmt.Errorf("predicateTypeTerm is not a string")
	}
	predicateType := string(predicateTypeStr)

	envelopes, err := regoOpts.attestationResolver.Attestations(rCtx.Context, predicateType)
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

// because we don't control the function signature here (blame rego)
// nolint:gocritic
func (regoOpts *RegoFnOpts) verifyInTotoEnvelope(rCtx rego.BuiltinContext, envTerm, optsTerm *ast.Term) (*ast.Term, error) {
	env := new(attestation.Envelope)
	opts := new(attestation.VerifyOptions)
	err := ast.As(envTerm.Value, env)
	if err != nil {
		return nil, fmt.Errorf("failed to cast envelope: %w", err)
	}
	err = ast.As(optsTerm.Value, &opts)
	if err != nil {
		return nil, fmt.Errorf("failed to cast verifier options: %w", err)
	}
	// normally this could be done in the constructor, but we don't control it
	err = processKeys(rCtx.Context, regoOpts.attestationResolver, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to process keys: %w", err)
	}

	payload, err := attestation.VerifyDSSE(rCtx.Context, regoOpts.attestationVerifier, env, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to verify envelope: %w", err)
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

	err = VerifySubject(rCtx.Context, statement.Subject, regoOpts.attestationResolver)
	if err != nil {
		return nil, fmt.Errorf("failed to verify subject: %w", err)
	}

	value, err := ast.InterfaceToValue(statement)
	if err != nil {
		return nil, err
	}
	return ast.NewTerm(value), nil
}

// because we don't control the signature here (blame rego)
// nolint:gocritic
func (regoOpts *RegoFnOpts) internalParseLibraryDefinition(_ rego.BuiltinContext, definitionTerm *ast.Term) (*ast.Term, error) {
	definitionStr, ok := definitionTerm.Value.(ast.String)
	if !ok {
		return nil, fmt.Errorf("predicateTypeTerm is not a string")
	}
	definition := string(definitionStr)
	defBuffer := bytes.NewBufferString(definition)
	parsed, err := manifest.Parse2822(defBuffer)
	if err != nil {
		return nil, err
	}
	value, err := ast.InterfaceToValue(parsed)
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

func processKeys(ctx context.Context, resolver attestation.Resolver, opts *attestation.VerifyOptions) error {
	imageName, err := resolver.ImageName(ctx)
	if err != nil {
		return fmt.Errorf("failed to resolve image name: %w", err)
	}
	parsed, err := reference.ParseNormalizedNamed(imageName)
	if err != nil {
		return fmt.Errorf("failed to parse image name: %w", err)
	}
	imageName = parsed.Name()
	platform, err := resolver.ImagePlatform(ctx)
	if err != nil {
		return fmt.Errorf("failed to get image platform: %w", err)
	}
	for _, key := range opts.Keys {
		if err := key.UpdateImageExpirey(imageName, platform); err != nil {
			return fmt.Errorf("error failed to process expiries for key %s: %w", key.ID, err)
		}
	}
	return nil
}
