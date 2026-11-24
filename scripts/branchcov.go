//go:build ignore

// branchcov instruments an ephemeral copy of the current-platform Go sources.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type pkg struct {
	Dir, ImportPath   string
	GoFiles, CgoFiles []string
}
type outcome struct {
	Line     int
	Location string
	Kind     string
}
type edit struct {
	offset int
	text   string
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) == 2 && os.Args[1] == "selftest" {
		return selftest()
	}
	if len(os.Args) != 1 {
		return fmt.Errorf("usage: go run scripts/branchcov.go [selftest]")
	}
	project, err := os.Getwd()
	if err != nil {
		return err
	}
	list := exec.Command("go", "list", "-f", "{{.Dir}}", "./...")
	list.Stderr = os.Stderr
	dirs, err := list.Output()
	if err != nil {
		return fmt.Errorf("list working tree packages: %w", err)
	}
	for _, path := range strings.Split(strings.TrimSpace(string(dirs)), "\n") {
		rel, err := filepath.Rel(project, path)
		if err != nil {
			return err
		}
		top, _, _ := strings.Cut(rel, string(filepath.Separator))
		if top != "cmd" && top != "internal" {
			return fmt.Errorf("Go package outside copied project roots: %s", path)
		}
	}
	dir, err := os.MkdirTemp("", "peertty-branchcov-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	for _, name := range []string{"cmd", "internal"} {
		if err := os.CopyFS(filepath.Join(dir, name), os.DirFS(name)); err != nil {
			return err
		}
	}
	for _, name := range []string{"go.mod", "go.sum"} {
		b, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0600); err != nil {
			return err
		}
	}
	return measure(dir, os.Stdout)
}

func measure(dir string, out io.Writer) error {
	list := exec.Command("go", "list", "-json", "./...")
	list.Dir = dir
	list.Stderr = os.Stderr
	b, err := list.Output()
	if err != nil {
		return fmt.Errorf("go list: %w", err)
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	var packages []string
	files := map[string][]outcome{}
	for {
		var p pkg
		if err := d.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		packages = append(packages, p.ImportPath)
		if len(p.CgoFiles) > 0 {
			return fmt.Errorf("no cgo support: %s", p.ImportPath)
		}
		for _, file := range p.GoFiles {
			path := filepath.Join(p.Dir, file)
			src, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			result, points, err := instrument(path, src)
			if err != nil {
				return err
			}
			if len(points) == 0 {
				continue
			}
			if err := os.WriteFile(path, result, 0600); err != nil {
				return err
			}
			files[p.ImportPath+"/"+file] = points
		}
	}
	profile := filepath.Join(dir, "branches.out")
	cmd := exec.Command("go", "test", "-short", "-count=1", "-covermode=atomic", "-coverpkg="+strings.Join(packages, ","), "-coverprofile", profile, "./...")
	cmd.Dir = dir
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("instrumented unit tests: %w", err)
	}
	return summarize(profile, files, out)
}

func instrument(path string, src []byte) ([]byte, []outcome, error) {
	fs := token.NewFileSet()
	f, err := parser.ParseFile(fs, path, src, 0)
	if err != nil {
		return nil, nil, err
	}
	if strings.Contains(string(src), "peerTTYBranchProbe") {
		return nil, nil, fmt.Errorf("probe name collision in %s", path)
	}
	var edits []edit
	var points []outcome
	var helpers strings.Builder
	base := strings.Count(string(src), "\n") + 2
	add := func(pos token.Pos, value string) {
		edits = append(edits, edit{fs.Position(pos).Offset, value})
	}
	probe := func(pos token.Pos, kind string, cond bool) string {
		p := fs.Position(pos)
		name := fmt.Sprintf("peerTTYBranchProbe%x_%d", filepath.Base(path), len(points))
		line := base
		loc := fmt.Sprintf("%d:%d", p.Line, p.Column)
		if cond {
			base += 6
			fmt.Fprintf(&helpers, "func %s[T ~bool](v T) T {\nif v {\nreturn v\n}\nreturn v\n}\n", name)
			points = append(points, outcome{Line: line + 2, Location: loc, Kind: kind + " true"}, outcome{Line: line + 4, Location: loc, Kind: kind + " false"})
		} else {
			base += 3
			// Mark entry with a Go statement distinguishable in coverprofile.
			fmt.Fprintf(&helpers, "func %s() {\nreturn\n}\n", name)
			points = append(points, outcome{Line: line + 1, Location: loc, Kind: kind})
		}
		return name
	}
	wrap := func(e ast.Expr, kind string) {
		add(e.Pos(), probe(e.Pos(), kind, true)+"(")
		add(e.End(), ")")
	}
	seenOperands := map[[2]token.Pos]bool{}
	var operands func(ast.Expr)
	operands = func(e ast.Expr) {
		switch n := e.(type) {
		case *ast.ParenExpr:
			operands(n.X)
			return
		case *ast.UnaryExpr:
			if n.Op == token.NOT {
				operands(n.X)
				return
			}
		case *ast.BinaryExpr:
			if n.Op == token.LAND || n.Op == token.LOR {
				operands(n.X)
				operands(n.Y)
				return
			}
		}
		key := [2]token.Pos{e.Pos(), e.End()}
		if !seenOperands[key] {
			seenOperands[key] = true
			wrap(e, "operand")
		}
	}
	condition := func(e ast.Expr, kind string) {
		wrap(e, kind)
	}
	var instrumentErr error
	ast.Inspect(f, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.LabeledStmt:
			if _, ok := s.Stmt.(*ast.RangeStmt); ok {
				instrumentErr = fmt.Errorf("unsupported labeled range at %s", fs.Position(s.Pos()))
				return false
			}
		case *ast.IfStmt:
			condition(s.Cond, "if")
		case *ast.ForStmt:
			if s.Cond != nil {
				condition(s.Cond, "for")
			}
		case *ast.RangeStmt:
			id := "peerTTYBranchProbeSeen" + strconv.Itoa(fs.Position(s.Pos()).Offset)
			add(s.Pos(), "{ "+id+" := false; ")
			add(s.Body.Lbrace+1, " "+id+" = true; "+probe(s.For, "range nonempty", false)+"(); ")
			add(s.End(), "; if !"+id+" { "+probe(s.For, "range empty", false)+"() }; }")
		case *ast.SwitchStmt:
			hasDefault := false
			for _, l := range s.Body.List {
				c := l.(*ast.CaseClause)
				hasDefault = hasDefault || c.List == nil
				if s.Tag == nil {
					for _, expr := range c.List {
						condition(expr, "case condition")
					}
				}
				add(c.Colon+1, " "+probe(c.Pos(), "switch arm", false)+"(); ")
			}
			if !hasDefault {
				add(s.Body.Rbrace, "; default: "+probe(s.Switch, "switch no match", false)+"(); ")
			}
		case *ast.TypeSwitchStmt:
			hasDefault := false
			for _, l := range s.Body.List {
				c := l.(*ast.CaseClause)
				hasDefault = hasDefault || c.List == nil
				add(c.Colon+1, " "+probe(c.Pos(), "type switch arm", false)+"(); ")
			}
			if !hasDefault {
				add(s.Body.Rbrace, "; default: "+probe(s.Switch, "type switch no match", false)+"(); ")
			}
		case *ast.CommClause:
			add(s.Colon+1, " "+probe(s.Pos(), "select arm", false)+"(); ")
		case *ast.BranchStmt:
			if s.Tok == token.FALLTHROUGH || s.Tok == token.GOTO {
				instrumentErr = fmt.Errorf("unsupported %s at %s", s.Tok, fs.Position(s.Pos()))
			}
		}
		return true
	})
	// Walk executable Boolean groups; preserve short-circuit evaluation and skip constant declarations.
	ast.Inspect(f, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.GenDecl:
			if s.Tok == token.CONST || s.Tok == token.TYPE {
				return false
			}
		case *ast.BinaryExpr:
			if s.Op == token.LAND || s.Op == token.LOR {
				operands(s)
			}
		}
		return true
	})
	if instrumentErr != nil {
		return nil, nil, instrumentErr
	}
	sort.SliceStable(edits, func(i, j int) bool { return edits[i].offset < edits[j].offset })
	var rewritten strings.Builder
	prev := 0
	for _, e := range edits {
		rewritten.Write(src[prev:e.offset])
		rewritten.WriteString(e.text)
		prev = e.offset
	}
	rewritten.Write(src[prev:])
	rewritten.WriteString("\n")
	rewritten.WriteString(helpers.String())
	return []byte(rewritten.String()), points, nil
}

func summarize(path string, files map[string][]outcome, w io.Writer) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	// Probe return statements each begin a distinct coverage block.
	seen := map[string]map[int]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		s := sc.Text()
		colon := strings.LastIndex(s, ":")
		if colon < 0 {
			continue
		}
		positions := strings.Fields(s[colon+1:])
		if len(positions) != 3 {
			continue
		}
		sp := strings.Split(positions[0], ",")
		if len(sp) != 2 {
			continue
		}
		line, err := strconv.Atoi(strings.Split(sp[0], ".")[0])
		if err != nil {
			return err
		}
		if seen[s[:colon]] == nil {
			seen[s[:colon]] = map[int]bool{}
		}
		seen[s[:colon]][line] = seen[s[:colon]][line] || positions[2] != "0"
	}
	if err := sc.Err(); err != nil {
		return err
	}
	var names []string
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	covered, total := 0, 0
	for _, name := range names {
		hc := 0
		for _, p := range files[name] {
			// Each probe return has a unique position as the start of its Go block.
			hit, ok := seen[name][p.Line]
			if !ok {
				return fmt.Errorf("missing outcome counter for %s probe line %d (%s)", name, p.Line, p.Kind)
			}
			if hit {
				hc++
			} else {
				fmt.Fprintf(w, "MISS %s:%s %s\n", name, p.Location, p.Kind)
			}
		}
		fmt.Fprintf(w, "FILE %s %d/%d\n", name, hc, len(files[name]))
		covered += hc
		total += len(files[name])
	}
	if total == 0 {
		return fmt.Errorf("no branch outcomes")
	}
	fmt.Fprintf(w, "TOTAL %d/%d %.2f%% (strict >90%%: %t)\n", covered, total, 100*float64(covered)/float64(total), 10*covered > 9*total)
	return nil
}

func selftest() error {
	dir, err := os.MkdirTemp("", "branchcov-fixture-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	for name, body := range map[string]string{
		"go.mod": "module fixture\n\ngo 1.25.0\n",
		"fixture.go": `package fixture
var calls int
func rhs(v bool) bool { calls++; return v }
func both(a,b bool) bool {
	if a && rhs(b) { return true }
	return false
}
func either(a,b bool) bool {
	return a || rhs(b)
}
func count(xs []int) int {
	n := 0
	for range xs { n++ }
	switch n {
	case 0: return 4
	case 1: return 5
	}
	return 6
}
func poll(ch <-chan int) {
	select {
	case <- ch:
	default:
	}
}
`,
		"fixture_test.go": `package fixture
import "testing"
func TestKnown(t *testing.T) {
	if both(false,true) || both(true,false) || calls!=1 {t.Fatal("AND semantics",calls)}
	if !either(true,false) || either(false,false) || calls!=2 {t.Fatal("OR semantics",calls)}
	if count(nil)!=4 || count([]int{8})!=5 {t.Fatal("range or switch semantics")}
	ch:=make(chan int,1)
	poll(ch)
	ch <- 1
	poll(ch)
}
`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			return err
		}
	}
	var out strings.Builder
	if err := measure(dir, &out); err != nil {
		return err
	}
	if !strings.Contains(out.String(), "TOTAL 13/17 ") ||
		strings.Count(out.String(), "operand true") != 2 ||
		!strings.Contains(out.String(), "switch no match") ||
		!strings.Contains(out.String(), "if true") {
		return fmt.Errorf("unexpected fixture counters:\n%s", out.String())
	}
	fmt.Print(out.String())
	return nil
}
