package main

import (
	"encoding/json"
	"fmt"
	"go/build"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/callgraph/static"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

type CallEdge struct {
	Callee        string `json:"callee"`
	CallSiteFile  string `json:"call_site_file,omitempty"` // File path where the call occurs (caller's file)
	CalleeModule  string `json:"callee_module,omitempty"`
	CalleePackage string `json:"callee_package,omitempty"`
}

type CallRelation struct {
	Caller         string      `json:"caller"`
	CallerModule   string      `json:"caller_module,omitempty"`
	CallerPackage  string      `json:"caller_package,omitempty"`
	Callees        []CallEdge  `json:"callees"`
}

type Result struct {
	CallGraph         []CallRelation                   `json:"call_graph"`
	Dependencies      []string                         `json:"dependencies"`
	Edges             int                              `json:"edges"`
	Functions         int                              `json:"functions"`
	MainModule        string                           `json:"main_module"`
	Packages          int                              `json:"packages"`
}

type SSAAnalyzer struct {
	rootPath     string
	prog         *ssa.Program
	pkgs         []*packages.Package
	pkgModuleMap map[string]string // package path -> module path (populated from SSA)
	stdLibPkgs  map[string]bool    // cache for standard library packages
	callGraphMap map[string][]string // caller -> []callee (for reachability analysis)
}

func NewSSAAnalyzer(rootPath string) *SSAAnalyzer {
	return &SSAAnalyzer{
		rootPath:      rootPath,
		stdLibPkgs:    make(map[string]bool),
		callGraphMap:  make(map[string][]string),
	}
}

func (sa *SSAAnalyzer) Analyze() (*Result, error) {
	fmt.Println("SSA Analysis: Building comprehensive call graph...")
	fmt.Println("   1. Loading packages...")

	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedImports | packages.NeedTypes | packages.NeedTypesSizes |
			packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedDeps,
		Dir:   sa.rootPath,
		Tests: false,
	}

	var err error
	sa.pkgs, err = packages.Load(cfg, "./...")
	if err != nil {
		return nil, fmt.Errorf("failed to load packages: %v", err)
	}
	fmt.Printf("   Loaded %d packages\n", len(sa.pkgs))
	
	// Print all package names for debugging
	fmt.Println("   Packages loaded:")
	for i, pkg := range sa.pkgs {
		if i < 10 {
			fmt.Printf("      - %s\n", pkg.PkgPath)
		}
	}
	if len(sa.pkgs) > 10 {
		fmt.Printf("      ... and %d more packages\n", len(sa.pkgs)-10)
	}

	fmt.Println("   2. Building SSA program...")
	sa.prog, _ = ssautil.AllPackages(sa.pkgs, ssa.InstantiateGenerics)
	sa.prog.Build()
	fmt.Printf("   Built SSA program\n")
	
	// Build package to module mapping from SSA packages
	sa.buildPackageModuleMap()
	
	// Build standard library package cache
	sa.buildStandardLibraryCache()

	fmt.Println("   3. Extracting call graphs...")
	callGraphMap := make(map[string][]CallEdge)
	edgeCount := 0

	chaCG := cha.CallGraph(sa.prog)
	staticCG := static.CallGraph(sa.prog)

	// Option 1: Extract all call relationships (current behavior)
	sa.processEdges(chaCG, &callGraphMap, &edgeCount)
	sa.processEdges(staticCG, &callGraphMap, &edgeCount)
	
	// Option 2: Extract reachable functions from main (if needed)
	// Uncomment the following lines to filter by main entry points:
	// sa.extractReachableFromMain(staticCG, &callGraphMap, &edgeCount)
	
	// Remove duplicates for reachability analysis
	// For reachability checking, we only need graph structure, not call frequency
	fmt.Printf("   Total call relationships before deduplication: %d\n", len(callGraphMap))
	fmt.Printf("   Total edges before deduplication: %d\n", edgeCount)
	sa.removeDuplicateCallees(&callGraphMap, &edgeCount)
	fmt.Printf("   Total call relationships: %d\n", len(callGraphMap))
	fmt.Printf("   Total edges: %d\n", edgeCount)
	
	// Convert map to structured array
	var callGraph []CallRelation
	for caller, callees := range callGraphMap {
		// Extract caller module and package information
		callerModule, callerPackage := sa.extractModuleAndPackage(caller)
		
		callGraph = append(callGraph, CallRelation{
			Caller:         caller,
			CallerModule:   callerModule,
			CallerPackage:  callerPackage,
			Callees:        callees,
		})
	}

	fmt.Println("   4. Extracting functions...")
	allFunctions := sa.extractAllFunctions()
	fmt.Printf("   Found %d functions\n", len(allFunctions))

	fmt.Println("   5. Counting all packages in SSA program...")
	totalPackages := sa.countAllPackages()
	fmt.Printf("   Found %d packages (including all dependencies)\n", totalPackages)

	mainModule := sa.extractMainModule()
	dependencies := sa.extractDependencies()

	return &Result{
		CallGraph:         callGraph,
		Dependencies:      dependencies,
		Edges:             edgeCount,
		Functions:         len(allFunctions),
		MainModule:        mainModule,
		Packages:          totalPackages,
	}, nil
}

func (sa *SSAAnalyzer) buildPackageModuleMap() {
	sa.pkgModuleMap = make(map[string]string)
	
	// First, extract from loaded packages
	for _, pkg := range sa.pkgs {
		if pkg.Module != nil && pkg.Module.Path != "" {
			sa.pkgModuleMap[pkg.PkgPath] = pkg.Module.Path
		}
	}
	
	// Try to read go.mod to get module dependencies
	goModPath := filepath.Join(sa.rootPath, "go.mod")
	if data, err := os.ReadFile(goModPath); err == nil {
		if modFile, err := modfile.Parse("go.mod", data, nil); err == nil {
			// Add the main module path
			if modFile.Module != nil && modFile.Module.Mod.Path != "" {
				mainModule := modFile.Module.Mod.Path
				sa.pkgModuleMap[mainModule] = mainModule
			}
			
			// Add all require entries
			for _, r := range modFile.Require {
				if r.Mod.Path != "" {
					// Map the module itself
					sa.pkgModuleMap[r.Mod.Path] = r.Mod.Path
				}
			}
			
			// Add all replace entries (to handle substituted modules)
			for _, r := range modFile.Replace {
				if r.Old.Path != "" && r.New.Path != "" {
					sa.pkgModuleMap[r.Old.Path] = r.New.Path
				}
			}
		}
	}
	
	// Now build reverse mapping: for each known module, add all package paths
	modulesToAdd := make(map[string][]string)
	for pkgPath, module := range sa.pkgModuleMap {
		modulesToAdd[module] = append(modulesToAdd[module], pkgPath)
	}
	
	// For packages not yet in map, try to find their module by checking if they start with known module paths
	for fn := range ssautil.AllFunctions(sa.prog) {
		if fn.Pkg == nil {
			continue
		}
		
		pkgPath := fn.Pkg.Pkg.Path()
		if _, exists := sa.pkgModuleMap[pkgPath]; !exists {
			// Check if this package belongs to any known module
			for modulePath, _ := range modulesToAdd {
				if pkgPath == modulePath || strings.HasPrefix(pkgPath, modulePath+"/") {
					sa.pkgModuleMap[pkgPath] = modulePath
					break
				}
			}
		}
	}
}

// buildStandardLibraryCache builds a cache of standard library packages using Go's official API
func (sa *SSAAnalyzer) buildStandardLibraryCache() {
	// Use Go's official standard library identification methods
	
	// Method 1: Check if package is in GOROOT (most reliable method)
	goroot := runtime.GOROOT()
	
	// Check all loaded packages
	for _, pkg := range sa.pkgs {
		// Skip vendor packages - they are external libraries, not standard library
		if strings.HasPrefix(pkg.PkgPath, "vendor/") {
			continue
		}
		if sa.isPackageInGOROOT(pkg.PkgPath, goroot) {
			sa.stdLibPkgs[pkg.PkgPath] = true
		}
	}
	
	// Method 2: Check packages from SSA program
	for fn := range ssautil.AllFunctions(sa.prog) {
		if fn.Pkg == nil {
			continue
		}
		pkgPath := fn.Pkg.Pkg.Path()
		
		// Skip vendor packages - they are external libraries, not standard library
		if strings.HasPrefix(pkgPath, "vendor/") {
			continue
		}
		
		// Skip if already processed
		if sa.stdLibPkgs[pkgPath] {
			continue
		}
		
		// Check if package is in GOROOT
		if sa.isPackageInGOROOT(pkgPath, goroot) {
			sa.stdLibPkgs[pkgPath] = true
		}
	}
	
	// Method 3: Use go list std command to get official standard library list
	sa.addOfficialStandardLibraryPackages()
}

// isPackageInGOROOT checks if a package is located in GOROOT
func (sa *SSAAnalyzer) isPackageInGOROOT(pkgPath, goroot string) bool {
	// Try to find the package in GOROOT
	pkg, err := build.Import(pkgPath, goroot, build.FindOnly)
	if err != nil {
		return false
	}
	
	// Check if the package directory is within GOROOT
	relPath, err := filepath.Rel(goroot, pkg.Dir)
	if err != nil {
		return false
	}
	
	// If the relative path doesn't start with "..", it's within GOROOT
	return !strings.HasPrefix(relPath, "..")
}

// addOfficialStandardLibraryPackages adds packages using go list std command
func (sa *SSAAnalyzer) addOfficialStandardLibraryPackages() {
	// Use go list std command to get the official list of standard library packages
	// This is the most reliable way to get the complete list without hardcoding
	
	// Execute "go list std" command to get official standard library packages
	cmd := exec.Command("go", "list", "std")
	cmd.Dir = sa.rootPath
	output, err := cmd.Output()
	if err != nil {
		// If go list std fails, we'll rely on GOROOT-based detection only
		return
	}
	
	// Parse the output to get package paths
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Skip vendor packages - they are external libraries, not standard library
		if line != "" && !strings.HasPrefix(line, "vendor/") && !sa.stdLibPkgs[line] {
			// Double-check that it's actually in GOROOT
			goroot := runtime.GOROOT()
			if sa.isPackageInGOROOT(line, goroot) {
				sa.stdLibPkgs[line] = true
			}
		}
	}
}



// removeDuplicateCallees removes duplicate callees for the same caller
// For reachability analysis, we only need the graph structure, not call frequency
// Duplicates are identified by: callee name + call_site_file (if present)
func (sa *SSAAnalyzer) removeDuplicateCallees(callGraphMap *map[string][]CallEdge, edgeCount *int) {
	newEdgeCount := 0
	duplicatesRemoved := 0
	
	for caller, callees := range *callGraphMap {
		seen := make(map[string]bool)
		var uniqueCallees []CallEdge
		
		for _, callee := range callees {
			// Create a unique key: callee + call_site_file (if present)
			key := callee.Callee
			if callee.CallSiteFile != "" {
				key = callee.Callee + "::" + callee.CallSiteFile
			}
			
			if !seen[key] {
				seen[key] = true
				uniqueCallees = append(uniqueCallees, callee)
				newEdgeCount++
			} else {
				duplicatesRemoved++
			}
		}
		
		(*callGraphMap)[caller] = uniqueCallees
	}
	
	fmt.Printf("   Removed %d duplicate callees\n", duplicatesRemoved)
	*edgeCount = newEdgeCount
}

func (sa *SSAAnalyzer) processEdges(cg *callgraph.Graph, callGraphMap *map[string][]CallEdge, edgeCount *int) {
	for _, node := range cg.Nodes {
		if node == nil || node.Func == nil {
			continue
		}
		caller := node.Func.String()
		
		// Process Out edges: node (caller) → edge.Callee (callee)
		for _, edge := range node.Out {
			if edge == nil || edge.Callee == nil || edge.Callee.Func == nil {
				continue
			}
			callee := edge.Callee.Func.String()
			
			// Extract callee module and package information
			calleeModule, calleePackage := sa.extractModuleAndPackage(callee)
			
			callEdge := CallEdge{
				Callee:        callee,
				CalleeModule:  calleeModule,
				CalleePackage: calleePackage,
			}
			
			// Extract call site file (where the caller calls the callee)
			if edge.Site != nil && edge.Site.Pos().IsValid() {
				pos := sa.prog.Fset.Position(edge.Site.Pos())
				if pos.Filename != "" {
					// Get relative path from project root
					relPath, err := filepath.Rel(sa.rootPath, pos.Filename)
					if err == nil && !strings.HasPrefix(relPath, "..") {
						callEdge.CallSiteFile = relPath  // Call site file (where caller calls callee)
					} else {
						// If relative path calculation fails, use absolute path
						callEdge.CallSiteFile = pos.Filename  // Call site file (where caller calls callee)
					}
				}
			}
			
			// Add all call relationships (duplicates will be removed later)
			(*callGraphMap)[caller] = append((*callGraphMap)[caller], callEdge)
			*edgeCount++
			
			// Also store in internal map for reachability analysis
			sa.callGraphMap[caller] = append(sa.callGraphMap[caller], callee)
		}
	}
}

// extractReachableFromMain extracts only functions reachable from main entry points
// This performs BFS traversal starting from main functions
func (sa *SSAAnalyzer) extractReachableFromMain(cg *callgraph.Graph, callGraphMap *map[string][]CallEdge, edgeCount *int) {
	// Find all main functions as entry points
	entryNodes := []*callgraph.Node{}
	for _, node := range cg.Nodes {
		if node == nil || node.Func == nil {
			continue
		}
		// Check if it's a main function or package init
		fn := node.Func.String()
		if strings.HasSuffix(fn, ".main") || strings.HasSuffix(fn, ".init") {
			entryNodes = append(entryNodes, node)
		}
	}
	
	fmt.Printf("   Found %d entry point(s): main/init functions\n", len(entryNodes))
	
	// Track visited nodes to avoid cycles
	visited := make(map[string]bool)
	
	// BFS traversal queue
	queue := make([]*callgraph.Node, 0)
	queue = append(queue, entryNodes...)
	
	for _, node := range entryNodes {
		visited[node.Func.String()] = true
	}
	
	// Process queue
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		
		if current == nil || current.Func == nil {
			continue
		}
		caller := current.Func.String()
		
		// Process Out edges: current (caller) → edge.Callee (callee)
		for _, edge := range current.Out {
			if edge == nil || edge.Callee == nil || edge.Callee.Func == nil {
				continue
			}
			callee := edge.Callee.Func.String()
			
			// Extract callee module and package information
			calleeModule, calleePackage := sa.extractModuleAndPackage(callee)
			
			callEdge := CallEdge{
				Callee:        callee,
				CalleeModule:  calleeModule,
				CalleePackage: calleePackage,
			}
			
			// Extract call site file (where the caller calls the callee)
			if edge.Site != nil && edge.Site.Pos().IsValid() {
				pos := sa.prog.Fset.Position(edge.Site.Pos())
				if pos.Filename != "" {
					relPath, err := filepath.Rel(sa.rootPath, pos.Filename)
					if err == nil && !strings.HasPrefix(relPath, "..") {
						callEdge.CallSiteFile = relPath  // Call site file (where caller calls callee)
					} else {
						callEdge.CallSiteFile = pos.Filename  // Call site file (where caller calls callee)
					}
				}
			}
			
			// Add call relationship
			(*callGraphMap)[caller] = append((*callGraphMap)[caller], callEdge)
			*edgeCount++
			
			// Add callee to queue if not visited
			if !visited[callee] {
				visited[callee] = true
				queue = append(queue, edge.Callee)
			}
		}
	}
	
	fmt.Printf("   Traversed %d reachable functions from entry points\n", len(visited))
}

// CheckReachability checks if a target function is reachable from main
// Returns true if reachable, along with a possible call chain
func (sa *SSAAnalyzer) CheckReachability(vulnerableFunc string) (bool, []string) {
	// Find main functions as entry points
	entryPoints := []string{}
	
	// Simple BFS to find path from any main to vulnerable function
	for caller := range sa.callGraphMap {
		if strings.HasSuffix(caller, ".main") || strings.HasSuffix(caller, ".init") {
			entryPoints = append(entryPoints, caller)
		}
	}
	
	// Perform BFS from each entry point
	for _, entry := range entryPoints {
		visited := make(map[string]bool)
		parent := make(map[string]string) // For path reconstruction
		queue := []string{entry}
		visited[entry] = true
		
		for len(queue) > 0 {
			current := queue[0]
			queue = queue[1:]
			
			// Check if we found the vulnerable function
			if strings.Contains(current, vulnerableFunc) {
				// Reconstruct path
				path := []string{}
				node := current
				for node != "" {
					path = append([]string{node}, path...)
					node = parent[node]
				}
				return true, path
			}
			
			// Add all callees to queue
			for _, callee := range sa.callGraphMap[current] {
				if !visited[callee] {
					visited[callee] = true
					parent[callee] = current
					queue = append(queue, callee)
				}
			}
		}
	}
	
	return false, nil
}

func (sa *SSAAnalyzer) extractAllFunctions() []string {
	var functions []string
	seen := make(map[string]bool)
	
	// Extract from SSA program (includes all dependencies)
	for fn := range ssautil.AllFunctions(sa.prog) {
		fnName := fn.String()
		if !seen[fnName] {
			seen[fnName] = true
			functions = append(functions, fnName)
		}
	}
	
	return functions
}

func (sa *SSAAnalyzer) extractMainModule() string {
	for _, pkg := range sa.pkgs {
		if pkg.Module != nil {
			return pkg.Module.Path
		}
	}
	return ""
}

func (sa *SSAAnalyzer) extractDependencies() []string {
	var deps []string
	seen := make(map[string]bool)
	for _, pkg := range sa.pkgs {
		if pkg.Module != nil && pkg.Module.Path != "" {
			if !seen[pkg.Module.Path] {
				seen[pkg.Module.Path] = true
				deps = append(deps, pkg.Module.Path)
			}
		}
	}
	return deps
}

func (sa *SSAAnalyzer) countAllPackages() int {
	return len(sa.prog.AllPackages())
}

// extractModuleAndPackage extracts module and package information from a function string
// This function now uses the package-module mapping built from actual Go module information
func (sa *SSAAnalyzer) extractModuleAndPackage(funcStr string) (module, pkg string) {
	// Remove Go SSA patterns ($1, $bound, $thunk, etc.) before processing
	// These are internal compiler-generated suffixes that should not affect package extraction
	funcStrCleaned := funcStr
	dollarPos := strings.Index(funcStrCleaned, "$")
	if dollarPos > 0 {
		funcStrCleaned = funcStrCleaned[:dollarPos]
	}
	
	// Handle method receivers FIRST (before removing generics)
	// This handles patterns like "(*sync/atomic.Pointer[Type]).Method[Type]"
	if strings.Contains(funcStrCleaned, ").") {
		// Find the closing parenthesis and dot
		closeParen := strings.Index(funcStrCleaned, ").")
		if closeParen != -1 {
			// Extract the type part before the closing parenthesis
			typePart := funcStrCleaned[1:closeParen] // Remove opening parenthesis
			
			// Remove any remaining generic parameters in the type part
			// (in case we have nested generics like (*Type[InnerType]).Method)
			bracketInType := strings.Index(typePart, "[")
			if bracketInType > 0 {
				typePart = typePart[:bracketInType]
			}
			
			// Handle pointer types like "*net/http.persistConn"
			if strings.HasPrefix(typePart, "*") {
				typePart = typePart[1:] // Remove the asterisk
			}
			
			// Find the last dot in the type part to get package path
			lastDot := strings.LastIndex(typePart, ".")
			if lastDot != -1 {
				pkgPath := typePart[:lastDot]
				return sa.extractModuleFromPackagePath(pkgPath), pkgPath
			}
		}
	}
	
	// Remove generic type parameters ([...]) before extracting package
	// This prevents dots inside type parameters from being mistaken as package separators
	// Only do this for regular functions (not method receivers, which were handled above)
	funcStrForPkg := funcStrCleaned
	bracketPos := strings.Index(funcStrForPkg, "[")
	if bracketPos > 0 {
		funcStrForPkg = funcStrForPkg[:bracketPos]
	}
	
	// Handle regular functions like "github.com/user/repo/pkg.Function"
	// Use the cleaned function string (without generics and SSA suffixes)
	lastDot := strings.LastIndex(funcStrForPkg, ".")
	if lastDot == -1 {
		// No dots, might be a simple function name - check if it's in our std lib cache
		if sa.stdLibPkgs[funcStrForPkg] {
			return "std", funcStrForPkg
		}
		// If not in std lib cache, return empty module
		return "", funcStrForPkg
	}
	
	pkgPath := funcStrForPkg[:lastDot]
	return sa.extractModuleFromPackagePath(pkgPath), pkgPath
}

// extractModuleFromPackagePath extracts module information from a package path
// This function uses only information from loaded packages and SSA - no heuristics
func (sa *SSAAnalyzer) extractModuleFromPackagePath(pkgPath string) string {
	// IMPORTANT: Check vendor packages FIRST before checking std lib cache
	// Vendor packages in GOROOT are external libraries, not standard library
	if strings.HasPrefix(pkgPath, "vendor/") {
		// Extract the actual module path from vendor path
		// e.g., "vendor/golang.org/x/crypto/cryptobyte" -> "golang.org/x/crypto"
		vendorPath := pkgPath[len("vendor/"):]
		parts := strings.Split(vendorPath, "/")
		
		// Handle golang.org/x/* modules
		if len(parts) >= 3 && parts[0] == "golang.org" && parts[1] == "x" {
			// Return the module path: golang.org/x/{module}
			return fmt.Sprintf("golang.org/x/%s", parts[2])
		}
		
		// Handle other vendor modules (e.g., "vendor/github.com/user/repo/pkg" -> "github.com/user/repo")
		if len(parts) >= 2 {
			return strings.Join(parts[:2], "/")
		}
		
		// If can't parse, try to find in package-module map
		if module, exists := sa.pkgModuleMap[vendorPath]; exists {
			return module
		}
		
		// Fallback: return the vendor path without "vendor/" prefix as module
		return vendorPath
	}
	
	// Check if it's a standard library package using our cache
	if sa.stdLibPkgs[pkgPath] {
		return "std"
	}
	
	// Check in package-module map (built from SSA and loaded packages)
	if module, exists := sa.pkgModuleMap[pkgPath]; exists {
		return module
	}
	
	// Find the longest matching package path prefix
	// This handles subpackages that weren't directly loaded
	bestMatch := ""
	bestMatchLen := 0
	for pkg, module := range sa.pkgModuleMap {
		if strings.HasPrefix(pkgPath, pkg+"/") || pkgPath == pkg {
			if len(pkg) > bestMatchLen {
				bestMatch = module
				bestMatchLen = len(pkg)
			}
		}
	}
	
	// If we found a match, return it
	if bestMatch != "" {
		return bestMatch
	}
	
	// If no match found, return empty string
	// This is better than guessing with heuristics
	return ""
}

// findPackageByPath finds a package by its path
func (sa *SSAAnalyzer) findPackageByPath(pkgPath string) *packages.Package {
	for _, pkg := range sa.pkgs {
		if pkg.PkgPath == pkgPath {
			return pkg
		}
	}
	return nil
}

// sanitizeFilename replaces characters that are unsafe for filenames
func sanitizeFilename(name string) string {
	replacer := strings.NewReplacer("/", "-", "\\", "-", " ", "_", ":", "-", "*", "-", "?", "-", "\"", "-", "<", "-", ">", "-", "|", "-")
	return replacer.Replace(name)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run goSSA.go <project_path>")
		fmt.Println("Example: go run goSSA.go ../golangModule/github-mcp-server")
		os.Exit(1)
	}

	projectPath := os.Args[1]
	if _, err := os.Stat(projectPath); os.IsNotExist(err) {
		log.Fatalf("Path does not exist: %s", projectPath)
	}

	analyzer := NewSSAAnalyzer(projectPath)
	result, err := analyzer.Analyze()
	if err != nil {
		log.Fatalf("Failed: %v", err)
	}

	// Use REPO_NAME from env if available, otherwise use directory name
	targetName := ""
	if repoName := os.Getenv("REPO_NAME"); repoName != "" {
		targetName = repoName
	} else {
		targetName = filepath.Base(projectPath)
		if targetName == "." || targetName == string(filepath.Separator) || targetName == "" {
			targetName = "project"
		}
	}
	safeName := sanitizeFilename(targetName)
	
	// Use OUTPUT_DIR from env if available, otherwise use current directory
	outputDir := os.Getenv("OUTPUT_DIR")
	if outputDir == "" {
		outputDir = "."
	}
	outputFile := filepath.Join(outputDir, fmt.Sprintf("%s-callGraph.json", safeName))
	
	jsonData, _ := json.MarshalIndent(result, "", "  ")
	os.WriteFile(outputFile, jsonData, 0644)
	
	fmt.Printf("\nSaved to %s\n", outputFile)
	fmt.Printf("Packages: %d\n", result.Packages)
	fmt.Printf("Functions: %d\n", result.Functions)
	fmt.Printf("Edges: %d\n", result.Edges)
	fmt.Printf("Call Graph Entries: %d\n", len(result.CallGraph))
	
	// TODO: Reachability check for vulnerable functions
	// if len(os.Args) >= 3 {
	// 	vulnerableFunc := os.Args[2]
	// 	fmt.Printf("\n--- Checking reachability for: %s ---\n", vulnerableFunc)
	// 	reachable, path := analyzer.CheckReachability(vulnerableFunc)
	// 	if reachable {
	// 		fmt.Printf("✓ REACHABLE from main/init\n")
	// 		fmt.Printf("Call chain:\n")
	// 		for i, fn := range path {
	// 			fmt.Printf("  %d. %s\n", i+1, fn)
	// 		}
	// 	} else {
	// 		fmt.Printf("✗ NOT REACHABLE from main/init\n")
	// 	}
	// }
}
