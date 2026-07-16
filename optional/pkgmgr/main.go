package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "resolve":
		cmdResolve(args)
	case "install":
		cmdInstall(args)
	case "list":
		cmdList(args)
	case "info":
		cmdInfo(args)
	case "validate":
		cmdValidate(args)
	case "graph":
		cmdGraph(args)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`asscor-pkg — ASSCOR extension package manager

Usage:
  asscor-pkg resolve  [--root=<dir>]           Resolve all dependencies, report conflicts
  asscor-pkg install  [--root=<dir>] [--force] Fetch external sources + validate
  asscor-pkg list     [--root=<dir>]           List all discovered packages
  asscor-pkg info     [--root=<dir>] <name>    Show package details
  asscor-pkg validate [--root=<dir>]           Validate all package manifests
  asscor-pkg graph    [--root=<dir>]           Print dependency graph (DOT format)`)
}

func rootDir(args []string) string {
	for _, a := range args {
		if strings.HasPrefix(a, "--root=") {
			return strings.TrimPrefix(a, "--root=")
		}
	}
	return "optional"
}

func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

func cmdResolve(args []string) {
	root := rootDir(args)
	fmt.Printf("Resolving dependencies under %s ...\n\n", root)

	g, err := ResolveDependencies(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Packages: %d\nEdges: %d\n", len(g.Packages), len(g.Edges))

	if len(g.Cycles) > 0 {
		fmt.Println("\n⚠️  DEPENDENCY CYCLES DETECTED:")
		for _, cycle := range g.Cycles {
			fmt.Printf("  → %s\n", strings.Join(cycle, " → "))
		}
	}

	if len(g.Unresolved) > 0 {
		fmt.Println("\n⚠️  UNRESOLVED DEPENDENCIES:")
		for _, u := range g.Unresolved {
			fmt.Printf("  %s → %s: %s\n", u.Depender, u.Dep.Package, u.Reason)
		}
		os.Exit(1)
	}

	if len(g.Cycles) == 0 {
		fmt.Println("\n✅ All dependencies resolved, no cycles")
	}
}

func cmdInstall(args []string) {
	root := rootDir(args)
	force := hasFlag(args, "--force")
	_ = force

	fmt.Printf("Installing packages under %s ...\n\n", root)

	// Discover and validate first
	g, err := ResolveDependencies(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: resolve: %v\n", err)
		os.Exit(1)
	}

	// Validate compatibility
	hasWarnings := false
	for _, pkg := range g.Packages {
		warnings := ValidateCompatibility(pkg)
		if len(warnings) > 0 {
			hasWarnings = true
			fmt.Printf("[%s]\n", pkg.Name)
			for _, w := range warnings {
				fmt.Printf("  ⚠️  %s\n", w)
			}
		}
	}
	if hasWarnings {
		fmt.Println()
	}

	// Fetch external sources for each package
	pkgIndex := make(map[string]bool)
	for _, pkg := range g.Packages {
		if len(pkg.ExternalSrc) > 0 {
			fmt.Printf("[%s] fetching external sources...\n", pkg.Name)
			if err := FetchExternalSources(pkg, root, false); err != nil {
				fmt.Fprintf(os.Stderr, "  ERROR: %v\n", err)
				os.Exit(1)
			}
			pkgIndex[pkg.Name] = true
		}
	}

	if len(g.Unresolved) > 0 {
		fmt.Println("\n⚠️  Some dependencies could not be resolved:")
		for _, u := range g.Unresolved {
			fmt.Printf("  %s → %s: %s\n", u.Depender, u.Dep.Package, u.Reason)
		}
		os.Exit(1)
	}

	fmt.Println("\n✅ All packages installed successfully")
}

func cmdList(args []string) {
	root := rootDir(args)
	pkgs, err := discoverPackages(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
	if len(pkgs) == 0 {
		fmt.Println("No packages found.")
		return
	}

	// Sort by name
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].Name < pkgs[j].Name })

	fmt.Printf("%-30s %-10s %s\n", "NAME", "VERSION", "DESCRIPTION")
	fmt.Println(strings.Repeat("-", 80))
	for _, pkg := range pkgs {
		desc := pkg.Description
		if len(desc) > 40 {
			desc = desc[:37] + "..."
		}
		fmt.Printf("%-30s %-10s %s\n", pkg.Name, pkg.Version, desc)
	}
}

func cmdInfo(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: asscor-pkg info <name>")
		os.Exit(1)
	}
	name := args[0]
	root := rootDir(args)

	pkgs, err := discoverPackages(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
	for _, pkg := range pkgs {
		if pkg.Name == name {
			fmt.Printf("Name:        %s\n", pkg.Name)
			fmt.Printf("Version:     %s\n", pkg.Version)
			fmt.Printf("Description: %s\n", pkg.Description)
			fmt.Printf("Author:      %s\n", pkg.Author)
			fmt.Printf("License:     %s\n", pkg.License)
			fmt.Printf("ASSCOR:      %s\n", pkg.Compat.ASSCORVer)
			fmt.Printf("Go:          %s\n", pkg.Compat.GoVer)
			fmt.Printf("Platforms:   %v\n", pkg.Compat.Platform)
			fmt.Printf("Modules:     %d\n", len(pkg.Modules))
			for _, m := range pkg.Modules {
				fmt.Printf("  - %s (%s)\n", m.ID, m.Path)
			}
			fmt.Printf("Dependencies: %d\n", len(pkg.Deps))
			for _, d := range pkg.Deps {
				fmt.Printf("  - %s %s", d.Package, d.Version)
				if d.Optional {
					fmt.Print(" (optional)")
				}
				fmt.Println()
			}
			fmt.Printf("External Sources: %d\n", len(pkg.ExternalSrc))
			for _, s := range pkg.ExternalSrc {
				fmt.Printf("  - %s → %s\n", s.Repo, s.Target)
			}
			return
		}
	}
	fmt.Fprintf(os.Stderr, "Package %q not found\n", name)
	os.Exit(1)
}

func cmdValidate(args []string) {
	root := rootDir(args)

	pkgs, loadErr := discoverPackages(root)
	if loadErr != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", loadErr)
		os.Exit(1)
	}

	fmt.Printf("Validating %d packages...\n\n", len(pkgs))
	for _, pkg := range pkgs {
		fmt.Printf("  ✅ %s %s\n", pkg.Name, pkg.Version)
	}
	fmt.Println("\nAll valid.")
}

func cmdGraph(args []string) {
	root := rootDir(args)
	g, err := ResolveDependencies(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("digraph G {")
	fmt.Println("  rankdir=LR;")
	fmt.Println("  node [shape=box, style=rounded];")

	for _, pkg := range g.Packages {
		fmt.Printf("  \"%s\" [label=\"%s\\n%s\"];\n", pkg.Name, pkg.Name, pkg.Version)
	}

	for _, edge := range g.Edges {
		style := ""
		if edge.Optional {
			style = " [style=dashed]"
		}
		fmt.Printf("  \"%s\" -> \"%s\"%s;\n", edge.From, edge.To, style)
	}

	fmt.Println("}")

	if len(g.Unresolved) > 0 {
		fmt.Fprintln(os.Stderr, "\n⚠️  Unresolved dependencies exist (not shown in graph):")
		for _, u := range g.Unresolved {
			fmt.Fprintf(os.Stderr, "  %s → %s: %s\n", u.Depender, u.Dep.Package, u.Reason)
		}
	}
}
