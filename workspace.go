package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/emicklei/dot"
)

const (
	tfext        = ".tf"
	preFileName  = "PreManual.md"
	postFileName = "PostManual.md"
)

// GetWorkspaces scans the given root directory recursively to discover workspaces,
// ignoring paths that match any of the provided ignore patterns. It collects all files
// with the specified extension (tfext) and organizes them into Workspace structs,
// gathering additional metadata such as remote state, dependencies, inputs, outputs,
// and manual configuration files for each workspace. The function also establishes
// relationships between workspace inputs and outputs based on dependencies.
// Returns a map of workspace paths to Workspace pointers, or an error if any occurs
// during processing.
func GetWorkspaces(root string, ignore []string) (map[string]*Workspace, error) {
	workspaces := map[string]*Workspace{}

	matchers := []*regexp.Regexp{}
	for _, i := range ignore {
		m, err := regexp.Compile(i)
		matchers = append(matchers, m)
		if err != nil {
			err = fmt.Errorf("error while compiling pattern '%s', error is: %s", i, err.Error())
			return workspaces, err
		}
	}

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		for _, m := range matchers {
			if m.MatchString(path) {
				return nil
			}
		}

		if filepath.Ext(path) == tfext {
			workspacePath, filename := filepath.Split(path)
			if w, found := workspaces[workspacePath]; found {
				w.Files[filename] = &File{}
			} else {
				files := map[string]*File{filename: {}}
				workspaces[workspacePath] = &Workspace{
					Files: files,
					Root:  workspacePath,
				}
			}
		}
		return nil
	})
	if err != nil {
		return workspaces, err
	}

	// fetch info per workspace
	for path, workspace := range workspaces {
		err = workspace.readFiles(path)
		if err != nil {
			return workspaces, err
		}

		rs, err := workspace.getRemoteState()
		if err != nil {
			return workspaces, err
		}
		workspace.RemoteState = rs

		td, err := workspace.getTerraformDependencies()
		if err != nil {
			return workspaces, err
		}
		workspace.Dependencies = append(workspace.Dependencies, td...)

		ti, err := workspace.getTerraformInputs()
		if err != nil {
			return workspaces, err
		}
		workspace.Inputs = append(workspace.Inputs, ti...)

		o, err := workspace.getOutputs()
		if err != nil {
			return workspaces, err
		}
		workspace.Outputs = append(workspace.Outputs, o...)
	}

	// fetch manual info per workspace
	for _, workspace := range workspaces {
		pre, err := workspace.getManual(preFileName)
		if err != nil {
			return workspaces, err
		}
		workspace.PreManual = pre

		post, err := workspace.getManual(postFileName)
		if err != nil {
			return workspaces, err
		}
		workspace.PostManual = post

		md, err := workspace.getManualDependencies(workspaces)
		if err != nil {
			return workspaces, err
		}
		workspace.Dependencies = append(workspace.Dependencies, md...)

		mi, err := workspace.getManualInputs(workspaces)
		if err != nil {
			return workspaces, err
		}
		workspace.Inputs = append(workspace.Inputs, mi...)
	}

	// get relations between workspace inputs and outputs
	for _, workspace := range workspaces {
		for i, input := range workspace.Inputs {
			for _, dep := range workspaces {
				if input.Dependency != nil && input.Dependency.equals(dep.RemoteState) {
					for o, output := range dep.Outputs {
						if input.Name == output.Name {
							workspace.Inputs[i].ReferesTo = &dep.Outputs[o]
							dep.Outputs[o].ReferedBy = append(dep.Outputs[o].ReferedBy, &workspace.Inputs[i])
						}
					}
				}
			}
		}
	}

	return workspaces, err
}

// Workspace represents a project workspace, encapsulating its files, root directory,
// remote state, dependencies, input and output variables, and associated manual content.
// It also maintains a reference to a graph element for internal use.
//
// Fields:
//   - Files: A map of file paths to File objects within the workspace (not serialized to JSON).
//   - Root: The root directory of the workspace.
//   - RemoteState: The current remote state associated with the workspace.
//   - Dependencies: A list of remote states that this workspace depends on.
//   - Inputs: A list of input variables for the workspace.
//   - Outputs: A list of output variables produced by the workspace.
//   - PreManual: Manual content to be rendered before main processing.
//   - PreManualRendered: The rendered output of the pre-manual content.
//   - PostManual: Manual content to be rendered after main processing.
//   - PostManualRendered: The rendered output of the post-manual content.
//   - graphElement: An internal reference to a dot.Graph element (not exported).
type Workspace struct {
	Files              map[string]*File `json:"-"`
	Root               string           `json:"root"`
	RemoteState        RemoteState      `json:"remote_state"`
	Dependencies       []RemoteState    `json:"dependencies"`
	Inputs             []Input          `json:"inputs"`
	Outputs            []Output         `json:"outputs"`
	PreManual          Manual           `json:"pre_manual"`
	PreManualRendered  string           `json:"pre_manual_rendered"`
	PostManual         Manual           `json:"post_manual"`
	PostManualRendered string           `json:"post_manual_rendered"`
	graphElement       *dot.Graph
}

type Manual string

type File struct {
	Raw []byte
}

// Input represents an input entity within the workspace, containing metadata such as its name,
// full name, and references to dependencies and outputs. It also tracks the files it is defined in,
// its parent workspace, and its corresponding graph node for visualization or analysis purposes.
type Input struct {
	Name         string       `json:"name"`
	FullName     string       `json:"full_name"`
	Dependency   *RemoteState `json:"dependency"`
	ReferesTo    *Output      `json:"referes_to"`
	InFile       []string     `json:"in_file"`
	BelongsTo    *Workspace   `json:"-"`
	graphElement dot.Node
}

// Output represents the result of a computation or process within a workspace.
// It contains metadata such as the output's name, the file it was generated from,
// and references to related inputs and the workspace it belongs to.
// Some fields are omitted from JSON serialization for internal use only.
type Output struct {
	Name         string      `json:"name"`
	Value        interface{} `json:"-"`
	InFile       string      `json:"in_file"`
	ReferedBy    []*Input    `json:"-"`
	BelongsTo    *Workspace  `json:"-"`
	graphElement dot.Node
}

// readFiles reads the contents of each file in the Workspace's Files map from the specified basepath.
// It updates the Raw field of each file with the file's contents.
// Returns an error if any file cannot be read.
func (ws *Workspace) readFiles(basepath string) error {
	for filename, file := range ws.Files {
		raw, err := os.ReadFile(basepath + filename)
		if err != nil {
			return err
		}
		file.Raw = raw
	}
	return nil
}

// getTerraformInputs scans all files in the Workspace for references to remote state outputs
// using predefined regular expressions. It extracts the referenced remote state name and variable,
// associates them with the corresponding Dependency if found, and returns a slice of Input structs
// representing these references. Each Input includes the variable name, full reference string,
// the files in which it appears, the associated Dependency, and a pointer to the Workspace.
// Returns an error only if an unexpected issue occurs during processing.
func (ws Workspace) getTerraformInputs() ([]Input, error) {
	inputs := []Input{}
	refs := []*regexp.Regexp{
		regexp.MustCompile(`data\.terraform_remote_state\.(?P<rs>[a-zA-Z0-9_-]*)\.outputs\.(?P<var>[a-zA-Z0-9_-]*)`),
	}

	appendIfMissing := func(slice []string, i string) []string {
		for _, ele := range slice {
			if ele == i {
				return slice
			}
		}
		return append(slice, i)
	}

	for filename, file := range ws.Files {
		for _, r := range refs {
			matches := r.FindAllSubmatch(file.Raw, -1)
			for _, match := range matches {
				if len(match) != 3 {
					continue
				}

				fullName := string(match[0])
				rsName := string(match[1])
				varName := string(match[2])

				var depRef *RemoteState

				for i, dep := range ws.Dependencies {
					if dep.Name == rsName {
						depRef = &ws.Dependencies[i]
					}
				}

				inputExists := false
				for i, input := range inputs {
					if depRef != nil && varName == input.Name && depRef.equals(*input.Dependency) {
						inputExists = true
						inputs[i].InFile = appendIfMissing(inputs[i].InFile, filename)
					}
				}

				if !inputExists {
					input := Input{
						Name:       varName,
						FullName:   fullName,
						InFile:     []string{filename},
						Dependency: depRef,
						BelongsTo:  &ws,
					}

					inputs = append(inputs, input)
				}
			}
		}
	}
	return inputs, nil
}

// getRemoteState scans the files in the Workspace for a Terraform remote state backend configuration,
// specifically looking for Azure backend parameters. It uses regular expressions to extract the values
// of storage_account_name, key, resource_group_name, and container_name from the Terraform configuration
// blocks. If all required parameters are found in a file, it constructs and returns a RemoteState struct
// populated with these values. If multiple remote state definitions are found in a single file, it returns
// an error. If no valid remote state configuration is found, it returns an empty RemoteState and nil error.
//
// Returns:
//   - RemoteState: The extracted remote state configuration, if found.
//   - error: An error if multiple remote state definitions are found in a file, otherwise nil.
func (ws Workspace) getRemoteState() (RemoteState, error) {
	rs := RemoteState{}

	refs := map[string]*regexp.Regexp{
		"terraform":            regexp.MustCompile(`terraform\s*\{(?:[^{}]*|\{(?:[^{}]*|\{[^{}]*\})*\})*\}`),
		"storage_account_name": regexp.MustCompile(`storage_account_name\s*=\s*\"(?P<val>[a-zA-Z0-9_\-${}.]*)\"`),
		"key":                  regexp.MustCompile(`key\s*=\s*\"(?P<val>[a-zA-Z0-9_\-${}.]*)\"`),
		"resource_group_name":  regexp.MustCompile(`resource_group_name\s*=\s*\"(?P<val>[a-zA-Z0-9_\-${}.]*)\"`),
		"container_name":       regexp.MustCompile(`container_name\s*=\s*\"(?P<val>[a-zA-Z0-9_\-${}.]*)\"`),
	}

	for filename, file := range ws.Files {
		terraformMatches := refs["terraform"].FindAll(file.Raw, -1)
		if len(terraformMatches) > 1 {
			return rs, fmt.Errorf("too many remote state definitions found in %s", filename)
		} else if len(terraformMatches) < 1 {
			continue
		}

		var storage_account_name, key, resource_group_name, container_name string

		storage_account_nameMatches := refs["storage_account_name"].FindAllSubmatch(terraformMatches[0], -1)
		if len(storage_account_nameMatches) > 0 && len(storage_account_nameMatches[0]) > 1 {
			storage_account_name = string(storage_account_nameMatches[0][1])
		}

		keyMatches := refs["key"].FindAllSubmatch(terraformMatches[0], -1)
		if len(keyMatches) > 0 && len(keyMatches[0]) > 1 {
			key = string(keyMatches[0][1])
		}

		resource_group_nameMatches := refs["resource_group_name"].FindAllSubmatch(terraformMatches[0], -1)
		if len(resource_group_nameMatches) > 0 && len(resource_group_nameMatches[0]) > 1 {
			resource_group_name = string(resource_group_nameMatches[0][1])
		}

		container_nameMatches := refs["container_name"].FindAllSubmatch(terraformMatches[0], -1)
		if len(container_nameMatches) > 0 && len(container_nameMatches[0]) > 1 {
			container_name = string(container_nameMatches[0][1])
		}

		if storage_account_name != "" && container_name != "" && key != "" && resource_group_name != "" {
			rs = RemoteState{
				InFile:  filename,
				Bucket:  storage_account_name,
				Key:     key,
				Profile: resource_group_name,
				Region:  container_name,
			}
		}
	}

	return rs, nil
}

// getTerraformDependencies parses the files in the Workspace to extract Terraform remote state dependencies.
// It searches for `terraform_remote_state` data blocks and extracts relevant backend configuration values such as
// storage account name, key, resource group name, and container name. The function returns a slice of RemoteState
// structs containing the extracted dependency information, or an error if any occurs during processing.
//
// Returns:
//   - []RemoteState: A slice of RemoteState structs representing the discovered Terraform remote state dependencies.
//   - error: An error if any issues are encountered during extraction, otherwise nil.
func (ws Workspace) getTerraformDependencies() ([]RemoteState, error) {
	d := []RemoteState{}

	refs := map[string]*regexp.Regexp{
		"rs":                   regexp.MustCompile(`data\s*\"terraform_remote_state\"\s*\"(?P<val>[a-zA-Z0-9_-]*)\"\s*\{[^\{\}]*\{\n.*\n.*\n.*\n.*\n.*\}[^\{\}]*\}`),
		"storage_account_name": regexp.MustCompile(`storage_account_name\s*=\s*\"(?P<val>[a-zA-Z0-9_\-\${}./]*)\"`),
		"key":                  regexp.MustCompile(`key\s*=\s*\"(?P<val>[^\"]*)\"`),
		"resource_group_name":  regexp.MustCompile(`resource_group_name\s*=\s*\"(?P<val>[a-zA-Z0-9_\-]*)\"`),
		"container_name":       regexp.MustCompile(`container_name\s*=\s*\"(?P<val>[a-zA-Z0-9_\-]*)\"`),
	}

	for filename, file := range ws.Files {
		rsMatches := refs["rs"].FindAllSubmatch(file.Raw, -1)
		if len(rsMatches) < 1 {
			continue
		}

		for _, definition := range rsMatches {
			if len(definition) < 2 {
				continue
			}
			name := string(definition[1])
			var storage_account_name, key, resource_group_name, container_name string

			storage_account_nameMatches := refs["storage_account_name"].FindAllSubmatch(definition[0], -1)
			if len(storage_account_nameMatches) > 0 && len(storage_account_nameMatches[0]) > 1 {
				storage_account_name = string(storage_account_nameMatches[0][1])
			}

			keyMatches := refs["key"].FindAllSubmatch(definition[0], -1)
			if len(keyMatches) > 0 && len(keyMatches[0]) > 1 {
				key = string(keyMatches[0][1])
			}

			resource_group_nameMatches := refs["resource_group_name"].FindAllSubmatch(definition[0], -1)
			if len(resource_group_nameMatches) > 0 && len(resource_group_nameMatches[0]) > 1 {
				resource_group_name = string(resource_group_nameMatches[0][1])
			}

			container_nameMatches := refs["container_name"].FindAllSubmatch(definition[0], -1)
			if len(container_nameMatches) > 0 && len(container_nameMatches[0]) > 1 {
				container_name = string(container_nameMatches[0][1])
			}

			if storage_account_name == "" || container_name == "" || key == "" || resource_group_name == "" {
				continue
			}
			rs := RemoteState{
				InFile:  filename,
				Name:    name,
				Bucket:  storage_account_name,
				Key:     key,
				Profile: resource_group_name,
				Region:  container_name,
			}
			d = append(d, rs)
		}

	}

	return d, nil
}

// getManualDependencies parses the PreManual and PostManual fields of the Workspace for references
// to remote states in the form of {{workspace.key}}. It searches for these references using a regular
// expression, extracts the workspace path, and matches it against the provided workspaces map.
// For each match, it constructs a RemoteState object containing relevant information from the referenced
// workspace and returns a slice of these RemoteState objects. If a reference is malformed, an error is returned.
//
// Parameters:
//   - workspaces: a map of workspace names to Workspace pointers, used to resolve references.
//
// Returns:
//   - A slice of RemoteState objects representing the manually referenced remote states.
//   - An error if any reference is malformed.
func (ws Workspace) getManualDependencies(workspaces map[string]*Workspace) ([]RemoteState, error) {
	d := []RemoteState{}
	manuals := map[string]Manual{
		preFileName:  ws.PreManual,
		postFileName: ws.PostManual,
	}
	re := regexp.MustCompile(`\{\{.*\}\}`)
	for filename, m := range manuals {
		submaches := re.FindAllStringSubmatch(string(m), -1)
		for _, sm := range submaches {
			match := sm[0]
			seg := strings.SplitN(strings.Trim(match, "{}"), ".", 2)
			if len(seg) != 2 {
				return d, fmt.Errorf("reference '%s' seems to be malformed", match)
			}

			workspacePath := seg[0]

			for name, workspace := range workspaces {
				if strings.Contains(name, workspacePath) {

					rs := RemoteState{
						InFile:  filename,
						Name:    workspacePath,
						Bucket:  workspace.RemoteState.Bucket,
						Key:     workspace.RemoteState.Key,
						Profile: workspace.RemoteState.Profile,
						Region:  workspace.RemoteState.Region,
					}

					d = append(d, rs)

				}
			}
		}
	}
	return d, nil

}

// getManualInputs scans the PreManual and PostManual fields of the Workspace for template references
// in the form of {{workspace.output}}. It parses these references, validates their format, and attempts
// to resolve them against the provided map of workspaces and their outputs. For each valid reference found,
// it constructs an Input object containing metadata about the dependency. If a reference is malformed or
// cannot be resolved, an error is returned. The function returns a slice of all successfully resolved Inputs.
func (ws Workspace) getManualInputs(workspaces map[string]*Workspace) ([]Input, error) {
	inputs := []Input{}

	manuals := map[string]Manual{
		preFileName:  ws.PreManual,
		postFileName: ws.PostManual,
	}
	re := regexp.MustCompile(`\{\{.*\}\}`)
	for filename, m := range manuals {
		submaches := re.FindAllSubmatch([]byte(m), -1)
		for _, sm := range submaches {
			match := string(sm[0])
			seg := strings.SplitN(strings.Trim(match, "{}"), ".", 2)
			if len(seg) != 2 {
				return inputs, fmt.Errorf("reference '%s' seems to be malformed", match)
			}

			workspacePath := filepath.FromSlash(seg[0])
			outputName := seg[1]

			var o *Output
			for name, workspace := range workspaces {
				if strings.Contains(name, workspacePath) {
					for _, output := range workspace.Outputs {
						if output.Name == outputName {
							o = &output
						}
					}
				}
			}
			if o == nil {
				return inputs, fmt.Errorf("reference to '%s' in workspace '%s' does not exist", outputName, workspacePath)
			}

			input := Input{
				Name:       outputName,
				FullName:   match,
				InFile:     []string{filename},
				Dependency: &o.BelongsTo.RemoteState,
				BelongsTo:  &ws,
			}

			inputs = append(inputs, input)
		}
	}

	return inputs, nil
}

// getOutputs scans all files in the Workspace for output definitions using a regular expression,
// extracts their names, and returns a slice of Output structs representing each found output.
// Each Output includes its name, the file it was found in, and a reference to the Workspace.
// Returns an error only if an unexpected issue occurs during processing (currently always returns nil).
func (ws Workspace) getOutputs() ([]Output, error) {
	o := []Output{}
	refs := map[string]*regexp.Regexp{
		"output": regexp.MustCompile(`output\s*\"(?P<val>[a-zA-Z0-9_-]*)\"\s*\{`),
	}
	for filename, file := range ws.Files {
		outputMatches := refs["output"].FindAllSubmatch(file.Raw, -1)
		if len(outputMatches) < 1 {
			continue
		}

		for _, m := range outputMatches {
			if len(m) < 2 {
				continue
			}
			output := Output{
				Name:      string(m[1]),
				InFile:    filename,
				BelongsTo: &ws,
			}
			o = append(o, output)
		}
	}

	return o, nil
}

// getManual attempts to read the contents of the specified file within the workspace root
// and returns it as a Manual type. If the file does not exist, it returns an empty Manual.
// Returns an error if there is a problem reading the file.
func (ws Workspace) getManual(filename string) (Manual, error) {
	m := Manual("")
	path := ws.Root + "/" + filename
	if _, err := os.Stat(path); err == nil {
		raw, err := os.ReadFile(path)
		if err != nil {
			return m, err
		}
		m = Manual(raw)
	}
	return m, nil
}

// render replaces placeholders in the Manual string with the output of external commands.
// For each Input in the inputs slice, if the Input's FullName is wrapped in double curly braces (e.g., "{{...}}"),
// it executes the "terraform output <name>" command in the directory specified by the Input's ReferesTo.BelongsTo.Root.
// The output of the command replaces the corresponding placeholder in the Manual string.
// Returns the rendered string and an error if any command execution fails.
func (m Manual) render(inputs []Input) (string, error) {
	rendered := string(m)

	for _, input := range inputs {
		if strings.HasPrefix(input.FullName, "{{") &&
			strings.HasSuffix(input.FullName, "}}") {
			chdir := input.ReferesTo.BelongsTo.Root
			command := "terraform"
			args := []string{
				"output",
				input.ReferesTo.Name,
			}

			cmd := exec.Command(command, args...)
			cmd.Dir = chdir

			out, err := cmd.Output()
			if err != nil {
				errOut := fmt.Errorf("could not run command '%s %s' in '%s': %s", command, strings.Join(args, " "), chdir, err.Error())
				return rendered, errOut
			}
			outStr := strings.TrimSpace(string(out))

			rendered = strings.Replace(rendered, input.FullName, outStr, -1)
		}
	}

	return rendered, nil
}
