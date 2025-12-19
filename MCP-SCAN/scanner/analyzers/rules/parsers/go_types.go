package main

import "regexp"

type ASTData struct {
	FilePath     string        `json:"file_path"`
	Functions    []Function    `json:"functions"`
	Calls        []Call        `json:"calls"`
	Vars         []Variable    `json:"vars"`
	TaintSources []TaintSource `json:"taint_sources"`
	DataFlows    []DataFlow    `json:"data_flows"`
	Imports      []Import      `json:"imports"`
	Exports      []Export      `json:"exports"`
	Conditions   []Condition   `json:"conditions"`
	Loops        []Loop        `json:"loops"`
	Returns      []Return      `json:"returns"`
	Error        string        `json:"error,omitempty"`
}

type Function struct {
	Name   string  `json:"name"`
	Line   int     `json:"line"`
	Column int     `json:"column"`
	Type   string  `json:"type"`
	Params []Param `json:"params"`
}

type Param struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type Call struct {
	Package       string   `json:"package"`
	Function      string   `json:"function"`
	Args          []string `json:"args"`
	Line          int      `json:"line"`
	Column        int      `json:"column"`
	IsTaintSource bool     `json:"is_taint_source"`
	IsTaintSink   bool     `json:"is_taint_sink"`
}

type Variable struct {
	Name string `json:"name"`
	Line int    `json:"line"`
	Type string `json:"type"`
}

type TaintSource struct {
	VarName string `json:"var_name"`
	Source  string `json:"source"`
	Line    int    `json:"line"`
	Column  int    `json:"column"`
}

type DataFlow struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
	FlowType string `json:"flow_type"`
}

type Import struct {
	Module string `json:"module"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}

type Export struct {
	Name   string `json:"name"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}

type Condition struct {
	Condition     string   `json:"condition"`
	Line          int      `json:"line"`
	Column        int      `json:"column"`
	Variables     []string `json:"variables"`
	IsNegated     bool     `json:"is_negated"`
	HasValidation bool     `json:"has_validation"`
	ValidationType string  `json:"validation_type"`
	ThenLine      int      `json:"then_line"` // Start of then block
	ElseLine      int      `json:"else_line"` // Start of else block (0 if no else)
	EndLine       int      `json:"end_line"`  // End of if/else statement
}

type Loop struct {
	Type      string   `json:"type"`
	Condition string   `json:"condition"`
	Line      int      `json:"line"`
	Column    int      `json:"column"`
	Variables []string `json:"variables"`
	BodyStart int      `json:"body_start"` // Start of loop body
	BodyEnd   int      `json:"body_end"`   // End of loop body
}

type Return struct {
	Function string   `json:"function"` // Function name this return belongs to
	Value    string   `json:"value"`    // Return value expression
	Line     int      `json:"line"`
	Column   int      `json:"column"`
}

type GoParser struct {
	sourceRegexes []*regexp.Regexp
	sinkRegexes   []*regexp.Regexp
}

func newASTData(filePath string) *ASTData {
	return &ASTData{
		FilePath:     filePath,
		Functions:    []Function{},
		Calls:        []Call{},
		Vars:         []Variable{},
		TaintSources: []TaintSource{},
		DataFlows:    []DataFlow{},
		Imports:      []Import{},
		Exports:      []Export{},
		Conditions:   []Condition{},
		Loops:        []Loop{},
		Returns:      []Return{},
	}
}
