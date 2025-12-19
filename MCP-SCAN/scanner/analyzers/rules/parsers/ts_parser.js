#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const ts = require('typescript');
const { ARRAY_METHODS, TAINT_SOURCE_LIST, TAINT_SINK_LIST } = require('./ts_types');

class TypeScriptParser {
    constructor() {
        this.taintSourceSet = new Set(TAINT_SOURCE_LIST);
        this.taintSinkSet = new Set(TAINT_SINK_LIST);
        
        this.nodeHandlers = this.buildDispatchTable();
    }
    
    buildDispatchTable() {
        return new Map([
            [ts.SyntaxKind.FunctionDeclaration, this.extractFunction.bind(this)],
            [ts.SyntaxKind.MethodDeclaration, this.extractFunction.bind(this)],
            [ts.SyntaxKind.ArrowFunction, this.extractFunction.bind(this)],
            [ts.SyntaxKind.FunctionExpression, this.extractFunction.bind(this)],
            [ts.SyntaxKind.CallExpression, this.extractCall.bind(this)],
            [ts.SyntaxKind.NewExpression, this.extractNewExpression.bind(this)],
            [ts.SyntaxKind.VariableDeclaration, this.extractVariable.bind(this)],
            [ts.SyntaxKind.ImportDeclaration, this.extractImport.bind(this)],
            [ts.SyntaxKind.ExportDeclaration, this.extractExport.bind(this)],
            [ts.SyntaxKind.ExportAssignment, this.extractExport.bind(this)],
            [ts.SyntaxKind.ObjectBindingPattern, this.extractDestructuring.bind(this)],
            [ts.SyntaxKind.ObjectLiteralExpression, this.extractObjectLiteral.bind(this)],
            [ts.SyntaxKind.ArrayLiteralExpression, this.extractArrayLiteral.bind(this)],
            [ts.SyntaxKind.IfStatement, this.extractCondition.bind(this)],
            [ts.SyntaxKind.ForStatement, this.extractLoop.bind(this)],
            [ts.SyntaxKind.ForInStatement, this.extractLoop.bind(this)],
            [ts.SyntaxKind.ForOfStatement, this.extractLoop.bind(this)],
            [ts.SyntaxKind.WhileStatement, this.extractLoop.bind(this)],
            [ts.SyntaxKind.SwitchStatement, this.extractSwitch.bind(this)],
            [ts.SyntaxKind.ReturnStatement, this.extractReturn.bind(this)],
        ]);
    }
    
    parseFile(filePath) {
        try {
            const content = fs.readFileSync(filePath, 'utf8');
            
            const sourceFile = ts.createSourceFile(
                filePath,
                content,
                ts.ScriptTarget.Latest,
                true
            );
            
            const ast = {
                file_path: filePath,
                functions: [],
                calls: [],
                vars: [],
                taint_sources: [],
                data_flows: [],
                imports: [],
                exports: [],
                conditions: [],
                loops: [],
                returns: []
            };
            
            this.visitNode(sourceFile, ast, sourceFile);
            
            return ast;
            
        } catch (error) {
            console.error(`Error parsing ${filePath}:`, error.message);
            return {
                file_path: filePath,
                error: error.message,
                functions: [],
                calls: [],
                vars: [],
                taint_sources: [],
                data_flows: [],
                imports: [],
                exports: [],
                conditions: [],
                loops: [],
                returns: []
            };
        }
    }
    
    visitNode(node, ast, sourceFile) {
        const handler = this.nodeHandlers.get(node.kind);
        if (handler) {
            handler(node, ast, sourceFile);
        }
        
        if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
            this.extractAssignment(node, ast, sourceFile);
        }
        
        ts.forEachChild(node, child => this.visitNode(child, ast, sourceFile));
    }
    
    extractDestructuring(node, ast, sourceFile) {
        const pos = this.getPos(sourceFile, node);
        
        if (node.parent && ts.isVariableDeclaration(node.parent) && node.parent.initializer) {
            const sourceExpr = node.parent.initializer;
            let sourceText = '';
            
            if (ts.isIdentifier(sourceExpr)) {
                sourceText = sourceExpr.text;
            } else if (ts.isPropertyAccessExpression(sourceExpr)) {
                sourceText = this.getPropertyChain(sourceExpr, sourceFile).join('.');
            }
            
            node.elements.forEach(element => {
                if (ts.isBindingElement(element) && ts.isIdentifier(element.name)) {
                    const varName = element.name.text;
                    const propertyName = element.propertyName && ts.isIdentifier(element.propertyName) 
                        ? element.propertyName.text 
                        : varName;
                    
                    const fromText = sourceText ? `${sourceText}.${propertyName}` : propertyName;
                    
                    if (this.isTaintSource(fromText)) {
                        this.markTaint(ast, varName, fromText, pos);
                    }
                    
                    this.pushDataFlow(ast, fromText, varName, pos, 'destructuring');
                }
            });
        }
    }
    
    extractFunction(node, ast, sourceFile) {
        let funcName = 'anonymous';
        let context = '';
        
        // 1. 이름이 있는 함수
        if (node.name && ts.isIdentifier(node.name)) {
            funcName = node.name.text;
        } 
        // 2. 변수에 할당된 함수
        else if (ts.isVariableDeclaration(node.parent) && ts.isIdentifier(node.parent.name)) {
            funcName = node.parent.name.text;
        } 
        // 3. 객체 프로퍼티에 할당된 함수
        else if (ts.isPropertyAssignment(node.parent)) {
            if (ts.isIdentifier(node.parent.name)) {
                funcName = node.parent.name.text;
                let current = node.parent.parent;
                if (ts.isObjectLiteralExpression(current)) {
                    if (current.parent && ts.isVariableDeclaration(current.parent) && ts.isIdentifier(current.parent.name)) {
                        funcName = `${current.parent.name.text}.${funcName}`;
                    }
                }
            }
        } 
        // 4. 타입 정의나 인터페이스 Carmen에서의 프로퍼티
        else if (ts.isPropertySignature(node.parent)) {
            if (ts.isIdentifier(node.parent.name)) {
                funcName = node.parent.name.text;
            }
        }
        // 5a. IIFE 체크: (function() {...})() 형태
        // 함수 -> ParenthesizedExpression -> CallExpression 구조
        else if (ts.isParenthesizedExpression(node.parent)) {
            if (node.parent.parent && ts.isCallExpression(node.parent.parent)) {
                funcName = 'IIFE';
                context = 'iife';
            }
        }
        // 5b. 콜백으로 직접 사용된 경우: arr.map(x => x + 1)
        else if (ts.isCallExpression(node.parent)) {
            // 일반 콜백
            if (ts.isPropertyAccessExpression(node.parent.expression)) {
                const methodName = node.parent.expression.name.text;
                let receiverText = '';
                try {
                    const chain = this.getPropertyChain(node.parent.expression.expression, sourceFile);
                    receiverText = chain.length > 0 ? chain.join('.') : node.parent.expression.expression.getText(sourceFile);
                } catch (e) {
                    receiverText = node.parent.expression.expression.getText(sourceFile);
                }
                funcName = `${receiverText}.${methodName} callback`;
                context = 'callback';
            } else if (ts.isIdentifier(node.parent.expression)) {
                funcName = `${node.parent.expression.text} callback`;
                context = 'callback';
            }
        } 
        // 6. 프로퍼티 할당: obj.prop = () => {}
        else if (ts.isBinaryExpression(node.parent)) {
            if (ts.isPropertyAccessExpression(node.parent.left)) {
                funcName = this.getPropertyChain(node.parent.left, sourceFile).join('.');
            }
        }
        // 7. 조건부 함수 (삼항 연산자): condition ? () => {} : () => {}
        else if (ts.isConditionalExpression(node.parent)) {
            const pos = sourceFile.getLineAndCharacterOfPosition(node.parent.getStart());
            const isTrueBranch = node === node.parent.whenTrue;
            funcName = `conditional (${isTrueBranch ? 'true' : 'false'} branch)`;
            context = 'conditional';
        }
        // 8. 반환문의 함수: return () => {}
        else if (ts.isReturnStatement(node.parent)) {
            // 부모 함수 찾기
            const parentFunc = this.findParentFunction(node.parent);
            if (parentFunc) {
                const parentFuncName = this.getFunctionName(parentFunc, sourceFile);
                funcName = `${parentFuncName || 'parent'} return value`;
                context = 'return_value';
            }
        }
        // 9. 중첩 함수: 함수 내부에 정의된 함수
        else {
            const parentFunc = this.findParentFunction(node);
            if (parentFunc && parentFunc !== node) {
                const parentFuncName = this.getFunctionName(parentFunc, sourceFile);
                if (parentFuncName && parentFuncName !== 'anonymous') {
                    funcName = `${parentFuncName} nested`;
                    context = 'nested';
                }
            }
        }
        
        const pos = sourceFile.getLineAndCharacterOfPosition(node.getStart());
        
        const params = [];
        if (node.parameters) {
            node.parameters.forEach(param => {
                if (ts.isIdentifier(param.name)) {
                    params.push({
                        name: param.name.text,
                        type: param.type ? param.type.getText(sourceFile) : undefined
                    });
                }
            });
        }
        
        ast.functions.push({
            name: funcName,
            line: pos.line + 1,
            column: pos.character + 1,
            type: this.getFunctionType(node),
            params: params,
            variables: [],
            context: context || undefined
        });
    }
    
    extractCall(node, ast, sourceFile) {
        const pos = this.getPos(sourceFile, node);
        const fullText = node.expression.getText(sourceFile);
        
        let propChain = null;
        
        if (ts.isPropertyAccessExpression(node.expression)) {
            const methodName = node.expression.name.text;
            
            if (ARRAY_METHODS.includes(methodName)) {
                const arrayText = node.expression.expression.getText(sourceFile);
                
                if (node.arguments.length > 0) {
                    const callback = node.arguments[0];
                    
                    if ((ts.isArrowFunction(callback) || ts.isFunctionExpression(callback)) 
                        && callback.parameters && callback.parameters.length > 0) {
                        
                        const elemParam = callback.parameters[0];
                        if (ts.isIdentifier(elemParam.name)) {
                            this.pushDataFlow(ast, arrayText, elemParam.name.text, pos, 'array_iteration');
                        }
                    }
                }
            }
            
            propChain = this.getPropertyChain(node.expression, sourceFile);
        }
        
        let pkg = '';
        let funcName = fullText;
        
        if (propChain) {
            if (propChain.length > 1) {
                pkg = propChain.slice(0, -1).join('.');
                funcName = propChain[propChain.length - 1];
            }
        } else if (ts.isIdentifier(node.expression)) {
            funcName = node.expression.text;
        }
        
        const args = [];
        node.arguments.forEach(arg => {
            args.push(arg.getText(sourceFile));
            this.emitArgFlows(arg, funcName, pos, ast, sourceFile);
        });
        
        const call = {
            package: pkg,
            function: funcName,
            args: args,
            line: pos.line,
            column: pos.column,
            is_taint_source: this.isTaintSource(fullText),
            is_taint_sink: this.isTaintSink(fullText)
        };
        
        ast.calls.push(call);
        
        if (call.is_taint_source && node.parent && ts.isVariableDeclaration(node.parent)) {
            if (ts.isIdentifier(node.parent.name)) {
                this.markTaint(ast, node.parent.name.text, fullText, pos);
            }
        }
    }
    
    extractNewExpression(node, ast, sourceFile) {
        const pos = this.getPos(sourceFile, node);
        const expr = node.expression;
        
        let className = '';
        let pkg = '';
        
        if (ts.isIdentifier(expr)) {
            className = expr.text;
        } else if (ts.isPropertyAccessExpression(expr)) {
            const propChain = this.getPropertyChain(expr, sourceFile);
            if (propChain.length > 1) {
                pkg = propChain.slice(0, -1).join('.');
                className = propChain[propChain.length - 1];
            } else if (propChain.length === 1) {
                className = propChain[0];
            }
        }
        
        if (!className) {
            return;
        }
        
        const dangerousConstructors = [
            'Function', 'MCPToolkit', 'MCPClient', 'MCPServer',
            'vm.Script', 'vm2.NodeVM', 'vm2.VM'
        ];
        
        const isDangerous = this.isTaintSink(className) || 
                           dangerousConstructors.includes(className) ||
                           dangerousConstructors.some(dc => className.includes(dc));
        
        if (isDangerous) {
            const args = [];
            node.arguments.forEach(arg => {
                args.push(arg.getText(sourceFile));
                this.emitArgFlows(arg, className, pos, ast, sourceFile);
            });
            
            const call = {
                package: pkg,
                function: className,
                args: args,
                line: pos.line,
                column: pos.column,
                is_taint_source: false,
                is_taint_sink: true,
                is_new_expression: true
            };
            
            ast.calls.push(call);
            
            if (node.parent && ts.isVariableDeclaration(node.parent)) {
                if (ts.isIdentifier(node.parent.name)) {
                    this.markTaint(ast, node.parent.name.text, className + ' (new)', pos);
                }
            }
        }
    }
    
    extractVariable(node, ast, sourceFile) {
        if (!ts.isIdentifier(node.name)) return;
        
        const pos = this.getPos(sourceFile, node);
        const varName = node.name.text;
        
        ast.vars.push({
            name: varName,
            line: pos.line,
            type: node.type ? node.type.getText(sourceFile) : 'any'
        });
        
        if (node.initializer) {
            // ✅ Check if initializer is a taint source (e.g., process.argv[2])
            const initText = node.initializer.getText(sourceFile);
            if (this.isTaintSource(initText)) {
                this.markTaint(ast, varName, initText, pos);
            }
            
            this.handleInitializer(node.initializer, varName, pos, ast, sourceFile, 'assignment');
        }
    }
    
    extractAssignment(node, ast, sourceFile) {
        const pos = this.getPos(sourceFile, node);
        
        if (ts.isIdentifier(node.left) && ts.isIdentifier(node.right)) {
            this.pushDataFlow(ast, node.right.text, node.left.text, pos, 'assignment');
        }
        
        this.analyzeAdvancedDataFlow(node.left, node.right, pos, ast, sourceFile);
    }
    
    extractImport(node, ast, sourceFile) {
        const pos = sourceFile.getLineAndCharacterOfPosition(node.getStart());
        
        if (node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) {
            ast.imports.push({
                module: node.moduleSpecifier.text,
                line: pos.line + 1,
                column: pos.character + 1
            });
        }
    }
    
    extractExport(node, ast, sourceFile) {
        const pos = sourceFile.getLineAndCharacterOfPosition(node.getStart());
        let exportName = 'default';
        
        if (ts.isExportAssignment(node) && ts.isIdentifier(node.expression)) {
            exportName = node.expression.text;
        }
        
        ast.exports.push({
            name: exportName,
            line: pos.line + 1,
            column: pos.character + 1
        });
    }
    
    extractObjectLiteral(node, ast, sourceFile) {
        const pos = this.getPos(sourceFile, node);
        
        let targetVar = null;
        if (node.parent && ts.isVariableDeclaration(node.parent) && ts.isIdentifier(node.parent.name)) {
            targetVar = node.parent.name.text;
        }
        
        node.properties.forEach(prop => {
            if (ts.isSpreadAssignment(prop)) {
                const sourceExpr = prop.expression;
                let sourceText = '';
                
                if (ts.isIdentifier(sourceExpr)) {
                    sourceText = sourceExpr.text;
                } else if (ts.isPropertyAccessExpression(sourceExpr)) {
                    sourceText = this.getPropertyChain(sourceExpr, sourceFile).join('.');
                }
                
                if (sourceText && targetVar) {
                    this.pushDataFlow(ast, sourceText, targetVar, pos, 'object_spread');
                }
            }
            
            if (ts.isPropertyAssignment(prop) && ts.isIdentifier(prop.name) && targetVar) {
                const propName = prop.name.text;
                const fullPropName = `${targetVar}.${propName}`;
                const propPos = this.getPos(sourceFile, prop);
                
                this.handleInitializer(prop.initializer, fullPropName, propPos, ast, sourceFile, 'property_access');
            }
        });
    }
    
    extractArrayLiteral(node, ast, sourceFile) {
        const pos = this.getPos(sourceFile, node);
        
        if (node.parent && ts.isVariableDeclaration(node.parent) && ts.isIdentifier(node.parent.name)) {
            const arrayVarName = node.parent.name.text;
            
            node.elements.forEach(element => {
                const actualElement = this.unwrapAs(element);
                
                if (ts.isPropertyAccessExpression(actualElement)) {
                    const propText = this.getPropertyChain(actualElement, sourceFile).join('.');
                    if (this.isTaintSource(propText)) {
                        this.markTaint(ast, arrayVarName, propText + ' (in array)', pos);
                    }
                }
            });
        }
    }
    
    // 헬퍼 함수들 (ts_utils.js에서 이동)
    getPos(sourceFile, node) {
        const pos = sourceFile.getLineAndCharacterOfPosition(node.getStart());
        return {
            line: pos.line + 1,
            column: pos.character + 1
        };
    }
    
    pushDataFlow(ast, from, to, pos, flowType) {
        ast.data_flows.push({
            from: from,
            to: to,
            line: pos.line,
            column: pos.column,
            flow_type: flowType
        });
    }
    
    markTaint(ast, varName, source, pos) {
        ast.taint_sources.push({
            var_name: varName,
            source: source,
            line: pos.line,
            column: pos.column
        });
    }
    
    unwrapAs(expression) {
        let expr = expression;
        while (expr && ts.isAsExpression(expr)) {
            expr = expr.expression;
        }
        return expr;
    }
    
    collectTemplateRefs(templateExpr, sourceFile) {
        const refs = [];
        
        if (!ts.isTemplateExpression(templateExpr)) {
            return refs;
        }
        
        templateExpr.templateSpans.forEach(span => {
            if (ts.isIdentifier(span.expression)) {
                refs.push(span.expression.text);
            } else if (ts.isPropertyAccessExpression(span.expression)) {
                const propChain = this.getPropertyChain(span.expression, sourceFile);
                refs.push(propChain.join('.'));
            }
        });
        
        return refs;
    }
    
    emitArgFlows(arg, targetName, pos, ast, sourceFile) {
        if (ts.isIdentifier(arg)) {
            this.pushDataFlow(ast, arg.text, targetName, pos, 'func_with_tainted_arg');
        } else if (ts.isTemplateExpression(arg)) {
            const refs = this.collectTemplateRefs(arg, sourceFile);
            refs.forEach(ref => {
                this.pushDataFlow(ast, ref, targetName, pos, 'template_var');
            });
        } else if (ts.isPropertyAccessExpression(arg)) {
            const propText = this.getPropertyChain(arg, sourceFile).join('.');
            this.pushDataFlow(ast, propText, targetName, pos, 'func_with_tainted_arg');
        }
    }
    
    handleInitializer(expr, target, pos, ast, sourceFile, flowType = 'assignment') {
        const actualInit = this.unwrapAs(expr);
        
        if (ts.isCallExpression(actualInit)) {
            const callText = actualInit.expression.getText(sourceFile);
            if (this.isTaintSource(callText)) {
                this.markTaint(ast, target, callText, pos);
            }
        }
        
        if (ts.isIdentifier(actualInit)) {
            this.pushDataFlow(ast, actualInit.text, target, pos, flowType);
        } else if (ts.isPropertyAccessExpression(actualInit)) {
            const propText = this.getPropertyChain(actualInit, sourceFile).join('.');
            
            if (this.isTaintSource(propText)) {
                this.markTaint(ast, target, propText, pos);
            }
            
            this.pushDataFlow(ast, propText, target, pos, flowType);
        } else if (ts.isTemplateExpression(actualInit)) {
            const refs = this.collectTemplateRefs(actualInit, sourceFile);
            refs.forEach(ref => {
                this.pushDataFlow(ast, ref, target, pos, 'template_var');
            });
        } else if (ts.isBinaryExpression(actualInit)) {
            this.extractBinaryExpressionFlows(actualInit, target, pos, ast, sourceFile);
        }
    }
    
    extractBinaryExpressionFlows(expr, target, pos, ast, sourceFile) {
        const collectOperands = (node) => {
            const operands = [];
            
            if (ts.isBinaryExpression(node)) {
                operands.push(...collectOperands(node.left));
                operands.push(...collectOperands(node.right));
            } else if (ts.isIdentifier(node)) {
                operands.push(node.text);
            } else if (ts.isPropertyAccessExpression(node)) {
                operands.push(this.getPropertyChain(node, sourceFile).join('.'));
            }
            
            return operands;
        };
        
        const operands = collectOperands(expr);
        operands.forEach(operand => {
            this.pushDataFlow(ast, operand, target, pos, 'binary_expression');
        });
    }
    
    getPropertyChain(node, sourceFile) {
        const parts = [];
        let current = node;
        
        while (ts.isPropertyAccessExpression(current)) {
            if (ts.isIdentifier(current.name)) {
                parts.unshift(current.name.text);
            }
            current = current.expression;
        }
        
        if (ts.isIdentifier(current)) {
            parts.unshift(current.text);
        }
        
        return parts;
    }
    
    getFunctionType(node) {
        if (node.modifiers && node.modifiers.some(m => m.kind === ts.SyntaxKind.AsyncKeyword)) {
            return 'async_function';
        }
        if (ts.isArrowFunction(node)) {
            return 'arrow_function';
        }
        if (ts.isMethodDeclaration(node)) {
            return 'class_method';
        }
        return 'function';
    }
    
    isTaintSource(funcName) {
        if (this.taintSourceSet.has(funcName)) {
            return true;
        }
        for (const source of this.taintSourceSet) {
            if (funcName.includes(source)) {
                return true;
            }
        }
        return false;
    }
    
    isTaintSink(funcName) {
        if (this.taintSinkSet.has(funcName)) {
            return true;
        }
        for (const sink of this.taintSinkSet) {
            if (funcName.includes(sink)) {
                return true;
            }
        }
        return false;
    }
    
    analyzeAdvancedDataFlow(lhs, rhsExpr, pos, ast, sourceFile) {
        this.analyzeFunctionChain(rhsExpr, lhs, pos, ast, sourceFile);
        
        this.analyzeConditionalAssignment(lhs, rhsExpr, pos, ast, sourceFile);
        
        this.analyzeLoopAssignment(lhs, rhsExpr, pos, ast, sourceFile);
        
        this.analyzeObjectPropertyAssignment(lhs, rhsExpr, pos, ast, sourceFile);
        
        this.analyzeCollectionAssignment(lhs, rhsExpr, pos, ast, sourceFile);
        
        this.analyzeTemplateLiteralAssignment(lhs, rhsExpr, pos, ast, sourceFile);
        
        this.analyzeAsyncAssignment(lhs, rhsExpr, pos, ast, sourceFile);
    }
    
    analyzeFunctionChain(expr, targetVar, pos, ast, sourceFile) {
        if (ts.isCallExpression(expr)) {
            if (ts.isPropertyAccessExpression(expr.expression)) {
                const chain = this.buildFunctionChain(expr.expression, sourceFile);
                if (chain.length > 1) {
                    const lhsStr = this.getExprString(targetVar);
                    this.pushDataFlow(ast, chain[0], lhsStr, pos, 'function_chain');
                    for (let i = 1; i < chain.length; i++) {
                        this.pushDataFlow(ast, chain[i-1], chain[i], pos, 'chain_link');
                    }
                }
            }
        }
    }
    
    buildFunctionChain(expr, sourceFile) {
        const chain = [];
        
        if (ts.isPropertyAccessExpression(expr)) {
            const parentChain = this.buildFunctionChain(expr.expression, sourceFile);
            chain.push(...parentChain);
            chain.push(expr.name.text);
        } else if (ts.isIdentifier(expr)) {
            chain.push(expr.text);
        } else if (ts.isCallExpression(expr)) {
            const callChain = this.buildFunctionChain(expr.expression, sourceFile);
            chain.push(...callChain);
        }
        
        return chain;
    }
    
    analyzeConditionalAssignment(lhs, rhsExpr, pos, ast, sourceFile) {
        if (ts.isConditionalExpression(rhsExpr)) {
            const lhsStr = this.getExprString(lhs);
            this.pushDataFlow(ast, this.getExprString(rhsExpr.condition), lhsStr, pos, 'conditional_condition');
            this.pushDataFlow(ast, this.getExprString(rhsExpr.whenTrue), lhsStr, pos, 'conditional_true');
            this.pushDataFlow(ast, this.getExprString(rhsExpr.whenFalse), lhsStr, pos, 'conditional_false');
        }
        
        if (ts.isBinaryExpression(rhsExpr)) {
            if (rhsExpr.operatorToken.kind === ts.SyntaxKind.BarBarToken || 
                rhsExpr.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken) {
                const lhsStr = this.getExprString(lhs);
                this.pushDataFlow(ast, this.getExprString(rhsExpr.left), lhsStr, pos, 'logical_left');
                this.pushDataFlow(ast, this.getExprString(rhsExpr.right), lhsStr, pos, 'logical_right');
            }
        }
    }
    
    analyzeLoopAssignment(lhs, rhsExpr, pos, ast, sourceFile) {
        if (ts.isForStatement(rhsExpr) || ts.isForOfStatement(rhsExpr) || ts.isForInStatement(rhsExpr)) {
            const lhsStr = this.getExprString(lhs);
            this.traverseBlockForAssignments(rhsExpr.statement, lhsStr, pos, ast, sourceFile);
        }
        
        if (ts.isWhileStatement(rhsExpr)) {
            const lhsStr = this.getExprString(lhs);
            this.traverseBlockForAssignments(rhsExpr.statement, lhsStr, pos, ast, sourceFile);
        }
    }
    
    traverseBlockForAssignments(block, targetVar, pos, ast, sourceFile) {
        if (!block || !ts.isBlock(block)) {
            return;
        }
        
        for (const stmt of block.statements) {
            if (ts.isExpressionStatement(stmt) && ts.isBinaryExpression(stmt.expression)) {
                const binaryExpr = stmt.expression;
                if (binaryExpr.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
                    const lhsStr = this.getExprString(binaryExpr.left);
                    const rhsStr = this.getExprString(binaryExpr.right);
                    if (lhsStr === targetVar && rhsStr) {
                        this.pushDataFlow(ast, rhsStr, targetVar, pos, 'loop_assignment');
                    }
                }
            }
        }
    }
    
    analyzeObjectPropertyAssignment(lhs, rhsExpr, pos, ast, sourceFile) {
        if (ts.isPropertyAccessExpression(lhs)) {
            const objName = this.getExprString(lhs.expression);
            const propName = lhs.name.text;
            const fullPropName = `${objName}.${propName}`;
            const rhsStr = this.getExprString(rhsExpr);
            
            this.pushDataFlow(ast, rhsStr, fullPropName, pos, 'object_property_assignment');
            this.pushDataFlow(ast, rhsStr, objName, pos, 'object_modification');
        }
        
        if (ts.isElementAccessExpression(lhs)) {
            const objName = this.getExprString(lhs.expression);
            const indexName = this.getExprString(lhs.argumentExpression);
            const rhsStr = this.getExprString(rhsExpr);
            
            this.pushDataFlow(ast, rhsStr, objName, pos, 'bracket_property_assignment');
            this.pushDataFlow(ast, indexName, objName, pos, 'index_influence');
        }
    }
    
    analyzeCollectionAssignment(lhs, rhsExpr, pos, ast, sourceFile) {
        // 배열 할당: arr[index] = value
        if (ts.isElementAccessExpression(lhs)) {
            const collectionName = this.getExprString(lhs.expression);
            const indexName = this.getExprString(lhs.argumentExpression);
            const rhsStr = this.getExprString(rhsExpr);
            
            this.pushDataFlow(ast, rhsStr, collectionName, pos, 'array_assignment');
            this.pushDataFlow(ast, indexName, collectionName, pos, 'array_index_influence');
        }
    }
    
    analyzeTemplateLiteralAssignment(lhs, rhsExpr, pos, ast, sourceFile) {
        if (ts.isTemplateExpression(rhsExpr)) {
            const lhsStr = this.getExprString(lhs);
            const templateRefs = this.collectTemplateRefs(rhsExpr, sourceFile);
            
            templateRefs.forEach(ref => {
                this.pushDataFlow(ast, ref, lhsStr, pos, 'template_literal_ref');
            });
        }
    }
    
    analyzeAsyncAssignment(lhs, rhsExpr, pos, ast, sourceFile) {
        // 비동기 함수 할당: const result = await asyncFunction()
        if (ts.isAwaitExpression(rhsExpr)) {
            const lhsStr = this.getExprString(lhs);
            const awaitedExpr = this.getExprString(rhsExpr.expression);
            
            this.pushDataFlow(ast, awaitedExpr, lhsStr, pos, 'async_await');
        }
        
        if (ts.isCallExpression(rhsExpr)) {
            if (ts.isPropertyAccessExpression(rhsExpr.expression)) {
                const methodName = rhsExpr.expression.name.text;
                if (['then', 'catch', 'finally'].includes(methodName)) {
                    const lhsStr = this.getExprString(lhs);
                    const promiseExpr = this.getExprString(rhsExpr.expression.expression);
                    
                    this.pushDataFlow(ast, promiseExpr, lhsStr, pos, 'promise_chain');
                }
            }
        }
    }
    
    getExprString(expr) {
        if (!expr) return '';
        
        if (ts.isIdentifier(expr)) {
            return expr.text;
        } else if (ts.isPropertyAccessExpression(expr)) {
            return this.getPropertyChain(expr, null).join('.');
        } else if (ts.isElementAccessExpression(expr)) {
            const objStr = this.getExprString(expr.expression);
            const indexStr = this.getExprString(expr.argumentExpression);
            return `${objStr}[${indexStr}]`;
        } else if (ts.isCallExpression(expr)) {
            return this.getExprString(expr.expression) + '()';
        } else if (ts.isTemplateExpression(expr)) {
            return '`template`';
        } else if (ts.isStringLiteral(expr)) {
            return `"${expr.text}"`;
        } else if (ts.isNumericLiteral(expr)) {
            return expr.text;
        } else if (ts.isBinaryExpression(expr)) {
            const leftStr = this.getExprString(expr.left);
            const rightStr = this.getExprString(expr.right);
            const operator = expr.operatorToken.text;
            return `${leftStr} ${operator} ${rightStr}`;
        } else if (ts.isConditionalExpression(expr)) {
            const conditionStr = this.getExprString(expr.condition);
            const trueStr = this.getExprString(expr.whenTrue);
            const falseStr = this.getExprString(expr.whenFalse);
            return `${conditionStr} ? ${trueStr} : ${falseStr}`;
        } else if (ts.isAwaitExpression(expr)) {
            return `await ${this.getExprString(expr.expression)}`;
        }
        
        return '';
    }
    
    findParentFunction(node) {
        if (!node || !node.parent) {
            return null;
        }
        
        let current = node.parent;
        while (current) {
            if (ts.isFunctionDeclaration(current) || 
                ts.isFunctionExpression(current) || 
                ts.isArrowFunction(current) ||
                ts.isMethodDeclaration(current)) {
                return current;
            }
            current = current.parent;
        }
        
        return null;
    }
    
    getFunctionName(funcNode, sourceFile) {
        if (!funcNode) {
            return 'anonymous';
        }
        
        // 이름이 있는 함수
        if (funcNode.name && ts.isIdentifier(funcNode.name)) {
            return funcNode.name.text;
        }
        
        // 변수에 할당된 함수
        if (funcNode.parent && ts.isVariableDeclaration(funcNode.parent) && ts.isIdentifier(funcNode.parent.name)) {
            return funcNode.parent.name.text;
        }
        
        // 객체 프로퍼티 메서드
        if (funcNode.parent && ts.isPropertyAssignment(funcNode.parent) && ts.isIdentifier(funcNode.parent.name)) {
            return funcNode.parent.name.text;
        }
        
        // 메서드 선언
        if (ts.isMethodDeclaration(funcNode) && funcNode.name && ts.isIdentifier(funcNode.name)) {
            return funcNode.name.text;
        }
        
        return 'anonymous';
    }
    
    extractCondition(node, ast, sourceFile) {
        const pos = this.getPos(sourceFile, node);
        const condition = node.expression.getText(sourceFile);
        
        // Extract variables used in condition
        const variables = this.extractVariablesFromCondition(node.expression, sourceFile);
        
        // Check if condition is negated
        const isNegated = this.isNegatedCondition(node.expression);
        
        // Check for validation patterns
        const hasValidation = this.detectValidationPattern(condition);
        const validationType = hasValidation ? this.getValidationType(condition) : null;
        
        // Extract block line numbers for CFG
        let thenLine = 0;
        let elseLine = 0;
        const endLine = sourceFile.getLineAndCharacterOfPosition(node.end).line + 1;
        
        // Then block (always exists in if statement)
        if (node.thenStatement) {
            const thenPos = sourceFile.getLineAndCharacterOfPosition(node.thenStatement.pos);
            thenLine = thenPos.line + 1;
        }
        
        // Else block (if exists)
        if (node.elseStatement) {
            const elsePos = sourceFile.getLineAndCharacterOfPosition(node.elseStatement.pos);
            elseLine = elsePos.line + 1;
        }
        
        ast.conditions.push({
            condition: condition,
            line: pos.line,
            column: pos.column,
            variables: variables,
            is_negated: isNegated,
            has_validation: hasValidation,
            validation_type: validationType,
            then_line: thenLine,
            else_line: elseLine,
            end_line: endLine
        });
    }
    
    extractLoop(node, ast, sourceFile) {
        const pos = this.getPos(sourceFile, node);
        let loopType = 'for';
        let condition = '';
        const variables = [];
        
        if (ts.isForStatement(node)) {
            loopType = 'for';
            if (node.condition) {
                condition = node.condition.getText(sourceFile);
                variables.push(...this.extractVariablesFromCondition(node.condition, sourceFile));
            }
            if (node.initializer) {
                const initVars = this.extractVariablesFromNode(node.initializer, sourceFile);
                variables.push(...initVars);
            }
        } else if (ts.isForInStatement(node)) {
            loopType = 'for-in';
            if (ts.isVariableDeclarationList(node.initializer)) {
                const decl = node.initializer.declarations[0];
                if (ts.isIdentifier(decl.name)) {
                    variables.push(decl.name.text);
                }
            }
            condition = node.expression.getText(sourceFile);
        } else if (ts.isForOfStatement(node)) {
            loopType = 'for-of';
            if (ts.isVariableDeclarationList(node.initializer)) {
                const decl = node.initializer.declarations[0];
                if (ts.isIdentifier(decl.name)) {
                    variables.push(decl.name.text);
                }
            }
            condition = node.expression.getText(sourceFile);
        } else if (ts.isWhileStatement(node)) {
            loopType = 'while';
            condition = node.expression.getText(sourceFile);
            variables.push(...this.extractVariablesFromCondition(node.expression, sourceFile));
        }
        
        // Extract loop body line numbers for CFG
        let bodyStart = 0;
        let bodyEnd = sourceFile.getLineAndCharacterOfPosition(node.end).line + 1;
        
        if (node.statement) {
            const bodyPos = sourceFile.getLineAndCharacterOfPosition(node.statement.pos);
            bodyStart = bodyPos.line + 1;
            const bodyEndPos = sourceFile.getLineAndCharacterOfPosition(node.statement.end);
            bodyEnd = bodyEndPos.line + 1;
        }
        
        ast.loops.push({
            type: loopType,
            condition: condition,
            line: pos.line,
            column: pos.column,
            variables: variables,
            body_start: bodyStart,
            body_end: bodyEnd
        });
    }
    
    extractSwitch(node, ast, sourceFile) {
        const pos = this.getPos(sourceFile, node);
        const condition = node.expression ? node.expression.getText(sourceFile) : '';
        const variables = node.expression ? this.extractVariablesFromCondition(node.expression, sourceFile) : [];
        
        ast.conditions.push({
            condition: 'switch ' + condition,
            line: pos.line,
            column: pos.column,
            variables: variables,
            is_negated: false,
            has_validation: false,
            validation_type: null
        });
    }
    
    extractVariablesFromCondition(expression, sourceFile) {
        const variables = [];
        const seen = new Set();
        
        const extract = (node) => {
            if (!node) return;
            
            if (ts.isIdentifier(node)) {
                const name = node.text;
                if (name !== 'undefined' && name !== 'null' && name !== 'true' && name !== 'false' && !seen.has(name)) {
                    variables.push(name);
                    seen.add(name);
                }
            } else if (ts.isPropertyAccessExpression(node)) {
                const propChain = this.getPropertyChain(node, sourceFile).join('.');
                if (!seen.has(propChain)) {
                    variables.push(propChain);
                    seen.add(propChain);
                }
            } else if (ts.isBinaryExpression(node)) {
                extract(node.left);
                extract(node.right);
            } else if (ts.isCallExpression(node)) {
                const funcName = node.expression.getText(sourceFile);
                if (!seen.has(funcName)) {
                    variables.push(funcName);
                    seen.add(funcName);
                }
            } else if (ts.isPrefixUnaryExpression(node)) {
                extract(node.operand);
            } else if (ts.isParenthesizedExpression(node)) {
                extract(node.expression);
            }
        };
        
        extract(expression);
        return variables;
    }
    
    extractVariablesFromNode(node, sourceFile) {
        const variables = [];
        
        if (ts.isVariableDeclarationList(node)) {
            node.declarations.forEach(decl => {
                if (ts.isIdentifier(decl.name)) {
                    variables.push(decl.name.text);
                }
            });
        } else if (ts.isIdentifier(node)) {
            variables.push(node.text);
        }
        
        return variables;
    }
    
    isNegatedCondition(expression) {
        if (ts.isPrefixUnaryExpression(expression) && expression.operator === ts.SyntaxKind.ExclamationToken) {
            return true;
        }
        if (ts.isBinaryExpression(expression)) {
            const operator = expression.operatorToken.kind;
            return operator === ts.SyntaxKind.ExclamationEqualsToken || 
                   operator === ts.SyntaxKind.ExclamationEqualsEqualsToken;
        }
        return false;
    }
    
    detectValidationPattern(condition) {
        const validationPatterns = [
            /\.match\(/i,
            /\.test\(/i,
            /\.includes\(/i,
            /\.startsWith\(/i,
            /\.endsWith\(/i,
            /^[a-zA-Z0-9]+$/,
            /validator\./i,
            /validate/i,
            /sanitize/i,
            /escape/i,
            /new\s+URL\(/i,
            /\.protocol/i,
            /\.hostname/i,
            /isValid/i,
            /checkValid/i,
        ];
        
        return validationPatterns.some(pattern => pattern.test(condition));
    }
    
    getValidationType(condition) {
        if (/\.match\(|\.test\(/i.test(condition)) return 'regex_validation';
        if (/\.includes\(|\.startsWith\(|\.endsWith\(/i.test(condition)) return 'string_validation';
        if (/new\s+URL\(/i.test(condition)) return 'url_parsing';
        if (/\.protocol|\.hostname/i.test(condition)) return 'url_validation';
        if (/validator\.|validate|sanitize|escape/i.test(condition)) return 'sanitization';
        if (/isValid|checkValid/i.test(condition)) return 'validation_function';
        return 'unknown';
    }
    
    extractReturn(node, ast, sourceFile) {
        const pos = this.getPos(sourceFile, node);
        
        // Find parent function
        const parentFunc = this.findParentFunction(node);
        let funcName = 'anonymous';
        
        if (parentFunc) {
            funcName = this.getFunctionName(parentFunc, sourceFile);
        }
        
        if (node.expression) {
            const returnValue = this.getExprString(node.expression);
            if (returnValue) {
                ast.returns.push({
                    function: funcName,
                    value: returnValue,
                    line: pos.line,
                    column: pos.column
                });
            }
        }
    }
}

if (require.main === module) {
    const filePath = process.argv[2];
    
    if (!filePath) {
        console.error('Usage: node ts_parser.js <file_path>');
        process.exit(1);
    }
    
    if (!fs.existsSync(filePath)) {
        console.error(`File not found: ${filePath}`);
        process.exit(1);
    }
    
    const parser = new TypeScriptParser();
    const ast = parser.parseFile(filePath);
    
    console.log(JSON.stringify(ast, null, 2));
}

module.exports = TypeScriptParser;