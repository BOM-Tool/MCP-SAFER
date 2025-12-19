import { Project, SourceFile, Node, CallExpression, NewExpression, FunctionDeclaration, MethodDeclaration, ClassDeclaration, InterfaceDeclaration, TypeAliasDeclaration, VariableDeclaration, ArrowFunction, FunctionExpression, Identifier, PropertyAccessExpression, ConditionalExpression, BinaryExpression, ParenthesizedExpression, AsExpression, NonNullExpression, SyntaxKind, SymbolFlags, ElementAccessExpression, ImportDeclaration, ImportClause, ImportSpecifier, NamespaceImport, StringLiteral, TypeNode, TypeReferenceNode, QualifiedName, ExpressionWithTypeArguments } from 'ts-morph';
import * as ts from 'typescript';
import * as path from 'path';
import * as fs from 'fs';
import globals from 'globals';
import builtinModules from 'builtin-modules';

interface CallEdge {
  functionName: string;
  filePath?: string;
  implementationPath?: string;
  packageName?: string;
  isExternal: boolean;
  moduleType: 'global' | 'node_builtin' | 'npm' | 'internal' | 'builtin';
  callType: 'function' | 'method' | 'static_method' | 'constructor' | 'builtin' | 'external' | 'unresolved';
  fullSignature?: string;
  position: {
    line: number;
    column: number;
  };
}

interface CallGraphEntry {
  filePath: string;
  edges: CallEdge[];
}

interface PackageInfo {
  name: string;
  version: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

interface ImportInfo {
  moduleSpecifier: string;
  packageName: string;
  isExternal: boolean;
  isNodeBuiltin: boolean;
  isGlobal: boolean;
  importType: 'default' | 'named' | 'namespace' | 'type';
  originalName: string;
  importedName: string;
}

interface SymbolInfo {
  name: string;
  filePath: string;
  isExternal: boolean;
  moduleType: 'global' | 'node_builtin' | 'npm' | 'internal' | 'builtin';
  packageName?: string;
  symbolType: 'function' | 'class' | 'interface' | 'variable' | 'type' | 'unknown';
  declaration?: Node;
}

class TypeScriptCallGraphAnalyzer {
  private project: Project;
  private callGraphMap = new Map<string, CallGraphEntry>();
  private trackedFunctions = new Set<string>();
  private rootPath: string;
  private packageJson: PackageInfo | null = null;
  private globalSymbols = new Set<string>();
  private nodeBuiltinModules = new Set<string>();
  private importMap = new Map<string, ImportInfo>();
  private symbolMap = new Map<string, SymbolInfo>();
  private analyzeNodeModules: boolean = false;
  // 성능 최적화: 심볼 분석 결과 캐싱
  private symbolAnalysisCache = new Map<string, SymbolInfo | null>();
  private typeInfoCache = new Map<string, { filePath: string; isExternal: boolean; packageName?: string; module?: string; moduleType?: 'global' | 'node_builtin' | 'npm' | 'internal' | 'builtin'; } | null>();

  constructor(projectPath: string, options?: { analyzeNodeModules?: boolean }) {
    this.rootPath = projectPath;
    this.analyzeNodeModules = options?.analyzeNodeModules || false;
    
    const tsconfigPath = path.join(projectPath, 'tsconfig.json');
    const hasTsConfig = fs.existsSync(tsconfigPath);
    
    if (hasTsConfig) {
      this.project = new Project({
        tsConfigFilePath: tsconfigPath,
        skipAddingFilesFromTsConfig: false,
        skipFileDependencyResolution: false,
        skipLoadingLibFiles: false,
      });
      console.log('Using tsconfig.json for file selection');
      
      // analyzeNodeModules가 true이면 node_modules 파일도 강제로 추가
      if (this.analyzeNodeModules) {
        console.log('Force adding node_modules files despite tsconfig.json...');
        
        // glob 패턴이 작동하지 않을 수 있으므로 직접 파일 찾기
        const nodeModulesPath = path.join(projectPath, 'node_modules');
        if (fs.existsSync(nodeModulesPath)) {
          const jsFiles: string[] = [];
          const tsFiles: string[] = [];
          
          // 재귀적으로 .js와 .ts 파일 찾기
          const findFiles = (dir: string) => {
            try {
              const entries = fs.readdirSync(dir, { withFileTypes: true });
              for (const entry of entries) {
                const fullPath = path.join(dir, entry.name);
                
                // 테스트/빌드 디렉토리는 스킵
                if (entry.isDirectory()) {
                  if (entry.name === 'test' || entry.name === 'tests' || 
                      entry.name === '__tests__' || entry.name === 'spec' ||
                      entry.name === 'dist' || entry.name === 'build') {
                    continue;
                  }
                  findFiles(fullPath);
                } else if (entry.isFile()) {
                  if (entry.name.endsWith('.js') && !entry.name.endsWith('.d.ts')) {
                    jsFiles.push(fullPath);
                  } else if (entry.name.endsWith('.ts') && !entry.name.endsWith('.d.ts')) {
                    tsFiles.push(fullPath);
                  }
                }
              }
            } catch (e) {
              // 권한 오류 등 무시
            }
          };
          
          findFiles(nodeModulesPath);
          
          console.log(`  Found ${jsFiles.length} .js files and ${tsFiles.length} .ts files in node_modules`);
          
          // 파일 추가 (너무 많으면 일부만 추가)
          const maxFiles = 1000; // 성능을 위해 제한
          const filesToAdd = [...jsFiles, ...tsFiles].slice(0, maxFiles);
          
          for (const file of filesToAdd) {
            try {
              this.project.addSourceFileAtPath(file);
            } catch (e) {
              // 이미 추가되었거나 오류 발생 시 무시
            }
          }
          
          console.log(`  Added ${filesToAdd.length} files from node_modules`);
        }
      }
    } else {
      this.project = new Project({
        skipAddingFilesFromTsConfig: false,
        skipFileDependencyResolution: false,
        skipLoadingLibFiles: false,
      });
      
      const sourcePatterns = [
        path.join(projectPath, 'src/**/*.ts'),
        path.join(projectPath, 'src/**/*.tsx'),
        path.join(projectPath, '**/*.ts'),
        path.join(projectPath, '**/*.tsx')
      ];
      
      // node_modules 분석이 활성화되면 node_modules 내부 파일도 추가
      if (this.analyzeNodeModules) {
        sourcePatterns.push(
          path.join(projectPath, 'node_modules/**/*.js'),
          path.join(projectPath, 'node_modules/**/*.ts')
        );
      }
      
      this.project.addSourceFilesAtPaths(sourcePatterns);
      console.log('No tsconfig.json found, using pattern-based file selection');
    }
    
    if (this.analyzeNodeModules) {
      console.log('Node modules analysis enabled - will analyze external package internals');
    }

    const packageJsonPath = path.join(projectPath, 'package.json');
    if (fs.existsSync(packageJsonPath)) {
      try {
        this.packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
      } catch (e) {
        console.warn('Failed to parse package.json:', e);
      }
    }

    this.initializeGlobalSymbols();
    this.initializeNodeBuiltinModules();
    
    // 모든 소스 파일의 import 분석
    this.analyzeAllImports();
  }

  async analyze(): Promise<void> {
    console.log('TypeScript Call Graph Analysis with comprehensive call tracking...');
    
    try {
    const sourceFiles = this.project.getSourceFiles();
    console.log(`Found ${sourceFiles.length} source files`);

    for (const sourceFile of sourceFiles) {
      if (this.shouldSkipFile(sourceFile)) continue;
      
      this.analyzeSourceFile(sourceFile);
    }

      console.log('[analyze] Analysis loop completed, calling saveResults()...');
    this.saveResults();
      console.log('[analyze] saveResults() completed');
    } catch (error) {
      // 전체 분석 실패 시에도 부분 결과라도 저장
      console.error('[analyze] Error during analysis:', error instanceof Error ? error.message : String(error));
      console.error('[analyze] Error stack:', error instanceof Error ? error.stack : 'No stack trace');
      try {
        console.log('[analyze] Attempting to save results despite error...');
        this.saveResults();
        console.log('[analyze] saveResults() completed after error');
      } catch (saveError) {
        console.error('[analyze] Failed to save results:', saveError instanceof Error ? saveError.message : String(saveError));
        console.error('[analyze] Save error stack:', saveError instanceof Error ? saveError.stack : 'No stack trace');
      }
    }
  }

  private shouldSkipFile(sourceFile: SourceFile): boolean {
    const filePath = sourceFile.getFilePath();
    
    // .d.ts 파일은 항상 스킵 (타입 정의만 있고 구현이 없음)
    if (filePath.includes('.d.ts')) {
      return true;
    }
    
    // node_modules 스킵 여부는 옵션에 따라 결정
    if (filePath.includes('node_modules')) {
      // analyzeNodeModules가 true이면 node_modules도 분석
      // 단, .d.ts 파일은 이미 위에서 스킵됨
      if (!this.analyzeNodeModules) {
        return true;
      }
      // node_modules 내부에서도 테스트 파일이나 빌드 결과물은 스킵
      if (filePath.includes('node_modules') && (
        filePath.includes('/test/') ||
        filePath.includes('/tests/') ||
        filePath.includes('/__tests__/') ||
        filePath.includes('/spec/') ||
        filePath.includes('/dist/') ||
        filePath.includes('/build/')
      )) {
        return true;
      }
      // analyzeNodeModules가 true이고 node_modules 내부 파일이면
      // shouldExcludeFile 체크를 건너뛰고 분석 진행
      return false;
    }
    
    // tsconfig 통합 exclude 규칙 적용
    return this.shouldExcludeFile(filePath);
  }

  private shouldExcludeFile(filePath: string): boolean {
    const relativePath = path.relative(this.rootPath, filePath);
    
    // tsconfig 파일들에서 exclude 패턴 수집
    const excludePatterns = this.getTsConfigExcludePatterns();
    
    for (const pattern of excludePatterns) {
      if (this.matchesPattern(relativePath, pattern)) {
        return true;
      }
    }
    
    return false;
  }

  private getTsConfigExcludePatterns(): string[] {
    const patterns = new Set<string>();
    
    // 기본 제외 패턴
    patterns.add('node_modules');
    patterns.add('dist');
    
    // tsconfig.json 읽기
    const tsconfigPath = path.join(this.rootPath, 'tsconfig.json');
    if (fs.existsSync(tsconfigPath)) {
      try {
        const configText = fs.readFileSync(tsconfigPath, 'utf-8');
        const { config: tsconfig, error } = ts.parseConfigFileTextToJson(tsconfigPath, configText);
        if (error) {
          console.warn('Failed to parse tsconfig.json:', error.messageText);
        } else if (tsconfig && tsconfig.exclude) {
          tsconfig.exclude.forEach((pattern: string) => patterns.add(pattern));
        }
      } catch (e) {
        console.warn('Failed to parse tsconfig.json:', e);
      }
    }
    
    // tsconfig.prod.json 읽기
    const prodConfigPath = path.join(this.rootPath, 'tsconfig.prod.json');
    if (fs.existsSync(prodConfigPath)) {
      try {
        const configText = fs.readFileSync(prodConfigPath, 'utf-8');
        const { config: prodConfig, error } = ts.parseConfigFileTextToJson(prodConfigPath, configText);
        if (error) {
          console.warn('Failed to parse tsconfig.prod.json:', error.messageText);
        } else if (prodConfig && prodConfig.exclude) {
          prodConfig.exclude.forEach((pattern: string) => patterns.add(pattern));
        }
      } catch (e) {
        console.warn('Failed to parse tsconfig.prod.json:', e);
      }
    }
    
    // tsconfig.cjs.json 읽기
    const cjsConfigPath = path.join(this.rootPath, 'tsconfig.cjs.json');
    if (fs.existsSync(cjsConfigPath)) {
      try {
        const configText = fs.readFileSync(cjsConfigPath, 'utf-8');
        const { config: cjsConfig, error } = ts.parseConfigFileTextToJson(cjsConfigPath, configText);
        if (error) {
          console.warn('Failed to parse tsconfig.cjs.json:', error.messageText);
        } else if (cjsConfig && cjsConfig.exclude) {
          cjsConfig.exclude.forEach((pattern: string) => patterns.add(pattern));
        }
      } catch (e) {
        console.warn('Failed to parse tsconfig.cjs.json:', e);
      }
    }
    
    // console.log(`Using exclude patterns: ${Array.from(patterns).join(', ')}`);
    return Array.from(patterns);
  }

  private matchesPattern(filePath: string, pattern: string): boolean {
    // 간단한 glob 패턴 매칭
    if (pattern === 'node_modules') {
      return filePath.includes('node_modules');
    }
    
    if (pattern === 'dist') {
      return filePath.includes('dist');
    }
    
    if (pattern === '**/*.test.ts') {
      return filePath.endsWith('.test.ts');
    }
    
    if (pattern === '**/*.spec.ts') {
      return filePath.endsWith('.spec.ts');
    }
    
    if (pattern === 'src/__mocks__/**/*') {
      return filePath.includes('src/__mocks__/');
    }
    
    return false;
  }

  private analyzeSourceFile(sourceFile: SourceFile): void {
    try {
    // 함수 선언 추출
    this.extractFunctionDeclarations(sourceFile);
    
    // 콜백 함수 내부의 호출 추적 (먼저 실행 - 콜백 함수를 함수로 등록)
    this.trackCallbackFunctions(sourceFile);
    
    // 호출 표현식 분석
    this.analyzeCallExpressions(sourceFile);
    
    // 생성자 호출 분석
    this.analyzeNewExpressions(sourceFile);
    
    // Dynamic import 분석
    this.analyzeDynamicImports(sourceFile);
    
    // require 호출 분석
    this.analyzeRequireCalls(sourceFile);
    } catch (error) {
      // 개별 파일 분석 실패 시 경고만 출력하고 계속 진행
      console.warn(`Error analyzing file ${sourceFile.getFilePath()}:`, error instanceof Error ? error.message : String(error));
    }
  }

  private trackCallbackFunctions(sourceFile: SourceFile): void {
    // CallExpression의 인자에서 콜백 함수 찾기
    const callExpressions = sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression);
    for (const callExpr of callExpressions) {
      const args = callExpr.getArguments();
      for (const arg of args) {
        if (Node.isArrowFunction(arg) || Node.isFunctionExpression(arg)) {
          // 콜백 함수를 별도 함수로 추적
          const callbackName = this.getCallbackFunctionName(arg, callExpr, sourceFile);
          const filePath = path.relative(this.rootPath, sourceFile.getFilePath());
          const callbackKey = `${filePath}::${callbackName}`;
          
          if (!this.trackedFunctions.has(callbackKey)) {
            this.trackedFunctions.add(callbackKey);
          }
          
          // 콜백 함수 내부의 모든 호출 표현식 추적
          this.analyzeFunctionBodyCalls(arg, callbackKey, filePath, sourceFile);
        }
      }
    }
  }

  private analyzeFunctionBodyCalls(functionNode: Node, callerKey: string, callerFilePath: string, sourceFile: SourceFile): void {
    // 함수 본문 내부의 모든 CallExpression 찾기
    const callExpressions = functionNode.getDescendantsOfKind(SyntaxKind.CallExpression);
    
    for (const callExpr of callExpressions) {
      // import()와 require()는 별도로 처리하므로 제외
      const expression = callExpr.getExpression();
      if (Node.isIdentifier(expression)) {
        const name = expression.getText();
        if (name === 'import' || name === 'require') {
          continue;
        }
      }

      const callees = this.getCalleeInfos(callExpr, sourceFile);
      if (callees.length === 0) continue;

      const start = callExpr.getStart();
      const lineAndChar = sourceFile.getLineAndColumnAtPos(start);
      
      this.addCallEdges(callerKey, callerFilePath, callees, lineAndChar);
    }
    
    // 함수 본문 내부의 모든 NewExpression 찾기
    const newExpressions = functionNode.getDescendantsOfKind(SyntaxKind.NewExpression);
    for (const newExpr of newExpressions) {
      const callees = this.getCalleeInfos(newExpr, sourceFile);
      if (callees.length === 0) continue;

      const start = newExpr.getStart();
      const lineAndChar = sourceFile.getLineAndColumnAtPos(start);
      
      this.addCallEdges(callerKey, callerFilePath, callees, lineAndChar);
    }
  }

  private extractFunctionDeclarations(sourceFile: SourceFile): void {
    const filePath = path.relative(this.rootPath, sourceFile.getFilePath());
    
    // 함수 선언
    const functionDeclarations = sourceFile.getDescendantsOfKind(SyntaxKind.FunctionDeclaration);
    for (const func of functionDeclarations) {
      const name = func.getName();
      if (name) {
        this.trackedFunctions.add(`${filePath}::${name}`);
      }
    }
    
    // 메서드 선언 (클래스 내부)
    const methodDeclarations = sourceFile.getDescendantsOfKind(SyntaxKind.MethodDeclaration);
    for (const method of methodDeclarations) {
      const name = method.getName();
      const classDecl = this.findContainingClass(method);
      const className = classDecl && Node.isClassDeclaration(classDecl) ? classDecl.getName() : null;
      if (name) {
        const fullName = className ? `${className}.${name}` : name;
        this.trackedFunctions.add(`${filePath}::${fullName}`);
      }
    }
    
    // 변수 선언 (화살표 함수, 함수 표현식)
    const variableDeclarations = sourceFile.getDescendantsOfKind(SyntaxKind.VariableDeclaration);
    for (const variable of variableDeclarations) {
      const name = variable.getName();
      if (name && (variable.hasInitializer() && 
          (Node.isArrowFunction(variable.getInitializer()!) || 
           Node.isFunctionExpression(variable.getInitializer()!)))) {
        this.trackedFunctions.add(`${filePath}::${name}`);
      }
    }
    
    // 클래스 선언
    const classDeclarations = sourceFile.getDescendantsOfKind(SyntaxKind.ClassDeclaration);
    for (const classDecl of classDeclarations) {
      const name = classDecl.getName();
      if (name) {
        this.trackedFunctions.add(`${filePath}::${name}`);
        // 생성자도 추가
        this.trackedFunctions.add(`${filePath}::${name}.constructor`);
      }
    }
    
    // 모든 화살표 함수 추출 (변수 선언 외의 경우들)
    const arrowFunctions = sourceFile.getDescendantsOfKind(SyntaxKind.ArrowFunction);
    for (const arrowFunc of arrowFunctions) {
      const parent = arrowFunc.getParent();
      let functionName = this.generateFunctionName(arrowFunc, sourceFile);
      
      // generateFunctionName이 null을 반환해도 강제로 이름 생성
      if (!functionName) {
        functionName = this.generateFallbackFunctionName(arrowFunc, sourceFile);
      }
      
      if (functionName) {
        this.trackedFunctions.add(`${filePath}::${functionName}`);
      }
    }
    
    // 모든 함수 표현식 추출
    const functionExpressions = sourceFile.getDescendantsOfKind(SyntaxKind.FunctionExpression);
    for (const funcExpr of functionExpressions) {
      const parent = funcExpr.getParent();
      let functionName = this.generateFunctionName(funcExpr, sourceFile);
      
      // generateFunctionName이 null을 반환해도 강제로 이름 생성
      if (!functionName) {
        functionName = this.generateFallbackFunctionName(funcExpr, sourceFile);
      }
      
      if (functionName) {
        this.trackedFunctions.add(`${filePath}::${functionName}`);
      }
    }
    
    // 인터페이스 메서드 시그니처 추출
    const methodSignatures = sourceFile.getDescendantsOfKind(SyntaxKind.MethodSignature);
    for (const methodSig of methodSignatures) {
      const name = methodSig.getName();
      if (name) {
        this.trackedFunctions.add(`${filePath}::${name}_signature`);
      }
    }
    
    // PropertySignature 추출 (화살표 함수가 있는 경우)
    const propertySignatures = sourceFile.getDescendantsOfKind(SyntaxKind.PropertySignature);
    for (const propSig of propertySignatures) {
      const name = propSig.getName();
      if (name && propSig.getTypeNode()) {
        // 화살표 함수 타입이 있는 경우
        const typeNode = propSig.getTypeNode();
        if (Node.isFunctionTypeNode(typeNode)) {
          this.trackedFunctions.add(`${filePath}::${name}_signature`);
        }
      }
    }
  }

  private analyzeCallExpressions(sourceFile: SourceFile): void {
    const callExpressions = sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression);
    for (const callExpr of callExpressions) {
      this.handleCallExpression(callExpr, sourceFile);
    }
  }

  private analyzeNewExpressions(sourceFile: SourceFile): void {
    const newExpressions = sourceFile.getDescendantsOfKind(SyntaxKind.NewExpression);
    for (const newExpr of newExpressions) {
      this.handleNewExpression(newExpr, sourceFile);
    }
  }

  private analyzeDynamicImports(sourceFile: SourceFile): void {
    // Dynamic import() 호출 찾기
    const importExpressions = sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression);
    for (const callExpr of importExpressions) {
      const expression = callExpr.getExpression();
      if (Node.isIdentifier(expression) && expression.getText() === 'import') {
        const args = callExpr.getArguments();
        if (args.length > 0) {
          const moduleArg = args[0];
          if (Node.isStringLiteral(moduleArg)) {
            const moduleSpecifier = moduleArg.getLiteralValue();
            const position = this.getPosition(callExpr, sourceFile);
            console.log(`Found dynamic import: ${moduleSpecifier} at ${sourceFile.getFilePath()}:${position.line}`);
            this.trackDynamicImport(sourceFile, moduleSpecifier, position);
          }
        }
      }
    }
  }

  private analyzeRequireCalls(sourceFile: SourceFile): void {
    // require() 호출 찾기
    const callExpressions = sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression);
    for (const callExpr of callExpressions) {
      const expression = callExpr.getExpression();
      if (Node.isIdentifier(expression) && expression.getText() === 'require') {
        const args = callExpr.getArguments();
        if (args.length > 0) {
          const moduleArg = args[0];
          if (Node.isStringLiteral(moduleArg)) {
            const moduleSpecifier = moduleArg.getLiteralValue();
            const position = this.getPosition(callExpr, sourceFile);
            this.trackRequireCall(sourceFile, moduleSpecifier, position);
          }
        }
      }
    }
  }

  private trackDynamicImport(sourceFile: SourceFile, moduleSpecifier: string, position: { line: number; column: number }): void {
    const callerFilePath = path.relative(this.rootPath, sourceFile.getFilePath());
    const callerKey = callerFilePath;
    
    if (!this.callGraphMap.has(callerKey)) {
      this.callGraphMap.set(callerKey, { filePath: callerFilePath, edges: [] });
    }
    const existing = this.callGraphMap.get(callerKey)!;

    const isExternal = !moduleSpecifier.startsWith('.');
    const packageName = isExternal ? this.extractPackageName(moduleSpecifier) : undefined;
    
    const moduleType: CallEdge['moduleType'] = isExternal
      ? (moduleSpecifier.startsWith('node:')
          ? 'node_builtin'
          : (packageName ? 'npm' : 'builtin'))
      : 'internal';

    // 중복 체크
    const filePath = moduleSpecifier.startsWith('node:') 
      ? `node/${moduleSpecifier.substring(5)}`
      : moduleSpecifier;
    
    const isDuplicate = existing.edges.some(e =>
      e.functionName === 'import' &&
      e.filePath === filePath
    );

    if (!isDuplicate) {
      const callEdge: CallEdge = {
        functionName: 'import',
        filePath,
        packageName,
        isExternal,
        moduleType,
        callType: 'external',
        fullSignature: `import('${moduleSpecifier}')`,
        position
      };

      existing.edges.push(callEdge);
    }
  }

  private trackRequireCall(sourceFile: SourceFile, moduleSpecifier: string, position: { line: number; column: number }): void {
    const callerFilePath = path.relative(this.rootPath, sourceFile.getFilePath());
    const callerKey = callerFilePath;
    
    if (!this.callGraphMap.has(callerKey)) {
      this.callGraphMap.set(callerKey, { filePath: callerFilePath, edges: [] });
    }
    const existing = this.callGraphMap.get(callerKey)!;

    const isExternal = !moduleSpecifier.startsWith('.');
    const packageName = isExternal ? this.extractPackageName(moduleSpecifier) : undefined;
    
    const moduleType: CallEdge['moduleType'] = isExternal
      ? (this.isNodeBuiltin(moduleSpecifier)
          ? 'node_builtin'
          : (packageName ? 'npm' : 'builtin'))
      : 'internal';

    // 중복 체크
    const filePath = this.isNodeBuiltin(moduleSpecifier) 
      ? `node/${moduleSpecifier}`
      : moduleSpecifier;
    
    const isDuplicate = existing.edges.some(e =>
      e.functionName === 'require' &&
      e.filePath === filePath
    );

    if (!isDuplicate) {
      const callEdge: CallEdge = {
        functionName: 'require',
        filePath,
        packageName,
        isExternal,
        moduleType,
        callType: 'external',
        fullSignature: `require('${moduleSpecifier}')`,
        position
      };

      existing.edges.push(callEdge);
    }
  }

  private getPosition(node: Node, sourceFile: SourceFile): { line: number; column: number } {
    const start = node.getStart();
    const lineAndChar = sourceFile.getLineAndColumnAtPos(start);
    return {
      line: lineAndChar.line,
      column: lineAndChar.column
    };
  }

  private handleCallExpression(callExpr: CallExpression, sourceFile: SourceFile): void {
    try {
    // import()와 require()는 별도로 처리하므로 제외
    const expression = callExpr.getExpression();
    if (Node.isIdentifier(expression)) {
      const name = expression.getText();
      if (name === 'import' || name === 'require') {
        return;
      }
    }

    const callees = this.getCalleeInfos(callExpr, sourceFile);
    if (callees.length === 0) return;

    const caller = this.getCurrentFunction(callExpr, sourceFile) || '[top-level]';
    const callerFilePath = path.relative(this.rootPath, sourceFile.getFilePath());
    const callerKey = `${callerFilePath}::${caller}`;

    const start = callExpr.getStart();
    const lineAndChar = sourceFile.getLineAndColumnAtPos(start);

    this.addCallEdges(callerKey, callerFilePath, callees, lineAndChar);
    } catch (error) {
      // 개별 호출 표현식 분석 실패 시 경고만 출력하고 계속 진행
      console.warn(`Error analyzing call expression at ${sourceFile.getFilePath()}:${callExpr.getStartLineNumber()}:`, error instanceof Error ? error.message : String(error));
    }
  }

  private handleNewExpression(newExpr: NewExpression, sourceFile: SourceFile): void {
    try {
    const callees = this.getCalleeInfos(newExpr, sourceFile);
    if (callees.length === 0) return;

    const caller = this.getCurrentFunction(newExpr, sourceFile) || '[top-level]';
    const callerFilePath = path.relative(this.rootPath, sourceFile.getFilePath());
    const callerKey = `${callerFilePath}::${caller}`;

    const start = newExpr.getStart();
    const lineAndChar = sourceFile.getLineAndColumnAtPos(start);

    this.addCallEdges(callerKey, callerFilePath, callees, lineAndChar);
    } catch (error) {
      // 개별 생성자 호출 분석 실패 시 경고만 출력하고 계속 진행
      console.warn(`Error analyzing new expression at ${sourceFile.getFilePath()}:${newExpr.getStartLineNumber()}:`, error instanceof Error ? error.message : String(error));
    }
  }

  private addCallEdges(
    callerKey: string, 
    callerFilePath: string, 
    callees: Array<{ 
      name: string; 
      module?: string; 
      implementation?: string; 
      package?: string; 
      isExternal: boolean;
      callType: CallEdge['callType'];
      fullSignature?: string;
    }>, 
    position: { line: number; column: number }
  ): void {
    if (!this.callGraphMap.has(callerKey)) {
      this.callGraphMap.set(callerKey, { filePath: callerFilePath, edges: [] });
    }
    const existing = this.callGraphMap.get(callerKey)!;

    // 중복 제거를 위한 Set 사용 (reachability 분석에는 graph structure만 필요)
    const seen = new Set<string>();

    for (const callee of callees) {
      const moduleType: CallEdge['moduleType'] = callee.isExternal
        ? (callee.package
            ? 'npm'
            : (callee.module?.startsWith('global/')
                ? 'global'
                : (callee.module?.startsWith('node/') ? 'node_builtin' : 'builtin')))
        : 'internal';

      // 중복 체크 키 생성: functionName + module (module이 있으면)
      // position은 무시 (reachability 분석에는 불필요)
      const duplicateKey = callee.module 
        ? `${callee.name}::${callee.module}`
        : callee.name;

      // 이미 추가된 callee인지 확인
      if (seen.has(duplicateKey)) {
        continue; // 중복이면 스킵
      }
      seen.add(duplicateKey);

      const callEdge: CallEdge = {
        functionName: callee.name,
        filePath: callee.module,
        implementationPath: callee.implementation,
        packageName: callee.package,
        isExternal: callee.isExternal,
        moduleType,
        callType: callee.callType,
        fullSignature: callee.fullSignature,
        position: {
          line: position.line,
          column: position.column
        }
      };

      existing.edges.push(callEdge);

      if (!callee.isExternal && callee.module) {
        this.trackInternalFunctionCalls(callee.name, callee.module);
      }
    }
  }

  private getCalleeInfos(
    callExpr: CallExpression | NewExpression,
    sourceFile: SourceFile
  ): Array<{ 
    name: string; 
    module?: string; 
    implementation?: string; 
    package?: string; 
    isExternal: boolean;
    callType: CallEdge['callType'];
    fullSignature?: string;
  }> {
    const expressions = this.expandCalleeAlternatives(callExpr.getExpression());
    const results: Array<{ 
      name: string; 
      module?: string; 
      implementation?: string; 
      package?: string; 
      isExternal: boolean;
      callType: CallEdge['callType'];
      fullSignature?: string;
    }> = [];
    
    for (const expr of expressions) {
      const info = this.getCalleeInfoForExpression(expr, callExpr, sourceFile);
      if (info) {
        const exists = results.some(r => 
          r.name === info.name && 
          r.module === info.module && 
          r.package === info.package &&
          r.callType === info.callType
        );
        if (!exists) results.push(info);
      }
    }
    
    return results;
  }

  private expandCalleeAlternatives(expression: Node): Node[] {
    // 괄호/단언 제거
    const unwrap = (expr: Node): Node => {
      let current = expr;
      while (Node.isParenthesizedExpression(current) || 
             Node.isAsExpression(current) || 
             Node.isNonNullExpression(current)) {
        if (Node.isParenthesizedExpression(current)) {
          current = current.getExpression();
        } else if (Node.isAsExpression(current)) {
          current = current.getExpression();
        } else if (Node.isNonNullExpression(current)) {
          current = current.getExpression();
        } else {
          break;
        }
      }
      return current;
    };

    const unwrapped = unwrap(expression);

    // 선택적 체이닝 처리 (obj?.method())
    if (Node.isCallExpression(unwrapped)) {
      const innerExpr = unwrap(unwrapped.getExpression());
      if (Node.isPropertyAccessExpression(innerExpr)) {
        return [innerExpr];
      }
    }

    // 조건부 표현식 처리 (a ? b : c)
    if (Node.isConditionalExpression(unwrapped)) {
      const alternatives: Node[] = [];
      alternatives.push(unwrapped.getWhenTrue());
      alternatives.push(unwrapped.getWhenFalse());
      return alternatives.flatMap(alt => this.expandCalleeAlternatives(alt));
    }

    // 이진 표현식 처리 (a || b, a ?? b)
    if (Node.isBinaryExpression(unwrapped)) {
      const operator = unwrapped.getOperatorToken().getKind();
      if (operator === SyntaxKind.BarBarToken || operator === SyntaxKind.QuestionQuestionToken) {
        const alternatives: Node[] = [];
        alternatives.push(unwrapped.getLeft());
        alternatives.push(unwrapped.getRight());
        return alternatives.flatMap(alt => this.expandCalleeAlternatives(alt));
      }
    }

    return [unwrapped];
  }

  private getCalleeInfoForExpression(
    expression: Node,
    callExpr: CallExpression | NewExpression,
    sourceFile: SourceFile
  ): { 
    name: string; 
    module?: string; 
    implementation?: string; 
    package?: string; 
    isExternal: boolean;
    callType: CallEdge['callType'];
    fullSignature?: string;
  } | null {
    try {
      const fullSignature = this.getFullCallSignature(expression, callExpr);
      
      // 1. 생성자 호출 (new Class())
      if (Node.isNewExpression(callExpr)) {
        return this.handleConstructorCall(expression, sourceFile, fullSignature);
      }
      
      // 2. 식별자 호출 (functionName())
      if (Node.isIdentifier(expression)) {
        return this.handleIdentifierCall(expression, sourceFile, fullSignature);
      }
      
      // 3. 프로퍼티 접근 호출 (obj.method(), Class.staticMethod())
      if (Node.isPropertyAccessExpression(expression)) {
        return this.handlePropertyAccessCall(expression, sourceFile, fullSignature);
      }
      
      // 4. 요소 접근 호출 (obj['method'](), obj[0]())
      if (Node.isElementAccessExpression(expression)) {
        return this.handleElementAccessCall(expression, sourceFile, fullSignature);
      }
      
      // 5. 텍스트 기반 분석 (fallback)
      return this.handleTextBasedCall(expression, sourceFile, fullSignature);

    } catch (error) {
      // 에러 발생 시 텍스트 기반으로 fallback
      return this.handleTextBasedCall(expression, sourceFile, this.getFullCallSignature(expression, callExpr));
    }
  }

  private getFullCallSignature(expression: Node, callExpr: CallExpression | NewExpression): string {
    const exprText = expression.getText();
    const args = callExpr.getArguments().map((arg: Node) => arg.getText()).join(', ');
    return `${exprText}(${args})`;
  }

  private handleConstructorCall(
    expression: Node, 
    sourceFile: SourceFile, 
    fullSignature: string
  ): { 
    name: string; 
    module?: string; 
    implementation?: string; 
    package?: string; 
    isExternal: boolean;
    callType: CallEdge['callType'];
    fullSignature?: string;
  } | null {
    let name = 'unknown';
    let module: string | undefined;
    let packageName: string | undefined;
    let isExternal = false;

    if (Node.isIdentifier(expression)) {
      name = expression.getText();
      
      // 1. 먼저 import 정보 확인 (가장 정확함)
      const importedInfo = this.getImportedInfo(expression, sourceFile);
      if (importedInfo) {
        
        return {
          ...importedInfo,
          callType: 'constructor',
          fullSignature
        };
      }
      
      // 2. TypeScript Compiler API로 정확한 심볼 분석
      const symbolInfo = this.analyzeSymbolWithTypeScript(expression, sourceFile);
      if (symbolInfo) {
        return {
          name: symbolInfo.name,
          module: symbolInfo.filePath,
          package: symbolInfo.packageName,
          isExternal: symbolInfo.isExternal,
          callType: 'constructor',
          fullSignature
        };
      }
      
      // 3. 전역 함수 확인
      if (this.isGlobalFunction(name)) {
        return {
          name,
          module: `global/${name}`,
          isExternal: true,
          callType: 'builtin',
          fullSignature
        };
      }
      
      // 4. Node.js 빌트인 확인
      if (this.isNodeBuiltin(name)) {
        return {
          name,
          module: `node/${name}`,
          isExternal: true,
          callType: 'builtin',
          fullSignature
        };
      }
      
      // 5. 프로젝트 내부 (fallback)
      const filePath = path.relative(this.rootPath, sourceFile.getFilePath());
      return {
        name,
        module: filePath,
        isExternal: false,
        callType: 'constructor',
        fullSignature
      };
    }

    if (Node.isPropertyAccessExpression(expression)) {
      const objectName = expression.getExpression().getText();
      const propertyName = expression.getName();
      name = `${objectName}.${propertyName}`;
      
      // 1. TypeScript Compiler API로 정확한 심볼 분석
      const symbolInfo = this.analyzeSymbolWithTypeScript(expression, sourceFile);
      if (symbolInfo) {
        return {
          name: symbolInfo.name,
          module: symbolInfo.filePath,
          package: symbolInfo.packageName,
          isExternal: symbolInfo.isExternal,
          callType: 'constructor',
          fullSignature
        };
      }
      
      // 2. 기존 import 정보 확인 (fallback)
      const importedInfo = this.getImportedInfo(expression.getExpression(), sourceFile);
      if (importedInfo) {
        return {
          name: propertyName,
          module: importedInfo.module,
          package: importedInfo.package,
          isExternal: true,
          callType: 'constructor',
          fullSignature
        };
      }
      
      // 3. 전역 객체 확인
      if (this.isGlobalFunction(objectName)) {
        return {
          name: propertyName,
          module: `global/${objectName}`,
          isExternal: true,
          callType: 'builtin',
          fullSignature
        };
      }
      
      // 4. 프로젝트 내부 (fallback)
      const filePath = path.relative(this.rootPath, sourceFile.getFilePath());
      return {
        name: propertyName,
        module: filePath,
        isExternal: false,
        callType: 'constructor',
        fullSignature
      };
    }

    return {
      name,
      module,
      package: undefined,
      isExternal,
      callType: 'constructor',
      fullSignature
    };
  }

  private handleIdentifierCall(
    identifier: Identifier, 
    sourceFile: SourceFile, 
    fullSignature: string
  ): { 
    name: string; 
    module?: string; 
    implementation?: string; 
    package?: string; 
    isExternal: boolean;
    callType: CallEdge['callType'];
    fullSignature?: string;
  } | null {
    const name = identifier.getText();
    
    // 1. 먼저 import 정보 확인 (가장 정확함)
    const importedInfo = this.getImportedInfo(identifier, sourceFile);
    if (importedInfo) {
      let callType: CallEdge['callType'] = 'function';
      
      // import된 심볼의 타입에 따라 callType 결정
      if (importedInfo.module?.includes('Client') || name === 'Client') {
        callType = 'constructor';
      } else if (importedInfo.module?.startsWith('node/')) {
        callType = 'builtin';
      } else if (importedInfo.isExternal) {
        callType = 'external';
      }
      
      
      return {
        name: importedInfo.name,
        module: importedInfo.module,
        package: importedInfo.package,
        isExternal: importedInfo.isExternal,
        callType,
        fullSignature
      };
    }
    
    // 2. TypeScript Compiler API로 정확한 심볼 분석
    const symbolInfo = this.analyzeSymbolWithTypeScript(identifier, sourceFile);
    if (symbolInfo) {
      let callType: CallEdge['callType'] = 'function';
      
      if (symbolInfo.symbolType === 'class') {
        callType = 'constructor';
      } else if (symbolInfo.symbolType === 'function') {
        callType = 'function';
      } else if (symbolInfo.symbolType === 'variable') {
        callType = 'function'; // 변수로 선언된 함수
      }
      
      return {
        name: symbolInfo.name,
        module: symbolInfo.filePath,
        package: symbolInfo.packageName,
        isExternal: symbolInfo.isExternal,
        callType,
        fullSignature
      };
    }
    
    // 3. 전역 함수 확인
    if (this.isGlobalFunction(name)) {
      return {
        name,
        module: `global/${name}`,
        isExternal: true,
        callType: 'builtin',
        fullSignature
      };
    }
    
    // 4. Node.js 빌트인 확인
    if (this.isNodeBuiltin(name)) {
      return {
        name,
        module: `node/${name}`,
        isExternal: true,
        callType: 'builtin',
        fullSignature
      };
    }
    
    // 5. 프로젝트 내부 함수 (fallback)
    const filePath = path.relative(this.rootPath, sourceFile.getFilePath());
    return {
      name,
      module: filePath,
      isExternal: false,
      callType: 'function',
      fullSignature
    };
  }

  private handlePropertyAccessCall(
    propertyAccess: PropertyAccessExpression, 
    sourceFile: SourceFile, 
    fullSignature: string
  ): { 
    name: string; 
    module?: string; 
    implementation?: string; 
    package?: string; 
    isExternal: boolean;
    callType: CallEdge['callType'];
    fullSignature?: string;
  } | null {
    const objectName = propertyAccess.getExpression().getText();
    const propertyName = propertyAccess.getName();
    const name = `${objectName}.${propertyName}`;
    
    // 먼저 전역 객체 확인 (console, process 등) - Node.js 빌트인 체크 전에!
    const globalObjects = ['console', 'process', 'global', 'window', 'document'];
    if (this.isGlobalFunction(objectName) || globalObjects.includes(objectName)) {
      // console.error, process.exit 등을 올바르게 처리
      let module: string;
      let callType: CallEdge['callType'] = 'builtin';
      
      if (objectName === 'console') {
        module = 'node/console';
      } else if (objectName === 'process') {
        module = 'node/process';
      } else {
        module = `global/${objectName}`;
      }
      
      return {
        name: `${objectName}.${propertyName}`, // 전체 이름 반환 (console.error, process.exit 등)
        module,
        isExternal: true,
        callType,
        fullSignature
      };
    }
    
    // import 정보 확인 (Node.js 스키마 포함)
    const importedInfo = this.getImportedInfo(propertyAccess.getExpression(), sourceFile);
    if (importedInfo) {
      return {
        name: propertyName,
        module: importedInfo.module,
        package: importedInfo.package,
        isExternal: true,
        callType: importedInfo.module?.startsWith('node/') ? 'builtin' : 'external',
        fullSignature
      };
    }
    
    // Node.js 빌트인 직접 확인 (fs.readFileSync 등)
    if (this.isNodeBuiltin(objectName)) {
      return {
        name: `${objectName}.${propertyName}`, // 전체 이름 반환
        module: `node/${objectName}`,
        isExternal: true,
        callType: 'builtin',
        fullSignature
      };
    }
    
    // 외부 패키지 확인 (zod.parse, express.json 등)
    const packageInfo = this.getPackageInfo(objectName, sourceFile);
    if (packageInfo) {
      return {
        name: propertyName,
        module: packageInfo.module,
        package: packageInfo.package,
        isExternal: true,
        callType: 'external',
        fullSignature
      };
    }
    
    // 정적 메서드 확인 (Class.method)
    if (this.isStaticMethodCall(propertyAccess, sourceFile)) {
      const filePath = path.relative(this.rootPath, sourceFile.getFilePath());
      return {
        name: propertyName,
        module: filePath,
        isExternal: false,
        callType: 'static_method',
        fullSignature
      };
    }
    
    // 인스턴스 메서드: 변수 타입 추적하여 외부 패키지 확인
    const expression = propertyAccess.getExpression();
    
    // 방법 1: 변수 타입 직접 추적
    const typeInfo = this.getVariableTypeInfo(expression, sourceFile);
    if (typeInfo && typeInfo.isExternal && typeInfo.packageName) {
      // 외부 패키지 클래스의 인스턴스 메서드
      return {
        name: propertyName,
        module: typeInfo.module || typeInfo.filePath,
        package: typeInfo.packageName,
        isExternal: true,
        callType: 'external',
        fullSignature
      };
    }
    
    // 방법 2: 변수의 초기화 표현식에서 생성자 호출 추적
    if (Node.isIdentifier(expression)) {
      const varName = expression.getText();
      const constructorInfo = this.findConstructorCallForVariable(varName, sourceFile, expression);
      if (constructorInfo && constructorInfo.isExternal && constructorInfo.packageName) {
        return {
          name: propertyName,
          module: constructorInfo.module || constructorInfo.filePath,
          package: constructorInfo.packageName,
          isExternal: true,
          callType: 'external',
          fullSignature
        };
      }
    }
    
    // 내부 인스턴스 메서드
    const filePath = path.relative(this.rootPath, sourceFile.getFilePath());
    return {
      name: propertyName,
      module: filePath,
      isExternal: false,
      callType: 'method',
      fullSignature
    };
  }

  private handleElementAccessCall(
    elementAccess: ElementAccessExpression, 
    sourceFile: SourceFile, 
    fullSignature: string
  ): { 
    name: string; 
    module?: string; 
    implementation?: string; 
    package?: string; 
    isExternal: boolean;
    callType: CallEdge['callType'];
    fullSignature?: string;
  } | null {
    const objectName = elementAccess.getExpression().getText();
    const argument = elementAccess.getArgumentExpression();
    const propertyName = argument ? argument.getText() : 'unknown';
    const name = `${objectName}[${propertyName}]`;
    
    // 외부 패키지 확인
    const importedInfo = this.getImportedInfo(elementAccess.getExpression(), sourceFile);
    if (importedInfo) {
      return {
        name: propertyName,
        module: importedInfo.module,
        package: importedInfo.package,
        isExternal: true,
        callType: 'external',
        fullSignature
      };
    }
    
    // 프로젝트 내부
    const filePath = path.relative(this.rootPath, sourceFile.getFilePath());
    return {
      name: propertyName,
      module: filePath,
      isExternal: false,
      callType: 'method',
      fullSignature
    };
  }

  private handleTextBasedCall(
    expression: Node, 
    sourceFile: SourceFile, 
    fullSignature: string
  ): { 
    name: string; 
    module?: string; 
    implementation?: string; 
    package?: string; 
    isExternal: boolean;
    callType: CallEdge['callType'];
    fullSignature?: string;
  } | null {
    const text = expression.getText();
    
    // super() 호출 처리
    if (text === 'super') {
      const parent = expression.getParent();
      if (Node.isCallExpression(parent)) {
        const classDecl = this.findContainingClass(expression);
        if (classDecl && Node.isClassDeclaration(classDecl)) {
          const className = classDecl.getName() || 'AnonymousClass';
          return {
            name: `${className}.constructor`,
            module: path.relative(this.rootPath, sourceFile.getFilePath()),
            isExternal: false,
            callType: 'constructor',
            fullSignature
          };
        }
      }
    }
    
    const name = this.generateContextualName(expression, sourceFile) || 'unknown';
    
    // 전역 함수 패턴 확인
    if (this.isGlobalFunction(text)) {
      return {
        name: text,
        module: `global/${text}`,
        isExternal: true,
        callType: 'builtin',
        fullSignature
      };
    }
    
    // Node.js 빌트인 패턴 확인
    if (this.isNodeBuiltin(text)) {
      return {
        name: text,
        module: `node/${text}`,
        isExternal: true,
        callType: 'builtin',
        fullSignature
      };
    }
    
    // 프로젝트 내부
    const filePath = path.relative(this.rootPath, sourceFile.getFilePath());
    return {
      name,
      module: filePath,
      isExternal: false,
      callType: 'unresolved',
      fullSignature
    };
  }

  private findContainingClass(node: Node): Node | null {
    let current = node.getParent();
    while (current) {
      if (Node.isClassDeclaration(current)) {
        return current;
      }
      current = current.getParent();
    }
    return null;
  }

  private isStaticMethodCall(propertyAccess: PropertyAccessExpression, sourceFile: SourceFile): boolean {
    const expression = propertyAccess.getExpression();
    if (Node.isIdentifier(expression)) {
      const symbol = expression.getSymbol();
      if (symbol) {
        const declarations = symbol.getDeclarations();
        if (declarations && declarations.length > 0) {
          return declarations.some((decl: ts.Declaration) => Node.isClassDeclaration(decl));
        }
      }
    }
    return false;
  }

  private getImportedInfo(identifier: Node, sourceFile: SourceFile): { name: string; module?: string; implementation?: string; package?: string; isExternal: boolean } | null {
    const name = identifier.getText();
    
    // Import 정보 확인
    const imports = sourceFile.getImportDeclarations();
    for (const importDecl of imports) {
      const moduleSpecifier = importDecl.getModuleSpecifierValue();
      
      // Node.js 스키마 import 처리 (node:fs, node:crypto 등)
      if (moduleSpecifier.startsWith('node:')) {
        const nodeModule = moduleSpecifier.substring(5); // 'node:' 제거
        if (this.isNodeBuiltin(nodeModule)) {
          const namedImports = importDecl.getNamedImports();
          for (const namedImport of namedImports) {
            if (namedImport.getName() === name) {
              return {
                name,
                module: `node/${nodeModule}`,
                package: undefined,
                isExternal: true
              };
            }
          }
          
          const defaultImport = importDecl.getDefaultImport();
          if (defaultImport && defaultImport.getText() === name) {
            return {
              name: name, // 원래 이름 유지
              module: `node/${nodeModule}`,
              package: undefined,
              isExternal: true
            };
          }
        }
        continue;
      }
      
      // 일반 외부 패키지 import 처리
      const namedImports = importDecl.getNamedImports();
      for (const namedImport of namedImports) {
        if (namedImport.getName() === name) {
          const packageName = this.extractPackageName(moduleSpecifier);
          const isExternal = !moduleSpecifier.startsWith('.');
          
          return {
            name,
            module: moduleSpecifier,
            package: packageName,
            isExternal
          };
        }
      }
      
      // Namespace import 처리 (import * as X)
      const namespaceImport = importDecl.getNamespaceImport();
      if (namespaceImport && namespaceImport.getText() === name) {
        const packageName = this.extractPackageName(moduleSpecifier);
        const isExternal = !moduleSpecifier.startsWith('.');
        return {
          name,
          module: moduleSpecifier,
          package: packageName,
          isExternal
        };
      }
      
      const defaultImport = importDecl.getDefaultImport();
      if (defaultImport && defaultImport.getText() === name) {
        const packageName = this.extractPackageName(moduleSpecifier);
        const isExternal = !moduleSpecifier.startsWith('.');
        return {
          name,
          module: moduleSpecifier,
          package: packageName,
          isExternal
        };
      }
    }
    
    return null;
  }

  private getPackageInfo(objectName: string, sourceFile: SourceFile): { module?: string; package?: string } | null {
    // Import 정보에서 패키지 정보 찾기
    const imports = sourceFile.getImportDeclarations();
    for (const importDecl of imports) {
      const moduleSpecifier = importDecl.getModuleSpecifierValue();
      if (moduleSpecifier.startsWith('.')) continue; // 상대 경로는 내부 모듈
      
      const namedImports = importDecl.getNamedImports();
      for (const namedImport of namedImports) {
        if (namedImport.getName() === objectName) {
          const packageName = this.extractPackageName(moduleSpecifier);
          return {
            module: moduleSpecifier,
            package: packageName
          };
        }
      }
      
      // Namespace import 처리 (import * as X)
      const namespaceImport = importDecl.getNamespaceImport();
      if (namespaceImport && namespaceImport.getText() === objectName) {
        const packageName = this.extractPackageName(moduleSpecifier);
        return {
          module: moduleSpecifier,
          package: packageName
        };
      }
      
      const defaultImport = importDecl.getDefaultImport();
      if (defaultImport && defaultImport.getText() === objectName) {
        const packageName = this.extractPackageName(moduleSpecifier);
        return {
          module: moduleSpecifier,
          package: packageName
        };
      }
    }
    
    return null;
  }

  private extractPackageName(moduleSpecifier: string): string {
    const parts = moduleSpecifier.split('/');
    
    if (parts[0].startsWith('@')) {
      return parts.length >= 2 ? `${parts[0]}/${parts[1]}` : parts[0];
    }
    
    return parts[0];
  }

  private generateContextualName(declaration: Node, sourceFile: SourceFile): string | null {
    const text = declaration.getText();
    
    // 프로퍼티 접근 패턴 (obj.method, Class.staticMethod)
    if (Node.isPropertyAccessExpression(declaration)) {
      const objectName = declaration.getExpression().getText();
      const propertyName = declaration.getName();
      return `${objectName}.${propertyName}`;
    }
    
    // 요소 접근 패턴 (obj['method'])
    if (Node.isElementAccessExpression(declaration)) {
      const objectName = declaration.getExpression().getText();
      const argument = declaration.getArgumentExpression();
      const propertyName = argument ? argument.getText() : 'unknown';
      return `${objectName}[${propertyName}]`;
    }
    
    // 파일명 기반 이름 생성
    const fileName = path.basename(sourceFile.getFilePath(), '.ts');
    const lineNumber = sourceFile.getLineAndColumnAtPos(declaration.getStart()).line;
    return `${fileName}_line${lineNumber}`;
  }

  private generateFallbackFunctionName(funcNode: Node, sourceFile: SourceFile): string {
    const parent = funcNode.getParent();
    const lineNumber = sourceFile.getLineAndColumnAtPos(funcNode.getStart()).line;
    const fileName = path.basename(sourceFile.getFilePath(), '.ts');
    
    // 다양한 컨텍스트에 따른 이름 생성
    if (Node.isPropertySignature(parent)) {
      // 인터페이스 메서드 시그니처: onclose?: () => void;
      return `${parent.getName()}_signature`;
    }
    
    if (Node.isMethodSignature(parent)) {
      // 인터페이스 메서드 시그니처: onclose?(): void;
      return `${parent.getName()}_signature`;
    }
    
    if (Node.isCallExpression(parent)) {
      // Promise 콜백: new Promise((resolve, reject) => {})
      const callee = parent.getExpression();
      if (Node.isNewExpression(callee)) {
        const constructorName = callee.getExpression().getText();
        return `${constructorName}_callback`;
      }
      if (Node.isPropertyAccessExpression(callee)) {
        const methodName = callee.getName();
        return `${methodName}_callback`;
      }
      return `callback_line${lineNumber}`;
    }
    
    if (Node.isPropertyAssignment(parent)) {
      // 객체 리터럴 메서드: { method: () => {} }
      return `${parent.getName()}_method`;
    }
    
    if (Node.isArrayLiteralExpression(parent)) {
      // 배열 내 함수: [() => {}, () => {}]
      return `array_func_line${lineNumber}`;
    }
    
    if (Node.isConditionalExpression(parent)) {
      // 삼항 연산자: condition ? () => {} : () => {}
      return `conditional_func_line${lineNumber}`;
    }
    
    if (Node.isBinaryExpression(parent)) {
      // 할당: obj.method = () => {}
      const left = parent.getLeft();
      if (Node.isPropertyAccessExpression(left)) {
        return `${left.getName()}_arrow`;
      }
    }
    
    // 기본 fallback
    return `${fileName}_arrow_line${lineNumber}`;
  }

  private generateFunctionName(funcNode: Node, sourceFile: SourceFile): string | null {
    const parent = funcNode.getParent();
    
    // 변수 선언인 경우
    if (Node.isVariableDeclaration(parent)) {
      return parent.getName();
    }
    
    // 프로퍼티 할당인 경우
    if (Node.isPropertyAssignment(parent)) {
      return parent.getName();
    }
    
    // BinaryExpression인 경우 (obj.method = () => {})
    if (Node.isBinaryExpression(parent)) {
      const left = parent.getLeft();
      if (Node.isPropertyAccessExpression(left)) {
        const objectName = left.getExpression().getText();
        const propertyName = left.getName();
        return `${objectName}.${propertyName}`;
      }
      if (Node.isIdentifier(left)) {
        return left.getText();
      }
    }
    
    // CallExpression인 경우 (콜백 함수)
    if (Node.isCallExpression(parent)) {
      return this.getCallbackFunctionName(funcNode, parent, sourceFile);
    }
    
    // ObjectLiteralExpression인 경우
    if (Node.isObjectLiteralExpression(parent)) {
      const grandParent = parent.getParent();
      if (Node.isVariableDeclaration(grandParent)) {
        return `${grandParent.getName()}_method`;
      }
    }
    
    // PropertySignature인 경우 (인터페이스 메서드 시그니처)
    if (Node.isPropertySignature(parent)) {
      return `${parent.getName()}_signature`;
    }
    
    // MethodSignature인 경우 (인터페이스 메서드 시그니처)
    if (Node.isMethodSignature(parent)) {
      return `${parent.getName()}_signature`;
    }
    
    // ArrayLiteralExpression인 경우
    if (Node.isArrayLiteralExpression(parent)) {
      const lineNumber = sourceFile.getLineAndColumnAtPos(funcNode.getStart()).line;
      return `array_func_line${lineNumber}`;
    }
    
    // 기본적으로 fallback 사용
    return this.generateFallbackFunctionName(funcNode, sourceFile);
  }

  private getCurrentFunction(node: Node, sourceFile: SourceFile): string | null {
    let current = node.getParent();
    
    while (current) {
      if (Node.isFunctionDeclaration(current)) {
        const name = current.getName();
        if (name) return name;
        // 익명 함수 선언은 매우 드물므로 그냥 anonymous로 표시
        return 'anonymous_function';
      }
      if (Node.isMethodDeclaration(current)) {
        return current.getName();
      }
      if (Node.isArrowFunction(current) || Node.isFunctionExpression(current)) {
        const parent = current.getParent();
        if (Node.isVariableDeclaration(parent)) {
          return parent.getName();
        }
        if (Node.isPropertyAssignment(parent)) {
          return parent.getName();
        }
        // BinaryExpression: server.onclose = () => { ... }
        if (Node.isBinaryExpression(parent)) {
          const left = parent.getLeft();
          if (Node.isPropertyAccessExpression(left)) {
            const objectName = left.getExpression().getText();
            const propertyName = left.getName();
            return `${objectName}.${propertyName}`;
          }
          if (Node.isIdentifier(left)) {
            return left.getText();
          }
        }
        if (Node.isCallExpression(parent)) {
          // 콜백 함수의 경우 실제 호출 맥락을 정확히 파악
          return this.getCallbackFunctionName(current, parent, sourceFile);
        }
        // 화살표 함수나 익명 함수는 컨텍스트 정보를 포함한 이름 생성
        const lineNumber = sourceFile.getLineAndColumnAtPos(current.getStart()).line;
        const fileName = path.basename(sourceFile.getFilePath(), '.ts');
        return `${fileName}#arrow@L${lineNumber}`;
      }
      if (Node.isClassDeclaration(current)) {
        return current.getName() || 'AnonymousClass';
      }
      if (Node.isConstructorDeclaration(current)) {
        const classDecl = current.getParent();
        if (Node.isClassDeclaration(classDecl)) {
          return `${classDecl.getName() || 'AnonymousClass'}.constructor`;
        }
        return 'constructor';
      }
      current = current.getParent();
    }
    
    return null;
  }

  private classifyCallbackType(methodName: string, baseName: string): string {
    // 패턴 기반 타입 분류 (확장 가능)
    const patterns = {
      // Promise 관련
      promise: ['then', 'catch', 'finally', 'resolve', 'reject'],
      // 이벤트 관련
      event: ['on', 'addEventListener', 'once', 'off', 'removeEventListener', 'emit'],
      // HTTP 라우트 관련
      route: ['get', 'post', 'put', 'delete', 'patch', 'head', 'options'],
      // 배열 메서드 관련
      array: ['map', 'filter', 'reduce', 'forEach', 'find', 'some', 'every'],
      // 타이머 관련
      timer: ['setTimeout', 'setInterval', 'setImmediate'],
      // 파일/스트림 관련
      io: ['read', 'write', 'create', 'update', 'delete', 'open', 'close'],
      // 검증/유틸리티 관련
      util: ['validate', 'check', 'verify', 'parse', 'stringify', 'serialize'],
      // 네트워크 관련
      network: ['send', 'receive', 'transmit', 'connect', 'disconnect'],
      // 테스트 관련
      test: ['test', 'spec', 'describe', 'it', 'beforeEach', 'afterEach', 'beforeAll', 'afterAll']
    };

    // 패턴 매칭
    for (const [type, methods] of Object.entries(patterns)) {
      if (methods.includes(methodName)) {
        return type;
      }
    }

    // 기본 객체명 기반 분류
    if (baseName.includes('app') || baseName.includes('router')) {
      return 'route';
    }
    if (baseName.includes('promise') || baseName.includes('async')) {
      return 'promise';
    }
    if (baseName.includes('event') || baseName.includes('emitter')) {
      return 'event';
    }
    if (baseName.includes('array') || baseName.includes('list')) {
      return 'array';
    }

    // 기본값
    return 'callback';
  }

  private getCallbackFunctionName(funcNode: Node, callExpr: Node, sourceFile: SourceFile): string {
    if (!Node.isCallExpression(callExpr)) return 'anonymous_callback';
    
    const callee = callExpr.getExpression();
    let baseName = 'callback';
    
    if (Node.isPropertyAccessExpression(callee)) {
      const objectName = callee.getExpression().getText();
      const methodName = callee.getName();
      baseName = `${objectName}.${methodName}`;
    } else if (Node.isIdentifier(callee)) {
      baseName = callee.getText();
    }
    
    // 실제 함수명 + 타입 + 라인번호 형식으로 생성
    const lineNumber = sourceFile.getLineAndColumnAtPos(funcNode.getStart()).line;
    
    // 메서드 이름에 따라 적절한 타입 분류 (동적 패턴 매칭)
    const methodName = Node.isPropertyAccessExpression(callee) ? callee.getName() : '';
    const callbackType = this.classifyCallbackType(methodName, baseName);
    
    // Format: 실제함수명#타입@라인번호
    return `${baseName}#${callbackType}@L${lineNumber}`;
  }

  private extractFirstMeaningfulCall(text: string): string | null {
    // 첫 번째 함수 호출이나 의미 있는 표현식 찾기
    const patterns = [
      /console\.(log|error|warn|info)\(['"`]([^'"`]+)['"`]\)/,  // console.log('message')
      /\.(then|catch|finally)\(/,  // .then(, .catch(
      /\.(map|filter|reduce|forEach)\(/,  // .map(, .filter(
      /\.(get|post|put|delete|patch)\(/,  // .get(, .post(
      /\.(on|emit|addEventListener)\(/,  // .on(, .emit(
      /\.(connect|disconnect|close)\(/,  // .connect(, .close(
      /\.(read|write|create|update|delete)\(/,  // .read(, .write(
      /\.(validate|check|verify)\(/,  // .validate(, .check(
      /\.(parse|stringify|serialize)\(/,  // .parse(, .stringify(
      /\.(send|receive|transmit)\(/,  // .send(, .receive(
      /error|Error|exception/,  // error, Error, exception
      /test|spec|describe|it/,  // test, spec, describe, it
      /mock|stub|spy/,  // mock, stub, spy
      /async|await|Promise/,  // async, await, Promise
      /return|yield/  // return, yield
    ];
    
    for (const pattern of patterns) {
      const match = text.match(pattern);
      if (match) {
        return match[0].replace(/[^a-zA-Z0-9]/g, '_');
      }
    }
    
    return null;
  }

  private analyzeAnonymousFunction(funcNode: Node, sourceFile: SourceFile): string {
    const text = funcNode.getText();
    const lineNumber = sourceFile.getLineAndColumnAtPos(funcNode.getStart()).line;
    const fileName = path.basename(sourceFile.getFilePath(), '.ts');
    
    // 함수 내용에서 의미 있는 키워드 추출
    const keywords = this.extractMeaningfulKeywords(text);
    if (keywords.length > 0) {
      return `${fileName}_${keywords[0]}_line${lineNumber}`;
    }
    
    // 매개변수 분석
    const params = this.extractParameters(funcNode);
    if (params.length > 0) {
      return `${fileName}_${params[0]}_handler_line${lineNumber}`;
    }
    
    return `${fileName}_func_line${lineNumber}`;
  }

  private analyzeCallbackFunction(funcNode: Node, callExpr: Node, sourceFile: SourceFile): string {
    let baseName = 'callback';
    
    if (Node.isCallExpression(callExpr)) {
      const callee = callExpr.getExpression();
      if (Node.isPropertyAccessExpression(callee)) {
        const objectName = callee.getExpression().getText();
        const methodName = callee.getName();
        baseName = `${objectName}.${methodName}`;
      } else if (Node.isIdentifier(callee)) {
        baseName = callee.getText();
      }
    }
    
    // 함수 내용에서 의미 있는 키워드 추출
    const text = funcNode.getText();
    const keywords = this.extractMeaningfulKeywords(text);
    if (keywords.length > 0) {
      return `${baseName}_${keywords[0]}`;
    }
    
    // 매개변수 분석
    const params = this.extractParameters(funcNode);
    if (params.length > 0) {
      return `${baseName}_${params[0]}_handler`;
    }
    
    return `${baseName}_callback`;
  }

  private extractMeaningfulKeywords(text: string): string[] {
    const keywords = [];
    
    // 일반적인 함수 패턴들
    const patterns = [
      { pattern: /console\.(log|error|warn|info)/, name: 'logger' },
      { pattern: /\.(then|catch|finally)/, name: 'promise' },
      { pattern: /\.(map|filter|reduce|forEach)/, name: 'array' },
      { pattern: /\.(get|post|put|delete|patch)/, name: 'http' },
      { pattern: /\.(on|emit|addEventListener)/, name: 'event' },
      { pattern: /\.(connect|disconnect|close)/, name: 'connection' },
      { pattern: /\.(read|write|create|update|delete)/, name: 'file' },
      { pattern: /\.(validate|check|verify)/, name: 'validator' },
      { pattern: /\.(parse|stringify|serialize)/, name: 'parser' },
      { pattern: /\.(send|receive|transmit)/, name: 'message' },
      { pattern: /error|Error|exception/, name: 'error' },
      { pattern: /test|spec|describe|it/, name: 'test' },
      { pattern: /mock|stub|spy/, name: 'mock' },
      { pattern: /async|await|Promise/, name: 'async' },
      { pattern: /return|yield/, name: 'return' }
    ];
    
    for (const { pattern, name } of patterns) {
      if (pattern.test(text)) {
        keywords.push(name);
      }
    }
    
    return keywords;
  }

  private extractParameters(funcNode: Node): string[] {
    const params = [];
    
    if (Node.isFunctionDeclaration(funcNode)) {
      const paramNodes = funcNode.getParameters();
      for (const param of paramNodes) {
        if (Node.isParameterDeclaration(param)) {
          const name = param.getName();
          if (name && name !== 'this') {
            params.push(name);
          }
        }
      }
    } else if (Node.isArrowFunction(funcNode) || Node.isFunctionExpression(funcNode)) {
      const paramNodes = funcNode.getParameters();
      for (const param of paramNodes) {
        if (Node.isParameterDeclaration(param)) {
          const name = param.getName();
          if (name && name !== 'this') {
            params.push(name);
          }
        }
      }
    }
    
    return params;
  }

  private trackInternalFunctionCalls(functionName: string, filePath: string): void {
    const key = `${filePath}::${functionName}`;
    if (this.trackedFunctions.has(key)) return;
    this.trackedFunctions.add(key);
  }

  private initializeGlobalSymbols(): void {
    // globals 라이브러리를 사용하여 환경별 전역 함수 수집
    const environments = ['browser', 'node', 'es2020', 'es2021', 'es2022', 'es2023'] as const;
    
    for (const env of environments) {
      if (env in globals) {
        const envGlobals = globals[env];
        for (const globalName of Object.keys(envGlobals)) {
          this.globalSymbols.add(globalName);
        }
      }
    }
    
    console.log(`Initialized ${this.globalSymbols.size} global symbols from globals library`);
  }

  private initializeNodeBuiltinModules(): void {
    // builtin-modules 라이브러리를 사용하여 Node.js 빌트인 모듈 수집
    const modules = (builtinModules as any).default || builtinModules;
    for (const builtin of modules) {
      this.nodeBuiltinModules.add(builtin);
    }
    
    // 런타임에서 추가 확인 (Node.js 버전에 따라 다를 수 있음)
    if (typeof require !== 'undefined') {
      try {
        const module = require('module');
        if (module.builtinModules) {
          // Node.js 12+ 에서 사용 가능한 builtinModules로 추가 확인
          for (const builtin of module.builtinModules) {
            this.nodeBuiltinModules.add(builtin);
          }
        }
      } catch (e) {
        // require('module') 실패 시 builtin-modules만 사용
      }
    }
    
    console.log(`Initialized ${this.nodeBuiltinModules.size} Node.js builtin modules from builtin-modules library`);
  }

  private analyzeAllImports(): void {
    console.log('Analyzing all imports...');
    
    const sourceFiles = this.project.getSourceFiles();
    for (const sourceFile of sourceFiles) {
      if (this.shouldSkipFile(sourceFile)) continue;
      
      this.analyzeImportsInFile(sourceFile);
    }
    
    console.log(`Analyzed imports: ${this.importMap.size} imports, ${this.symbolMap.size} symbols`);
  }

  private analyzeImportsInFile(sourceFile: SourceFile): void {
    const filePath = path.relative(this.rootPath, sourceFile.getFilePath());
    const importDeclarations = sourceFile.getImportDeclarations();
    
    for (const importDecl of importDeclarations) {
      const moduleSpecifier = importDecl.getModuleSpecifierValue();
      const packageName = this.extractPackageName(moduleSpecifier);
      const isExternal = !moduleSpecifier.startsWith('.');
      const isNodeBuiltin = this.isNodeBuiltin(moduleSpecifier);
      const isGlobal = this.isGlobalModule(moduleSpecifier);
      
      // Default import 분석
      const defaultImport = importDecl.getDefaultImport();
      if (defaultImport) {
        const importInfo: ImportInfo = {
          moduleSpecifier,
          packageName,
          isExternal,
          isNodeBuiltin,
          isGlobal,
          importType: 'default',
          originalName: 'default',
          importedName: defaultImport.getText()
        };
        
        this.importMap.set(defaultImport.getText(), importInfo);
        this.addSymbolInfo(defaultImport.getText(), importInfo, sourceFile);
      }
      
      // Named imports 분석
      const namedImports = importDecl.getNamedImports();
      for (const namedImport of namedImports) {
        const importInfo: ImportInfo = {
          moduleSpecifier,
          packageName,
          isExternal,
          isNodeBuiltin,
          isGlobal,
          importType: 'named',
          originalName: namedImport.getName(),
          importedName: namedImport.getName()
        };
        
        this.importMap.set(namedImport.getName(), importInfo);
        this.addSymbolInfo(namedImport.getName(), importInfo, sourceFile);
      }
      
      // Namespace import 분석
      const namespaceImport = importDecl.getNamespaceImport();
      if (namespaceImport) {
        const importInfo: ImportInfo = {
          moduleSpecifier,
          packageName,
          isExternal,
          isNodeBuiltin,
          isGlobal,
          importType: 'namespace',
          originalName: '*',
          importedName: namespaceImport.getText()
        };
        
        this.importMap.set(namespaceImport.getText(), importInfo);
        this.addSymbolInfo(namespaceImport.getText(), importInfo, sourceFile);
      }
    }
  }

  // TypeScript Compiler API를 사용한 정확한 심볼 분석
  private analyzeSymbolWithTypeScript(node: Node, sourceFile: SourceFile): SymbolInfo | null {
    // 캐시 확인
    const cacheKey = this.getSymbolCacheKey(node, sourceFile);
    if (this.symbolAnalysisCache.has(cacheKey)) {
      return this.symbolAnalysisCache.get(cacheKey)!;
    }

    try {
      const tsNode = node.compilerNode;
      const typeChecker = this.project.getTypeChecker().compilerObject;
      
      // 심볼 가져오기
      const symbol = typeChecker.getSymbolAtLocation(tsNode);
      if (!symbol) {
        this.symbolAnalysisCache.set(cacheKey, null);
        return null;
      }
      
      // 심볼의 선언들 가져오기
      const declarations = symbol.getDeclarations();
      if (!declarations || declarations.length === 0) {
        this.symbolAnalysisCache.set(cacheKey, null);
        return null;
      }
      
      const declaration = declarations[0];
      const sourceFileOfDeclaration = declaration.getSourceFile();
      
      // 파일 경로 결정
      let filePath: string;
      let isExternal = false;
      let moduleType: 'global' | 'node_builtin' | 'npm' | 'internal' | 'builtin' = 'internal';
      let packageName: string | undefined;
      
      if (sourceFileOfDeclaration.isDeclarationFile) {
        // .d.ts 파일인 경우
        const fileName = sourceFileOfDeclaration.fileName;
        if (fileName.includes('node_modules')) {
          isExternal = true;
          moduleType = 'npm';
          packageName = this.extractPackageNameFromPath(fileName);
        } else if (fileName.includes('lib.') || fileName.includes('typescript/lib')) {
          isExternal = true;
          moduleType = 'builtin';
        } else {
          isExternal = true;
          moduleType = 'builtin';
        }
        filePath = fileName;
      } else {
        // 소스 파일인 경우
        filePath = path.relative(this.rootPath, sourceFileOfDeclaration.fileName);
        isExternal = false;
        moduleType = 'internal';
      }
      
      // 심볼 타입 결정
      let symbolType: 'function' | 'class' | 'interface' | 'variable' | 'type' | 'unknown' = 'unknown';
      
      if (symbol.flags & ts.SymbolFlags.Function) {
        symbolType = 'function';
      } else if (symbol.flags & ts.SymbolFlags.Class) {
        symbolType = 'class';
      } else if (symbol.flags & ts.SymbolFlags.Interface) {
        symbolType = 'interface';
      } else if (symbol.flags & ts.SymbolFlags.Variable) {
        symbolType = 'variable';
      } else if (symbol.flags & ts.SymbolFlags.TypeAlias) {
        symbolType = 'type';
      }
      
      
      const result: SymbolInfo = {
        name: symbol.getName(),
        filePath,
        isExternal,
        moduleType,
        packageName,
        symbolType,
        declaration: node
      };
      
      // 캐시에 저장
      this.symbolAnalysisCache.set(cacheKey, result);
      return result;
      
    } catch (error) {
      console.warn('Error analyzing symbol with TypeScript API:', error);
      this.symbolAnalysisCache.set(cacheKey, null);
      return null;
    }
  }

  // 심볼 캐시 키 생성 (심볼 이름과 선언 위치 기반으로 고유성 보장)
  private getSymbolCacheKey(node: Node, sourceFile: SourceFile): string {
    try {
      const tsNode = node.compilerNode;
      const typeChecker = this.project.getTypeChecker().compilerObject;
      const symbol = typeChecker.getSymbolAtLocation(tsNode);
      
      if (symbol) {
        // 심볼 이름과 선언 위치를 조합하여 고유한 키 생성
        const symbolName = symbol.getName();
        const declarations = symbol.getDeclarations();
        if (declarations && declarations.length > 0) {
          const firstDecl = declarations[0];
          const declFile = firstDecl.getSourceFile();
          const declPos = firstDecl.getStart();
          const filePath = sourceFile.getFilePath();
          return `symbol:${symbolName}:${declFile.fileName}:${declPos}:${filePath}`;
        }
        // 선언이 없으면 이름과 현재 위치 사용
        const filePath = sourceFile.getFilePath();
        const pos = node.getStart();
        return `symbol:${symbolName}:${filePath}:${pos}`;
      }
    } catch (e) {
      // fallback
    }
    
    // fallback: 노드 위치와 텍스트 기반
    const pos = node.getStart();
    const text = node.getText();
    const filePath = sourceFile.getFilePath();
    return `node:${filePath}:${pos}:${text.substring(0, 50)}`; // 텍스트는 처음 50자만 사용
  }

  private extractPackageNameFromPath(filePath: string): string {
    const parts = filePath.split('node_modules/');
    if (parts.length < 2) return 'unknown';
    
    const packagePath = parts[1];
    const pathParts = packagePath.split('/');
    
    // pnpm 구조 처리: node_modules/.pnpm/package@version/node_modules/package
    if (pathParts[0] === '.pnpm') {
      // .pnpm 다음 부분에서 패키지 이름 추출 (버전 정보 제거)
      if (pathParts.length >= 2) {
        const pnpmPackagePart = pathParts[1];
        // 패키지 이름은 @ 또는 + 이전까지, 또는 첫 번째 _ 이전까지
        // 예: vite@6.3.4_@types+node@22.15.17 -> vite
        // 예: @types+node@22.15.17 -> @types/node
        let packageName = pnpmPackagePart;
        
        // @로 시작하는 scoped 패키지 처리
        if (packageName.startsWith('@')) {
          // @types+node@22.15.17 -> @types/node
          // @scope+package@version -> @scope/package
          packageName = packageName.replace(/^@([^@+]+)\+([^@+]+).*/, '@$1/$2');
        } else {
          // vite@6.3.4_... -> vite
          // package@version -> package
          packageName = packageName.split('@')[0];
          packageName = packageName.split('_')[0];
        }
        
        // 마지막 node_modules/ 다음의 실제 패키지 이름도 확인 (더 정확함)
        const nodeModulesIndex = pathParts.indexOf('node_modules', 2);
        if (nodeModulesIndex !== -1 && nodeModulesIndex + 1 < pathParts.length) {
          const actualPackageIndex = nodeModulesIndex + 1;
          if (pathParts[actualPackageIndex].startsWith('@')) {
            // scoped package: @scope/package
            if (actualPackageIndex + 1 < pathParts.length) {
              return `${pathParts[actualPackageIndex]}/${pathParts[actualPackageIndex + 1]}`;
            }
          } else {
            // regular package
            return pathParts[actualPackageIndex];
          }
        }
        
        return packageName;
      }
    }
    
    // 일반 npm 구조 처리
    if (pathParts[0].startsWith('@')) {
      return `${pathParts[0]}/${pathParts[1]}`;
    }
    
    return pathParts[0];
  }

  // 변수의 타입 정보를 추적하여 외부 패키지 여부 확인
  private getVariableTypeInfo(
    expression: Node,
    sourceFile: SourceFile
  ): { 
    filePath: string; 
    isExternal: boolean; 
    packageName?: string; 
    module?: string;
    moduleType?: 'global' | 'node_builtin' | 'npm' | 'internal' | 'builtin';
  } | null {
    // 캐시 확인
    const cacheKey = this.getTypeInfoCacheKey(expression, sourceFile);
    if (this.typeInfoCache.has(cacheKey)) {
      return this.typeInfoCache.get(cacheKey)!;
    }

    try {
      const tsNode = expression.compilerNode;
      const typeChecker = this.project.getTypeChecker().compilerObject;
      
      // 먼저 변수의 심볼 가져오기
      const symbol = typeChecker.getSymbolAtLocation(tsNode);
      if (symbol) {
        // 심볼의 타입 가져오기
        const symbolType = typeChecker.getTypeOfSymbolAtLocation(symbol, tsNode);
        if (symbolType) {
          // 타입의 심볼 가져오기
          let typeSymbol = symbolType.getSymbol();
          
          // 심볼이 없으면 타입의 알리아스 심볼 확인
          if (!typeSymbol) {
            const aliasSymbol = symbolType.aliasSymbol;
            if (aliasSymbol) {
              typeSymbol = aliasSymbol;
            }
          }
          
          // 심볼이 있으면 패키지 정보 추출
          if (typeSymbol) {
            const info = this.getSymbolPackageInfo(typeSymbol);
            if (info && info.isExternal && info.packageName) {
              this.typeInfoCache.set(cacheKey, info);
              return info;
            }
          }
        }
      }
      
      // 심볼 추적 실패 시 타입 직접 추적
      const type = typeChecker.getTypeAtLocation(tsNode);
      if (!type) {
        this.typeInfoCache.set(cacheKey, null);
        return null;
      }
      
      // 타입의 심볼 가져오기
      let typeSymbol = type.getSymbol();
      
      // 심볼이 없으면 타입의 알리아스 심볼 확인
      if (!typeSymbol) {
        const aliasSymbol = type.aliasSymbol;
        if (aliasSymbol) {
          typeSymbol = aliasSymbol;
        }
      }
      
      // 여전히 심볼이 없으면 생성자 시그니처 확인
      if (!typeSymbol) {
        const constructorSignatures = type.getConstructSignatures();
        if (constructorSignatures.length > 0) {
          const constructorType = constructorSignatures[0].getReturnType();
          typeSymbol = constructorType.getSymbol();
        }
      }
      
      // 심볼이 있으면 패키지 정보 추출
      if (typeSymbol) {
        const info = this.getSymbolPackageInfo(typeSymbol);
        if (info) {
          this.typeInfoCache.set(cacheKey, info);
          return info;
        }
      }
      
      // 타입의 모든 베이스 타입 확인 (클래스 상속 체인)
      const baseTypes = type.getBaseTypes();
      if (baseTypes && baseTypes.length > 0) {
        for (const baseType of baseTypes) {
          const baseSymbol = baseType.getSymbol();
          if (baseSymbol) {
            const info = this.getSymbolPackageInfo(baseSymbol);
            if (info && info.isExternal && info.packageName) {
              this.typeInfoCache.set(cacheKey, info);
              return info;
            }
          }
        }
      }
      
      this.typeInfoCache.set(cacheKey, null);
      return null;
      
    } catch (error) {
      // 타입 추적 실패 시 null 반환
      this.typeInfoCache.set(cacheKey, null);
      return null;
    }
  }

  // 타입 정보 캐시 키 생성
  private getTypeInfoCacheKey(expression: Node, sourceFile: SourceFile): string {
    try {
      const tsNode = expression.compilerNode;
      const typeChecker = this.project.getTypeChecker().compilerObject;
      const symbol = typeChecker.getSymbolAtLocation(tsNode);
      
      if (symbol) {
        // 심볼 이름과 선언 위치를 조합하여 고유한 키 생성
        const symbolName = symbol.getName();
        const declarations = symbol.getDeclarations();
        if (declarations && declarations.length > 0) {
          const firstDecl = declarations[0];
          const declFile = firstDecl.getSourceFile();
          const declPos = firstDecl.getStart();
          const filePath = sourceFile.getFilePath();
          return `type:${symbolName}:${declFile.fileName}:${declPos}:${filePath}`;
        }
        // 선언이 없으면 이름과 현재 위치 사용
        const filePath = sourceFile.getFilePath();
        const pos = expression.getStart();
        return `type:${symbolName}:${filePath}:${pos}`;
      }
    } catch (e) {
      // fallback
    }
    
    // fallback: 노드 위치와 텍스트 기반
    const pos = expression.getStart();
    const text = expression.getText();
    const filePath = sourceFile.getFilePath();
    return `type:${filePath}:${pos}:${text.substring(0, 50)}`;
  }

  // 변수의 초기화 표현식에서 생성자 호출 찾기
  private findConstructorCallForVariable(
    varName: string,
    sourceFile: SourceFile,
    usageNode: Node
  ): { 
    filePath: string; 
    isExternal: boolean; 
    packageName?: string; 
    module?: string;
    moduleType?: 'global' | 'node_builtin' | 'npm' | 'internal' | 'builtin';
  } | null {
    try {
      // 사용 노드의 부모 노드들을 따라가며 변수 선언 찾기
      let current: Node | undefined = usageNode;
      const visited = new Set<Node>();
      
      while (current && !visited.has(current)) {
        visited.add(current);
        
        // 현재 노드와 그 하위에서 변수 선언 찾기
        const descendants = current.getDescendants();
        for (const node of descendants) {
          if (Node.isVariableDeclaration(node)) {
            if (node.getName() === varName) {
              const initializer = node.getInitializer();
              if (initializer && Node.isNewExpression(initializer)) {
                // new FormData() 같은 생성자 호출 찾음
                const newExpr = initializer as NewExpression;
                const callees = this.getCalleeInfos(newExpr, sourceFile);
                if (callees.length > 0) {
                  const callee = callees[0];
                  if (callee.isExternal && callee.package) {
                    return {
                      filePath: callee.module || '',
                      isExternal: true,
                      packageName: callee.package,
                      module: callee.module,
                      moduleType: 'npm'
                    };
                  }
                }
              }
            }
          }
        }
        
        // 부모 노드로 이동
        current = current.getParent();
        
        // 함수나 클래스 범위를 벗어나면 중단
        if (current) {
          if (Node.isFunctionDeclaration(current) || 
              Node.isClassDeclaration(current) ||
              Node.isSourceFile(current)) {
            // 함수/클래스/파일 내에서 찾기
            if (Node.isSourceFile(current)) {
              break;
            }
          }
        }
      }
      
      // 전체 파일에서 찾기 (fallback)
      const variableDeclarations = sourceFile.getVariableDeclarations();
      for (const varDecl of variableDeclarations) {
        if (varDecl.getName() === varName) {
          const initializer = varDecl.getInitializer();
          if (initializer && Node.isNewExpression(initializer)) {
            const newExpr = initializer as NewExpression;
            const callees = this.getCalleeInfos(newExpr, sourceFile);
            if (callees.length > 0) {
              const callee = callees[0];
              if (callee.isExternal && callee.package) {
                return {
                  filePath: callee.module || '',
                  isExternal: true,
                  packageName: callee.package,
                  module: callee.module,
                  moduleType: 'npm'
                };
              }
            }
          }
        }
      }
      
      return null;
    } catch (error) {
      return null;
    }
  }

  // 심볼의 패키지 정보 추출
  private getSymbolPackageInfo(
    symbol: ts.Symbol
  ): { 
    filePath: string; 
    isExternal: boolean; 
    packageName?: string; 
    module?: string;
    moduleType?: 'global' | 'node_builtin' | 'npm' | 'internal' | 'builtin';
  } | null {
    const declarations = symbol.getDeclarations();
    if (!declarations || declarations.length === 0) return null;
    
    const declaration = declarations[0];
    const sourceFileOfDeclaration = declaration.getSourceFile();
    
    if (sourceFileOfDeclaration.isDeclarationFile) {
      // .d.ts 파일인 경우
      const fileName = sourceFileOfDeclaration.fileName;
      if (fileName.includes('node_modules')) {
        const packageName = this.extractPackageNameFromPath(fileName);
        return {
          filePath: fileName,
          isExternal: true,
          packageName,
          module: packageName,
          moduleType: 'npm'
        };
      } else if (fileName.includes('lib.') || fileName.includes('typescript/lib')) {
        return {
          filePath: fileName,
          isExternal: true,
          moduleType: 'builtin'
        };
      }
    }
    
    // 내부 파일인 경우
    const filePath = path.relative(this.rootPath, sourceFileOfDeclaration.fileName);
    return {
      filePath,
      isExternal: false,
      moduleType: 'internal'
    };
  }

  private addSymbolInfo(name: string, importInfo: ImportInfo, sourceFile: SourceFile): void {
    let moduleType: 'global' | 'node_builtin' | 'npm' | 'internal' | 'builtin' = 'internal';
    
    if (importInfo.isGlobal) {
      moduleType = 'global';
    } else if (importInfo.isNodeBuiltin) {
      moduleType = 'node_builtin';
    } else if (importInfo.isExternal && importInfo.packageName) {
      moduleType = 'npm';
    } else if (importInfo.isExternal) {
      moduleType = 'builtin';
    }
    
    const symbolInfo: SymbolInfo = {
      name,
      filePath: importInfo.isExternal ? importInfo.moduleSpecifier : path.relative(this.rootPath, sourceFile.getFilePath()),
      isExternal: importInfo.isExternal,
      moduleType,
      packageName: importInfo.packageName,
      symbolType: 'unknown'
    };
    
    this.symbolMap.set(name, symbolInfo);
  }

  private isGlobalModule(moduleSpecifier: string): boolean {
    // 전역 모듈들 (URL, WebSocket 등)
    const globalModules = ['url', 'websocket', 'crypto', 'buffer', 'util', 'events', 'stream'];
    return globalModules.includes(moduleSpecifier.toLowerCase());
  }

  private isGlobalFunction(name: string): boolean {
    return this.globalSymbols.has(name);
  }

  private isNodeBuiltin(name: string): boolean {
    return this.nodeBuiltinModules.has(name);
  }

  private saveResults(): void {
    console.log('[saveResults] Starting to save call graph results...');
    console.log(`[saveResults] callGraphMap size: ${this.callGraphMap.size}`);
    
    const callGraph = Array.from(this.callGraphMap.entries()).map(([caller, entry]) => {
      // filePath에서 packageName과 isExternal 추출
      let packageName = this.packageJson?.name;
      let isExternal = false;
      
      const filePath = entry.filePath;
      
      // node_modules 경로에서 패키지 이름 추출 (상대 경로 또는 절대 경로 모두 체크)
      if (filePath.includes('node_modules')) {
        isExternal = true;
        // 절대 경로로 변환해서 패키지 이름 추출 시도
        let absPath = filePath;
        if (!path.isAbsolute(filePath)) {
          // 상대 경로인 경우 절대 경로로 변환
          try {
            absPath = path.resolve(this.rootPath, filePath);
          } catch (e) {
            // 변환 실패 시 원본 사용
            absPath = filePath;
          }
        }
        const packageNameFromPath = this.extractPackageNameFromPath(absPath);
        if (packageNameFromPath !== 'unknown') {
          packageName = packageNameFromPath;
        }
      } else if (path.isAbsolute(filePath)) {
        // 절대 경로인 경우 rootPath 밖에 있으면 외부
        try {
          const relativePath = path.relative(this.rootPath, filePath);
          if (relativePath.startsWith('..')) {
            isExternal = true;
          }
        } catch (e) {
          // relative path 계산 실패 시 외부로 간주
          isExternal = true;
        }
      } else {
        // 상대 경로인 경우, rootPath 기준으로 절대 경로 계산해서 확인
        try {
          const absPath = path.resolve(this.rootPath, filePath);
          if (absPath.includes('node_modules')) {
            isExternal = true;
            const packageNameFromPath = this.extractPackageNameFromPath(absPath);
            if (packageNameFromPath !== 'unknown') {
              packageName = packageNameFromPath;
            }
          }
        } catch (e) {
          // 변환 실패 시 내부로 간주
        }
      }
      
      // 내부 파일이면 메인 패키지 이름 사용
      if (!isExternal && !packageName) {
        packageName = this.packageJson?.name;
      }
      
      return {
      functionName: caller,
      filePath: entry.filePath,
        packageName: packageName || this.packageJson?.name,
        isExternal: isExternal,
      callees: entry.edges
      };
    });

    const externalDependencies = this.getExternalDependencies();
    const files = Array.from(new Set(Array.from(this.callGraphMap.values()).map(e => e.filePath)));
    const functions = Array.from(this.trackedFunctions);

    // 중복 제거 후 최종 통계 계산
    const totalEdges = callGraph.reduce((sum, entry) => sum + entry.callees.length, 0);

    const result = {
      main_module: this.packageJson?.name || 'unknown',
      files: files.length,
      functions: functions.length,
      edges: totalEdges, // 중복 제거 후 edges 개수
      call_graph: callGraph,
      external_dependencies: externalDependencies,
      packages: Object.keys(externalDependencies),
      dependencies: this.packageJson?.dependencies || {}
    };

    // 프로젝트명 프리픽스 파일명 구성 - use REPO_NAME from env if available
    let safeName: string;
    if (process.env.REPO_NAME) {
      safeName = process.env.REPO_NAME;
    } else {
      const rawName = this.packageJson?.name || path.basename(this.rootPath);
      // @scope/pkg -> pkg, pkg -> pkg
      safeName = rawName;
      if (safeName.includes('/')) {
        safeName = safeName.split('/').pop() || safeName; // 마지막 세그먼트만 추출
      }
      safeName = safeName.replace(/^@/, '').replace(/[\/\\\s]+/g, '-');
    }
    
    // Use OUTPUT_DIR from env if available, otherwise use cwd
    const baseDir = process.env.OUTPUT_DIR || process.cwd();
    const outputPath = path.join(baseDir, `${safeName}-callGraph.json`);
    
    console.log(`[saveResults] Output directory: ${baseDir}`);
    console.log(`[saveResults] Output file path: ${outputPath}`);
    console.log(`[saveResults] Result data: files=${result.files}, functions=${result.functions}, edges=${result.edges}`);
    
    try {
    fs.writeFileSync(outputPath, JSON.stringify(result, null, 2));
    
    console.log('Analysis Complete!');
    console.log(`Saved to: ${outputPath}`);
    console.log(`\nStatistics:`);
    console.log(`   Main Module: ${result.main_module}`);
    console.log(`   Source Files: ${result.files}`);
    console.log(`   Functions/Methods: ${result.functions}`);
    console.log(`   Call Graph Entries: ${result.call_graph.length}`);
    console.log(`   Total Edges: ${result.edges}`);
    console.log(`   External Dependencies: ${result.packages.length}`);
    console.log(`\nPerformance Cache Statistics:`);
    console.log(`   Symbol Analysis Cache: ${this.symbolAnalysisCache.size} entries`);
    console.log(`   Type Info Cache: ${this.typeInfoCache.size} entries`);
    const totalCacheEntries = this.symbolAnalysisCache.size + this.typeInfoCache.size;
    if (totalCacheEntries > 0) {
      console.log(`   Total Cached Entries: ${totalCacheEntries}`);
    }
    
    if (result.packages.length > 0) {
      console.log(`\nExternal Dependencies:`);
      result.packages.slice(0, 10).forEach(pkg => {
        const version = externalDependencies[pkg] || 'unknown';
        console.log(`   - ${pkg}@${version}`);
      });
      if (result.packages.length > 10) {
        console.log(`   ... and ${result.packages.length - 10} more`);
        }
      }
    } catch (error) {
      // 파일 저장 실패 시에도 최소한의 결과라도 저장 시도
      console.error(`Error saving call graph to ${outputPath}:`, error instanceof Error ? error.message : String(error));
      try {
        // 빈 결과라도 저장하여 파일이 생성되도록 함
        const minimalResult = {
          main_module: this.packageJson?.name || 'unknown',
          files: 0,
          functions: 0,
          edges: 0,
          call_graph: [],
          external_dependencies: {},
          packages: [],
          dependencies: this.packageJson?.dependencies || {},
          error: error instanceof Error ? error.message : String(error)
        };
        fs.writeFileSync(outputPath, JSON.stringify(minimalResult, null, 2));
        console.log(`Saved minimal result to: ${outputPath}`);
      } catch (fallbackError) {
        console.error(`Failed to save even minimal result:`, fallbackError instanceof Error ? fallbackError.message : String(fallbackError));
      }
    }
  }

  private getExternalDependencies(): Record<string, string> {
    const deps: Record<string, string> = {};
    
    // package.json에서 실제 버전 정보 수집
    const allDependencies: Record<string, string> = {};
    
    if (this.packageJson) {
      // dependencies와 devDependencies 병합
      Object.assign(allDependencies, this.packageJson.dependencies || {});
      Object.assign(allDependencies, this.packageJson.devDependencies || {});
      Object.assign(allDependencies, this.packageJson.peerDependencies || {});
      Object.assign(allDependencies, this.packageJson.optionalDependencies || {});
    }
    
    // call graph에서 발견된 외부 패키지들의 버전 정보 매핑
    for (const entry of this.callGraphMap.values()) {
      for (const edge of entry.edges) {
        if (edge.isExternal && edge.packageName) {
          // package.json에서 실제 버전 찾기
          const version = allDependencies[edge.packageName] || 'unknown';
          deps[edge.packageName] = version;
        }
      }
    }
    
    return deps;
  }
}

// CLI 실행
async function main() {
  const projectPath = process.argv[2];
  if (!projectPath) {
    console.error('Usage: npx ts-node tsCallGraph.ts <project-path> [--analyze-node-modules]');
    process.exit(1);
  }

  const analyzeNodeModules = process.argv.includes('--analyze-node-modules');
  const analyzer = new TypeScriptCallGraphAnalyzer(projectPath, { analyzeNodeModules });
  await analyzer.analyze();
}

// CLI 실행
main().catch(console.error);

export { TypeScriptCallGraphAnalyzer };
