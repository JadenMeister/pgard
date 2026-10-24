import ts from "typescript-api";

const SYNTHETIC_NAMES: Partial<Record<ts.ScriptKind, string>> = {
  [ts.ScriptKind.TS]: "/pgard-input.ts",
  [ts.ScriptKind.TSX]: "/pgard-input.tsx",
  [ts.ScriptKind.JS]: "/pgard-input.js",
  [ts.ScriptKind.JSX]: "/pgard-input.jsx",
};

/** File name the analyzed source is parsed under, so a one-file program accepts it. */
export function syntheticFileName(scriptKind: ts.ScriptKind): string {
  return SYNTHETIC_NAMES[scriptKind] ?? "/pgard-input.jsx";
}

const LOGICAL_ASSIGNMENTS = new Set([
  ts.SyntaxKind.BarBarEqualsToken,
  ts.SyntaxKind.AmpersandAmpersandEqualsToken,
  ts.SyntaxKind.QuestionQuestionEqualsToken,
]);

function isAssignmentOperator(kind: ts.SyntaxKind): boolean {
  return kind >= ts.SyntaxKind.FirstAssignment && kind <= ts.SyntaxKind.LastAssignment;
}

function skipParentheses(node: ts.Node): ts.Node {
  let current = node;
  while (ts.isParenthesizedExpression(current.parent)) current = current.parent;
  return current;
}

/**
 * True when `reference` sits inside a destructuring target (`[h] = a`, `({ h } = o)`,
 * `for ([h] of a)`), so its value comes from elsewhere.
 */
function isInDestructuringTarget(reference: ts.Identifier): boolean {
  let current: ts.Node = reference;
  let isInPattern = false;
  for (;;) {
    const parent = current.parent;
    if (ts.isParenthesizedExpression(parent)) {
      current = parent;
      continue;
    }
    if (
      ts.isArrayLiteralExpression(parent) ||
      ts.isObjectLiteralExpression(parent) ||
      ts.isSpreadElement(parent) ||
      ts.isSpreadAssignment(parent) ||
      ts.isShorthandPropertyAssignment(parent) ||
      (ts.isPropertyAssignment(parent) && parent.initializer === current) ||
      // A default inside a pattern: `[h = x] = a`, `({ k: h = x } = o)`.
      (ts.isBinaryExpression(parent) &&
        parent.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        parent.left === current &&
        (ts.isArrayLiteralExpression(parent.parent) ||
          (ts.isPropertyAssignment(parent.parent) && parent.parent.initializer === parent)))
    ) {
      isInPattern = true;
      current = parent;
      continue;
    }
    if (!isInPattern) return false;
    if (
      ts.isBinaryExpression(parent) &&
      isAssignmentOperator(parent.operatorToken.kind) &&
      parent.left === current
    ) {
      return true;
    }
    if (
      (ts.isForOfStatement(parent) || ts.isForInStatement(parent)) &&
      parent.initializer === current
    ) {
      return true;
    }
    return false;
  }
}

/** True for an identifier that names a property, never a variable (`o.h`, `{ h: 1 }`). */
function isPropertyName(node: ts.Identifier): boolean {
  const parent = node.parent;
  return (
    (ts.isPropertyAccessExpression(parent) && parent.name === node) ||
    ((ts.isPropertyAssignment(parent) ||
      ts.isPropertyDeclaration(parent) ||
      ts.isMethodDeclaration(parent) ||
      ts.isPropertySignature(parent) ||
      ts.isMethodSignature(parent) ||
      ts.isGetAccessorDeclaration(parent) ||
      ts.isSetAccessorDeclaration(parent)) &&
      parent.name === node) ||
    (ts.isQualifiedName(parent) && parent.right === node)
  );
}

/**
 * Decides whether an identifier at an HTML sink holds only sanitized values. The identifier is
 * resolved to its declaration with the TypeScript checker of a one-file program (no lib, no
 * module resolution), so shadowing, closures and hoisting follow the language's scoping rules.
 *
 * Sanitized means: the resolved symbol is declared only by plain `var`/`let`/`const`
 * declarations whose initializers (if any) are sanitizer calls, and every write to it in the
 * file (`=`, `||=`/`&&=`/`??=` with a sanitizer call; anything else disqualifies, including
 * compound operators, `++`/`--`, for-in/for-of targets and destructuring targets) is a sanitizer
 * call. Imports, parameters, catch and loop variables, functions, classes, globals and
 * unresolved names are never sanitized, and nothing is when the file uses direct `eval` or
 * `with`. Any doubt keeps the finding: a missed XSS is worse than a low-confidence report.
 */
export function createSanitizedBindingCheck(
  sourceFile: ts.SourceFile,
  isSanitizerCall: (expression: ts.Expression) => boolean,
): (identifier: ts.Identifier) => boolean {
  let checker: ts.TypeChecker | null = null;
  const cache = new Map<ts.Symbol, boolean>();
  let identifiersByText: Map<string, ts.Identifier[]> | null = null;
  // References of each symbol. Each name's identifiers are resolved once, on first use, so the
  // total work stays linear in the file size however many symbols share a name.
  const referencesBySymbol = new Map<ts.Symbol, ts.Identifier[]>();
  const resolvedNames = new Set<string>();
  // Direct `eval(...)` or `with` can write any variable without a visible assignment.
  let hasDynamicScope = false;

  const getChecker = (): ts.TypeChecker => {
    if (checker) return checker;
    const host: ts.CompilerHost = {
      getSourceFile: (fileName) => (fileName === sourceFile.fileName ? sourceFile : undefined),
      getDefaultLibFileName: () => "/lib.d.ts",
      writeFile: () => undefined,
      getCurrentDirectory: () => "/",
      getCanonicalFileName: (fileName) => fileName,
      useCaseSensitiveFileNames: () => true,
      getNewLine: () => "\n",
      fileExists: (fileName) => fileName === sourceFile.fileName,
      readFile: () => undefined,
    };
    const program = ts.createProgram({
      rootNames: [sourceFile.fileName],
      options: {
        noLib: true,
        noResolve: true,
        allowJs: true,
        checkJs: false,
        jsx: ts.JsxEmit.Preserve,
        types: [],
        noEmit: true,
      },
      host,
    });
    checker = program.getTypeChecker();
    return checker;
  };

  const identifiersNamed = (text: string): ts.Identifier[] => {
    if (!identifiersByText) {
      const index = new Map<string, ts.Identifier[]>();
      const visit = (node: ts.Node): void => {
        if (
          ts.isWithStatement(node) ||
          (ts.isCallExpression(node) &&
            ts.isIdentifier(node.expression) &&
            node.expression.text === "eval")
        ) {
          hasDynamicScope = true;
        }
        if (ts.isIdentifier(node) && !isPropertyName(node)) {
          const list = index.get(node.text) ?? [];
          list.push(node);
          index.set(node.text, list);
        }
        ts.forEachChild(node, visit);
      };
      visit(sourceFile);
      identifiersByText = index;
    }
    return identifiersByText.get(text) ?? [];
  };

  const referencesOf = (symbol: ts.Symbol, name: string): ts.Identifier[] => {
    if (!resolvedNames.has(name)) {
      resolvedNames.add(name);
      for (const identifier of identifiersNamed(name)) {
        const resolved = symbolOf(identifier);
        if (!resolved) continue;
        const list = referencesBySymbol.get(resolved) ?? [];
        list.push(identifier);
        referencesBySymbol.set(resolved, list);
      }
    }
    return referencesBySymbol.get(symbol) ?? [];
  };

  const symbolOf = (identifier: ts.Identifier): ts.Symbol | undefined => {
    const typeChecker = getChecker();
    if (
      ts.isShorthandPropertyAssignment(identifier.parent) &&
      identifier.parent.name === identifier
    ) {
      return typeChecker.getShorthandAssignmentValueSymbol(identifier.parent);
    }
    return typeChecker.getSymbolAtLocation(identifier);
  };

  const isDeclarationSanitized = (declaration: ts.Declaration): boolean => {
    if (!ts.isVariableDeclaration(declaration) || !ts.isIdentifier(declaration.name)) return false;
    const list = declaration.parent;
    if (!ts.isVariableDeclarationList(list)) return false;
    const owner = list.parent;
    if (ts.isForOfStatement(owner) || ts.isForInStatement(owner)) return false;
    if (!ts.isVariableStatement(owner) && !ts.isForStatement(owner)) return false;
    return declaration.initializer === undefined || isSanitizerCall(declaration.initializer);
  };

  /** `null` for a read, `true` for a sanitized write, `false` for any other write. */
  const writeKind = (reference: ts.Identifier): boolean | null => {
    if (isInDestructuringTarget(reference)) return false;
    const outer = skipParentheses(reference);
    const parent = outer.parent;
    if (
      (ts.isPrefixUnaryExpression(parent) || ts.isPostfixUnaryExpression(parent)) &&
      (parent.operator === ts.SyntaxKind.PlusPlusToken ||
        parent.operator === ts.SyntaxKind.MinusMinusToken)
    ) {
      return false;
    }
    if (
      (ts.isForOfStatement(parent) || ts.isForInStatement(parent)) &&
      parent.initializer === outer
    ) {
      return false;
    }
    if (
      ts.isBinaryExpression(parent) &&
      parent.left === outer &&
      isAssignmentOperator(parent.operatorToken.kind)
    ) {
      const kind = parent.operatorToken.kind;
      const isPlainOrLogical = kind === ts.SyntaxKind.EqualsToken || LOGICAL_ASSIGNMENTS.has(kind);
      return isPlainOrLogical && isSanitizerCall(parent.right);
    }
    return null;
  };

  const evaluate = (symbol: ts.Symbol, name: string): boolean => {
    identifiersNamed(name); // also detects dynamic scope
    if (hasDynamicScope) return false;
    const declarations = symbol.getDeclarations() ?? [];
    if (declarations.length === 0 || (symbol.flags & ts.SymbolFlags.Alias) !== 0) return false;
    if (!declarations.every(isDeclarationSanitized)) return false;
    let hasSanitizedValue = declarations.some(
      (declaration) =>
        ts.isVariableDeclaration(declaration) && declaration.initializer !== undefined,
    );
    for (const reference of referencesOf(symbol, name)) {
      const kind = writeKind(reference);
      if (kind === false) return false;
      if (kind === true) hasSanitizedValue = true;
    }
    return hasSanitizedValue;
  };

  return (identifier) => {
    const symbol = symbolOf(identifier);
    if (!symbol) return false;
    const cached = cache.get(symbol);
    if (cached !== undefined) return cached;
    const result = evaluate(symbol, identifier.text);
    cache.set(symbol, result);
    return result;
  };
}
