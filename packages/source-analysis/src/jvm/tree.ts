import type { Node } from "web-tree-sitter";

/**
 * A plain copy of the part of a tree-sitter syntax tree the JVM rules read. The WASM nodes are
 * slow to walk repeatedly and must be freed with their tree, so the tree is copied once, in one
 * iterative pass (no recursion: a 10 000-term `+` chain must not overflow the stack), and the
 * analyzers then work on ordinary objects. Positions are UTF-16 offsets into `source`.
 */
export interface AstNode {
  type: string;
  /** Field name this node has in its parent (`name`, `value`, `condition`, ...), or "". */
  field: string;
  start: number;
  end: number;
  /** 1-based line of the start. */
  line: number;
  /** Named children, plus the operator tokens (`+`, `+=`, `!`, `in`, ...) between them. */
  children: AstNode[];
  /** Anonymous (operator or keyword) token. */
  anonymous: boolean;
}

/** A tree this large is not copied (a 1 MiB file has far fewer nodes). */
export const MAX_AST_NODES = 3_000_000;

const OPERATOR_TOKEN = /^(?:[-+*/%=!<>&|?:^~]+|in|!in|is|!is|as|as\?)$/;

export interface AstResult {
  root: AstNode;
  source: string;
  /** The copy stopped at MAX_AST_NODES; the rest of the file was not analyzed. */
  truncated: boolean;
}

/** Operator and keyword tokens of PHP that are kept as anonymous children (`.`, `??`, `and`, ...). */
export const PHP_OPERATOR_TOKEN =
  /^(?!(?:->|\?->|=>|::|\.\.\.)$)(?:[-+*/%=!<>&|?:^~.]+|and|or|xor|instanceof)$/;

export function toAst(
  root: Node,
  source: string,
  /** Which anonymous tokens are copied; the default suits Java and Kotlin. */
  operatorToken: RegExp = OPERATOR_TOKEN,
): AstResult {
  const cursor = root.walk();
  try {
    const make = (field: string, anonymous: boolean): AstNode => ({
      type: cursor.nodeType,
      field,
      start: cursor.startIndex,
      end: cursor.endIndex,
      line: cursor.startPosition.row + 1,
      children: [],
      anonymous,
    });
    const top = make("", false);
    if (!cursor.gotoFirstChild()) return { root: top, source, truncated: false };
    const stack: AstNode[] = [top];
    let count = 1;
    let truncated = false;
    for (;;) {
      const parent = stack[stack.length - 1] as AstNode;
      const named = cursor.nodeIsNamed;
      let node: AstNode | null = null;
      if (named || operatorToken.test(cursor.nodeType)) {
        if (count >= MAX_AST_NODES) {
          truncated = true;
          break;
        }
        count += 1;
        node = make(cursor.currentFieldName ?? "", !named);
        parent.children.push(node);
      }
      if (node !== null && named && cursor.gotoFirstChild()) {
        stack.push(node);
        continue;
      }
      let finished = false;
      while (!cursor.gotoNextSibling()) {
        if (!cursor.gotoParent()) {
          finished = true;
          break;
        }
        stack.pop();
        if (stack.length === 0) {
          finished = true;
          break;
        }
      }
      if (finished) break;
    }
    return { root: top, source, truncated };
  } finally {
    cursor.delete();
  }
}

/** Source text of a node. */
export function textOf(ast: AstResult, node: AstNode): string {
  return ast.source.slice(node.start, node.end);
}
