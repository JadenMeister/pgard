import type { Expr, Stmt, Unit } from "./ir.js";

/**
 * Calls `onExpr` for every expression and `onStmt` for every statement of a file. A long `+`
 * chain is followed along its left side in a loop, not by recursion.
 */
export function walkUnit(
  unit: Unit,
  onExpr: (expr: Expr) => void,
  onStmt: (stmt: Stmt) => void,
): void {
  const stmts = (list: readonly Stmt[] | null): void => {
    for (const stmt of list ?? []) stmtVisit(stmt);
  };
  const exprs = (list: ReadonlyArray<Expr | null | undefined>): void => {
    for (const expr of list) if (expr !== null && expr !== undefined) exprVisit(expr);
  };
  function exprVisit(expr: Expr): void {
    let current: Expr = expr;
    while (current.k === "bin") {
      onExpr(current);
      exprVisit(current.right);
      current = current.left;
    }
    onExpr(current);
    switch (current.k) {
      case "member":
        exprVisit(current.obj);
        break;
      case "index":
        exprs([current.obj, current.index]);
        break;
      case "call":
        exprs([current.recv, ...current.args]);
        break;
      case "new":
        exprs(current.args);
        break;
      case "tmpl":
        exprs(current.parts.map((part) => (typeof part === "string" ? null : part)));
        break;
      case "cond":
        exprs([current.test, current.a, current.b]);
        break;
      case "alt":
        exprs(current.options);
        break;
      case "cast":
        exprVisit(current.expr);
        break;
      case "array":
        exprs(current.elems);
        break;
      case "lambda":
        stmts(current.body);
        break;
      case "other":
        exprs(current.kids);
        break;
      default:
        break;
    }
  }
  function stmtVisit(stmt: Stmt): void {
    onStmt(stmt);
    switch (stmt.s) {
      case "local":
        exprs([stmt.init]);
        break;
      case "assign":
        exprs([stmt.target, stmt.value]);
        break;
      case "expr":
        exprVisit(stmt.expr);
        break;
      case "if":
        exprVisit(stmt.test);
        stmts(stmt.then);
        stmts(stmt.else);
        break;
      case "loop":
        stmts(stmt.init);
        exprs([stmt.test, stmt.each?.iter]);
        stmts(stmt.update);
        stmts(stmt.body);
        break;
      case "block":
        stmts(stmt.body);
        break;
      case "arms":
        exprs([stmt.subject]);
        for (const arm of stmt.arms) stmts(arm.body);
        break;
      case "exit":
        exprs([stmt.value]);
        break;
      case "assert":
        exprVisit(stmt.test);
        break;
    }
  }
  for (const cls of [unit.top, ...unit.classes]) {
    for (const field of cls.fields.values()) exprs([field.init]);
    stmts(cls.initializers);
    for (const method of cls.methods) stmts(method.body);
  }
}
